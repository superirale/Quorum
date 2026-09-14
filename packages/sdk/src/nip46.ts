/**
 * NIP-46 — the key is somewhere else, and this process never sees it.
 *
 * Deferred from M3 and named in three READMEs as the thing that removes
 * plaintext secret keys from `apps/console` and the dev key from `apps/web`. It
 * waited for M9 for one reason: the transport is NIP-44, and until this
 * milestone Quorum could not do NIP-44.
 *
 * ## Shape
 *
 * Two keypairs, and keeping them straight is most of understanding this file:
 *
 *   **the user key** — the identity everything is signed as. Lives in the
 *   bunker. We only ever learn its pubkey.
 *
 *   **the client key** — a throwaway generated here, used to address and
 *   encrypt the RPC. It signs the kind 24133 envelopes and nothing else. It is
 *   not an identity; losing it costs a reconnect.
 *
 * A request is a kind 24133 event, `p`-tagged to the *remote signer pubkey*
 * (which is usually but not always the user pubkey), whose content is a
 * NIP-44 payload of `{id, method, params}` under the client↔signer conversation
 * key. The response comes back the same way, `p`-tagged to the client pubkey.
 *
 * ## What this does not do
 *
 * **No nostrconnect:// flow.** That is the other direction — client publishes
 * an invitation, bunker connects to it — and it needs a UI to show a QR code.
 * `bunker://` covers the console and covers a browser paste box, which is both
 * places Quorum needs it today.
 *
 * **No secret storage.** `Nip46Signer` holds a connection, not a credential.
 * Persisting the client key and the bunker URI is the caller's job, because the
 * console and the browser store things very differently and neither should
 * inherit the other's idea of safe.
 *
 * ## The auth challenge is a real UX obligation
 *
 * A bunker may answer any request with `auth_url` instead of a result, meaning
 * "a human must approve this in a browser first". Swallowing that turns every
 * first signature into a silent thirty-second hang ending in a timeout. So
 * `onAuth` is a constructor option and the error thrown when it is absent says
 * what the caller failed to handle, not what the bunker failed to return.
 */

import { verifyEvent, type NostrEvent, type UnsignedEvent } from '@quorum/protocol'
import { RelayClient, type Logger } from './client.ts'
import { LocalSigner, generateSecretKey, type Signer } from './signer.ts'

/**
 * NIP-46's RPC kind. Ephemeral, so no relay keeps a record of a session — and
 * that is the right range for it: a stored `sign_event` request replayed later
 * would be a bunker asked to sign the same thing twice, months apart.
 */
export const NIP46_KIND = 24133

/** A parsed `bunker://` connection string. */
export interface BunkerUri {
  /** The pubkey to address RPC to. Not necessarily the user pubkey. */
  remote: string
  relays: string[]
  /** Handed back in `connect` so the bunker can recognise an expected client. */
  secret?: string
}

/**
 * Parse `bunker://<remote-pubkey>?relay=<url>&relay=<url>&secret=<s>`.
 *
 * Throws on a missing relay rather than defaulting to the workspace relay. A
 * bunker is reached on the relays its operator chose; guessing would send a
 * request containing a NIP-44 payload to a relay the bunker is not watching,
 * and the symptom would be an unexplained timeout rather than a bad URI.
 */
export function parseBunkerUri(uri: string): BunkerUri {
  const trimmed = uri.trim()
  if (!trimmed.startsWith('bunker://')) {
    throw new Error(`not a bunker URI: ${trimmed.slice(0, 20)}…`)
  }
  // `new URL` mangles a non-special scheme's host case in some runtimes, so the
  // pubkey is taken from the raw string and only the query is parsed.
  const rest = trimmed.slice('bunker://'.length)
  const [host, query = ''] = rest.split('?', 2)
  const remote = (host ?? '').toLowerCase()
  if (!/^[0-9a-f]{64}$/.test(remote)) {
    throw new Error('a bunker URI must name a 64-hex remote signer pubkey')
  }
  const params = new URLSearchParams(query)
  const relays = params.getAll('relay').filter(Boolean)
  if (relays.length === 0) throw new Error('a bunker URI must carry at least one ?relay=')
  const secret = params.get('secret') ?? undefined
  return { remote, relays, secret }
}

interface Rpc {
  id: string
  method: string
  params: string[]
}

interface RpcResponse {
  id: string
  result?: string
  error?: string
}

export interface Nip46Options {
  /** Where to reach the bunker. Only the first is used; the rest are fallbacks. */
  uri: string | BunkerUri
  /** Reuse a client key across restarts so the bunker's approvals stick. */
  clientSecretKey?: string
  /**
   * Called when the bunker wants a human in a browser.
   *
   * Absent, the first request that triggers a challenge fails loudly. That is
   * deliberately not a silent wait: a hung `approve` with no explanation is the
   * single most confusing failure this transport can produce.
   */
  onAuth?: (url: string) => void
  requestTimeoutMs?: number
  log?: Logger
}

/**
 * A signer backed by a remote bunker.
 *
 * Connect once with `open()`; every method after that is a round trip. Nothing
 * else in the SDK changes — which is the whole point of `Signer` being four
 * methods wide, and is the claim this class exists to test.
 */
export class Nip46Signer implements Signer {
  private readonly bunker: BunkerUri
  private readonly client: RelayClient
  private readonly clientSigner: LocalSigner
  private readonly pending = new Map<string, { resolve: (r: RpcResponse) => void }>()
  private readonly timeoutMs: number
  private readonly onAuth: ((url: string) => void) | undefined
  private readonly log: Logger

  private userPubkey: string | undefined
  private nextId = 0

  private constructor(
    options: Nip46Options,
    bunker: BunkerUri,
    clientSigner: LocalSigner,
    clientSecret: string,
  ) {
    this.bunker = bunker
    this.clientSigner = clientSigner
    this.#clientSecret = clientSecret
    this.timeoutMs = options.requestTimeoutMs ?? 60_000
    this.onAuth = options.onAuth
    this.log = options.log ?? console
    this.client = new RelayClient({
      url: bunker.relays[0]!,
      // No signer: a bunker relay that demanded NIP-42 would want the *client*
      // key to authenticate, and the client key is not an identity anyone has
      // granted anything to. Authenticating as it would be meaningless.
      reconnect: { minDelayMs: 500, maxDelayMs: 5_000 },
      log: this.log,
    })
  }

  /** The client pubkey. Useful for an operator adding this session to a bunker allowlist. */
  get clientPubkey(): string {
    return this.clientSigner.publicKey
  }

  /**
   * The client secret, so a caller can persist it and keep the session.
   *
   * A private field rather than a property, so it does not turn up in a JSON
   * dump of somebody's config the way an ordinary one would — the same reason
   * `LocalSigner` hides its key. This one is far less dangerous to leak: it
   * grants nothing except the right to ask a bunker that has already approved
   * it, and the bunker can revoke that.
   */
  readonly #clientSecret: string

  get clientSecretKey(): string {
    return this.#clientSecret
  }

  /**
   * Connect, handshake, and learn the user pubkey.
   *
   * `connect` is sent before `get_public_key` because a bunker may refuse
   * everything until it has been sent, and because that is when the auth
   * challenge — if there is one — happens. Doing it at open time means a human
   * approves once, at the moment they asked to connect, rather than at some
   * later moment when an agent happened to need a signature.
   */
  static async open(options: Nip46Options): Promise<Nip46Signer> {
    const bunker = typeof options.uri === 'string' ? parseBunkerUri(options.uri) : options.uri
    const secret = options.clientSecretKey ?? generateSecretKey()
    const signer = new Nip46Signer(options, bunker, LocalSigner.fromHex(secret), secret)

    await signer.client.connect()
    signer.listen()

    const params = bunker.secret ? [bunker.remote, bunker.secret] : [bunker.remote]
    await signer.request('connect', params)
    signer.userPubkey = await signer.request('get_public_key', [])
    return signer
  }

  /** Close the bunker connection. The workspace relay connection is separate. */
  close(): void {
    this.client.close()
  }

  async pubkey(): Promise<string> {
    if (!this.userPubkey) throw new Error('nip46: not connected; call Nip46Signer.open()')
    return this.userPubkey
  }

  /**
   * Ask the bunker to sign.
   *
   * The returned event is checked the same three ways `Nip07Signer` checks one,
   * and for a stronger reason: a bunker is a remote service on somebody else's
   * machine. If it signs as a different key, or edits a field on the way past,
   * the failure we want is an exception here — not a production approval
   * attributed to a pubkey the human did not think they were using.
   */
  async sign(event: UnsignedEvent): Promise<NostrEvent> {
    const expected = await this.pubkey()
    const result = await this.request('sign_event', [JSON.stringify({ ...event, pubkey: expected })])
    const signed = JSON.parse(result) as NostrEvent

    if (signed.pubkey !== expected) {
      throw new Error(`nip46: bunker signed as ${signed.pubkey}, expected ${expected}`)
    }
    if (signed.kind !== event.kind || signed.content !== event.content) {
      throw new Error('nip46: bunker altered the event before signing it')
    }
    if (!verifyEvent(signed)) {
      throw new Error('nip46: bunker returned an event with an invalid id or signature')
    }
    return signed
  }

  async nip44Encrypt(peer: string, plaintext: string): Promise<string> {
    return this.request('nip44_encrypt', [peer, plaintext])
  }

  async nip44Decrypt(peer: string, payload: string): Promise<string> {
    return this.request('nip44_decrypt', [peer, payload])
  }

  /** A cheap liveness check, for a console that wants to say "connected". */
  async ping(): Promise<string> {
    return this.request('ping', [])
  }

  private listen(): void {
    this.client.subscribe(
      [{ kinds: [NIP46_KIND], '#p': [this.clientSigner.publicKey] }],
      {
        onEvent: (event) => void this.receive(event),
        onClosed: (reason) => this.log.error(`nip46: bunker subscription closed: ${reason}`),
      },
    )
  }

  private async receive(event: NostrEvent): Promise<void> {
    if (event.pubkey !== this.bunker.remote) return
    let response: RpcResponse
    try {
      response = JSON.parse(await this.clientSigner.nip44Decrypt(event.pubkey, event.content))
    } catch (error) {
      this.log.error('nip46: could not read a response from the bunker', error)
      return
    }

    // `auth_url` is a result, not an error, and it arrives *instead of* the
    // answer — the bunker will send the real response once the human has
    // clicked through. So this resolves nothing and leaves the request pending.
    if (response.result === 'auth_url' && response.error) {
      if (!this.onAuth) {
        const waiting = this.pending.get(response.id)
        this.pending.delete(response.id)
        waiting?.resolve({
          id: response.id,
          error: `the bunker needs a human to approve this at ${response.error}, and no onAuth handler was given`,
        })
        return
      }
      this.onAuth(response.error)
      return
    }

    const waiting = this.pending.get(response.id)
    if (!waiting) return
    this.pending.delete(response.id)
    waiting.resolve(response)
  }

  private async request(method: string, params: string[]): Promise<string> {
    const id = `${Date.now().toString(36)}-${this.nextId++}`
    const rpc: Rpc = { id, method, params }

    const content = await this.clientSigner.nip44Encrypt(this.bunker.remote, JSON.stringify(rpc))
    const event = await this.clientSigner.sign({
      pubkey: this.clientSigner.publicKey,
      created_at: Math.floor(Date.now() / 1000),
      kind: NIP46_KIND,
      tags: [['p', this.bunker.remote]],
      content,
    })

    const answer = new Promise<RpcResponse>((resolve) => {
      this.pending.set(id, { resolve })
    })

    // A timeout here is nearly always one of two things, and the message names
    // both — because the third possibility, "the bunker is broken", is the one
    // people assume and the one it almost never is.
    let timer: ReturnType<typeof setTimeout> | undefined
    const expiry = new Promise<never>((_, reject) => {
      timer = setTimeout(
        () =>
          reject(
            new Error(
              `nip46: the bunker did not answer \`${method}\` within ${this.timeoutMs}ms — it may not be watching ${this.bunker.relays[0]}, or it may be waiting for a human to approve the session`,
            ),
          ),
        this.timeoutMs,
      )
    })

    try {
      await this.client.publish(event)
      const response = await Promise.race([answer, expiry])
      if (response.error) throw new Error(`nip46: ${method} failed: ${response.error}`)
      return response.result ?? ''
    } finally {
      clearTimeout(timer)
      this.pending.delete(id)
    }
  }
}

/** Build a `bunker://` URI. Used by test bunkers and by anything that hosts one. */
export function bunkerUri(remote: string, relays: string[], secret?: string): string {
  const params = new URLSearchParams()
  for (const relay of relays) params.append('relay', relay)
  if (secret) params.set('secret', secret)
  return `bunker://${remote}?${params.toString()}`
}
