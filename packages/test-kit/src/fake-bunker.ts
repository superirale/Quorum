/**
 * An in-process NIP-46 bunker, so both halves of the transport are testable.
 *
 * `Nip46Signer` is the interesting half and it is also the half that cannot be
 * tested alone: every method on it is a round trip, so a test with no bunker on
 * the other end can only assert that requests time out. Mocking the transport
 * instead would test the SDK against this author's idea of what a bunker does,
 * which is precisely the thing that needs checking.
 *
 * So this holds a real secret key, watches a real relay for kind 24133, and
 * decrypts with the same NIP-44 implementation the client encrypts with. It is
 * the smallest thing that is genuinely a bunker rather than a stub.
 *
 * # It can misbehave, and that is most of the point
 *
 * A bunker is a remote service on somebody else's machine, and `Nip46Signer`
 * checks three things about every event it gets back for that reason. Those
 * checks are unfalsifiable claims until something can sign as the wrong key or
 * edit an event on the way past — hence {@link FakeBunkerOptions.tamper} and
 * {@link FakeBunkerOptions.signAs}. The `auth_url` branch is the same: a
 * challenge is a normal thing for a bunker to send and a hard thing to produce
 * by hand, so {@link FakeBunkerOptions.authUrl} produces it.
 */

import { schnorr } from '@noble/curves/secp256k1.js'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import { randomBytes } from 'node:crypto'
import {
  computeId,
  conversationKey,
  nip44Decrypt,
  nip44Encrypt,
  verifyEvent,
  type NostrEvent,
  type UnsignedEvent,
} from '@quorum/protocol'
import WebSocket from 'ws'

/** NIP-46's RPC kind, repeated here so test-kit does not depend on the SDK. */
export const NIP46_KIND = 24133

export interface FakeBunkerOptions {
  /** The relay both sides meet on. */
  relay: string
  /** The user key this bunker holds. Generated if absent. */
  secretKey?: string
  /** Required in `connect` before anything else is answered. */
  secret?: string
  /**
   * Answer the first request of this method with `auth_url` instead of a
   * result, then answer it properly once {@link FakeBunker.approve} is called.
   */
  authUrl?: { method: string; url: string }
  /** Edit an event after signing it — what a hostile bunker would do. */
  tamper?: (event: NostrEvent) => NostrEvent
  /**
   * Sign with a different key while still reporting the real pubkey from
   * `get_public_key`. The hostile case: a bunker attributing a human's
   * production approval to a key they never agreed to use.
   */
  signAs?: string
}

interface Rpc {
  id: string
  method: string
  params: string[]
}

/** One request the bunker was asked to serve. The audit trail a test asserts on. */
export interface BunkerRequest {
  method: string
  params: string[]
  from: string
}

export class FakeBunker {
  readonly pubkey: string
  /** Every request seen, in arrival order, including ones held for approval. */
  readonly requests: BunkerRequest[] = []

  readonly #secret: string
  private readonly options: FakeBunkerOptions
  private readonly socket: WebSocket
  private readonly held = new Map<string, { rpc: Rpc; client: string }>()
  private challenged = new Set<string>()
  private connected = new Set<string>()
  private closed = false

  private constructor(options: FakeBunkerOptions, secret: string, socket: WebSocket) {
    this.options = options
    this.#secret = secret
    this.pubkey = bytesToHex(schnorr.getPublicKey(hexToBytes(secret)))
    this.socket = socket
  }

  static async start(options: FakeBunkerOptions): Promise<FakeBunker> {
    const secret = options.secretKey ?? bytesToHex(randomBytes(32))
    const socket = new WebSocket(options.relay)
    await new Promise<void>((resolve, reject) => {
      socket.once('open', () => resolve())
      socket.once('error', reject)
    })

    const bunker = new FakeBunker(options, secret, socket)
    socket.on('message', (raw) => bunker.receive(String(raw)))
    socket.send(
      JSON.stringify(['REQ', 'bunker', { kinds: [NIP46_KIND], '#p': [bunker.pubkey] }]),
    )
    return bunker
  }

  /** The `bunker://` string a client connects with. */
  get uri(): string {
    const params = new URLSearchParams()
    params.append('relay', this.options.relay)
    if (this.options.secret) params.set('secret', this.options.secret)
    return `bunker://${this.pubkey}?${params.toString()}`
  }

  /**
   * Release a request that was answered with `auth_url`.
   *
   * This is the human clicking through in a browser. The request is still
   * pending on the client side — `auth_url` resolves nothing — so answering it
   * now is what the real flow does, and a client that treated the challenge as
   * a failure would already have given up.
   */
  approve(): void {
    for (const [id, { rpc, client }] of this.held) {
      this.held.delete(id)
      void this.answer(client, { id: rpc.id, result: this.result(rpc, client) })
    }
  }

  close(): void {
    this.closed = true
    this.socket.close()
  }

  private receive(raw: string): void {
    if (this.closed) return
    let message: unknown[]
    try {
      message = JSON.parse(raw)
    } catch {
      return
    }
    if (message[0] !== 'EVENT' || typeof message[2] !== 'object') return
    const event = message[2] as NostrEvent
    if (event.kind !== NIP46_KIND || !verifyEvent(event)) return

    const key = conversationKey(this.#secret, event.pubkey)
    let rpc: Rpc
    try {
      rpc = JSON.parse(nip44Decrypt(event.content, key))
    } catch {
      return
    }
    this.requests.push({ method: rpc.method, params: rpc.params, from: event.pubkey })

    // The challenge fires once per method, not once per session: a bunker that
    // re-challenged every request would make `approve()` untestable, and one
    // that never challenged again would hide a client that only handles the
    // first.
    const challenge = this.options.authUrl
    if (challenge && challenge.method === rpc.method && !this.challenged.has(rpc.method)) {
      this.challenged.add(rpc.method)
      this.held.set(rpc.id, { rpc, client: event.pubkey })
      // `auth_url` goes in `result` and the URL in `error`, which reads
      // backwards and is what NIP-46 specifies. A client that looked for the
      // URL in `result` would silently treat the challenge as a signature.
      void this.answer(event.pubkey, { id: rpc.id, result: 'auth_url', error: challenge.url })
      return
    }

    if (this.options.secret && rpc.method !== 'connect' && !this.connected.has(event.pubkey)) {
      void this.answer(event.pubkey, { id: rpc.id, error: 'not connected' })
      return
    }

    try {
      void this.answer(event.pubkey, { id: rpc.id, result: this.result(rpc, event.pubkey) })
    } catch (error) {
      void this.answer(event.pubkey, { id: rpc.id, error: String(error) })
    }
  }

  private result(rpc: Rpc, client: string): string {
    switch (rpc.method) {
      case 'connect': {
        const [, offered] = rpc.params
        if (this.options.secret && offered !== this.options.secret) {
          throw new Error('the connect secret did not match')
        }
        this.connected.add(client)
        return 'ack'
      }
      case 'ping':
        return 'pong'
      case 'get_public_key':
        return this.pubkey
      case 'sign_event': {
        const draft = JSON.parse(rpc.params[0] ?? '{}') as UnsignedEvent
        const secret = this.options.signAs ?? this.#secret
        const unsigned: UnsignedEvent = {
          ...draft,
          pubkey: bytesToHex(schnorr.getPublicKey(hexToBytes(secret))),
        }
        const id = computeId(unsigned)
        const signed: NostrEvent = {
          ...unsigned,
          id,
          sig: bytesToHex(schnorr.sign(id, secret)),
        }
        return JSON.stringify(this.options.tamper ? this.options.tamper(signed) : signed)
      }
      case 'nip44_encrypt': {
        const [peer, plaintext] = rpc.params
        return nip44Encrypt(plaintext ?? '', conversationKey(this.#secret, peer ?? ''))
      }
      case 'nip44_decrypt': {
        const [peer, payload] = rpc.params
        return nip44Decrypt(payload ?? '', conversationKey(this.#secret, peer ?? ''))
      }
      default:
        throw new Error(`unsupported method ${rpc.method}`)
    }
  }

  private async answer(client: string, response: Record<string, string>): Promise<void> {
    const key = conversationKey(this.#secret, client)
    const draft: UnsignedEvent = {
      pubkey: this.pubkey,
      created_at: Math.floor(Date.now() / 1000),
      kind: NIP46_KIND,
      tags: [['p', client]],
      content: nip44Encrypt(JSON.stringify(response), key),
    }
    const id = computeId(draft)
    const event: NostrEvent = { ...draft, id, sig: bytesToHex(schnorr.sign(id, this.#secret)) }
    if (this.closed) return
    this.socket.send(JSON.stringify(['EVENT', event]))
  }
}
