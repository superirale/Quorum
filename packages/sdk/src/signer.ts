/**
 * Signers — the only place in Quorum that touches a private key.
 *
 * An agent's identity *is* its keypair, so this is the file where a mistake is
 * unrecoverable: there is no server that can rotate a bot token, and every
 * approval the agent ever verified was verified against a pubkey someone now
 * has the key for. The abstraction is therefore two methods wide, so that the
 * key can live somewhere this process cannot read it.
 *
 *   LocalSigner   the key is in memory here. Fine for a server-side agent whose
 *                 process boundary is the security boundary.
 *   Nip07Signer   a browser extension holds the key; we send it events to sign.
 *   Nip46Signer   a remote bunker holds the key. NOT IMPLEMENTED — it is a
 *                 NIP-44-encrypted RPC, and NIP-44 lands in M9. Nothing else in
 *                 the SDK needs to change when it does, which is the point of
 *                 `Signer` being this small.
 *
 * `@quorum/protocol` deliberately stops at unsigned events for the same reason.
 */

import { schnorr } from '@noble/curves/secp256k1.js'
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js'
import { computeId, verifyEvent, type NostrEvent, type UnsignedEvent } from '@quorum/protocol'
import { bech32 } from '@scure/base'

/**
 * Everything the SDK is allowed to know about a key.
 *
 * Both methods are async because the interesting implementations are: a browser
 * extension prompts a human, a bunker makes a network round trip. Code written
 * against a synchronous signer would have to be rewritten to use either.
 */
export interface Signer {
  /** The public key, 64 lowercase hex characters. */
  pubkey(): Promise<string>
  /** Attach `id` and `sig`. Implementations MUST NOT alter the other fields. */
  sign(event: UnsignedEvent): Promise<NostrEvent>
}

/** 32 random bytes, as hex. Use a real key management story in production. */
export function generateSecretKey(): string {
  return bytesToHex(randomBytes(32))
}

/**
 * A signer holding the key in this process's memory.
 *
 * The key is stored as bytes in a private field and every stringification path
 * is overridden to redact it. That is not paranoia about a determined attacker
 * who already has heap access — it is about the ordinary way secrets leak,
 * which is an object landing in a log line, an error report or a JSON dump of
 * some config someone is debugging.
 */
export class LocalSigner implements Signer {
  readonly #secret: Uint8Array
  readonly #pubkey: string

  private constructor(secret: Uint8Array) {
    if (secret.length !== 32) throw new Error(`secret key must be 32 bytes, got ${secret.length}`)
    this.#secret = secret
    this.#pubkey = bytesToHex(schnorr.getPublicKey(secret))
  }

  static generate(): LocalSigner {
    return new LocalSigner(randomBytes(32))
  }

  static fromHex(hex: string): LocalSigner {
    if (!/^[0-9a-fA-F]{64}$/.test(hex)) throw new Error('secret key must be 64 hex characters')
    return new LocalSigner(hexToBytes(hex.toLowerCase()))
  }

  /** A NIP-19 `nsec1…` key, as every Nostr client shows it to a human. */
  static fromNsec(nsec: string): LocalSigner {
    const { prefix, words } = bech32.decode(nsec as `${string}1${string}`, 1000)
    if (prefix !== 'nsec') throw new Error(`expected an nsec, got a ${prefix}`)
    return new LocalSigner(Uint8Array.from(bech32.fromWords(words)))
  }

  /**
   * From an environment variable, accepting either encoding.
   *
   * Agents are processes, and a process gets its identity from its environment.
   * Making this one call means nobody writes the "is it hex or nsec" branch
   * themselves and gets it subtly wrong on the nsec path.
   */
  static fromEnv(name: string, env: Record<string, string | undefined> = process.env): LocalSigner {
    const value = env[name]?.trim()
    if (!value) throw new Error(`${name} is not set; an agent needs a key to have an identity`)
    return value.startsWith('nsec1') ? LocalSigner.fromNsec(value) : LocalSigner.fromHex(value)
  }

  /** Synchronous accessor, for the many places that just need the hex pubkey. */
  get publicKey(): string {
    return this.#pubkey
  }

  /** The NIP-19 form, for showing a human which agent this is. */
  get npub(): string {
    return bech32.encode('npub', bech32.toWords(hexToBytes(this.#pubkey)), 1000)
  }

  async pubkey(): Promise<string> {
    return this.#pubkey
  }

  async sign(event: UnsignedEvent): Promise<NostrEvent> {
    if (event.pubkey !== this.#pubkey) {
      throw new Error(
        `refusing to sign an event authored by ${event.pubkey || '(empty)'}: this signer is ${this.#pubkey}`,
      )
    }
    const id = computeId(event)
    return { ...event, id, sig: bytesToHex(schnorr.sign(id, this.#secret)) }
  }

  toJSON(): string {
    return `LocalSigner(${this.#pubkey})`
  }

  toString(): string {
    return this.toJSON()
  }

  /** `console.log` and `util.inspect` go through this. */
  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return this.toJSON()
  }
}

/** The subset of NIP-07 the SDK uses. Provided by a browser extension. */
export interface Nip07Provider {
  getPublicKey(): Promise<string>
  signEvent(event: UnsignedEvent): Promise<NostrEvent>
}

/**
 * A signer backed by a NIP-07 browser extension.
 *
 * The returned event is verified before it is handed back, which is not
 * ceremony: the extension is a separate program with its own update channel,
 * and if it ever signs with a different key or edits a field on the way past,
 * the failure we want is a thrown error here — not an event the relay rejects
 * for reasons nobody can trace, or worse, an approval attributed to a pubkey
 * the human did not think they were using.
 */
export class Nip07Signer implements Signer {
  private readonly provider: Nip07Provider
  private cached: string | undefined

  constructor(provider: Nip07Provider | undefined = (globalThis as { nostr?: Nip07Provider }).nostr) {
    if (!provider) throw new Error('no NIP-07 provider: window.nostr is undefined')
    this.provider = provider
  }

  /** True if an extension is present, so a client can offer the option. */
  static available(): boolean {
    return typeof (globalThis as { nostr?: Nip07Provider }).nostr?.signEvent === 'function'
  }

  async pubkey(): Promise<string> {
    this.cached ??= await this.provider.getPublicKey()
    return this.cached
  }

  async sign(event: UnsignedEvent): Promise<NostrEvent> {
    const expected = await this.pubkey()
    const signed = await this.provider.signEvent({ ...event, pubkey: expected })

    if (signed.pubkey !== expected) {
      throw new Error(`NIP-07 provider signed as ${signed.pubkey}, expected ${expected}`)
    }
    if (signed.kind !== event.kind || signed.content !== event.content) {
      throw new Error('NIP-07 provider altered the event before signing it')
    }
    if (!verifyEvent(signed)) {
      throw new Error('NIP-07 provider returned an event with an invalid id or signature')
    }
    return signed
  }
}
