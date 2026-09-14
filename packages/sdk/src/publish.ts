/**
 * Building, signing and publishing, in one place.
 *
 * Tag assembly is `@quorum/protocol`'s job and stays there — if the SDK grew
 * its own idea of which tags an event needs, "valid Quorum event" would have
 * two definitions and they would drift. What belongs here is the part the
 * protocol package deliberately refuses to do: reach a key, allocate a counter,
 * and put the result on a wire.
 */

import {
  build,
  isEphemeral,
  type BuildOptions,
  type EncMode,
  type NostrEvent,
  type UnsignedEvent,
} from '@quorum/protocol'
import type { RelayClient } from './client.ts'
import type { Counters } from './counter.ts'
import type { Signer } from './signer.ts'

/**
 * The encrypted-channel hook: what tags a kind needs, and how to seal it.
 *
 * An interface rather than a `ChannelCrypto` import, so `publish.ts` does not
 * depend on `channel.ts` depending on it back. Implemented by `ChannelCrypto`.
 */
export interface ChannelSealer {
  buildOptions(kind: number): { enc?: EncMode; epoch?: number }
  /**
   * Returns a promise because `mls` sealing cannot be synchronous.
   *
   * `nip44` sealing is a pure function of the event and a key, so `ChannelCrypto`
   * returns the event directly. A ratchet step is asynchronous, must be persisted
   * before the caller can publish, and has to consult the retry cache first — so
   * the narrower signature would have forced `MlsCrypto` to seal off the side of
   * the call and hand back a stale or half-written envelope. Widening the
   * interface rather than adding a second hook keeps one answer to "is this
   * channel encrypted, and how", which is the whole argument for the sealer
   * living on the `Publisher` at all.
   */
  seal(unsigned: UnsignedEvent): UnsignedEvent | Promise<UnsignedEvent>
}

/** What a caller supplies; identity, channel and counter come from the agent. */
export type PublishOptions = Omit<BuildOptions, 'pubkey' | 'group' | 'counter'> & {
  /** Override the agent's default channel. */
  group?: string
  /**
   * Use this counter instead of allocating one.
   *
   * Supplied when a `once()` retry has to rebuild an event byte-identically:
   * a fresh counter would change the id and the relay would store a second copy
   * of a message the agent already sent.
   */
  counter?: number
}

export interface PublisherDeps {
  client: RelayClient
  signer: Signer
  pubkey: string
  group: string
  counters: Counters
  /**
   * Encryption, if this channel has any.
   *
   * Deliberately here rather than at every call site. An encrypted channel
   * where *most* things are sealed is not an encrypted channel, and the way
   * that happens is one code path that forgot to pass a flag — so the flag does
   * not exist and the policy is consulted on every publish instead.
   */
  channel?: ChannelSealer
}

export class Publisher {
  private readonly deps: PublisherDeps

  constructor(deps: PublisherDeps) {
    this.deps = deps
  }

  /** Build → sign → publish → return the signed event. */
  async publish(options: PublishOptions): Promise<NostrEvent> {
    const event = await this.sign(options)
    await this.deps.client.publish(event)
    return event
  }

  /**
   * Everything but the wire. Useful for tests, and for computing an id first.
   *
   * Sealing sits between `build()` and `sign()`, and that is the only place it
   * can go. Before `build()` there are no tags to derive a nonce from and no
   * `alt` decision made; after `sign()` the id is already committed to the
   * plaintext. An explicit `enc` on the call wins over the channel policy, so a
   * caller can still publish an unsealed event on an encrypted channel — which
   * the key-management kinds have to do.
   */
  async sign(options: PublishOptions): Promise<NostrEvent> {
    const policy = this.deps.channel?.buildOptions(options.kind) ?? {}
    const unsigned = build({
      ...options,
      enc: options.enc ?? policy.enc,
      epoch: options.epoch ?? policy.epoch,
      pubkey: this.deps.pubkey,
      group: options.group ?? this.deps.group,
      counter: await this.counterFor(options),
    })
    // The parentheses are load-bearing. `await a?.b() ?? c` parses as
    // `await (a?.b() ?? c)`, which awaits the *event* when there is no channel
    // and is fine, but reads as though it might not be — and the version that
    // is actually wrong, `(await a?.b()) ?? unsigned` vs `await (a?.b() ??
    // unsigned)`, differ only when `seal()` resolves to `undefined`. Written out
    // so the next reader does not have to work that out.
    const sealed = (await this.deps.channel?.seal(unsigned)) ?? unsigned
    return this.deps.signer.sign(sealed)
  }

  /**
   * Ephemeral events get no counter, and that is not an omission.
   *
   * The counter sequence exists so a reader can tell that something is missing
   * from an author. Relays do not store ephemeral events, so numbering them
   * would burn sequence positions that *nobody* can ever backfill — every
   * reader replaying from history would see a permanent gap for each heartbeat
   * and lease renewal the agent ever sent, and gap detection would report a
   * loss roughly twice a minute forever. Numbering the durable record only
   * keeps the signal worth having.
   */
  private async counterFor(options: PublishOptions): Promise<number | undefined> {
    if (options.counter !== undefined) return options.counter
    if (isEphemeral(options.kind)) return undefined
    return this.deps.counters.next()
  }
}
