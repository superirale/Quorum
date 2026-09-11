/**
 * Building, signing and publishing, in one place.
 *
 * Tag assembly is `@quorum/protocol`'s job and stays there — if the SDK grew
 * its own idea of which tags an event needs, "valid Quorum event" would have
 * two definitions and they would drift. What belongs here is the part the
 * protocol package deliberately refuses to do: reach a key, allocate a counter,
 * and put the result on a wire.
 */

import { build, isEphemeral, type BuildOptions, type NostrEvent } from '@quorum/protocol'
import type { RelayClient } from './client.ts'
import type { Counters } from './counter.ts'
import type { Signer } from './signer.ts'

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

  /** Everything but the wire. Useful for tests, and for computing an id first. */
  async sign(options: PublishOptions): Promise<NostrEvent> {
    const unsigned = build({
      ...options,
      pubkey: this.deps.pubkey,
      group: options.group ?? this.deps.group,
      counter: await this.counterFor(options),
    })
    return this.deps.signer.sign(unsigned)
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
