/**
 * The durable local archive — what forward secrecy forces a client to keep.
 *
 * Under `plaintext` and `nip44` the relay is the record. An agent restarting
 * after a week backfills its channel, an auditor pulls a chain it has never
 * seen, the packer gathers a thread by filter, and a new member is handed the
 * old epochs and reads everything. All four of those rest on the same
 * assumption: *the copy on the relay can be read again later*.
 *
 * `mls` removes it. MLS deletes the material that opens old messages — that is
 * what forward secrecy **is**, not a side effect of it — so an event this client
 * opened on Tuesday is, by Friday, a blob it can no longer decrypt, sitting on a
 * relay that will serve it forever. The relay becomes the transport and each
 * member becomes the record. This file is that record.
 *
 * ## Two durable records, for two different reasons
 *
 * {@link Archive} is history: the event as published, plus the plaintext this
 * client read out of it at the time. {@link SealedEnvelopes} is a retry cache,
 * and it exists because a ratchet cannot produce byte-identical retries. Both
 * are here rather than in two files so that "what does this agent write to disk
 * in the clear" has one answer in one place.
 *
 * ## The cost, stated rather than buried
 *
 * A plaintext archive gives back, on this disk, exactly the property MLS bought
 * on the wire. Forward secrecy says a key compromised today does not open
 * yesterday's traffic; an archive says yesterday's traffic is in a file next to
 * the key. There is no clever resolution — sealing the archive under a local key
 * stores the key beside it, and the cleverness would only obscure where the
 * plaintext actually is. So the choice is a workspace's to make and the
 * mechanism is {@link Archive.prune}: keep forever and have an audit trail, keep
 * a window and get some of the forward secrecy back, keep nothing and accept
 * that an agent restart loses the thread. The default is to keep, because an
 * approval nobody can produce in six months is the thing pillar two exists to
 * prevent — but a default is not an argument, and an operator who wants the
 * other trade must be able to have it.
 */

import type { NostrEvent } from '@quorum/protocol'
import { TagName, tagValue } from '@quorum/protocol'
import type { Store } from './store.ts'

const ARCHIVE = 'archive'
const SEALED = 'sealed'

/** One event as this client saw it, and what it could make of it at the time. */
export interface ArchivedEvent {
  /**
   * The event exactly as published — sealed `content`, signature intact.
   *
   * The whole event and not only the body, because a record that needs the
   * relay to still be serving the envelope is not a record. An auditor six
   * months and one relay migration later needs the signature, and the signature
   * is over the sealed bytes.
   */
  event: NostrEvent
  /**
   * The body, if this client could read it when it arrived.
   *
   * Absent means it never could: an event sealed under an epoch this identity
   * was not in, which is the normal condition for everything said before it
   * joined. Recorded anyway, because "the thread has ten events and I can read
   * seven" is a sentence a reader must be able to say. An archive that silently
   * held only the readable ones would present a complete-looking history with
   * three messages missing from it.
   */
  plaintext?: string
  /** When this client wrote it down, which is not when it was sent. */
  archived_at: number
}

export interface ArchiveOptions {
  /** Overridable so tests are not at the mercy of the wall clock. */
  now?: () => number
}

/**
 * Every event this client has seen in a channel, with the plaintext it read.
 *
 * Keyed by group so a workspace with forty channels does not scan all of them
 * to render one, and by event id within it so recording twice is idempotent.
 */
export class Archive {
  private readonly store: Store
  private readonly now: () => number

  constructor(store: Store, options: ArchiveOptions = {}) {
    this.store = store
    this.now = options.now ?? (() => Math.floor(Date.now() / 1000))
  }

  /**
   * Write an event down, with its plaintext if this client has it.
   *
   * **A re-record without a plaintext never erases one already held**, and that
   * rule is the whole reason this is a method rather than a `store.set`. The way
   * a client destroys its own archive under `mls` is mundane: it restarts,
   * backfills the channel, re-sees every event it recorded last month, can no
   * longer open any of them because the epochs are gone, and writes each one
   * back as unreadable. One ordinary reconnect, and the only surviving copy of
   * six weeks of decisions is overwritten by the blob it was made from.
   */
  async record(event: NostrEvent, plaintext?: string): Promise<void> {
    const key = this.key(event)
    if (key === undefined) return

    const existing = await this.store.get<ArchivedEvent>(key)
    const kept = plaintext ?? existing?.plaintext
    await this.store.set(key, {
      event,
      ...(kept !== undefined ? { plaintext: kept } : {}),
      archived_at: existing?.archived_at ?? this.now(),
    } satisfies ArchivedEvent)
  }

  /** Record a batch, keeping the no-erasure rule. */
  async recordAll(entries: readonly { event: NostrEvent; plaintext?: string }[]): Promise<void> {
    for (const entry of entries) await this.record(entry.event, entry.plaintext)
  }

  async get(group: string, id: string): Promise<ArchivedEvent | undefined> {
    return this.store.get<ArchivedEvent>(`${ARCHIVE}:${encode(group)}:${id}`)
  }

  /** Everything held for a channel, oldest first. */
  async all(group: string): Promise<ArchivedEvent[]> {
    const prefix = `${ARCHIVE}:${encode(group)}:`
    const keys = await this.store.keys(prefix)
    const out: ArchivedEvent[] = []
    for (const key of keys) {
      const record = await this.store.get<ArchivedEvent>(key)
      if (record) out.push(record)
    }
    // `Store.keys` says its order is unspecified and means it — the file store
    // hands back insertion order and a future one need not. Sorting here is
    // what lets every caller treat the archive as a timeline.
    return out.sort((a, b) => a.event.created_at - b.event.created_at || cmp(a.event.id, b.event.id))
  }

  /**
   * The events of a channel with the archived plaintext substituted back in.
   *
   * The shape `packContext`, the feed and `verifyActionChain` already take: a
   * `NostrEvent` whose `content` is readable. Same caveat as
   * `ChannelCrypto.opened()` and it is worth repeating — the result is **not** a
   * valid Nostr event, because its `id` commits to the ciphertext. Do not
   * re-verify it and never publish it.
   *
   * Events with no archived plaintext are dropped rather than returned sealed,
   * and `onMissing` is how the caller learns it happened. Returning them sealed
   * would put base64 in front of a model as though it were the conversation,
   * which is the M9 keyless-packer failure; returning nothing and saying nothing
   * is the same lie by omission `openReadable` documents.
   */
  async opened(
    group: string,
    onMissing?: (missing: number, held: number) => void,
  ): Promise<NostrEvent[]> {
    const records = await this.all(group)
    const out: NostrEvent[] = []
    let missing = 0
    for (const record of records) {
      if (record.plaintext === undefined) missing += 1
      else out.push({ ...record.event, content: record.plaintext })
    }
    if (missing) onMissing?.(missing, out.length)
    return out
  }

  /** Ids held for a channel that this client never managed to read. */
  async unreadable(group: string): Promise<string[]> {
    return (await this.all(group))
      .filter((r) => r.plaintext === undefined)
      .map((r) => r.event.id)
  }

  async has(group: string, id: string): Promise<boolean> {
    return (await this.get(group, id)) !== undefined
  }

  /**
   * Drop everything sent before `cutoff`, and say how much went.
   *
   * By the event's `created_at` rather than by `archived_at`, so a retention
   * window means "we keep six weeks of conversation" and not "we keep whatever
   * this replica happened to see in the last six weeks" — two agents that joined
   * at different times would otherwise hold different windows of the same
   * channel and neither would be wrong.
   *
   * This is the only way to get any of the forward secrecy back, so it is a
   * deliberate call by an operator and never a default. Nothing here runs it on
   * a timer: a background thread quietly deleting the audit trail is not a
   * feature, it is the incident.
   */
  async prune(group: string, cutoff: number): Promise<number> {
    const prefix = `${ARCHIVE}:${encode(group)}:`
    let dropped = 0
    for (const key of await this.store.keys(prefix)) {
      const record = await this.store.get<ArchivedEvent>(key)
      if (record && record.event.created_at < cutoff) {
        await this.store.delete(key)
        dropped += 1
      }
    }
    return dropped
  }

  /**
   * The key for an event, or nothing if it names no channel.
   *
   * An event with no `h` tag is not in a channel, so there is no timeline to
   * file it under. Returning `undefined` rather than throwing because the caller
   * is usually a subscription handler iterating a batch, and one stray event
   * must not take down the archiving of the rest.
   */
  private key(event: NostrEvent): string | undefined {
    const group = tagValue(event.tags, TagName.Group)
    if (group === undefined || group === '') return undefined
    return `${ARCHIVE}:${encode(group)}:${event.id}`
  }
}

/**
 * Sealed envelopes, kept so a retry republishes bytes rather than re-sealing.
 *
 * `once()` buys exactly-once by making a retry rebuild a **byte-identical**
 * event, whose id the relay already holds and therefore discards. Under `nip44`
 * that works because the nonce is derived from the plaintext event, so sealing
 * is a pure function. MLS is not: the secret tree advances per message, so
 * sealing the same body twice yields two ciphertexts, two ids, two messages in
 * the channel, and a consumed generation that cannot be given back.
 *
 * So the sealed envelope is written down **before** it is published, keyed by
 * the id of the event *in the clear* — which is stable across retries precisely
 * because `once()` fixes `created_at` and reuses the reserved `counter`. A
 * retry finds it and republishes it verbatim.
 *
 * The window this does not close is the one between the ratchet step and the
 * write. A crash there produces a generation consumed with nothing recorded, and
 * the retry seals again: two events, one counter. That is not a hole so much as
 * the reason the counter rule gains a second reading — *same counter and same
 * plaintext* is a retry that lost its cache, *same counter and different
 * plaintext* is still "this key is in two places", which is the alarming one.
 */
export class SealedEnvelopes {
  private readonly store: Store

  constructor(store: Store) {
    this.store = store
  }

  /** The sealed event previously stored for this plaintext id, if any. */
  async get(plaintextId: string): Promise<NostrEvent | undefined> {
    return this.store.get<NostrEvent>(`${SEALED}:${plaintextId}`)
  }

  /** Record a sealed event against the id of the event it was sealed from. */
  async put(plaintextId: string, sealed: NostrEvent): Promise<void> {
    await this.store.set(`${SEALED}:${plaintextId}`, sealed)
  }

  /**
   * Return the stored envelope, or seal once and store it before handing it back.
   *
   * The store write is awaited before the caller ever sees the event, which is
   * the entire point: a `publish()` that reached the relay and a crash before
   * the cache was written would leave the retry re-sealing, and the relay would
   * hold the same sentence twice under two ids.
   */
  async sealOnce(
    plaintextId: string,
    seal: () => NostrEvent | Promise<NostrEvent>,
  ): Promise<NostrEvent> {
    const stored = await this.get(plaintextId)
    if (stored) return stored
    const sealed = await seal()
    await this.put(plaintextId, sealed)
    return sealed
  }

  /** Forget one envelope. For tests and for a caller pruning a completed chain. */
  async forget(plaintextId: string): Promise<void> {
    await this.store.delete(`${SEALED}:${plaintextId}`)
  }
}

/**
 * Group ids go in a key, and a NIP-29 group id is an arbitrary string.
 *
 * `encodeURIComponent` rather than trusting that nobody names a channel
 * `ops:prod`: with a raw `:` the prefix scan for one channel can match another,
 * and the failure is a reader shown somebody else's messages rather than an
 * error.
 */
function encode(group: string): string {
  return encodeURIComponent(group)
}

function cmp(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0
}
