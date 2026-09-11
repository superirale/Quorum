/**
 * The cursor: where to resume, what to re-run, and what was missed.
 *
 * M0 built this on a gapless `acked_seq` and advanced it across the contiguous
 * acked prefix. That cannot survive the move to Nostr — there is no total order
 * to take a prefix of, `created_at` is a client's own wall clock, and a relay is
 * free to withhold events. The three mechanisms M0 actually validated survive
 * unchanged; only the representation moved:
 *
 *   replay, not resume    an event whose handler has not *completed* is
 *                         re-delivered after a restart. A handler blocked on a
 *                         human has not completed, so its trigger replays and
 *                         the `await` picks up where it left off. Advancing
 *                         past it silently abandons the work.
 *   dedup by id           completed events are remembered so a wider replay
 *                         window does not re-run them.
 *   gaps are detectable   per-author `counter` tags make "I have definitely
 *                         missed something from this author" a local check that
 *                         needs no cooperation from the relay.
 *
 * The persisted shape is `AgentCursorBody` from `@quorum/protocol`, so this can
 * be published as a kind 38105 later without a migration. It is stored locally
 * for now: a cursor is an operational detail, and on Nostr you cannot unpublish.
 */

import { counter as counterTagValue, type NostrEvent } from '@quorum/protocol'
import type { Store } from './store.ts'

export interface CursorState {
  /** Highest *contiguous* counter seen per author. A gap here is a known loss. */
  watermarks: Record<string, number>
  /** Delivered to a handler that has not finished. These replay. */
  in_flight: string[]
  /** Completed, but still inside the replay window. Skipped on redelivery. */
  completed_ahead: string[]
  last_seen_at?: number
  /** Local: `created_at` per remembered id, so the replay floor can be exact. */
  event_times?: Record<string, number>
}

export interface Gap {
  pubkey: string
  /** The next counter we expected from this author. */
  expected: number
  /** Counters received above the gap, so the loss is bounded. */
  seen: number[]
}

export interface CursorOptions {
  /**
   * How far before the replay floor to actually ask for.
   *
   * `created_at` is the author's clock, not the relay's, so events do not
   * arrive in `created_at` order and a floor with no slack drops the ones that
   * were merely a few seconds behind. Over-fetching is free: `completed_ahead`
   * discards the duplicates.
   */
  slackSeconds?: number
  /**
   * Cap on `completed_ahead`. Entries normally age out when the replay floor
   * passes them; this is the backstop for ids restored from disk, whose
   * timestamps a previous process may not have recorded.
   */
  maxCompleted?: number
}

const DEFAULTS = { slackSeconds: 300, maxCompleted: 4096 }

export class Cursor {
  private readonly store: Store
  private readonly key: string
  private readonly options: Required<CursorOptions>

  private watermarks = new Map<string, number>()
  private inFlight = new Set<string>()
  private completed = new Set<string>()
  private times = new Map<string, number>()
  private lastSeenAt: number | undefined
  /** Counters received above an author's watermark. In memory: a live gap report. */
  private pending = new Map<string, Set<number>>()
  private dirty = false

  private constructor(store: Store, key: string, options: CursorOptions) {
    this.store = store
    this.key = key
    this.options = { ...DEFAULTS, ...options }
  }

  /** `id` names the subscription, and becomes the `d` tag if this is published. */
  static async load(store: Store, id: string, options: CursorOptions = {}): Promise<Cursor> {
    const cursor = new Cursor(store, `cursor:${id}`, options)
    const state = await store.get<CursorState>(cursor.key)
    if (state) {
      cursor.watermarks = new Map(Object.entries(state.watermarks ?? {}))
      cursor.inFlight = new Set(state.in_flight ?? [])
      cursor.completed = new Set(state.completed_ahead ?? [])
      cursor.times = new Map(Object.entries(state.event_times ?? {}))
      cursor.lastSeenAt = state.last_seen_at
    }
    return cursor
  }

  /**
   * Where a subscription should start.
   *
   * The floor is the oldest event still in flight, because that is the one that
   * has to come back. With nothing in flight it is the newest event seen. Never
   * `now`: an event published while the process was down would be skipped.
   */
  since(): number {
    let floor = this.lastSeenAt
    for (const id of this.inFlight) {
      const at = this.times.get(id)
      if (at !== undefined && (floor === undefined || at < floor)) floor = at
    }
    if (floor === undefined) return 0
    return Math.max(0, floor - this.options.slackSeconds)
  }

  /** True if the handler queue should see this event at all. */
  shouldDispatch(event: NostrEvent): boolean {
    return !this.completed.has(event.id)
  }

  /** Record an event's arrival and update this author's watermark. */
  observe(event: NostrEvent): void {
    this.times.set(event.id, event.created_at)
    if (this.lastSeenAt === undefined || event.created_at > this.lastSeenAt) {
      this.lastSeenAt = event.created_at
      this.dirty = true
    }

    const n = counterTagValue(event.tags)
    if (n === undefined) return

    // First contact with an author starts the watermark just below whatever we
    // saw, rather than at zero. An agent that joins a busy channel has not
    // "missed" the 4,000 events that predate it, and reporting that as a gap
    // would make the gap report worthless on its first day.
    const watermark = this.watermarks.get(event.pubkey) ?? n - 1
    if (n <= watermark) return

    const pending = this.pending.get(event.pubkey) ?? new Set<number>()
    pending.add(n)

    let next = watermark
    while (pending.delete(next + 1)) next++

    this.watermarks.set(event.pubkey, next)
    if (pending.size) this.pending.set(event.pubkey, pending)
    else this.pending.delete(event.pubkey)
    this.dirty = true
  }

  /** An event has been handed to a handler. It replays until `complete`. */
  begin(event: NostrEvent): void {
    this.times.set(event.id, event.created_at)
    this.inFlight.add(event.id)
    this.dirty = true
  }

  /** The handler finished — successfully or not; either way it will not be re-run. */
  complete(event: NostrEvent): void {
    this.inFlight.delete(event.id)
    this.completed.add(event.id)
    this.dirty = true
  }

  /** Events whose handler was interrupted by a restart, oldest first. */
  get inFlightIds(): string[] {
    return [...this.inFlight].sort((a, b) => (this.times.get(a) ?? 0) - (this.times.get(b) ?? 0))
  }

  /**
   * Authors we have provably missed something from.
   *
   * Provably, because the counter is signed by the author: no relay can forge a
   * contiguous sequence it does not have. This is ordering layer 1, and it is
   * the part that works on a relay with no Quorum support at all.
   */
  gaps(): Gap[] {
    const out: Gap[] = []
    for (const [pubkey, seen] of this.pending) {
      if (!seen.size) continue
      out.push({
        pubkey,
        expected: (this.watermarks.get(pubkey) ?? 0) + 1,
        seen: [...seen].sort((a, b) => a - b),
      })
    }
    return out
  }

  toJSON(): CursorState {
    return {
      watermarks: Object.fromEntries(this.watermarks),
      in_flight: [...this.inFlight],
      completed_ahead: [...this.completed],
      last_seen_at: this.lastSeenAt,
      event_times: Object.fromEntries(this.times),
    }
  }

  async save(): Promise<void> {
    if (!this.dirty) return
    this.prune()
    this.dirty = false
    await this.store.set(this.key, this.toJSON())
  }

  /**
   * Forget everything the replay window can no longer reach.
   *
   * Without this, `completed_ahead` is a list of every event the agent has ever
   * handled, and the state file grows forever — which is fine for a week and a
   * production incident after a year.
   */
  private prune(): void {
    const floor = this.since()
    for (const id of this.completed) {
      const at = this.times.get(id)
      if (at !== undefined && at < floor) this.completed.delete(id)
    }
    while (this.completed.size > this.options.maxCompleted) {
      const oldest = this.completed.values().next().value as string
      this.completed.delete(oldest)
    }
    for (const id of this.times.keys()) {
      if (!this.completed.has(id) && !this.inFlight.has(id)) this.times.delete(id)
    }
  }
}
