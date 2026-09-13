/**
 * Who is running right now — published as a heartbeat, read as a list.
 *
 * Kind 28103 was allocated in M1 and nothing has ever published one. That was
 * fine while the only clients were agents, which do not care who else is up,
 * and stops being fine the moment a human opens a workspace: "I addressed a
 * message to the deploy agent and nothing happened" has two very different
 * causes, and the difference between them is whether the agent is alive.
 *
 * ## The honest caveat, which the UI has to repeat
 *
 * Presence is **ephemeral**, so no relay stores it and a client that has just
 * connected sees nobody until the next beat — up to one interval of silence
 * about a workspace that is fully staffed. That is the right trade: a stored
 * heartbeat is a claim about the past that outlives the process that made it,
 * and an agent that died in a crash would go on looking healthy from history
 * forever. Liveness that cannot be stale is worth more than liveness that is
 * always available.
 *
 * So an empty presence list means "nobody has said anything yet", never "nobody
 * is running", and any screen showing this must say so.
 *
 * ## Whose clock
 *
 * A heartbeat expires at `created_at + ttl_seconds`, both from the author. Two
 * clients therefore agree about who is online, which is the property that made
 * `outranks()` in `lease.ts` work and the one a local receipt time destroys.
 * The cost is that an agent with a skewed clock looks permanently stale or
 * permanently live — visible, bounded, and acceptable precisely because nothing
 * is ever authorised on the strength of a heartbeat.
 */

import { EphemeralKinds, PresenceBody, type NostrEvent } from '@quorum/protocol'
import type { Publisher } from './publish.ts'

export type PresenceStatus = 'online' | 'busy' | 'offline'

export interface Presence {
  pubkey: string
  status: PresenceStatus
  /** What it said it was doing, in its own words. */
  activity?: string
  /** `created_at` of the heartbeat this reading rests on. */
  at: number
  /** When we stop believing it: `at + ttl_seconds`. */
  until: number
  /** False once `until` has passed. Kept in the list as a last-seen. */
  live: boolean
  event: NostrEvent
}

/**
 * The newest heartbeat from each pubkey, live ones first.
 *
 * Expired beats are kept rather than dropped. "This agent was here four minutes
 * ago and has gone quiet" is a different and more useful thing to know than
 * nothing at all, and it is the shape of a crash.
 *
 * **`events` must be in arrival order**, because `created_at` has one-second
 * resolution and an agent that finishes a job inside a second publishes `busy`
 * and `online` in the same one. NIP-01's tiebreak — lowest id — would settle
 * that on a hash, leaving a working agent showing `busy` until the next beat
 * corrected it, or worse the other way round. This is the opposite call from
 * `threads.ts`, which refuses to rely on arrival order, and the difference is
 * that a projection is folded from stored history nobody can replay identically
 * while a heartbeat is only ever read as the live stream the reader is watching.
 * There is no history here to disagree with.
 */
export function presence(events: readonly NostrEvent[], now = Math.floor(Date.now() / 1000)): Presence[] {
  const newest = new Map<string, NostrEvent>()
  for (const event of events) {
    if (event.kind !== EphemeralKinds.Presence) continue
    const held = newest.get(event.pubkey)
    if (!held || event.created_at >= held.created_at) newest.set(event.pubkey, event)
  }

  const out: Presence[] = []
  for (const event of newest.values()) {
    const body = PresenceBody.safeParse(json(event.content))
    if (!body.success) continue
    const until = event.created_at + body.data.ttl_seconds
    out.push({
      pubkey: event.pubkey,
      status: body.data.status,
      ...(body.data.activity ? { activity: body.data.activity } : {}),
      at: event.created_at,
      until,
      live: until > now,
      event,
    })
  }

  return out.sort(
    (a, b) => Number(b.live) - Number(a.live) || b.at - a.at || a.pubkey.localeCompare(b.pubkey),
  )
}

export interface PresenceOptions {
  /** How long one beat stays believable. */
  ttlSeconds?: number
  /**
   * Seconds between beats. Defaults to a third of the TTL.
   *
   * A third rather than the lease's half because the reader is a human. A lost
   * renewal costs a lease its claim, which another replica picks up; a lost
   * heartbeat makes a working agent disappear off somebody's screen, and the
   * conclusion they draw from that is "it is down", which is wrong and
   * expensive. Two consecutive losses to be wrong instead of one.
   */
  intervalSeconds?: number
  /** What to say when idle. */
  activity?: string
}

const DEFAULTS = { ttlSeconds: 90 }

/**
 * Beats on a timer, and says goodbye on the way out.
 *
 * Status changes publish immediately; activity changes wait for the next beat.
 * That split is deliberate: online↔busy is what someone is watching for, and
 * activity is a caption. An agent draining a backfill of five hundred messages
 * would otherwise publish five hundred heartbeats to keep its caption current.
 */
export class PresenceReporter {
  private readonly publisher: Publisher
  private readonly ttlSeconds: number
  private readonly intervalSeconds: number
  private status: PresenceStatus = 'online'
  private activity: string | undefined
  private timer: ReturnType<typeof setInterval> | undefined
  private failing = false

  constructor(publisher: Publisher, options: PresenceOptions = {}) {
    this.publisher = publisher
    this.ttlSeconds = options.ttlSeconds ?? DEFAULTS.ttlSeconds
    this.intervalSeconds = options.intervalSeconds ?? Math.max(1, Math.floor(this.ttlSeconds / 3))
    this.activity = options.activity
  }

  async start(): Promise<void> {
    this.timer ??= interval(() => void this.beat(), this.intervalSeconds * 1000)
    await this.beat()
  }

  /** Say what this process is doing. Publishes now only if the status changed. */
  set(status: PresenceStatus, activity?: string): void {
    const changed = status !== this.status
    this.status = status
    this.activity = activity
    if (changed) void this.beat()
  }

  /**
   * Stop beating and publish an explicit `offline`.
   *
   * Best-effort, and the TTL reaches the same answer a minute and a half later.
   * Worth the one event anyway: a clean shutdown is the case where we know the
   * answer, and leaving a human to watch a stale badge time out teaches them
   * that the badge means nothing.
   */
  async stop(): Promise<void> {
    if (this.timer) clearInterval(this.timer)
    this.timer = undefined
    this.status = 'offline'
    this.activity = undefined
    await this.beat()
  }

  private async beat(): Promise<void> {
    try {
      await this.publisher.publish({
        kind: EphemeralKinds.Presence,
        body: {
          status: this.status,
          ttl_seconds: this.ttlSeconds,
          ...(this.activity ? { activity: clamp(this.activity) } : {}),
        },
      })
      this.failing = false
    } catch (error) {
      // Never fatal: an agent that stops working because it could not announce
      // that it was working would be a heartbeat causing the outage it reports.
      // Logged once per outage rather than every interval, so the log stays
      // readable across a long disconnection.
      if (!this.failing) {
        this.failing = true
        console.warn(`[presence] heartbeat failed, will keep trying: ${String(error)}`)
      }
    }
  }
}

/** The `activity` line is a caption, not a log line. */
function clamp(text: string, max = 80): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text
}

function interval(fn: () => void, ms: number): ReturnType<typeof setInterval> {
  const timer = setInterval(fn, ms)
  // Node only, and the reason a heartbeat must not hold a process open: an
  // agent that has called `stop()` and finished its work should exit.
  timer.unref?.()
  return timer
}

function json(text: string): unknown {
  try {
    return JSON.parse(text)
  } catch {
    return undefined
  }
}
