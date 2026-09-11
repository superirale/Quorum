/**
 * Leases — one replica answers, not both.
 *
 * ## What this is not
 *
 * It is not a lock. A lease is an ephemeral, advisory claim: the relay does not
 * arbitrate, nothing is stored, and a partitioned replica will believe it holds
 * something it does not. Making it authoritative would mean a consensus
 * protocol inside a chat relay, which is a large price for a problem that has a
 * cheaper answer.
 *
 * The cheaper answer is that correctness never rests here. Double execution is
 * prevented by `once()` and by action ids derived from content; the lease exists
 * to stop the *ordinary* case — two healthy replicas both replying to the same
 * message — from happening at all. Treat it as a way to avoid embarrassment,
 * not as a way to avoid a second deploy.
 *
 * ## Who wins
 *
 * The oldest live claim, by `created_at`; ties break on the highest `epoch`,
 * then on `pubkey:instance` ascending.
 *
 * Every term is something both replicas read off the same signed events, which
 * is the property that matters and the one an obvious implementation misses. An
 * earlier draft here preferred whichever claim *this process had seen first* —
 * and two replicas can each have seen the other first, so each politely
 * deferred and the thread went unanswered. A rule based on local observation
 * order cannot be agreed on; a rule based on the events can.
 *
 * "Oldest wins" also gives incumbency for free: a replica restarting publishes
 * a claim newer than the one already running, so a restart never yanks a thread
 * away from a working sibling. The claim's `created_at` is remembered as the
 * *earliest* we have seen from that holder, so renewing does not cost a holder
 * its seniority.
 *
 * The holder is `pubkey:instance` rather than `pubkey`, because the normal way
 * to run two replicas is to give both the same agent key. See `LeaseBody`.
 *
 * ## What is still racy
 *
 * If two replicas both decide before either has seen the other's claim, both
 * hold. `settleMs` makes that unlikely rather than impossible, and nothing here
 * pretends otherwise — which is why the paragraph above says correctness never
 * rests on this.
 */

import { randomUUID } from 'node:crypto'
import {
  EphemeralKinds,
  LeaseBody,
  threadId as threadIdOf,
  type EventRef,
  type NostrEvent,
} from '@quorum/protocol'
import type { RelayClient, Subscription } from './client.ts'
import { controlFilter } from './addressing.ts'
import type { Publisher } from './publish.ts'
import type { Store } from './store.ts'

export interface LeaseOptions {
  ttlSeconds?: number
  /**
   * How long to listen for competing claims before deciding.
   *
   * Long enough that a replica on the same relay has published and been
   * broadcast back; short enough that it is not felt as latency. If two
   * replicas somehow decide inside each other's window they both back off,
   * which is a wasted turn rather than a duplicated action.
   */
  settleMs?: number
}

export interface Lease {
  readonly threadId: string
  readonly held: boolean
  release(): void
}

interface Claim {
  holder: string
  epoch: number
  /**
   * The earliest `created_at` seen from this holder for this thread. Shared
   * across observers, unlike a local receipt time, and not moved by renewals.
   */
  createdAt: number
  /** Local clock. TTL is measured against our own, not the author's. */
  expiresAt: number
}

/** True if `a` outranks `b`. Both replicas run this over the same claims. */
function outranks(a: Claim, b: Claim): boolean {
  if (a.createdAt !== b.createdAt) return a.createdAt < b.createdAt
  if (a.epoch !== b.epoch) return a.epoch > b.epoch
  return a.holder < b.holder
}

const DEFAULTS = { ttlSeconds: 60, settleMs: 250 }

export interface LeaseManagerDeps {
  client: RelayClient
  publisher: Publisher
  store: Store
  pubkey: string
  group: string
}

export class LeaseManager {
  private readonly claims = new Map<string, Map<string, Claim>>()
  private readonly held = new Map<string, { thread: EventRef; timer: ReturnType<typeof setInterval> }>()
  private readonly options: Required<LeaseOptions>
  private readonly instance = randomUUID()
  private subscription: Subscription | undefined
  private epoch = 0

  private readonly deps: LeaseManagerDeps

  constructor(deps: LeaseManagerDeps, options: LeaseOptions = {}) {
    this.deps = deps
    this.options = { ...DEFAULTS, ...options }
  }

  /** `pubkey:instance` — who this process is, for lease purposes. */
  get holder(): string {
    return `${this.deps.pubkey}:${this.instance}`
  }

  async start(): Promise<void> {
    // One epoch per process, persisted, so a restart outranks its own previous
    // life without outranking a healthy sibling (rule 1 handles that).
    const key = `lease-epoch:${this.deps.pubkey}`
    this.epoch = ((await this.deps.store.get<number>(key)) ?? 0) + 1
    await this.deps.store.set(key, this.epoch)

    this.subscription = this.deps.client.subscribe(
      [{ ...controlFilter({ group: this.deps.group }), kinds: [EphemeralKinds.Lease] }],
      {
        onEvent: (event) => this.record(event),
        onClosed: (reason) => {
          // Losing the lease feed is not fatal — it degrades to "every replica
          // thinks it is alone" — but it must not be silent, because the
          // symptom is duplicated work with no obvious cause.
          console.warn(`[lease] claim feed closed: ${reason}. Replicas may now double-answer.`)
        },
      },
    )
  }

  stop(): void {
    for (const [threadId] of this.held) this.release(threadId)
    this.subscription?.close()
    this.subscription = undefined
  }

  private record(event: NostrEvent): void {
    const threadId = threadIdOf(event.tags)
    if (!threadId) return
    const parsed = LeaseBody.safeParse(safeJson(event.content))
    if (!parsed.success) return

    const holder = `${event.pubkey}:${parsed.data.instance}`
    const claims = this.claims.get(threadId) ?? new Map<string, Claim>()
    const existing = claims.get(holder)
    claims.set(holder, {
      holder,
      epoch: parsed.data.epoch,
      createdAt: Math.min(existing?.createdAt ?? Infinity, event.created_at),
      expiresAt: Date.now() + parsed.data.ttl_seconds * 1000,
    })
    this.claims.set(threadId, claims)
  }

  private live(threadId: string): Claim[] {
    const now = Date.now()
    return [...(this.claims.get(threadId)?.values() ?? [])].filter((c) => c.expiresAt > now)
  }

  /**
   * Try to become the single holder for a thread.
   *
   * Returns a lease whose `held` says whether it worked. It resolves rather than
   * throws when another replica wins, because losing is the expected outcome
   * half the time and an exception would push every caller into a try/catch
   * that means "fine".
   */
  async acquire(thread: EventRef, purpose?: string): Promise<Lease> {
    const threadId = thread.id
    if (this.held.has(threadId)) return this.leaseHandle(threadId, true)

    // Someone live already holds it and their claim is necessarily older than
    // one we have not made yet. Publishing a doomed claim would only add noise.
    if (this.live(threadId).some((c) => c.holder !== this.holder)) {
      return this.leaseHandle(threadId, false)
    }

    const claim = await this.claim(thread, purpose)
    await sleep(this.options.settleMs)

    // Our own claim comes back through the subscription, but not necessarily
    // before the window closes, so it is added explicitly rather than assumed.
    const mine: Claim = {
      holder: this.holder,
      epoch: this.epoch,
      createdAt: claim.created_at,
      expiresAt: Infinity,
    }
    const contenders = [mine, ...this.live(threadId).filter((c) => c.holder !== this.holder)]
    const winner = contenders.reduce((best, c) => (outranks(c, best) ? c : best))
    if (winner.holder !== this.holder) return this.leaseHandle(threadId, false)

    // Renew at half the TTL: one lost renewal must not expire the lease.
    const timer = setInterval(() => {
      void this.claim(thread, purpose).catch(() => {
        /* a failed renewal expires the lease, which is the intended outcome */
      })
    }, (this.options.ttlSeconds * 1000) / 2)
    timer.unref?.()
    this.held.set(threadId, { thread, timer })

    return this.leaseHandle(threadId, true)
  }

  /** Give up a held lease. Publishes a zero-TTL claim so nobody waits it out. */
  release(threadId: string): void {
    const entry = this.held.get(threadId)
    if (!entry) return
    clearInterval(entry.timer)
    this.held.delete(threadId)
    this.claims.get(threadId)?.delete(this.holder)
    // Best-effort: an expired lease reaches the same state, just a minute later.
    void this.claim(entry.thread, 'released', 1).catch(() => {})
  }

  private async claim(thread: EventRef, purpose: string | undefined, ttl?: number): Promise<NostrEvent> {
    return this.deps.publisher.publish({
      kind: EphemeralKinds.Lease,
      thread,
      body: {
        instance: this.instance,
        epoch: this.epoch,
        ttl_seconds: ttl ?? this.options.ttlSeconds,
        ...(purpose ? { purpose } : {}),
      },
    })
  }

  private leaseHandle(threadId: string, held: boolean): Lease {
    return { threadId, held, release: () => this.release(threadId) }
  }
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text)
  } catch {
    return undefined
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}
