/**
 * The agent runtime: subscribe, dispatch, reply, survive.
 *
 * Everything else in this package is a mechanism; this is where they are wired
 * into a shape someone would actually write an agent against. Three of the
 * decisions here are positions rather than conveniences.
 *
 * **`on()` only sees events addressed to you.** Not "sees everything and offers
 * you a helper to check". M0's agent deployed to production because a message
 * *described* how to mention it, and the fix that survives is structural: the
 * default handler is never handed an event it was not sent. `onAny()` exists
 * for the observers that genuinely need the firehose — a reference client, an
 * indexer — and its name is meant to be slightly uncomfortable.
 *
 * **Control-plane events skip the queue.** Conversation is handled one event at
 * a time, in order, because a handler that awaits a human is a normal thing to
 * write. That same property is a deadlock if the interrupt telling it to stop is
 * queued behind it. Ephemeral kinds are dispatched immediately, off the queue,
 * which is what the 20000–29999 range was chosen for.
 *
 * **A handler is replayed, not resumed.** After a restart, an event whose
 * handler never finished is delivered again from the top. This only works
 * because every effect goes through `ctx.once()` — see `once.ts`, which is the
 * file to read before writing a handler.
 */

import {
  Kinds,
  addressees as addresseesOf,
  digest,
  isEphemeral,
  refTo,
  threadRef,
  type EventRef,
  type Filter,
  type NostrEvent,
} from '@quorum/protocol'
import { WORK_KINDS, addressedFilter, channelFilter, controlFilter, isForMe } from './addressing.ts'
import { runAction, type ActOptions, type ActResult } from './approval.ts'
import { RelayClient, type Logger, type Subscription } from './client.ts'
import { Counters } from './counter.ts'
import { LeaseManager, type Lease, type LeaseOptions } from './lease.ts'
import { createOnce, incompleteEffects, type Once } from './once.ts'
import { Publisher, type PublishOptions } from './publish.ts'
import { Cursor, type Gap } from './replay.ts'
import { MemoryStore, type Store } from './store.ts'
import type { Signer } from './signer.ts'

export interface AgentOptions {
  /** A relay URL, or a client you already own (and will close yourself). */
  relay: string | RelayClient
  signer: Signer
  /** NIP-29 group id. An agent belongs to a channel. */
  group: string
  /**
   * Durable local state: the `once()` ledger, the cursor, counters.
   *
   * Defaults to memory, which is right for a test and wrong for anything else —
   * an agent with a memory store re-runs every effect it has ever performed the
   * next time it is restarted. Use `FileStore.in(dir)`.
   */
  store?: Store
  /** Names the cursor, so one process can run several subscriptions. */
  name?: string
  /** Kinds to subscribe to. Defaults to {@link WORK_KINDS}. */
  kinds?: readonly number[]
  leases?: LeaseOptions | false
  /** Deliver the agent's own events to handlers. Off: that is how loops start. */
  includeOwn?: boolean
  log?: Logger
}

/** Handed to every handler. Bound to one triggering event. */
export interface AgentContext {
  readonly event: NostrEvent
  /** This agent's pubkey. */
  readonly me: string
  readonly group: string
  /** The thread this event sits in, or undefined for channel-level chat. */
  readonly thread: EventRef | undefined
  readonly threadId: string | undefined
  /** True when the event carries a `to`-marked `p` tag for us. */
  readonly addressedToMe: boolean
  /** Every pubkey this event is addressed to — us included. */
  readonly addressees: string[]

  /** Exactly-once effects. Every side effect goes through this. Read `once.ts`. */
  readonly once: Once

  /** Publish, once, with a stable id across replays. */
  publish(label: string, options: PublishOptions): Promise<NostrEvent>
  /** Reply in this thread — or in the channel, if this is not a thread. */
  say(text: string, options?: SayOptions): Promise<NostrEvent>
  /**
   * Do something consequential: propose it, get a human's signature, run it,
   * and leave a chain anyone can verify offline. See `approval.ts`.
   */
  act<I, T>(options: ActOptions<I, T>): Promise<ActResult<T>>
  /** Claim this thread, so a sibling replica does not answer it too. */
  lease(purpose?: string): Promise<Lease>
  /** Authors we have provably missed something from. Ordering layer 1. */
  gaps(): Gap[]
  /** The connection, for anything this interface does not cover yet. */
  readonly client: RelayClient
}

export interface SayOptions {
  /** Who this is addressed to. Defaults to the author of the triggering event. */
  to?: string[]
  /**
   * The `once()` label. Defaults to a digest of the text.
   *
   * Override it when the same handler might legitimately say the same sentence
   * twice — and give it a name that says which of the two this is, never a
   * number. See `once.ts`.
   */
  label?: string
}

export type Handler = (event: NostrEvent, ctx: AgentContext) => void | Promise<void>

export class Agent {
  readonly client: RelayClient

  private readonly options: AgentOptions
  private readonly store: Store
  private readonly log: Logger
  private readonly addressed: Handler[] = []
  private readonly any: Handler[] = []
  private readonly control: Handler[] = []
  private readonly queue: NostrEvent[] = []
  private readonly queued = new Set<string>()
  /** Ids whose handler was interrupted by a restart. They go to the front. */
  private readonly replaying = new Set<string>()
  private readonly inFlightEffects = new Map<string, Promise<unknown>>()
  private readonly ownedClient: boolean

  private pubkey = ''
  private cursor!: Cursor
  private counters!: Counters
  private publisher!: Publisher
  private leases: LeaseManager | undefined
  private subscription: Subscription | undefined
  private draining = false
  private backfilling = false
  private running = false

  constructor(options: AgentOptions) {
    this.options = options
    this.store = options.store ?? new MemoryStore()
    this.log = options.log ?? console
    this.ownedClient = typeof options.relay === 'string'
    this.client =
      typeof options.relay === 'string'
        ? new RelayClient({ url: options.relay, signer: options.signer, log: this.log })
        : options.relay
  }

  /** This agent's pubkey. Empty until {@link start} has run. */
  get me(): string {
    return this.pubkey
  }

  /** Handle events addressed to this agent. The one you want. */
  on(handler: Handler): this {
    this.addressed.push(handler)
    return this
  }

  /**
   * Handle every event in the channel, addressed or not.
   *
   * For readers: a client, an indexer, an auditor. An agent that *acts* on this
   * is an agent that answers conversations it was not part of, which is the
   * behaviour `on()` exists to prevent.
   */
  onAny(handler: Handler): this {
    this.any.push(handler)
    return this
  }

  /**
   * Handle control-plane events — interrupt, lease, presence.
   *
   * Dispatched immediately, outside the queue and possibly while a conversation
   * handler is mid-await. Keep these short and non-blocking; they exist to set a
   * flag or abort a signal, not to do work.
   */
  onControl(handler: Handler): this {
    this.control.push(handler)
    return this
  }

  // --- lifecycle ------------------------------------------------------------

  /** Connect, restore state and subscribe. Resolves once backfill has arrived. */
  async start(): Promise<void> {
    if (this.running) return
    this.running = true

    this.pubkey = await this.options.signer.pubkey()
    this.cursor = await Cursor.load(this.store, this.options.name ?? 'default')
    this.counters = await Counters.load(this.store, this.pubkey)
    this.publisher = new Publisher({
      client: this.client,
      signer: this.options.signer,
      pubkey: this.pubkey,
      group: this.options.group,
      counters: this.counters,
    })

    await this.client.connect()
    await this.recoverCounter()
    await this.reportUnfinishedWork()

    if (this.options.leases !== false) {
      this.leases = new LeaseManager(
        {
          client: this.client,
          publisher: this.publisher,
          store: this.store,
          pubkey: this.pubkey,
          group: this.options.group,
        },
        this.options.leases ?? {},
      )
      await this.leases.start()
    }

    await this.subscribe()
  }

  async stop(): Promise<void> {
    this.running = false
    this.leases?.stop()
    this.subscription?.close()
    this.subscription = undefined
    await this.cursor?.save()
    if (this.ownedClient) this.client.close()
  }

  /**
   * Do not restart a counter sequence the channel has already seen.
   *
   * A lost state directory is an ordinary operational event — a container moved,
   * a volume was not mounted. Restarting at 1 would republish counters this
   * pubkey has already used, and duplicate counters do not read as "this agent
   * lost its notes"; they read as "this key is in two places", which is a much
   * more alarming thing to make an operator investigate.
   */
  private async recoverCounter(): Promise<void> {
    if (this.counters.current > 0) return
    try {
      const mine = await this.client.query([
        { ...channelFilter({ group: this.options.group }), authors: [this.pubkey], limit: 50 },
      ])
      let highest = 0
      for (const event of mine) {
        const n = Number(event.tags.find((t) => t[0] === 'counter')?.[1] ?? 0)
        if (Number.isInteger(n) && n > highest) highest = n
      }
      if (highest > 0) {
        await this.counters.observeOwn(highest)
        this.log.warn(`[agent] no local counter state; resuming this key's sequence at ${highest}`)
      }
    } catch (error) {
      this.log.warn(`[agent] could not check for a previous counter sequence: ${String(error)}`)
    }
  }

  /** Say out loud what a crash left half-done. No relay can reconstruct this. */
  private async reportUnfinishedWork(): Promise<void> {
    const pending = await incompleteEffects(this.store)
    for (const key of pending) {
      this.log.warn(`[agent] effect '${key}' was started but never completed; it will be retried`)
    }
    const replaying = this.cursor.inFlightIds
    for (const id of replaying) this.replaying.add(id)
    if (replaying.length) {
      this.log.warn(
        `[agent] ${replaying.length} handler(s) did not finish before shutdown; replaying from ${new Date(
          this.cursor.since() * 1000,
        ).toISOString()}`,
      )
    }
  }

  private filters(): Filter[] {
    const since = this.cursor.since()
    const base = { group: this.options.group, kinds: this.options.kinds ?? WORK_KINDS, since }
    // The firehose only when someone asked for it. Otherwise `#p` keeps the
    // relay from shipping a busy channel to an agent that will discard it —
    // and `#p` is a superset, so `isForMe` still decides.
    const work = this.any.length
      ? channelFilter(base)
      : addressedFilter({ ...base, pubkey: this.pubkey })
    return [work, controlFilter({ group: this.options.group })]
  }

  private subscribe(): Promise<void> {
    return new Promise<void>((resolve) => {
      let first = true
      // Nothing is handled until the backfill is complete. The events in it
      // arrive in whatever order the relay chose — `created_at`, which is other
      // people's clocks — and the queue is serial, so handling them as they
      // land lets that order decide which work gets to block on a human first.
      // Held, the backfill is a set rather than a sequence, and `enqueue` can
      // put unfinished work at the front of it. See `drain`.
      this.backfilling = true
      const opened = () => {
        if (!first) return
        first = false
        this.backfilling = false
        void this.drain()
        resolve()
      }
      this.subscription = this.client.subscribe(() => this.filters(), {
        onEvent: (event) => this.ingest(event),
        onEose: opened,
        onClosed: (reason) => {
          // A closed subscription is the failure mode this SDK was written to
          // make visible. An agent that treats it as silence looks healthy and
          // does nothing, forever.
          this.log.error(`[agent] the relay closed our subscription: ${reason}`)
          opened()
        },
      })
    })
  }

  // --- dispatch -------------------------------------------------------------

  private ingest(event: NostrEvent): void {
    if (isEphemeral(event.kind)) {
      if (event.pubkey === this.pubkey && !this.options.includeOwn) return
      void this.run(this.control, event)
      return
    }

    this.cursor.observe(event)

    if (event.pubkey === this.pubkey) {
      void this.counters.observeOwn(numericTag(event, 'counter') ?? 0)
      if (!this.options.includeOwn) return
    }
    if (!this.cursor.shouldDispatch(event)) return
    if (this.queued.has(event.id)) return

    this.queued.add(event.id)
    this.enqueue(event)
    void this.drain()
  }

  /**
   * Unfinished work first, then arrival order.
   *
   * A restart replays the triggers of handlers that never finished, but they
   * come back through the same subscription as everything published while the
   * process was down — and a relay sorts by `created_at`, which is a wall clock
   * with one-second resolution and ties broken arbitrarily. Since the queue is
   * serial, an event that happens to sort first can park on a human and starve
   * the very handler the restart was supposed to resume. Work already begun is
   * therefore not subject to the ordering the relay chose for it.
   */
  private enqueue(event: NostrEvent): void {
    if (!this.replaying.has(event.id)) {
      this.queue.push(event)
      return
    }
    const at = this.queue.findIndex((queued) => !this.replaying.has(queued.id))
    if (at === -1) this.queue.push(event)
    else this.queue.splice(at, 0, event)
  }

  /**
   * One event at a time, in arrival order.
   *
   * Serial because a handler may await a human, and letting the next event
   * start meanwhile means two half-finished handlers sharing a thread's state.
   * The cost is head-of-line blocking, which is why the control plane does not
   * come through here.
   */
  private async drain(): Promise<void> {
    if (this.draining || this.backfilling) return
    this.draining = true
    try {
      while (this.queue.length) {
        const event = this.queue.shift()!
        this.queued.delete(event.id)
        this.replaying.delete(event.id)

        this.cursor.begin(event)
        await this.cursor.save()

        const handlers = [...this.any, ...(isForMe(event, this.pubkey) ? this.addressed : [])]
        await this.run(handlers, event)

        // Shutdown reaches a running handler as a failure — `stop()` closes the
        // socket, so whatever it was awaiting rejects. Completing the event on
        // the way out would read that as "the handler is done" and the work
        // would never be replayed. It stays in flight, which is exactly what it
        // is: begun, not finished.
        if (!this.running) return

        // Otherwise completed even when a handler threw. Replaying a handler
        // that fails deterministically is an agent that does nothing else,
        // forever; the error is logged, and from M4 it is published as a kind
        // 8105 so the humans in the channel can see it too.
        this.cursor.complete(event)
        await this.cursor.save()
      }
    } finally {
      this.draining = false
    }
  }

  private async run(handlers: readonly Handler[], event: NostrEvent): Promise<void> {
    if (!handlers.length) return
    const ctx = this.context(event)
    for (const handler of handlers) {
      try {
        await handler(event, ctx)
      } catch (error) {
        if (!this.running) {
          // Not a failure: we pulled the socket out from under it. Said at warn
          // so it does not look like a bug in the handler, and so the "it will
          // be replayed" half is the part that gets read.
          this.log.warn(
            `[agent] shutting down mid-handler on ${event.id.slice(0, 8)}; it will be replayed`,
          )
          return
        }
        this.log.error(`[agent] handler failed on ${event.id.slice(0, 8)}:`, error)
      }
    }
  }

  private context(event: NostrEvent): AgentContext {
    const once = createOnce(this.store, event.id, this.inFlightEffects)
    const thread = threadRef(event)
    const agent = this

    const publish = async (label: string, options: PublishOptions): Promise<NostrEvent> =>
      once(label, async ({ createdAt }) => {
        // The counter is reserved under its own key so a retry reuses it. A
        // fresh number would change the event id, and the whole point of the
        // reservation is that a retry produces bytes the relay already has.
        const counter = isEphemeral(options.kind)
          ? undefined
          : await once(`${label}/counter`, () => agent.counters.next())
        return agent.publisher.publish({ created_at: createdAt, counter, ...options })
      })

    return {
      event,
      me: this.pubkey,
      group: this.options.group,
      thread,
      threadId: thread?.id,
      addressedToMe: isForMe(event, this.pubkey),
      addressees: addresseesOf(event.tags),
      once,
      client: this.client,
      publish,

      say(text, options = {}) {
        const to = options.to ?? [event.pubkey]
        const label = options.label ?? `say:${digest(text).slice(0, 16)}`
        return thread
          ? publish(label, { kind: Kinds.Comment, text, thread, parent: refTo(event), to })
          : publish(label, { kind: Kinds.ChatMessage, text, to })
      },

      act(options) {
        if (!thread) {
          throw new Error(
            'an action lives in a thread, and this event is not in one. Start a thread ' +
              '(kind 11) first: an approval with nowhere to be answered is not an approval.',
          )
        }
        return runAction(
          {
            once,
            publish,
            client: agent.client,
            group: agent.options.group,
            me: agent.pubkey,
            thread,
            parent: refTo(event),
            log: agent.log,
          },
          options,
        )
      },

      async lease(purpose) {
        if (!agent.leases) throw new Error('leases are disabled for this agent')
        if (!thread) {
          throw new Error(
            'a lease is scoped to a thread, and this event is not in one. Start a thread ' +
              '(kind 11) before claiming work: channel-level chat has no unit to hold.',
          )
        }
        return agent.leases.acquire(thread, purpose)
      },

      gaps: () => this.cursor.gaps(),
    }
  }
}

function numericTag(event: NostrEvent, name: string): number | undefined {
  const raw = event.tags.find((t) => t[0] === name)?.[1]
  if (raw === undefined) return undefined
  const n = Number(raw)
  return Number.isInteger(n) ? n : undefined
}

/** Shorthand for the common case. */
export function createAgent(options: AgentOptions): Agent {
  return new Agent(options)
}
