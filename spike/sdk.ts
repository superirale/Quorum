// The object under test. Everything else in the spike is scaffolding for this file.
//
// M0's question was whether `await ctx.requestApproval(...)` is a good abstraction.
// First answer from running it: the shape is right, but the naive implementation is
// a lie. A JS `await` cannot survive `kill -9`. The fix is not to avoid awaiting —
// it's to make the whole handler *replayable*:
//
//   1. acked_seq, not delivered_seq, drives resume. A handler that is still blocked
//      on a human has NOT acked, so its triggering event replays on reconnect.
//   2. Every side effect inside a handler goes through ctx.once(), keyed on the
//      triggering event. Replay re-runs the function but re-emits nothing.
//   3. requestApproval() derives a stable approval_id from once(), so on replay it
//      finds the human's answer already sitting in backfilled history and resolves
//      immediately instead of asking again.
//
// Net effect: the linear, readable `await` style survives process death.

import WebSocket from 'ws'

type ActorKind = 'human' | 'agent' | 'system'
type Actor = { id: string; kind: ActorKind; display_name?: string }

export type Event = {
  v: '0.1'
  id: string
  channel_id: string
  thread_id: string
  seq: number
  ts: string
  actor: Actor
  to: string[]
  type: string
  body: any
  fallback_text: string
  correlation_id: string
  causation_id?: string
}

export type Decision = {
  approved: boolean
  decision: 'approved' | 'denied' | 'expired'
  reason?: string
  decided_by?: Actor
}

type AgentOptions = {
  url?: string
  id: string
  name: string
}

/** Stable, content-derived suffix so replayed steps land on the same once() key. */
const slug = (s: string) => {
  let h = 0
  for (let i = 0; i < s.length; i++) h = (Math.imul(31, h) + s.charCodeAt(i)) | 0
  return (h >>> 0).toString(36)
}

export function connect(opts: AgentOptions) {
  const httpUrl = opts.url ?? 'http://localhost:4000'
  const wsUrl = httpUrl.replace(/^http/, 'ws')
  const me: Actor = { id: opts.id, kind: 'agent', display_name: opts.name }

  const handlers: Array<(evt: Event, ctx: Ctx) => void | Promise<void>> = []
  const pendingApprovals = new Map<string, (d: Decision) => void>()
  const knownDecisions = new Map<string, Decision>() // seen in backfill or live
  const dispatched = new Set<string>()

  let ackedSeq = 0
  const completed = new Set<number>()
  const queue: Event[] = []
  let draining = false

  async function post(input: any) {
    const res = await fetch(`${httpUrl}/events`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ actor: me, ...input }),
    })
    if (!res.ok) throw new Error(`post failed: ${res.status} ${await res.text()}`)
    return (await res.json()) as Event
  }

  async function kvGet(key: string) {
    const res = await fetch(
      `${httpUrl}/kv?actor_id=${me.id}&key=${encodeURIComponent(key)}`,
    )
    return (await res.json()) as { found: boolean; value?: any }
  }

  async function kvPut(key: string, value: any) {
    await fetch(`${httpUrl}/kv`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ actor_id: me.id, key, value }),
    })
  }

  async function saveCursor() {
    // Advance only across the contiguous acked prefix — a blocked handler holds
    // the line, which is precisely what makes its event replay after a restart.
    while (completed.has(ackedSeq + 1)) {
      completed.delete(ackedSeq + 1)
      ackedSeq++
    }
    await fetch(`${httpUrl}/cursor`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ actor_id: me.id, acked_seq: ackedSeq }),
    })
  }

  // --- the per-event context handed to handlers -----------------------------

  class Ctx {
    event: Event

    constructor(event: Event) {
      this.event = event
    }

    get threadId() {
      return this.event.thread_id
    }

    /**
     * Addressing is what keeps agents from replying to each other forever.
     * `to` is the ONLY source of truth. The spike originally also matched
     * `@handle` in the body text as a fallback and immediately misfired on a
     * system message that merely *described* how to mention the agent.
     * Mention-to-`to` resolution belongs in the sender, never in the receiver.
     */
    get addressedToMe() {
      return this.event.to.includes(me.id)
    }

    /** Exactly-once effects on top of at-least-once delivery. Not optional. */
    async once<T>(label: string, fn: () => Promise<T> | T): Promise<T> {
      const key = `${this.event.id}:${label}`
      const hit = await kvGet(key)
      if (hit.found) return hit.value as T
      const result = await fn()
      await kvPut(key, result)
      return result
    }

    async say(text: string, to: string[] = []) {
      return this.once(`say:${slug(text)}`, () =>
        post({
          thread_id: this.threadId,
          type: 'message',
          body: { text },
          fallback_text: text,
          to,
          causation_id: this.event.id,
        }),
      )
    }

    /** Server-packed, provenance-tagged, budget-bounded. The agent never scrapes history. */
    async getContext(budgetTokens = 2000) {
      const res = await fetch(
        `${httpUrl}/context?thread_id=${this.threadId}&budget_tokens=${budgetTokens}`,
      )
      return await res.json()
    }

    /** One action, many status events, one stable action_id across replays. */
    async startAction(input: { name: string; input?: any; summary: string }) {
      const self = this
      const action_id = await this.once(`action_id:${input.name}`, () => `act_${slug(this.event.id + input.name)}`)

      const emit = (status: string, extra: any = {}) =>
        self.once(`action:${action_id}:${status}`, () =>
          post({
            thread_id: self.threadId,
            type: 'action',
            body: {
              action_id,
              name: input.name,
              status,
              input: input.input,
              input_summary: input.summary,
              ...extra,
            },
            fallback_text: `[${input.name}] ${status}: ${extra.output_summary ?? input.summary}`,
            causation_id: self.event.id,
          }),
        )

      await emit('proposed')

      return {
        id: action_id,
        awaitingApproval: () => emit('awaiting_approval'),
        running: () => emit('running'),
        succeed: (output_summary: string) => emit('succeeded', { output_summary }),
        fail: (message: string) =>
          emit('failed', { error: { code: 'action_failed', message, retryable: true } }),
        deny: (reason: string) => emit('denied', { output_summary: reason }),
      }
    }

    /**
     * Blocks until a human decides — and survives the agent process dying while
     * it waits, because the approval_id is stable and the answer is in the log.
     */
    async requestApproval(input: {
      title: string
      summary: string
      risk: 'low' | 'medium' | 'high'
      actionId?: string
      grant?: { resource: string; action: string; ttl_seconds: number }
    }): Promise<Decision> {
      const approval_id = await this.once(
        `approval_id:${slug(input.title)}`,
        () => `apr_${slug(this.event.id + input.title)}`,
      )

      // Already answered while we were dead? Then we are done before we start.
      const known = knownDecisions.get(approval_id)
      if (known) return known

      const promise = new Promise<Decision>((resolve) => {
        pendingApprovals.set(approval_id, resolve)
      })

      await this.once(`approval_post:${approval_id}`, () =>
        post({
          thread_id: this.threadId,
          type: 'approval_request',
          body: {
            approval_id,
            action_id: input.actionId,
            title: input.title,
            summary: input.summary,
            risk: input.risk,
            requested_grant: input.grant,
            expires_at: new Date(Date.now() + 10 * 60_000).toISOString(),
          },
          fallback_text: `Approval requested: ${input.title}`,
          causation_id: this.event.id,
        }),
      )

      // Race: the response may have landed between the check and the post.
      const late = knownDecisions.get(approval_id)
      if (late) {
        pendingApprovals.delete(approval_id)
        return late
      }

      return promise
    }
  }

  // --- stream ---------------------------------------------------------------

  function recordDecision(evt: Event) {
    const decision: Decision = {
      approved: evt.body.decision === 'approved',
      decision: evt.body.decision,
      reason: evt.body.reason,
      decided_by: evt.body.decided_by,
    }
    knownDecisions.set(evt.body.approval_id, decision)
    const resolve = pendingApprovals.get(evt.body.approval_id)
    if (resolve) {
      pendingApprovals.delete(evt.body.approval_id)
      resolve(decision)
    }
  }

  async function drain() {
    if (draining) return
    draining = true
    while (queue.length) {
      const evt = queue.shift()!
      for (const handler of handlers) {
        try {
          await handler(evt, new Ctx(evt))
        } catch (err) {
          console.error('[handler error]', err)
        }
      }
      completed.add(evt.seq)
      await saveCursor()
    }
    draining = false
  }

  function ingest(evt: Event, isBackfill: boolean) {
    // Control-plane events bypass the queue so they can unblock a stalled handler.
    if (evt.type === 'approval_response') {
      recordDecision(evt)
      completed.add(evt.seq)
      if (!isBackfill) void saveCursor()
      return
    }

    if (dispatched.has(evt.id)) return
    dispatched.add(evt.id)

    if (evt.actor.id === me.id || evt.seq <= ackedSeq) {
      completed.add(evt.seq)
      return
    }

    queue.push(evt)
  }

  async function open() {
    const { acked_seq } = await (await fetch(`${httpUrl}/cursor?actor_id=${me.id}`)).json()
    ackedSeq = acked_seq

    const ws = new WebSocket(wsUrl)

    ws.on('open', () => console.log(`[${opts.name}] connected, resuming from seq ${ackedSeq}`))

    ws.on('message', (raw: any) => {
      const msg = JSON.parse(raw.toString())

      if (msg.kind === 'hello') {
        const backfill = msg.events.filter((e: Event) => e.seq > ackedSeq)
        // Decisions first: a replayed handler must be able to see its answer.
        for (const e of backfill) if (e.type === 'approval_response') recordDecision(e)
        for (const e of backfill) ingest(e, true)
        void drain()
        return
      }

      if (msg.kind === 'event') {
        ingest(msg.event, false)
        void drain()
      }
    })

    ws.on('close', () => {
      console.log(`[${opts.name}] disconnected, retrying in 1s`)
      setTimeout(open, 1000)
    })
    ws.on('error', () => {})
  }

  void open()

  return {
    me,
    on(handler: (evt: Event, ctx: Ctx) => void | Promise<void>) {
      handlers.push(handler)
    },
  }
}
