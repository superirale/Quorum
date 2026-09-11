// M0 spike server. In-memory, single channel, no auth, no Postgres.
// The only job here is to make the approval loop real enough to feel the SDK ergonomics.
// Shapes deliberately mirror the planned envelope so what we learn transfers to M1.

import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { WebSocketServer } from 'ws'

const PORT = 4000
const CHANNEL = 'C1'

type ActorKind = 'human' | 'agent' | 'system'
type Actor = { id: string; kind: ActorKind; display_name?: string }

type Event = {
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

type Thread = {
  id: string
  title: string
  status: 'open' | 'working' | 'blocked' | 'paused' | 'done'
  assignee_actor_id: string | null
  root_event_id: string | null
  last_activity_at: string
}

const events: Event[] = []
const threads = new Map<string, Thread>()
const actors = new Map<string, Actor>([
  ['sys', { id: 'sys', kind: 'system', display_name: 'Quorum' }],
  ['usr_ada', { id: 'usr_ada', kind: 'human', display_name: 'Ada' }],
])
let nextSeq = 1
let idCounter = 0

const id = (prefix: string) =>
  `${prefix}_${(++idCounter).toString().padStart(4, '0')}${Math.random().toString(36).slice(2, 6)}`

// --- append -----------------------------------------------------------------
// Stands in for the M2 seq-allocating transaction. Single-threaded here, so
// gapless + commit-ordered is free; in M2 it costs a row lock on channel_seq.

function append(input: {
  thread_id: string
  actor: Actor
  type: string
  body: any
  fallback_text: string
  to?: string[]
  correlation_id?: string
  causation_id?: string
}): Event {
  const thread = threads.get(input.thread_id)
  if (!thread) throw new Error(`unknown thread ${input.thread_id}`)

  const evt: Event = {
    v: '0.1',
    id: id('evt'),
    channel_id: CHANNEL,
    thread_id: input.thread_id,
    seq: nextSeq++,
    ts: new Date().toISOString(),
    actor: input.actor,
    to: input.to ?? [],
    type: input.type,
    body: input.body,
    fallback_text: input.fallback_text,
    correlation_id: input.correlation_id ?? thread.root_event_id ?? input.thread_id,
    causation_id: input.causation_id,
  }

  events.push(evt)
  if (!thread.root_event_id) thread.root_event_id = evt.id
  thread.last_activity_at = evt.ts
  actors.set(evt.actor.id, evt.actor)

  // Fanout happens strictly after the append, never inside it.
  broadcast(evt)
  return evt
}

function createThread(title: string): Thread {
  const thread: Thread = {
    id: id('thr'),
    title,
    status: 'open',
    assignee_actor_id: null,
    root_event_id: null,
    last_activity_at: new Date().toISOString(),
  }
  threads.set(thread.id, thread)
  return thread
}

// --- thread status ----------------------------------------------------------
// Thread-as-task. The UI's "blocked on you" state is just this field.

function setThreadStatus(thread_id: string, status: Thread['status']) {
  const thread = threads.get(thread_id)
  if (!thread || thread.status === status) return
  thread.status = status
  broadcastRaw({ kind: 'thread', thread })
}

// --- websocket fanout -------------------------------------------------------

const sockets = new Set<any>()

function broadcast(evt: Event) {
  broadcastRaw({ kind: 'event', event: evt })
}

function broadcastRaw(msg: any) {
  const payload = JSON.stringify(msg)
  for (const ws of sockets) {
    if (ws.readyState === 1) ws.send(payload)
  }
}

// --- deterministic context packing -----------------------------------------
// No LLM, no summarizer agent. Extractive only, and every segment carries
// provenance so the caller can see whose words these are.

function packContext(thread_id: string, budgetTokens: number) {
  const all = events.filter((e) => e.thread_id === thread_id)
  const approx = (s: string) => Math.ceil(s.length / 4)

  const keep: Event[] = []
  let spent = 0
  for (const evt of [...all].reverse()) {
    const cost = approx(evt.fallback_text)
    // Approvals and their outcomes are always kept verbatim, budget or not.
    const mandatory = evt.type === 'approval_request' || evt.type === 'approval_response'
    if (!mandatory && spent + cost > budgetTokens) continue
    spent += cost
    keep.unshift(evt)
  }

  const dropped = all.length - keep.length
  const thread = threads.get(thread_id)!

  return {
    thread: { id: thread.id, title: thread.title, status: thread.status },
    budget_tokens: budgetTokens,
    used_tokens: spent,
    dropped_events: dropped,
    segments: keep.map((evt) => ({
      seq: evt.seq,
      type: evt.type,
      text: evt.fallback_text,
      provenance: {
        actor_id: evt.actor.id,
        actor_kind: evt.actor.kind,
        trust: evt.actor.kind === 'system' ? 'system' : evt.actor.kind === 'human' ? 'human' : 'agent',
      },
    })),
    participants: [...new Set(all.map((e) => e.actor.id))].map((a) => actors.get(a)),
  }
}

// --- agent KV + cursors -----------------------------------------------------
// Server-side durable state for agents. Backs ctx.once() (exactly-once effects
// on top of at-least-once delivery) and acked_seq (safe handler replay).

const kv = new Map<string, any>()
const cursors = new Map<string, number>()

// --- http -------------------------------------------------------------------

const json = (res: any, code: number, body: any) => {
  const payload = JSON.stringify(body)
  res.writeHead(code, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) })
  res.end(payload)
}

const readBody = (req: any): Promise<any> =>
  new Promise((resolve, reject) => {
    let raw = ''
    req.on('data', (c: any) => (raw += c))
    req.on('end', () => {
      try {
        resolve(raw ? JSON.parse(raw) : {})
      } catch (err) {
        reject(err)
      }
    })
  })

const server = createServer(async (req, res) => {
  const url = new URL(req.url!, `http://localhost:${PORT}`)

  try {
    if (req.method === 'GET' && url.pathname === '/') {
      const html = await readFile(new URL('./index.html', import.meta.url), 'utf8')
      res.writeHead(200, { 'content-type': 'text/html' })
      return res.end(html)
    }

    if (req.method === 'GET' && url.pathname === '/snapshot') {
      return json(res, 200, {
        events,
        threads: [...threads.values()],
        actors: [...actors.values()],
      })
    }

    if (req.method === 'GET' && url.pathname === '/context') {
      const thread_id = url.searchParams.get('thread_id')!
      const budget = Number(url.searchParams.get('budget_tokens') ?? 2000)
      if (!threads.has(thread_id)) return json(res, 404, { error: 'no such thread' })
      return json(res, 200, packContext(thread_id, budget))
    }

    // Durable per-agent KV. Backs ctx.once(). Real impl gets CAS via a version column.
    if (req.method === 'GET' && url.pathname === '/kv') {
      const k = `${url.searchParams.get('actor_id')}:${url.searchParams.get('key')}`
      return json(res, 200, kv.has(k) ? { found: true, value: kv.get(k) } : { found: false })
    }

    if (req.method === 'PUT' && url.pathname === '/kv') {
      const { actor_id, key, value } = await readBody(req)
      kv.set(`${actor_id}:${key}`, value)
      return json(res, 200, { ok: true })
    }

    if (req.method === 'GET' && url.pathname === '/cursor') {
      const actor_id = url.searchParams.get('actor_id')!
      return json(res, 200, { acked_seq: cursors.get(actor_id) ?? 0 })
    }

    if (req.method === 'PUT' && url.pathname === '/cursor') {
      const { actor_id, acked_seq } = await readBody(req)
      cursors.set(actor_id, Math.max(cursors.get(actor_id) ?? 0, acked_seq))
      return json(res, 200, { acked_seq: cursors.get(actor_id) })
    }

    if (req.method === 'POST' && url.pathname === '/threads') {
      const body = await readBody(req)
      const thread = createThread(body.title ?? 'Untitled')
      broadcastRaw({ kind: 'thread', thread })
      return json(res, 201, thread)
    }

    if (req.method === 'POST' && url.pathname === '/events') {
      const body = await readBody(req)
      const evt = append(body)

      // Server-side reactions to event types with a lifecycle. In M5 these
      // become the approvals service and the capability engine.
      if (evt.type === 'approval_request') setThreadStatus(evt.thread_id, 'blocked')
      if (evt.type === 'approval_response') setThreadStatus(evt.thread_id, 'working')
      if (evt.type === 'action') {
        const status = evt.body.status
        if (status === 'running') setThreadStatus(evt.thread_id, 'working')
        if (status === 'succeeded' || status === 'failed' || status === 'denied') {
          setThreadStatus(evt.thread_id, 'done')
        }
      }

      return json(res, 201, evt)
    }

    json(res, 404, { error: 'not found' })
  } catch (err: any) {
    json(res, 500, { error: String(err?.message ?? err) })
  }
})

const wss = new WebSocketServer({ server })

wss.on('connection', (ws) => {
  sockets.add(ws)
  ws.send(
    JSON.stringify({
      kind: 'hello',
      after_seq: 0,
      events,
      threads: [...threads.values()],
      actors: [...actors.values()],
    }),
  )
  ws.on('close', () => sockets.delete(ws))
})

// Seed one thread so there is something to look at on first load.
const seed = createThread('Ship the payments hotfix')
append({
  thread_id: seed.id,
  actor: actors.get('sys')!,
  type: 'message',
  body: { text: 'Thread opened. Mention the deploy agent to give it work.' },
  fallback_text: 'Thread opened. Mention the deploy agent to give it work.',
})

server.listen(PORT, () => {
  console.log(`spike server  http://localhost:${PORT}`)
  console.log(`seed thread   ${seed.id}`)
})
