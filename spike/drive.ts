// Headless driver: plays Ada, so the M0 loop can be verified without a browser.
// Usage: node drive.ts [approve|deny]

import WebSocket from 'ws'

const MODE = (process.argv[2] ?? 'approve') as 'approve' | 'deny'
const BASE = 'http://localhost:4000'
const ME = { id: 'usr_ada', kind: 'human', display_name: 'Ada' }

const snap = await (await fetch(`${BASE}/snapshot`)).json()
const thread = snap.threads[0]

const post = (body: any) =>
  fetch(`${BASE}/events`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })

const seen = new Set<string>()
let done = false

const ws = new WebSocket('ws://localhost:4000')

ws.on('message', async (raw: any) => {
  const msg = JSON.parse(raw.toString())
  const incoming = msg.kind === 'hello' ? msg.events : msg.kind === 'event' ? [msg.event] : []

  for (const evt of incoming) {
    if (seen.has(evt.id)) continue
    seen.add(evt.id)

    const who = evt.actor.display_name
    if (evt.type === 'message') console.log(`  ${evt.seq}. ${who}: ${evt.body.text}`)
    else if (evt.type === 'action')
      console.log(`  ${evt.seq}. [action ${evt.body.status}] ${evt.body.name} — ${evt.body.output_summary ?? evt.body.input_summary}`)
    else if (evt.type === 'approval_request')
      console.log(`  ${evt.seq}. [approval requested] ${evt.body.title} (${evt.body.risk} risk)`)
    else if (evt.type === 'approval_response')
      console.log(`  ${evt.seq}. [approval ${evt.body.decision}] by ${evt.body.decided_by?.display_name}`)
    else console.log(`  ${evt.seq}. ${evt.fallback_text}`)

    if (evt.type === 'approval_request') {
      await new Promise((r) => setTimeout(r, 300)) // human think time
      await post({
        thread_id: evt.thread_id,
        actor: ME,
        type: 'approval_response',
        body: {
          approval_id: evt.body.approval_id,
          decision: MODE === 'approve' ? 'approved' : 'denied',
          decided_by: ME,
          reason: MODE === 'deny' ? 'Not during the freeze window.' : undefined,
        },
        fallback_text: `Approval ${MODE}d: ${evt.body.title}`,
        causation_id: evt.id,
      })
    }

    if (evt.type === 'action' && ['succeeded', 'failed', 'denied'].includes(evt.body.status)) {
      done = true
      setTimeout(async () => {
        const final = await (await fetch(`${BASE}/snapshot`)).json()
        const t = final.threads.find((x: any) => x.id === thread.id)
        console.log(`\nthread status: ${t.status}`)
        const ctx = await (await fetch(`${BASE}/context?thread_id=${thread.id}&budget_tokens=200`)).json()
        console.log(
          `context @200 tokens: ${ctx.segments.length} kept, ${ctx.dropped_events} dropped, ` +
            `trust levels: ${[...new Set(ctx.segments.map((s: any) => s.provenance.trust))].join(', ')}`,
        )
        process.exit(0)
      }, 600)
    }
  }
})

ws.on('open', async () => {
  console.log(`\n--- driving the loop in "${MODE}" mode ---`)
  await post({
    thread_id: thread.id,
    actor: ME,
    type: 'message',
    body: { text: '@deploy ship the payments hotfix to prod please' },
    fallback_text: '@deploy ship the payments hotfix to prod please',
    to: ['agt_deploy'],
  })
})

setTimeout(() => {
  if (!done) {
    console.error('TIMEOUT: loop did not complete')
    process.exit(1)
  }
}, 15000)
