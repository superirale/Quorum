/**
 * M8 against the real Go relay.
 *
 *   cd apps/relay && QUORUM_EVENTS_BURST=400 QUORUM_FILTERS_BURST=400 make run
 *   pnpm --filter @quorum/runaway-agent live
 *
 * Those two variables are the finding, and they are not the two you would reach
 * for. khatru's limiter is not a bucket that refills: a counter climbs to
 * `maxTokens` — our `QUORUM_*_BURST` — and a goroutine subtracts
 * `tokensPerInterval` once every interval. So the *burst* is the real ceiling
 * on anything that happens inside one minute, and `QUORUM_EVENTS_PER_MINUTE`
 * only says how much is forgiven at the tick. Raising the per-minute number on
 * its own — which is what M7's note about the read side implies — changes
 * nothing whatsoever, and this script proved it by dying at act 4 with
 * `QUORUM_FILTERS_PER_MINUTE=600` set and the burst left at 40.
 *
 * What trips it is the agent, not the script: a runaway agent hits the relay's
 * rate limit long before it hits its own budget. Both are backstops from the
 * same paragraph of the plan and the cheaper one fires first — the right order
 * in production, and useless in a script that wants to watch the other one
 * work. Ada and the agent also share 127.0.0.1 here, so they share one bucket.
 *
 * The budget exists twice, in two languages, and the two copies have to agree
 * on the arithmetic *and* on when to pause. `packages/protocol/src/cost.ts` and
 * `packages/sdk/src/threads.ts` fold ops in TypeScript;
 * `apps/relay/internal/threads/threads.go` folds the same ops in Go and signs
 * the result as a kind 38101. If they disagree by so much as a rounding rule,
 * `threads()` reports a relay that is telling the truth as `disagrees` — which
 * is the most serious thing a client can say about a relay, spent on nothing.
 * Neither test suite can catch that: the Go tests build events by hand, and the
 * fake relay projects nothing at all.
 *
 * So this file runs a real agent out of money over a socket and checks both
 * sides of everything:
 *
 *   1. one fold, two languages   the relay's signed 38101 replays to the same state
 *   2. the pause is the relay's  it wrote `paused`, and nobody published a status
 *   3. the relay has teeth       a kind 8101 into a paused thread is refused…
 *                                …and chat, status and budget ops are not
 *   4. two decisions             resuming is not raising, and the agent needs both
 *   5. Stop over a socket        an event the relay routes and refuses to store
 *
 * Act 5 is the one only a real relay can show. Kind 28101 is ephemeral, so the
 * claim is not "it arrived" but "it arrived and was not kept" — the relay
 * forwards it to a live subscriber and stores nothing, which is why a Stop
 * button can never have a receipt.
 *
 * Exits non-zero on the first failed expectation.
 */

import {
  ActionBody,
  Kinds,
  TagName,
  ThreadStateBody,
  checkBudget,
  describeBudget,
  digest,
  refTo,
  tagValue,
  tokensSpent,
  type EventRef,
  type NostrEvent,
  type UnsignedEvent,
} from '@quorum/protocol'
import {
  Counters,
  LocalSigner,
  MemoryStore,
  Publisher,
  RelayClient,
  interrupt,
  threadOp,
  threadState,
  threads,
} from '@quorum/sdk'
import { createRunawayAgent } from './agent.ts'

const url = process.env.QUORUM_RELAY ?? 'ws://localhost:3334'
// Fresh per run: the agent backfills its channel on start, so a reused group
// would have this run answering the last one's questions.
const group = process.env.QUORUM_GROUP ?? `cost-${Date.now().toString(36)}`
const PATIENCE_MS = Number(process.env.QUORUM_PATIENCE_MS ?? 30_000)
const CEILING = 30_000

const NIP29 = { createGroup: 9007, putUser: 9000 } as const

const ada = LocalSigner.generate()
const bot = LocalSigner.generate()
let failures = 0
let cachedRelayPubkey: string | undefined

console.log(`relay   ${url}`)
console.log(`group   #${group}`)
console.log(`ada     ${ada.npub.slice(0, 20)}…   (owner, so she may move the ceiling)`)
console.log(`crawl   ${bot.npub.slice(0, 20)}…   (reads pages until it runs out of pages)\n`)

const client = new RelayClient({ url, signer: ada })
await client.connect()

await publishRaw(ada, { kind: NIP29.createGroup, tags: [['h', group]], content: '' })
await publishRaw(ada, {
  kind: NIP29.putUser,
  tags: [
    ['h', group],
    ['p', bot.publicKey],
  ],
  content: '',
})

const publisher = new Publisher({
  client,
  signer: ada,
  pubkey: ada.publicKey,
  group,
  counters: await Counters.load(new MemoryStore(), ada.publicKey),
})

/** Swapped before act 5. The agent holds a stable reference to it. */
let read: (page: number, signal: AbortSignal) => Promise<string> = instantly

const agent = createRunawayAgent({
  relay: url,
  signer: bot,
  group,
  pages: 6,
  read: (page, signal) => read(page, signal),
})
await agent.start()

// --- 1. one fold, two languages -----------------------------------------------------

act('1. one fold, in two languages')

const archive = await task('index the archive', 'read the September ledger, page by page')
await op(archive, { op: 'set_budget', budget: { tokens: CEILING } })
await poke(archive)
say('ada', `opened a task capped at ${CEILING.toLocaleString()} tokens and set the agent on it`)

await waitFor('the agent to run out of money', async () =>
  (await said(archive)).some((t) => t.startsWith('stopping')),
)

const seen = await gather(archive)
const [task1] = threads(seen)
if (!task1) {
  fail('the relay served no thread at all — is the projector running?')
  process.exit(1)
}

expect(
  task1.check.verdict === 'agrees',
  'replaying the ops the relay says it folded reproduces the state it signed, field for field',
)
if (task1.check.verdict === 'disagrees') {
  report('instead', task1.check.fields.join(', '), 'the Go fold and the TypeScript fold differ')
}
report(
  'the relay says',
  describeBudget(task1.spent, task1.budget),
  `folded from the ${foldedFrom(seen, archive.id).length} ops it received, one at a time. ` +
    'Nothing estimated: every number in there was stated by the agent that spent it, which is ' +
    'also why the same mechanism works on a channel the relay cannot read',
)

const mine = threadState(seen, archive.id)
expect(
  tokensSpent(mine.spent) === tokensSpent(task1.spent) && mine.status === task1.status,
  `and a client that ignored the projection entirely folds the same ${tokensSpent(mine.spent).toLocaleString()} tokens`,
)

// --- 2. the pause is the relay's ------------------------------------------------------

act('2. the pause is the relay’s, not the agent’s')

const projection = task1.projection
expect(projection?.pubkey === (await relayPubkey()), 'the 38101 is signed by the relay itself')
expect(task1.status === 'paused', 'and it says `paused`')
expect(
  (await opsOfKind(archive, Kinds.ThreadOp)).every(
    (e) => !JSON.parse(e.content).op?.includes?.('set_status'),
  ),
  'with no `set_status` op anywhere in the thread — nobody asked for this',
)
expect(
  checkBudget(task1.spent, task1.budget).exhausted,
  `the relay reached the same verdict from its own numbers: over by ` +
    `${(tokensSpent(task1.spent) - CEILING).toLocaleString()} tokens`,
)

// --- 3. the relay has teeth -----------------------------------------------------------

act('3. what a paused thread refuses, and what it must not')

const work = {
  name: 'crawl.page',
  status: 'proposed',
  summary: 'read page 99 of the archive',
  input: { page: 99 },
  input_digest: digest({ page: 99 }),
} satisfies ActionBody

expect(
  await refused(await publisher.sign({ kind: Kinds.Action, thread: archive, body: work })),
  'a kind 8101 `proposed` into the paused thread is rejected — this is the half that bites',
)
expect(
  !(await refused(
    await publisher.sign({ kind: Kinds.Comment, thread: archive, text: 'what happened here?' }),
  )),
  'control: chat still goes through. A relay that silenced the thread it had just paused would ' +
    'turn a budget alert into an outage, in the one thread people need to talk in',
)
expect(
  !(await refused(
    await publisher.sign(threadOp(archive, { op: 'set_status', status: 'open' })),
  )),
  'control: `set_status` goes through — it is how a human gets out of this state',
)
expect(
  !(await refused(
    await publisher.sign(threadOp(archive, { op: 'set_budget', budget: { tokens: CEILING } })),
  )),
  'control: so does `set_budget`, which is gated on a `thread:budget` capability and not on this',
)

// --- 4. two decisions ------------------------------------------------------------------

act('4. resuming is not raising')

await op(archive, { op: 'set_status', status: 'working' })
say('ada', 'sets the thread back to working, leaving the ceiling where it is')
await waitFor('the relay to fold the status op', async () => (await state(archive))?.status === 'working')

// Counted, not sliced: the relay serves a filter newest-first, so the sentence
// this act is waiting for arrives at the *front* of the array and a tail slice
// looks at the oldest thing the agent ever said.
const refusalsBefore = await refusals(archive)
await poke(archive, 'try again')
await waitFor(
  'the agent to refuse a second time',
  async () => (await refusals(archive)) > refusalsBefore,
)
const stillThree = (await opsOfKind(archive, Kinds.Action)).filter(
  (e) => body(e)?.status === 'proposed',
)
expect(
  stillThree.length === 3,
  `still only ${stillThree.length} proposals, all from the first run: the agent checks the ` +
    'ceiling, and the ceiling is still spent. The relay would have refused it too, but nothing ' +
    'reached the relay',
)

await op(archive, { op: 'set_budget', budget: { tokens: 200_000 } })
say('ada', 'raises the ceiling to 200,000 tokens')
await poke(archive, 'now try again')
await waitFor('the agent to finish the archive', async () =>
  (await said(archive)).some((t) => t.startsWith('done')),
)

const [task2] = threads(await gather(archive))
expect(
  task2?.check.verdict === 'agrees' && task2?.status !== 'paused',
  `work resumed and the projection still agrees — ${describeBudget(task2?.spent, task2?.budget)}`,
)
report(
  'why both ops were needed',
  '`set_status` clears the pause; `set_budget` clears the reason for it',
  'the fold pauses on `add_spend` and `set_budget` and never on `set_status`, or a human ' +
    'resuming an exhausted thread would have their `working` rewritten to `paused` by the same ' +
    'fold that stored it',
)

// --- 5. Stop over a socket ---------------------------------------------------------------

act('5. Stop, over a real socket')

const started = deferred()
read = (_page, signal) =>
  new Promise<string>((_resolve, reject) => {
    started.resolve()
    signal.addEventListener('abort', () => reject(signal.reason))
  })

const rebuild = await task('rebuild the index', 'this one takes a while')
await op(rebuild, { op: 'set_budget', budget: { tokens: 1_000_000 } })
await poke(rebuild)
await started.promise
say('crawl', 'is mid-page, with plenty of budget left')

const [target] = (await opsOfKind(rebuild, Kinds.Action)).filter(
  (e) => body(e)?.status === 'proposed',
)
await publisher.publish(interrupt({ thread: rebuild, action: target!.id, reason: 'wrong shelf' }))
say('ada', 'publishes a kind 28101 naming that action')

await waitFor('the agent to give up', async () =>
  (await said(rebuild)).some((t) => t.startsWith('stopping')),
)
const chain = await opsOfKind(rebuild, Kinds.Action)
expect(
  chain.filter((e) => body(e)?.status === 'cancelled').length === 1 &&
    chain.filter((e) => body(e)?.status === 'failed').length === 0,
  'the chain ends `cancelled`, not `failed` — and the relay accepted that terminal event into a ' +
    'thread it would have refused a `proposed` in, which is the point of allowing transitions out',
)

const stored = await client.query([{ kinds: [28101], [`#${TagName.Group}`]: [group] }])
expect(
  stored.length === 0,
  'and the relay stored none of it: the interrupt was routed to a live subscriber and kept ' +
    'nowhere. There is no event to query, so there is no receipt — every Stop button in this ' +
    'system has to say so on the screen rather than in the docs',
)

await agent.stop()
client.close()
console.log(failures === 0 ? '\nall good.' : `\n${failures} failed.`)
process.exit(failures === 0 ? 0 : 1)

// --- the workspace --------------------------------------------------------------------------

async function task(title: string, text: string): Promise<EventRef> {
  // Not addressed to the agent: the budget op has to reach the relay before the
  // handler starts, and an addressed root would start it.
  const root = await publisher.publish({ kind: Kinds.Thread, text, tags: [['title', title]] })
  return refTo(root)
}

function poke(thread: EventRef, text = 'read the archive'): Promise<NostrEvent> {
  return publisher.publish({ kind: Kinds.Comment, thread, text, to: [agent.me] })
}

function op(thread: EventRef, spec: Parameters<typeof threadOp>[1]): Promise<NostrEvent> {
  return publisher.publish(threadOp(thread, spec))
}

/**
 * Everything `threads()` needs, and deliberately not a `#E` query alone.
 *
 * The relay's 38101 carries `d`, `h` and `alt` and no `E` tag, so a
 * thread-scoped `{"#E": [id]}` returns every op and none of the projections —
 * and the thread comes back `local` against a relay that folded and signed the
 * lot.
 */
function gather(thread: EventRef): Promise<NostrEvent[]> {
  return client.query([
    { ids: [thread.id] },
    { [`#${TagName.RootEvent}`]: [thread.id], [`#${TagName.Group}`]: [group] },
    {
      kinds: [Kinds.ThreadState],
      [`#${TagName.Identifier}`]: [thread.id],
      [`#${TagName.Group}`]: [group],
    },
  ])
}

async function opsOfKind(thread: EventRef, kind: number): Promise<NostrEvent[]> {
  return client.query([
    { kinds: [kind], [`#${TagName.RootEvent}`]: [thread.id], [`#${TagName.Group}`]: [group] },
  ])
}

async function said(thread: EventRef): Promise<string[]> {
  const comments = await opsOfKind(thread, Kinds.Comment)
  return comments.filter((e) => e.pubkey === agent.me).map((e) => e.content)
}

/** How many times the agent has announced it is giving up in this thread. */
async function refusals(thread: EventRef): Promise<number> {
  return (await said(thread)).filter((t) => t.startsWith('stopping')).length
}

async function state(thread: EventRef) {
  const [found] = await client.query([
    {
      kinds: [Kinds.ThreadState],
      [`#${TagName.Identifier}`]: [thread.id],
      [`#${TagName.Group}`]: [group],
    },
  ])
  return found && ThreadStateBody.safeParse(JSON.parse(found.content)).data
}

function foldedFrom(events: readonly NostrEvent[], id: string): string[] {
  const projection = events.find(
    (e) => e.kind === Kinds.ThreadState && tagValue(e.tags, TagName.Identifier) === id,
  )
  const parsed = projection && ThreadStateBody.safeParse(JSON.parse(projection.content)).data
  return parsed?.folded_from ?? []
}

function body(event: NostrEvent): ActionBody | undefined {
  return ActionBody.safeParse(JSON.parse(event.content)).data
}

/** Did the relay refuse it? The OK message is the interesting part of a no. */
async function refused(event: NostrEvent): Promise<boolean> {
  try {
    await client.publish(event)
    return false
  } catch (error) {
    report('refused', (error as Error).message, 'the relay’s own words')
    return true
  }
}

async function publishRaw(who: LocalSigner, unsigned: Omit<UnsignedEvent, 'pubkey' | 'created_at'>) {
  await client.publish(
    await who.sign({
      ...unsigned,
      pubkey: who.publicKey,
      created_at: Math.floor(Date.now() / 1000),
    }),
  )
}

async function relayPubkey(): Promise<string> {
  if (cachedRelayPubkey) return cachedRelayPubkey
  const http = url.replace(/^ws/, 'http')
  try {
    const response = await fetch(http, { headers: { Accept: 'application/nostr+json' } })
    const info = (await response.json()) as { pubkey?: string }
    if (info.pubkey) return (cachedRelayPubkey = info.pubkey)
  } catch (error) {
    console.error(`could not read ${http}: ${String(error)}`)
  }
  console.error('no pubkey in the relay’s NIP-11 document. Is the relay running? (cd apps/relay && make run)')
  process.exit(2)
}

async function instantly(page: number): Promise<string> {
  return `entry ${page * 37} of the September ledger`
}

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve!: () => void
  const promise = new Promise<void>((r) => {
    resolve = r
  })
  return { promise, resolve }
}

/**
 * Poll until something is true, paced against the relay's own filter limit.
 *
 * `QUORUM_FILTERS_PER_MINUTE` defaults to 120 and *closes the subscription*
 * rather than queueing, so a loop asking twice a second dies two acts later as
 * an unexplained CLOSED. Each tick here is more than one filter, hence the
 * second-and-a-bit.
 */
async function waitFor(what: string, done: () => Promise<boolean>): Promise<void> {
  const deadline = Date.now() + PATIENCE_MS
  for (;;) {
    if (await done()) return
    if (Date.now() >= deadline) break
    await new Promise((r) => setTimeout(r, 1200))
  }
  fail(`timed out after ${Math.round(PATIENCE_MS / 1000)}s waiting for ${what}`)
  console.log(`\n${failures} failed.`)
  process.exit(1)
}

// --- narration --------------------------------------------------------------------------------

function act(title: string): void {
  console.log(`\n\x1b[1m${title}\x1b[0m`)
}

function say(who: string, what: string): void {
  console.log(`  ${who.padEnd(7)} ${what}`)
}

function report(label: string, value: string, note: string): void {
  console.log(`  \x1b[2m→ ${label}:\x1b[0m ${value}\n  \x1b[2m  ${note}\x1b[0m`)
}

function expect(condition: boolean, what: string): void {
  if (condition) console.log(`  \x1b[32m✔\x1b[0m ${what}`)
  else fail(what)
}

function fail(what: string): void {
  failures += 1
  console.log(`  \x1b[31m✘\x1b[0m ${what}`)
}
