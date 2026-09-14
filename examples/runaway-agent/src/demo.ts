/**
 * The M8 demo: an agent runs out of money, and then an agent is stopped by hand.
 *
 * `pnpm --filter @quorum/runaway-agent demo` — no infrastructure, no keys, no
 * config.
 *
 *   1. the meter        every turn states what it cost; the thread folds the total
 *   2. the overrun      the ceiling is crossed, and the thread pauses itself
 *   3. it stops         the next action is refused before a single event is published
 *   4. Stop             a human interrupts mid-action and the effect aborts
 *   5. the human decides  resuming and raising are two decisions, and both are needed
 *
 * Every control in Quorum before this one decides whether work may *start*: a
 * capability, an approval, a manifest. These two are what you reach for when
 * those decisions turn out to have been wrong — one for an agent nobody is
 * watching, one for an agent somebody is.
 *
 * The agent in `agent.ts` cooperates with neither. It has no budget check, no
 * turn counter and no idea what an interrupt is; it reads pages until it runs
 * out of pages. That is deliberate, because an agent that policed itself would
 * demonstrate nothing: the mechanisms worth having are the ones that work on
 * the agent that was written badly.
 *
 * Act 3 is the one to read if you only read one. A budget that merely labels a
 * thread `paused` is a budget that announces the problem instead of stopping
 * it, so the assertion is not "the status changed" — it is that *no kind 8101
 * exists* for the fourth page.
 */

import {
  ActionBody,
  Kinds,
  TagName,
  ThreadOpBody,
  addressees,
  checkBudget,
  describeBudget,
  refTo,
  tagValue,
  tokensSpent,
  type Cost,
  type EventRef,
  type NostrEvent,
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
} from '@quorum/sdk'
import { FakeRelay, waitFor } from '@quorum/test-kit'
import { createRunawayAgent } from './agent.ts'

const GROUP = 'archive'
const CEILING = 30_000
const quiet = { debug() {}, info() {}, warn() {}, error() {} }

let failures = 0

const relay = await FakeRelay.start()
const ada = LocalSigner.generate()
const client = new RelayClient({ url: relay.url, signer: ada, reconnect: false, log: quiet })
await client.connect()
const publisher = new Publisher({
  client,
  signer: ada,
  pubkey: ada.publicKey,
  group: GROUP,
  counters: await Counters.load(new MemoryStore(), ada.publicKey),
})

/** Swapped between acts. The agent is handed a stable reference to it. */
let read: (page: number, signal: AbortSignal) => Promise<string> = instantly

const agent = createRunawayAgent({
  relay: relay.url,
  signer: LocalSigner.generate(),
  group: GROUP,
  pages: 6,
  read: (page, signal) => read(page, signal),
  log: quiet,
})
await agent.start()

console.log(`ada    ${ada.npub.slice(0, 20)}…   (opens the task, holds the purse, presses Stop)`)
console.log(`crawl  ${agent.me.slice(0, 16)}…   (reads pages until it runs out of pages)\n`)

// --- 1. the meter ---------------------------------------------------------------

act('1. the meter')

const archive = await task('index the archive', 'read the September ledger, page by page')
await op(archive, { op: 'set_budget', budget: { tokens: CEILING } })
say('ada', `opens a task and caps it at ${CEILING.toLocaleString()} tokens`)

await poke(archive)
say('crawl', 'starts reading, one `act()` per page, reporting what each one cost')
await until('the agent to stop talking', () => said(archive).some((t) => t.startsWith('stopping')))

const ledger = spends(archive)
report(
  'what it told the thread',
  `${ledger.length} kind 8109 \`add_spend\` ops`,
  ledger
    .map((s) => `· ${tokensSpent(s.cost).toLocaleString()} tokens — ${s.note ?? 'unexplained'}`)
    .join('\n    '),
)

const spent = threadState(relay.stored, archive.id)
expect(
  tokensSpent(spent.spent) === ledger.reduce((sum, s) => sum + tokensSpent(s.cost), 0),
  `the fold adds up to ${tokensSpent(spent.spent).toLocaleString()} tokens — the sum of the ops and nothing else`,
)
report(
  'both halves count',
  `${spent.spent?.tokens_in?.toLocaleString()} in + ${spent.spent?.tokens_out?.toLocaleString()} out`,
  'a budget states `tokens`; a spend states `tokens_in` and `tokens_out`. Compare either column ' +
    'against the ceiling on its own and a thread at 29,000 in and 28,000 out looks fine',
)

const succeeded = actions(archive, 'succeeded')
expect(
  succeeded.every((e) => ActionBody.safeParse(JSON.parse(e.content)).data?.cost !== undefined),
  'each action event carries its own cost as well — and the total counts it exactly once',
)
report(
  'why the op and not the action body',
  '`add_spend` is the only path into `spent`',
  'the action body says what one turn cost, which is audit detail; folding both would double ' +
    'every number in the workspace. It also works on a channel the relay cannot read, because ' +
    'the number is stated rather than estimated',
)

// --- 2. the overrun ---------------------------------------------------------------

act('2. the overrun')

expect(spent.status === 'paused', 'the thread paused itself — nobody published a `set_status`')
report(
  'the numbers',
  describeBudget(spent.spent, spent.budget),
  `over by ${(tokensSpent(spent.spent) - CEILING).toLocaleString()} tokens. A budget is a stop ` +
    'sign at the next junction, not a brake: the action already running finished and reported, ' +
    'because the alternative is losing the record of work that really happened',
)
report(
  'who pauses',
  'the fold, on `add_spend` and `set_budget` only',
  'never on `set_status`, or a human could not resume an exhausted thread — their `working` ' +
    'would be rewritten to `paused` by the same fold that stored it. And never on a `done` ' +
    'thread, because a late spend report must not un-finish delivered work',
)

// --- 3. it stops -------------------------------------------------------------------

act('3. it stops')

const proposed = actions(archive, 'proposed')
expect(
  proposed.length === succeeded.length && succeeded.length === 3,
  `${proposed.length} pages were proposed and ${succeeded.length} succeeded — and then nothing`,
)
report(
  'the assertion that matters',
  'there is no kind 8101 for page 4, of any status',
  'not a `proposed` the relay refused and not a `failed` — the action was stopped before it was ' +
    'an action. A rejected publish throws inside a handler, a throw is replayed, and a replay ' +
    'against a relay that will refuse it every time is a budget stop turned into a retry loop',
)

const ping = said(archive).at(-1) ?? ''
expect(/spent its budget/.test(ping), `and it told the human: "${ping}"`)
expect(
  addressedTo(archive).includes(ada.publicKey),
  'addressed to Ada with a `to`-marked p tag, so it lands in her queue rather than the channel',
)

// the control: a thread with a budget object and no dimensions in it
const uncapped = await task('read the other shelf', 'no ceiling on this one')
await op(uncapped, { op: 'set_budget', budget: {} })
await poke(uncapped)
await until('the agent to finish the uncapped thread', () =>
  said(uncapped).some((t) => t.startsWith('done')),
)
const free = threadState(relay.stored, uncapped.id)
expect(
  free.status !== 'paused' && actions(uncapped, 'succeeded').length === 6,
  'control: `set_budget {}` is "nobody has capped this", not a ceiling of zero — the same agent ' +
    `read all 6 pages and spent ${tokensSpent(free.spent).toLocaleString()} tokens unopposed`,
)

// --- 4. Stop --------------------------------------------------------------------------

act('4. Stop')

const started = deferred()
read = (_page, signal) =>
  new Promise<string>((_resolve, reject) => {
    started.resolve()
    signal.addEventListener('abort', () => reject(signal.reason))
  })

const deploy = await task('rebuild the index', 'this one takes a while')
await op(deploy, { op: 'set_budget', budget: { tokens: 1_000_000 } })
await poke(deploy)
await started.promise
say('crawl', 'is mid-page, with plenty of budget left — nothing is going to stop this one')

const running = actions(deploy, 'running')[0]
const [target] = actions(deploy, 'proposed')
await publisher.publish(interrupt({ thread: deploy, action: target!.id, reason: 'wrong shelf' }))
say('ada', 'publishes a kind 28101 naming that action')

await until('the agent to give up', () => said(deploy).some((t) => t.startsWith('stopping')))
expect(
  actions(deploy, 'cancelled').length === 1 && actions(deploy, 'failed').length === 0,
  'the chain ends `cancelled`, not `failed` — a job that broke and a job a human stopped send ' +
    'very different people to very different screens',
)
expect(
  tagValue(actions(deploy, 'cancelled')[0]!.tags, TagName.Event) === running?.id,
  'and the terminal event still answers the `running` one, so the chain an auditor walks is whole',
)
report(
  'no receipt, by construction',
  `the relay received ${relay.eventsOfKind(28101).length}, and stored ${relay.storedOfKind(28101).length}`,
  'kind 28101 is in the ephemeral range, so nothing keeps it. An agent that was down hears ' +
    'nothing — which is correct, because the action it was cancelling is not running either — ' +
    'but it does mean no OK from a relay ever means "an agent heard you". Every screen that ' +
    'offers a Stop button has to say so',
)

// the control: an interrupt naming somebody else's action stops nothing
const release = deferred()
const second = deferred()
read = async (_page, signal) => {
  second.resolve()
  await release.promise
  return signal.aborted ? 'aborted' : 'entry 37 of the September ledger'
}
const other = await task('read the annexe', 'a different job entirely')
await poke(other)
await second.promise
await publisher.publish(
  interrupt({ thread: other, action: 'f'.repeat(64), reason: 'meant for another agent' }),
)
await new Promise((r) => setTimeout(r, 50))
release.resolve()
await until('the annexe job to finish', () => said(other).some((t) => t.startsWith('done')))
expect(
  actions(other, 'cancelled').length === 0,
  'control: an interrupt naming an action this agent is not running matches nothing and is ' +
    'silent about it — in a channel with several agents in it, that is the normal case',
)

// --- 5. the human decides -----------------------------------------------------------------

act('5. the human decides')

read = instantly
await op(archive, { op: 'set_status', status: 'open' })
say('ada', 'reopens the archive task without touching the ceiling')
await poke(archive, 'try again')
await until('the agent to refuse again', () =>
  said(archive).filter((t) => t.startsWith('stopping')).length === 2,
)
expect(
  actions(archive, 'proposed').length === 3,
  'still refused, and still without publishing anything: resuming clears the pause, it does not ' +
    'buy budget. The agent checks the ceiling, and the ceiling is still spent',
)

await op(archive, { op: 'set_budget', budget: { tokens: 200_000 } })
say('ada', 'raises the ceiling to 200,000 tokens')
await poke(archive, 'now try again')
await until('the agent to finish the archive', () =>
  said(archive).some((t) => t.startsWith('done')),
)
const finished = threadState(relay.stored, archive.id)
expect(
  finished.status !== 'paused' && actions(archive, 'succeeded').length === 9,
  `work resumed — 6 more pages, ${describeBudget(finished.spent, finished.budget)}`,
)
report(
  'two decisions, two ops',
  '`set_status` and `set_budget`',
  'raising the ceiling does not un-pause the thread and resuming does not raise the ceiling, ' +
    'because "this task may continue" and "this task may spend more" are different questions ' +
    'with different answers — and only one of them is gated on a `thread:budget` capability',
)

// the freeze
const frozen = await task('stop this one now', 'somebody wants this halted')
await op(frozen, { op: 'set_budget', budget: { usd: 0 } })
await poke(frozen)
await until('the agent to refuse the frozen thread', () =>
  said(frozen).some((t) => t.startsWith('stopping')),
)
const halt = threadState(relay.stored, frozen.id)
expect(
  halt.status === 'paused' && checkBudget(halt.spent, halt.budget).exhausted,
  'and `set_budget {usd: 0}` is a freeze, with nothing spent at all: at the ceiling counts as ' +
    'exhausted, so stopping a thread right now needs no new verb',
)
expect(
  actions(frozen, 'proposed').length === 0,
  'control: the freeze is not cosmetic either — nothing was proposed in that thread',
)

await agent.stop()
client.close()
await relay.stop()
console.log(failures === 0 ? '\ndone.' : `\n${failures} failed.`)
process.exit(failures === 0 ? 0 : 1)

// --- the workspace ------------------------------------------------------------------------

async function task(title: string, text: string): Promise<EventRef> {
  // Deliberately not addressed to the agent: the budget op has to be in the
  // channel before the handler starts, and an addressed root would start it.
  const root = await publisher.publish({ kind: Kinds.Thread, text, tags: [['title', title]] })
  return refTo(root)
}

function poke(thread: EventRef, text = 'read the archive'): Promise<NostrEvent> {
  return publisher.publish({ kind: Kinds.Comment, thread, text, to: [agent.me] })
}

function op(thread: EventRef, body: Parameters<typeof threadOp>[1]): Promise<NostrEvent> {
  return publisher.publish(threadOp(thread, body))
}

function inThread(kind: number, thread: EventRef): NostrEvent[] {
  return relay.storedOfKind(kind).filter((e) => tagValue(e.tags, TagName.RootEvent) === thread.id)
}

/** What the agent has said in this thread, oldest first. */
function said(thread: EventRef): string[] {
  return inThread(Kinds.Comment, thread)
    .filter((e) => e.pubkey === agent.me)
    .map((e) => e.content)
}

function addressedTo(thread: EventRef): string[] {
  return inThread(Kinds.Comment, thread)
    .filter((e) => e.pubkey === agent.me)
    .flatMap((e) => addressees(e.tags))
}

function actions(thread: EventRef, status: string): NostrEvent[] {
  return inThread(Kinds.Action, thread).filter(
    (e) => ActionBody.safeParse(JSON.parse(e.content)).data?.status === status,
  )
}

function spends(thread: EventRef): { cost: Cost; note?: string }[] {
  return inThread(Kinds.ThreadOp, thread)
    .map((e) => ThreadOpBody.safeParse(JSON.parse(e.content)).data)
    .filter((b): b is Extract<ThreadOpBody, { op: 'add_spend' }> => b?.op === 'add_spend')
    .map((b) => ({ cost: b.cost, ...(b.note ? { note: b.note } : {}) }))
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

/** `waitFor`, but a timeout is a failed demo rather than an unhandled rejection. */
async function until(what: string, done: () => boolean): Promise<void> {
  try {
    await waitFor(done, { describe: what, timeoutMs: 8000 })
  } catch {
    fail(`timed out waiting for ${what}`)
    console.log(failures === 0 ? '\ndone.' : `\n${failures} failed.`)
    process.exit(1)
  }
}

// --- narration ------------------------------------------------------------------------------

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
