/**
 * M6 against the real Go relay: two packers, compared byte for byte.
 *
 *   cd apps/relay && QUORUM_EVENTS_PER_MINUTE=0 make run     # :3334, another terminal
 *   pnpm --filter @quorum/claude-agent live
 *
 * The rate limit has to go up because this script publishes a 120-message
 * thread from one address, and the relay's default — 120 events a minute,
 * bursting 40 — is the right setting for a workspace and the wrong one for
 * somebody building a thread as fast as a socket allows. It refuses rather than
 * queues, so the script says so and stops instead of producing a half-built
 * thread and a mysterious disagreement two steps later.
 *
 * What only a real relay can show:
 *
 *   1. the two packers agree      relay-side Go vs SDK-side TypeScript, byte for byte
 *   2. a pack that will not fit   refused with its own numbers, not silently trimmed
 *   3. addressed by pubkey        a request to somebody else goes unanswered
 *   4. memory is validated        38104 through the relay's own schema check
 *   5. the loop                   the agent answers from a pack it never computed
 *
 * Claim 1 is the milestone and it is the one that cannot be tested anywhere
 * else. `internal/contextpack`'s golden fixture holds the Go packer to the
 * TypeScript packer's *recorded* output; the SDK suite holds the TypeScript
 * packer to the same file. Neither notices if the two implementations gather
 * *different events* to pack — the fixture is the input to the pure function,
 * not the four filters that produce it. Here the events come from one store and
 * the answers are compared as bytes.
 *
 * Exits non-zero on the first failed expectation.
 */

import {
  ContextPackRequestBody,
  Kinds,
  Resource,
  TagName,
  canonicalJson,
  refTo,
  type UnsignedEvent,
} from '@quorum/protocol'
import {
  Counters,
  Grants,
  LocalSigner,
  MemoryStore,
  Publisher,
  RelayClient,
  contextRequest,
  createMemory,
  fetchContext,
  packContext,
  threadFilter,
  type Agent,
} from '@quorum/sdk'
import { announce, createClaudeAgent, type Turn } from './agent.ts'
import { createModel } from './model.ts'

const url = process.env.QUORUM_RELAY ?? 'ws://localhost:3334'
// Fresh per run: the agent backfills its channel on start, so a reused group
// would have this run answering the last one's questions.
const group = process.env.QUORUM_GROUP ?? `ctx-${Date.now().toString(36)}`
const MESSAGES = Number(process.env.QUORUM_MESSAGES ?? 120)

const NIP29 = { createGroup: 9007, joinRequest: 9021 } as const

const ada = LocalSigner.generate()
const bot = LocalSigner.generate()
const model = createModel()

let failures = 0

const packer = process.env.QUORUM_PACKER ?? (await relayPubkey(url))

console.log(`relay   ${url}`)
console.log(`group   #${group}`)
console.log(`packer  ${packer.slice(0, 16)}…   (the relay's own key, from its NIP-11 document)`)
console.log(`model   ${model.name}${model.live ? '' : '   — set ANTHROPIC_API_KEY for the real thing'}`)
console.log(`ada     ${ada.npub.slice(0, 20)}…`)
console.log(`bot     ${bot.npub.slice(0, 20)}…\n`)

const adaClient = new RelayClient({ url, signer: ada })
await adaClient.connect()

await publishRaw(adaClient, ada, { kind: NIP29.createGroup, tags: [['h', group]], content: '' })

const publisher = new Publisher({
  client: adaClient,
  signer: ada,
  pubkey: ada.publicKey,
  group,
  counters: await Counters.load(new MemoryStore(), ada.publicKey),
})
const grants = new Grants({ client: adaClient, group, publisher })

await grants.issue({
  grantee: bot.publicKey,
  resource: Resource.Join,
  actions: ['invoke'],
  scope: { group },
})
await publishRaw(adaClient, bot, { kind: NIP29.joinRequest, tags: [['h', group]], content: '' })

// --- the thread ---------------------------------------------------------------

const root = await publisher.publish({
  kind: Kinds.Thread,
  text:
    'Migrate the ledger to the new schema. The cutover window is Saturday 02:00–04:00 UTC, ' +
    'and the rollback is a restore from the pre-cutover snapshot. Priya signs off on the go/no-go.',
  tags: [['title', 'ledger migration']],
})

// Long enough to be cut at 400 code points, so the pack is dominated by
// optional segments — which is what makes act 2 honest. A thread whose
// *mandatory* set alone overflows could not be rescued by a smaller budget, and
// the relay's refusal says to ask for one.
let turn: Turn | undefined
const filler = (i: number) =>
  `${i}. ${'checked the ledger balances and they still reconcile to the penny. '.repeat(8)}`.trim()

console.log(`publishing ${MESSAGES} messages…`)
for (let i = 1; i <= MESSAGES; i++) {
  await publish(publisher, { kind: Kinds.Comment, text: filler(i), thread: refTo(root) })
}

// --- 1. the two packers agree --------------------------------------------------

act('1. the two packers agree')

// The local half of the comparison, gathered before the request goes out so
// nothing can land in between. Deliberately the same four filters the relay's
// `gather` uses and the same four `Agent.threadEvents` uses: the root by id (it
// carries no `E` tag — it *is* the root), the thread by `E`, the relay's
// projection by `d`, and the workspace's agent manifests, which are not about
// this thread at all and are what makes provenance more than guesswork.
const local = await adaClient.query([
  threadFilter({ group, threadId: root.id }),
  { ids: [root.id] },
  {
    kinds: [Kinds.ThreadState],
    [`#${TagName.Identifier}`]: [root.id],
    [`#${TagName.Group}`]: [group],
  },
  { kinds: [Kinds.AgentManifest], [`#${TagName.Group}`]: [group] },
])
expect(
  local.length === MESSAGES + 1,
  `gathered all ${local.length} events of the thread — an unlimited filter is served a quarter of the relay's MaxLimit, and this is the assertion that notices when the thread outgrows it`,
)

const asked = await publisher.publish(
  contextRequest(packer, ContextPackRequestBody.parse({ thread: root.id, budget_tokens: 4000 })),
)
const answer = await waitForOne('the relay to answer the context request', async () => {
  const [found] = await adaClient.query([
    { kinds: [Kinds.ContextPackResult, Kinds.JobFeedback], [`#${TagName.Event}`]: [asked.id] },
  ])
  return found
})

expect(answer.kind === Kinds.ContextPackResult, `the relay packed it (kind ${answer.kind})`)
expect(answer.pubkey === packer, 'and signed the result with the key it publishes in NIP-11')

const mine = packContext({
  thread: root.id,
  requester: ada.publicKey,
  events: local,
  budget_tokens: 4000,
})
expect(
  answer.content === canonicalJson(mine),
  `${answer.content.length} bytes from Go and ${canonicalJson(mine).length} from TypeScript, and they are the same bytes`,
)
if (answer.content !== canonicalJson(mine)) diff(answer.content, canonicalJson(mine))

const parsed = JSON.parse(answer.content) as { segments: unknown[]; used_tokens: number; dropped_events: number }
report(
  'the pack',
  `${parsed.segments.length} segments, ${parsed.used_tokens} tokens, ${parsed.dropped_events} dropped, of ${local.length} events gathered`,
  'two implementations, two languages, one answer — which is what lets the packer move into the SDK at M9',
)

// --- 2. a pack that will not fit -----------------------------------------------

act('2. a pack too large to deliver')

const refusal = await refused({ thread: root.id, budget_tokens: 200_000 })
expect(
  refusal !== undefined && /\b65535\b/.test(refusal) && refusal.includes('budget_tokens'),
  `the relay refused in words, with the numbers in them: ${refusal ?? 'it did not refuse'}`,
)
report(
  'why it matters',
  'refused, not trimmed',
  'a relay that quietly dropped what its store could not hold would answer the same request differently ' +
    'from the SDK packer — under the same `algorithm`, with nothing in the body saying so',
)

const smaller = await fetchContext(
  { client: adaClient, group, publish: (options) => publisher.publish(options) },
  { thread: root.id, packer, budget_tokens: 2000 },
)
expect(
  smaller.segments.length > 0,
  `and the same thread at a smaller budget comes back fine: ${smaller.segments.length} segments, ${smaller.used_tokens} tokens`,
)

// --- 3. addressed by pubkey ----------------------------------------------------

act('3. a request addressed to someone else')

const elsewhere = await publisher.publish(
  contextRequest(LocalSigner.generate().publicKey, ContextPackRequestBody.parse({ thread: root.id })),
)
await sleep(1500)
const overheard = await adaClient.query([
  { kinds: [Kinds.ContextPackResult, Kinds.JobFeedback], [`#${TagName.Event}`]: [elsewhere.id] },
])
expect(
  overheard.length === 0,
  'the relay saw a context request it could have answered, and did not',
)
report(
  'why it matters',
  'silence, not a second opinion',
  'a workspace may hold several packers; one that answered everything would leave a requester unable to ' +
    'say whose answer it got, and they are allowed to differ',
)

// --- 4 and 5. the agent -------------------------------------------------------

act('4. the agent, packing over the wire')

const agent: Agent = createClaudeAgent({
  relay: url,
  signer: bot,
  group,
  model,
  packer,
  budgetTokens: 2000,
  onTurn: (t) => {
    turn = t
  },
})
await agent.start()
await announce(agent, {
  name: 'reader',
  description: 'answers questions about a thread',
  operator: ada.publicKey,
})

await publisher.publish({
  kind: Kinds.Comment,
  text: 'What is the rollback for the cutover, and who signs off?',
  thread: refTo(root),
  to: [bot.publicKey],
})
await waitFor('the agent to fetch a pack from the relay and answer', async () => turn !== undefined)

// Checked by finding the relay's answer in the store rather than by trusting
// `pack.algorithm`, which a local pack would set to the same string. That is
// the whole point of the milestone: from inside the handler the two paths are
// indistinguishable, so proving which one ran has to be done from outside it.
const overTheWire = await adaClient.query([
  {
    kinds: [Kinds.ContextPackResult],
    authors: [packer],
    [`#${TagName.Pubkey}`]: [bot.publicKey],
    [`#${TagName.Group}`]: [group],
  },
])
expect(
  overTheWire.length > 0 && turn!.pack.algorithm === 'extractive-v1',
  `the agent answered from a pack it did not compute — ${overTheWire.length} 6600 addressed to it, signed by the relay`,
)
console.log(`  \x1b[2m  ${turn!.answer.text.split('\n').join('\n    ')}\x1b[0m`)

act('5. memory, through the relay’s own validation')

const remembered = await createMemory({
  client: adaClient,
  publish: () => Promise.reject(new Error('ada does not write the bot’s memory')),
  pubkey: bot.publicKey,
  group,
}).get<Record<string, unknown>>(`thread/${root.id}`)

expect(
  remembered !== undefined,
  `the bot's 38104 passed the relay's schema check and reads back: ${JSON.stringify(remembered)}`,
)

await agent.stop()
adaClient.close()

console.log(failures === 0 ? '\nall good.' : `\n${failures} failed.`)
process.exit(failures === 0 ? 0 : 1)

// --- helpers ------------------------------------------------------------------

/**
 * The packer's pubkey, from NIP-11.
 *
 * Worth doing rather than configuring, because it is the answer to "how does a
 * client find the packer" on a relay it has just met. khatru29 puts the relay's
 * own key in the document, and on this relay that key is the DVM's.
 */
async function relayPubkey(wsUrl: string): Promise<string> {
  const http = wsUrl.replace(/^ws/, 'http')
  try {
    const response = await fetch(http, { headers: { Accept: 'application/nostr+json' } })
    const info = (await response.json()) as { pubkey?: string }
    if (info.pubkey) return info.pubkey
  } catch (error) {
    console.error(`could not read ${http}: ${String(error)}`)
  }
  console.error(
    'no pubkey in the relay’s NIP-11 document. Is the relay running?\n' +
      '  cd apps/relay && QUORUM_EVENTS_PER_MINUTE=0 make run\n' +
      'Or set QUORUM_PACKER to its hex pubkey.',
  )
  process.exit(2)
}

/** Ask for a pack that cannot be delivered, and return the relay's reason. */
async function refused(body: { thread: string; budget_tokens: number }): Promise<string | undefined> {
  try {
    await fetchContext(
      { client: adaClient, group, publish: (options) => publisher.publish(options) },
      { ...body, packer },
    )
    return undefined
  } catch (error) {
    return (error as Error).message
  }
}

/**
 * Publish, and stop the run on a rate-limit refusal rather than carrying on.
 *
 * A half-built thread would still pack, still compare equal, and still print
 * every tick below — while quietly testing a quarter of what it says it does.
 */
async function publish(p: Publisher, options: Parameters<Publisher['publish']>[0]): Promise<void> {
  try {
    await p.publish(options)
  } catch (error) {
    const message = (error as Error).message
    if (!/rate|too fast|slow down/i.test(message)) throw error
    console.error(
      `\nthe relay is rate-limiting this run (${message}).\n` +
        'Building a thread this fast is not what the default limit is for. Restart it with:\n' +
        '  cd apps/relay && QUORUM_EVENTS_PER_MINUTE=0 make run\n',
    )
    process.exit(2)
  }
}

/** NIP-29 management events are not Quorum kinds, and `build()` is right to refuse them. */
async function publishRaw(
  client: RelayClient,
  signer: LocalSigner,
  event: Omit<UnsignedEvent, 'pubkey' | 'created_at'>,
): Promise<void> {
  await client.publish(
    await signer.sign({ ...event, pubkey: signer.publicKey, created_at: Math.floor(Date.now() / 1000) }),
  )
}

/** The first line the two packers disagree on, which is the only useful part. */
function diff(theirs: string, ours: string): void {
  for (let i = 0; i < Math.max(theirs.length, ours.length); i++) {
    if (theirs[i] === ours[i]) continue
    const from = Math.max(0, i - 60)
    console.log(`    \x1b[2mrelay: …${theirs.slice(from, i + 60)}\x1b[0m`)
    console.log(`    \x1b[2msdk:   …${ours.slice(from, i + 60)}\x1b[0m`)
    return
  }
}

async function waitFor(what: string, done: () => Promise<boolean>): Promise<void> {
  const deadline = Date.now() + 30_000
  while (Date.now() < deadline) {
    if (await done()) return
    await sleep(250)
  }
  fail(`timed out waiting for ${what}`)
  process.exit(1)
}

async function waitForOne<T>(what: string, read: () => Promise<T | undefined>): Promise<T> {
  let found: T | undefined
  await waitFor(what, async () => {
    found = await read()
    return found !== undefined
  })
  return found!
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function act(title: string): void {
  console.log(`\n\x1b[1m${title}\x1b[0m`)
}

function report(label: string, value: string, note: string): void {
  console.log(`  \x1b[2m→ ${label}:\x1b[0m ${value}\n  \x1b[2m  ${note}\x1b[0m`)
}

function expect(condition: unknown, what: string): void {
  if (condition) console.log(`  \x1b[32m✔\x1b[0m ${what}`)
  else fail(what)
}

function fail(what: string): void {
  failures += 1
  console.log(`  \x1b[31m✘\x1b[0m ${what}`)
}
