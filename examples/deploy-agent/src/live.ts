/**
 * M4 against the real Go relay.
 *
 *   cd apps/relay && make run          # :3334, in another terminal
 *   pnpm --filter @quorum/deploy-agent live
 *
 * M4 is enforced in two places that were written separately and must agree.
 * `packages/sdk` refuses to *act* without a signed approval bound to the right
 * digest; `apps/relay/internal/policy/approvals.go` separately refuses to
 * *store* an approval from someone nobody asked, or a transition to an action
 * somebody else proposed. Each has its own tests, and neither suite can catch
 * the failure that matters most here — that the relay's rules reject honest
 * traffic the SDK produces. `apps/relay/approvals_test.go` builds its events by
 * hand, so it proves the policy logic and says nothing about whether real SDK
 * events satisfy it; the fake relay has no policies at all, so the SDK suite
 * cannot notice either. A policy that is too strict looks like a green board on
 * both sides and a hung agent in production.
 *
 * So this file runs the whole loop over a socket and checks both directions:
 * the honest path goes through, and each of the two relay policies refuses what
 * it exists to refuse — with the SDK's own events, not hand-rolled ones.
 *
 * Exits non-zero on the first failed expectation.
 */

import {
  Kinds,
  Resource,
  TagName,
  digest,
  refTo,
  tagValue,
  threadRef,
  type NostrEvent,
  type UnsignedEvent,
} from '@quorum/protocol'
import {
  Counters,
  Grants,
  LocalSigner,
  MemoryStore,
  Publisher,
  RelayClient,
  approvalResponse,
  threadOp,
  threads,
  verifyActionChain,
} from '@quorum/sdk'
import { createDeployAgent } from './agent.ts'
import { Deploys, RESOURCE } from './deploy.ts'

const url = process.env.QUORUM_RELAY ?? 'ws://localhost:3334'
// Fresh per run: the agent backfills its channel on start, so a reused group
// would have this run answering the last one's questions.
const group = process.env.QUORUM_GROUP ?? `live-${Date.now().toString(36)}`

const NIP29 = { createGroup: 9007, joinRequest: 9021, putUser: 9000 } as const

const ada = LocalSigner.generate()
const mallory = LocalSigner.generate()
const bot = LocalSigner.generate()

let failures = 0

console.log(`relay   ${url}`)
console.log(`group   #${group}`)
console.log(`ada     ${ada.npub.slice(0, 20)}…   (asked to approve, trusted to grant)`)
console.log(`mallory ${mallory.npub.slice(0, 20)}…   (a member, and nothing more)`)
console.log(`bot     ${bot.npub.slice(0, 20)}…\n`)

const adaClient = new RelayClient({ url, signer: ada })
const malloryClient = new RelayClient({ url, signer: mallory })
await adaClient.connect()
await malloryClient.connect()

await publishRaw(adaClient, ada, { kind: NIP29.createGroup, tags: [['h', group]], content: '' })

const publisher = new Publisher({
  client: adaClient,
  signer: ada,
  pubkey: ada.publicKey,
  group,
  counters: await Counters.load(new MemoryStore(), ada.publicKey),
})
const malloryPublisher = new Publisher({
  client: malloryClient,
  signer: mallory,
  pubkey: mallory.publicKey,
  group,
  counters: await Counters.load(new MemoryStore(), mallory.publicKey),
})
const grants = new Grants({ client: adaClient, group, publisher })

// --- getting in ---------------------------------------------------------------

// Membership is a capability like any other, and this is the negative control
// for it. Mallory asks to join a workspace nobody invited her to; until the
// relay consulted grants, that request was the whole mechanism and it always
// worked. The rest of this file then makes her a member anyway — the interesting
// thing about mallory is what she can do once she is inside, not whether she can
// get in, and having Ada put her there is how she gets the same standing an
// ordinary colleague has.
expect(
  await refused(
    malloryClient,
    await signRaw(mallory, { kind: NIP29.joinRequest, tags: [['h', group]], content: '' }),
    'group:join',
  ),
  'the relay refused a join request from someone nobody invited',
)
await publishRaw(adaClient, ada, {
  kind: NIP29.putUser,
  tags: [
    ['h', group],
    ['p', mallory.publicKey],
  ],
  content: '',
})

// The bot gets in the other way: Ada signs it an invitation, and it presents
// itself. The join request below is signed by the bot, not by Ada — `publishRaw`
// signs with `who`, so Ada's client merely carries it — and the relay admits it
// on the strength of the grant rather than the asking.
await grants.issue({
  grantee: bot.publicKey,
  resource: Resource.Join,
  actions: ['invoke'],
  scope: { group },
})
await publishRaw(adaClient, bot, { kind: NIP29.joinRequest, tags: [['h', group]], content: '' })

await waitFor('the members to be admitted', async () => {
  const admitted = await adaClient.query([
    { kinds: [NIP29.putUser], '#h': [group], '#p': [bot.publicKey, mallory.publicKey] },
  ])
  return admitted.length >= 2
})
ok('the relay admitted mallory by put-user and the bot on Ada’s invitation')

// --- the grant ---------------------------------------------------------------

await grants.issue({
  grantee: bot.publicKey,
  resource: RESOURCE,
  actions: ['invoke'],
  scope: { env: 'production' },
})
ok('the relay accepted a capability grant (38102) built by the SDK')

// --- the agent ---------------------------------------------------------------

const deploys = new Deploys({ trustedIssuers: [ada.publicKey] })
const agent = createDeployAgent({
  relay: url,
  signer: bot,
  group,
  deploys,
  approvers: [ada.publicKey],
  store: new MemoryStore(),
  expiresInSeconds: 120,
})
await agent.start()
ok('the agent subscribed — its `#p` filter was not refused')

const thread = await publisher.publish({
  kind: Kinds.Thread,
  text: 'deploy api 1.4.2 to production with 3 replicas',
  to: [bot.publicKey],
  tags: [['title', 'deploy']],
})

const request = await waitForOne('the approval request', async () => {
  const found = await adaClient.query([
    { kinds: [Kinds.ApprovalRequest], '#h': [group], '#E': [thread.id] },
  ])
  return found[0]
})
ok('the relay stored the proposal and the approval_request, and the agent stopped there')
expect(
  deploys.deployed.length === 0,
  'nothing deployed while the request was pending',
)

const actionId = tagValue(request.tags, TagName.Action)
expect(!!actionId, 'the request names its action chain')

// --- the relay's own half, with real SDK events ------------------------------

// 1. An approval from a member nobody asked. The SDK would refuse to count it;
//    the point here is that it never reaches storage to be counted.
const unasked = await malloryPublisher.sign(approvalResponse({ request, decision: 'approved' }))
expect(
  await refused(malloryClient, unasked, 'did not ask'),
  'the relay refused an approval_response from someone who was never asked',
)

// 2. A transition to somebody else's action. Mallory declares it succeeded.
const forged = await malloryPublisher.sign({
  kind: Kinds.Action,
  thread: threadRef(request)!,
  parent: refTo(request),
  action: actionId!,
  body: {
    name: 'deploy',
    summary: 'deploy api 1.4.2 to production on 3 replicas',
    status: 'succeeded',
  },
})
expect(
  await refused(malloryClient, forged, 'proposed'),
  'the relay refused a transition on an action proposed by someone else',
)

// 3. An approval of a different payload, signed by the person who *was* asked.
//    This is the one a naive relay policy misses: the signature is right, the
//    approver is right, and the digest is not.
const wrongDigest = await publisher.sign({
  ...approvalResponse({ request, decision: 'approved' }),
  body: {
    decision: 'approved',
    input_digest: digest({ service: 'api', version: '1.4.2', env: 'production', replicas: 300 }),
  },
})
expect(
  await refused(adaClient, wrongDigest, 'input_digest'),
  'the relay refused an approval echoing a digest the request never carried',
)

// --- the honest path ---------------------------------------------------------

await publisher.publish(approvalResponse({ request, decision: 'approved' }))
ok('the relay accepted Ada’s approval — the policies do not reject honest traffic')

await waitFor('the deploy', async () => deploys.deployed.length > 0)
ok(`the deploy ran: ${deploys.deployed[0]!.ref}`)

// --- and the audit, from what the relay will serve anyone --------------------

const stored = await adaClient.query([
  { '#E': [thread.id], '#h': [group] },
  { ids: [thread.id] },
])
const chain = verifyActionChain(actionId!, stored, {})
expect(chain.ok, `the chain verifies offline from what the relay serves`)
expect(chain.status === 'succeeded', `the chain ended succeeded (got ${chain.status})`)
expect(
  chain.approvals.filter((a) => a.counted).length === 1,
  'exactly one approval counts, and it is Ada’s',
)
expect(
  chain.approvals.every((a) => a.pubkey !== mallory.publicKey),
  'mallory’s approval is not in the chain at all — the relay never stored it',
)

// --- the task the deploy was for ---------------------------------------------

// The other cross-language seam, and until M5 nothing in TypeScript exercised
// it: the relay has folded kind 8109 into a signed 38101 since M2, and every TS
// client read that projection without ever producing an op for it. So the
// projector was proved by Go tests building events by hand, and `threads()` by
// TS tests building projections by hand, and nobody had put the two halves in
// the same room.
//
// `check: 'agrees'` is the assertion that matters. It means this process
// replayed the ops the relay says it folded, in the order the relay says it
// folded them, and arrived at the state the relay signed — which is the only
// reason a client is entitled to display a relay's projection at all.
await publisher.publish(threadOp(refTo(thread), { op: 'assign', assignee: bot.publicKey }))
await publisher.publish(threadOp(refTo(thread), { op: 'set_status', status: 'done' }))

// An admin may set a budget; the relay checks that rather than taking the op's
// word, and Ada is an admin because she created the group.
await publisher.publish(threadOp(refTo(thread), { op: 'set_budget', budget: { usd: 5 } }))
ok('the relay accepted three thread ops built by the SDK, including a budget from an admin')

// And the negative control for the one op that is authority rather than
// coordination. Mallory is an ordinary member holding no `thread:budget` grant.
expect(
  await refused(
    malloryClient,
    await malloryPublisher.sign(threadOp(refTo(thread), { op: 'set_budget', budget: { usd: 500 } })),
    'thread:budget',
  ),
  'the relay refused a budget change from a member with no capability for it',
)

// The whole channel in one filter, which is what the reference client asks for
// too — and it has to be. The relay's 38101 carries `d`, `h` and `alt` and no
// `E` tag, so a thread-scoped `{"#E": [...]}` query returns every op and none of
// the projections, and `threads()` would report `local` on a relay that had in
// fact folded and signed the lot.
const task = await waitForOne('the relay’s projection to agree with a replay of its own ops', async () => {
  const [found] = threads(await adaClient.query([{ '#h': [group] }]))
  return found?.check.verdict === 'agrees' && found.status === 'done' ? found : undefined
})
expect(task.assignee === bot.publicKey, 'the projection assigns the task to the bot')
expect(task.budget?.usd === 5, `the budget folded through at $5 (got ${JSON.stringify(task.budget)})`)
ok('the task reads `done`, and this process recomputed that from the ops the relay folded')

await agent.stop()
adaClient.close()
malloryClient.close()

console.log(failures === 0 ? '\nall good.' : `\n${failures} failed.`)
process.exit(failures === 0 ? 0 : 1)

// --- helpers ----------------------------------------------------------------

/**
 * Publish and expect an OK: false whose message mentions `because`.
 *
 * Matching on the message is deliberate. "The relay said no" is satisfied by a
 * rate limit, a validation error or a group-membership refusal, so a test that
 * only checks for rejection passes even when the policy under test was never
 * reached — which is exactly the failure mode of a policy accidentally left
 * unregistered.
 */
async function refused(client: RelayClient, event: NostrEvent, because: string): Promise<boolean> {
  try {
    await client.publish(event)
    return false
  } catch (error) {
    const message = (error as Error).message
    if (message.includes(because)) return true
    console.log(`    \x1b[2mrejected, but for the wrong reason: ${message}\x1b[0m`)
    return false
  }
}

/** NIP-29 management events are not Quorum kinds, and `build()` is right to refuse them. */
async function publishRaw(
  client: RelayClient,
  signer: LocalSigner,
  event: Omit<UnsignedEvent, 'pubkey' | 'created_at'>,
): Promise<void> {
  await client.publish(await signRaw(signer, event))
}

/** The same, stopping short of publishing, for the ones expected to be refused. */
function signRaw(
  signer: LocalSigner,
  event: Omit<UnsignedEvent, 'pubkey' | 'created_at'>,
): Promise<NostrEvent> {
  return signer.sign({
    ...event,
    pubkey: signer.publicKey,
    created_at: Math.floor(Date.now() / 1000),
  })
}

async function waitFor(what: string, done: () => Promise<boolean>): Promise<void> {
  const deadline = Date.now() + 15_000
  while (Date.now() < deadline) {
    if (await done()) return
    await settle(250)
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

function settle(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function expect(condition: unknown, what: string): void {
  if (condition) ok(what)
  else fail(what)
}

function ok(what: string): void {
  console.log(`  \x1b[32m✔\x1b[0m ${what}`)
}

function fail(what: string): void {
  failures += 1
  console.log(`  \x1b[31m✘\x1b[0m ${what}`)
}
