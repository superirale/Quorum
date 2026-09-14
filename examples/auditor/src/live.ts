/**
 * M7 against the real Go relay: its own checkpoints, held to by a TypeScript
 * client.
 *
 *   cd apps/relay && QUORUM_CHECKPOINT_EVERY=5 QUORUM_CHECKPOINT_LAG=10 \
 *     QUORUM_CLOCK_SKEW_SECONDS=10 make run       # :3334, another terminal
 *   pnpm --filter @quorum/auditor live
 *
 * The three settings have to move together and the relay will tell you if they
 * do not: it refuses to boot when the lag is shorter than the clock skew. The
 * defaults — a window every five minutes closing fifteen minutes back — are the
 * right ones for a workspace and the wrong ones for a script that wants to see
 * two windows close before you lose interest.
 *
 * What only a real relay can show:
 *
 *   1. it publishes at all        a signed 8108 appears, by the key in its NIP-11
 *   2. completeness holds         refetch the closed window, recompute, agree
 *   3. the chain                  contiguous windows, each `prev` the one before
 *   4. it does not accuse itself  a superseded 38101 must not be in the commitment
 *   5. no proof against honesty   the artifact refuses to be produced
 *
 * Act 4 is the one worth waiting for. A relay that committed to addressable
 * event ids would fail its own checkpoint the first time a task changed status,
 * because the store drops the superseded copy and the next reader recomputes a
 * root short by one. Here a thread op is folded into a 38101, the window
 * containing it is committed, the 38101 is then *replaced* by a second op, and
 * the old window is verified again. It agrees, which it could not do if the
 * relay had committed to the copy that no longer exists.
 *
 * Exits non-zero on the first failed expectation.
 */

import { Kinds, TagName, type NostrEvent } from '@quorum/protocol'
import {
  Counters,
  LocalSigner,
  MemoryStore,
  Publisher,
  RelayClient,
  checkChain,
  checkpointFilter,
  checkpoints,
  threadOp,
  verifyWindow,
  windowFilter,
  withholdingProof,
  type Checkpoint,
} from '@quorum/sdk'

const url = process.env.QUORUM_RELAY ?? 'ws://localhost:3334'
// Fresh per run: a checkpoint chain is per group, and a reused group would have
// this run reading windows the last one committed to.
const group = process.env.QUORUM_GROUP ?? `audit-${Date.now().toString(36)}`
const PATIENCE_MS = Number(process.env.QUORUM_PATIENCE_MS ?? 90_000)

const NIP29 = { createGroup: 9007 } as const

const ada = LocalSigner.generate()
let failures = 0

const relay = await relayPubkey(url)
console.log(`relay   ${url}`)
console.log(`group   #${group}`)
console.log(`signer  ${relay.slice(0, 16)}…   (the relay's own key, from its NIP-11 document)`)
console.log(`ada     ${ada.npub.slice(0, 20)}…\n`)

const client = new RelayClient({ url, signer: ada })
await client.connect()

await client.publish(
  await ada.sign({
    kind: NIP29.createGroup,
    tags: [['h', group]],
    content: '',
    pubkey: ada.publicKey,
    created_at: Math.floor(Date.now() / 1000),
  }),
)

const publisher = new Publisher({
  client,
  signer: ada,
  pubkey: ada.publicKey,
  group,
  counters: await Counters.load(new MemoryStore(), ada.publicKey),
})

// --- 1. it publishes at all -----------------------------------------------------

act('1. the relay publishes checkpoints')

const thread = await publisher.publish({
  kind: Kinds.Thread,
  text: 'reconcile the September ledger',
  tags: [['title', 'reconciliation']],
})
const said: NostrEvent[] = [thread]
for (const text of ['pulled the statements', 'one account is short', 'raised it with treasury']) {
  said.push(await publisher.publish({ kind: Kinds.Comment, text, thread: { id: thread.id, kind: thread.kind, pubkey: thread.pubkey } }))
}
report('published', `${said.length} events into #${group}`, 'now wait for a window to close over them')

const newest = said.reduce((max, event) => Math.max(max, event.created_at), 0)
const covering = await waitForOne(
  'a checkpoint whose window closes over everything published',
  async () => (await chain()).find((c) => c.body.to >= newest),
)

expect(covering.relay === relay, 'it is signed by the key the relay publishes in NIP-11')
report(
  'the commitment',
  `${covering.body.count} events, ${covering.body.from} → ${covering.body.to}, root ${covering.body.merkle_root.slice(0, 16)}…`,
  `algorithm ${covering.body.algorithm} — and the signature is checked by \`checkpoints()\`, ` +
    'which drops anything it cannot verify rather than reporting it',
)

// --- 2. completeness holds ------------------------------------------------------

act('2. completeness, against an honest relay')

const served = await client.query([windowFilter(covering)])
const verdict = verifyWindow(covering, served)
expect(
  verdict.verdict === 'agrees',
  `recomputing the root from the ${served.length} events the relay served reproduces the one it signed`,
)
if (verdict.verdict !== 'agrees') {
  report('instead', JSON.stringify(verdict), 'the Go tree and the TypeScript tree disagree, or a kind rule does')
}
report(
  'what this rules out',
  'silent withholding, for this window, from now on',
  'not because the relay promised — because it signed a set, and any set it serves later either ' +
    'recomputes to that root or does not',
)

// --- 3. the chain ---------------------------------------------------------------

act('3. the chain')

const links = await waitForOne('a second checkpoint, so there is a chain to check', async () => {
  const all = await chain()
  const index = all.findIndex((c) => c.event.id === covering.event.id)
  return all.length > index + 1 ? all.slice(Math.max(0, index - 1)) : undefined
})

const walk = checkChain(links)
expect(
  walk.ok,
  `${links.length} consecutive windows, contiguous and each chaining on the last by event id ` +
    `(${walk.broken.length} broken, ${walk.gaps.length} gaps, ${walk.overlaps.length} overlaps)`,
)
report(
  'the seconds covered',
  `${links[0]!.body.from} → ${links[links.length - 1]!.body.to}, with no second claimed twice`,
  'an overlap is what re-cutting history needs, and `prev` being an event id rather than a root ' +
    'is what makes two identical-looking quiet windows distinguishable',
)

// --- 4. it does not accuse itself ------------------------------------------------

act('4. a superseded projection is not in the commitment')

await publisher.publish(threadOp(thread, { op: 'set_status', status: 'working' }))
const firstProjection = await waitForOne('the relay to fold the op into a 38101', () => projection())
report(
  'the relay folded it',
  `38101 ${firstProjection.id.slice(0, 8)}… at ${firstProjection.created_at}`,
  'an addressable event: the next one for this thread replaces it and this copy is gone from the store',
)

const after = await waitForOne(
  'a window closing over the projection',
  async () => (await chain()).find((c) => c.body.to >= firstProjection.created_at),
)
expect(
  verifyWindow(after, await client.query([windowFilter(after)])).verdict === 'agrees',
  'the window containing the projection verifies while the projection still exists',
)

await publisher.publish(threadOp(thread, { op: 'set_status', status: 'done' }))
await waitFor('the 38101 to be replaced', async () => {
  const current = await projection()
  return current !== undefined && current.id !== firstProjection.id
})

const recheck = verifyWindow(after, await client.query([windowFilter(after)]))
expect(
  recheck.verdict === 'agrees',
  'and it still verifies once the projection has been superseded and dropped from the store',
)
if (recheck.verdict !== 'agrees') {
  report(
    'instead',
    JSON.stringify(recheck),
    'the relay committed to an id its own store deletes — it is now accusing itself, on a schedule, ' +
      'every time a task changes status',
  )
}

// --- 5. no proof against honesty -------------------------------------------------

act('5. no proof against an honest relay')

const everything = await client.query([{ [`#${TagName.Group}`]: [group] }])
expect(
  withholdingProof(after, await client.query([windowFilter(after)]), everything) === undefined,
  `nothing the relay served plus everything else in #${group} produces an accusation`,
)
report(
  'why this is the assertion that matters',
  'a mechanism that cries withholding at an honest relay is worse than none',
  'the first false accusation is the last time anybody reads the output. ' +
    '`pnpm --filter @quorum/auditor demo` is the other half: a relay that really is withholding',
)

client.close()
console.log(failures === 0 ? '\nall good.' : `\n${failures} failed.`)
process.exit(failures === 0 ? 0 : 1)

// --- helpers --------------------------------------------------------------------

/** Every checkpoint the relay has published for this group, oldest window first. */
async function chain(): Promise<Checkpoint[]> {
  return checkpoints(await client.query([checkpointFilter(group, relay)]), relay)
}

/** The relay's current 38101 for the thread, if it has folded any op yet. */
async function projection(): Promise<NostrEvent | undefined> {
  const [found] = await client.query([
    {
      kinds: [Kinds.ThreadState],
      [`#${TagName.Identifier}`]: [thread.id],
      [`#${TagName.Group}`]: [group],
    },
  ])
  return found
}

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
      '  cd apps/relay && QUORUM_CHECKPOINT_EVERY=5 QUORUM_CHECKPOINT_LAG=10 \\\n' +
      '    QUORUM_CLOCK_SKEW_SECONDS=10 make run',
  )
  process.exit(2)
}

async function waitFor(what: string, done: () => Promise<boolean>): Promise<void> {
  const deadline = Date.now() + PATIENCE_MS
  while (Date.now() < deadline) {
    if (await done()) return
    // Paced against the relay's own filter rate limit, which defaults to 120 a
    // minute and closes the subscription rather than queueing. Polling for a
    // checkpoint twice a second is exactly the shape of client that limit is
    // for, and the failure lands three acts later as an unexplained CLOSED.
    await sleep(1500)
  }
  fail(
    `timed out after ${Math.round(PATIENCE_MS / 1000)}s waiting for ${what}. ` +
      'Is the relay running with QUORUM_CHECKPOINT_EVERY set? It is off when the interval is 0, ' +
      'and five minutes apart by default.',
  )
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
