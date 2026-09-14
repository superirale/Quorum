/**
 * The M7 demo: a relay withholding an event is caught, and then proven.
 *
 * `pnpm --filter @quorum/auditor demo` — no infrastructure, no keys, no config.
 *
 *   1. the commitment   the relay signs what it holds; a reader who has it all agrees
 *   2. caught           it stops serving one event, and completeness notices
 *   3. proven           a mirror puts the event back and reproduces the signed root
 *   4. the controls     an honest relay, a client that asked for less, a forged event
 *   5. the chain        a checkpoint removed from the log shows as a broken link
 *
 * Act 3 writes `proof.json`. `pnpm --filter @quorum/auditor verify` then reads
 * it back with no relay, no keys and no network, which is the point of the whole
 * mechanism: the accusation is an artifact, not a session.
 *
 * The relay here commits to what it *holds*, withheld events included. That is
 * the only arrangement in which any of this has anything to catch — a relay that
 * excluded what it was hiding would be committing to the lie and would never
 * contradict itself. The real relay has no such option, because it signs on a
 * timer, before it knows what it will later wish it had not committed to.
 *
 * Act 4 is the part to read if you only read one. A mechanism that cries
 * withholding at an honest relay is worse than no mechanism, because the first
 * false accusation is the last time anybody looks at the output.
 */

import { writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { Kinds, merkleRoot, type NostrEvent } from '@quorum/protocol'
import {
  Counters,
  LocalSigner,
  MemoryStore,
  Publisher,
  RelayClient,
  checkChain,
  checkpoints,
  verifyWindow,
  verifyWithholdingProof,
  windowFilter,
  withholdingProof,
  type Checkpoint,
} from '@quorum/sdk'
import { FakeRelay } from '@quorum/test-kit'

const GROUP = 'payments'
const PROOF = join(import.meta.dirname, '..', 'proof.json')
const quiet = { debug() {}, warn() {}, error() {} }

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

console.log(`relay ${relay.pubkey.slice(0, 16)}…   (it signs the checkpoints)`)
console.log(`ada   ${ada.npub.slice(0, 20)}…\n`)

// --- 1. the commitment --------------------------------------------------------

act('1. the commitment')

const lines = [
  'the invoice run finished',
  'reconciled against the ledger',
  'one account is short by 4,120',
  'raised it with treasury',
  'treasury says it is a timing difference',
]

/** Ada's own copy of what she sent — the mirror, in act 3. */
const mirror: NostrEvent[] = []
for (const text of lines) mirror.push(await publisher.publish({ kind: Kinds.ChatMessage, text }))
say('ada', `posts ${mirror.length} messages`)

const to = Math.floor(Date.now() / 1000) + 30
const point = one(checkpoints([relay.checkpoint(GROUP, { from: 0, to })], relay.pubkey))
say('relay', `signs a kind 8108 over the window it just closed`)
report(
  'the commitment',
  `${point.body.count} events, root ${point.body.merkle_root.slice(0, 16)}…`,
  'the relay cannot retract this: it is signed, content-addressed, and now in the channel',
)

const honest = verifyWindow(point, mirror)
report('a reader who holds everything', honest, 'the root recomputes — nothing to report')

// --- 2. caught ----------------------------------------------------------------

act('2. caught')

const hidden = mirror[2]!
relay.withhold(hidden.id)
say('relay', `stops serving "${hidden.content}" — it still holds it, it just will not hand it over`)

const reader = new RelayClient({ url: relay.url, signer: LocalSigner.generate(), reconnect: false, log: quiet })
await reader.connect()
const served = await reader.query([windowFilter(point)])
reader.close()

say('reader', 'refetches the closed window and recomputes the root')
report('verdict', verifyWindow(point, served), `${served.length} served against ${point.body.count} committed`)
report(
  'what this is not',
  'an accusation',
  'a reader that simply asked for less would see exactly this. Completeness says something is ' +
    'missing; it cannot say who is at fault, and a function that guessed would be wrong at the worst moment',
)

// --- 3. proven ----------------------------------------------------------------

act('3. proven')

say('ada', 'still has her own copy of the message the relay will not serve')
const proof = withholdingProof(point, served, mirror)
if (!proof) {
  fail('no proof was produced — the held events did not close the gap')
  process.exit(1)
}

report(
  'root(served ∪ held)',
  `${merkleRoot([...proof.served, ...proof.withheld.map((e) => e.id)]).slice(0, 16)}…`,
  `equal to the root the relay signed (${point.body.merkle_root.slice(0, 16)}…) — so the relay ` +
    'committed to an event it is not serving, and there is no innocent reading of that',
)

const verdict = verifyWithholdingProof(proof)
expect(verdict.proven, 'the proof verifies')
if (verdict.proven) {
  report(
    'named',
    `relay ${verdict.relay.slice(0, 16)}… is withholding ${verdict.withheld.map((id) => id.slice(0, 8)).join(', ')} from #${verdict.group}`,
    'one event id, one relay pubkey, one signature over each',
  )
}

await writeFile(PROOF, `${JSON.stringify(proof, null, 2)}\n`)
report(
  'the artifact',
  'proof.json',
  'run `pnpm --filter @quorum/auditor verify` — no relay, no keys, no network. ' +
    'Edit a byte of it first if you like',
)

// --- 4. the controls ----------------------------------------------------------

act('4. the controls')

expect(
  withholdingProof(point, mirror, mirror) === undefined,
  'an honest relay — one serving the whole window — produces no proof at all',
)

const partial = mirror.slice(0, 3)
const lazy = verifyWindow(point, partial)
expect(
  lazy.verdict === 'short' && withholdingProof(point, partial, partial) === undefined,
  'a client that only backfilled part of the window gets "short", and still no proof — ' +
    'it is short of its own accord',
)

const forged: NostrEvent = { ...hidden, content: 'a message nobody sent' }
const fabricated = verifyWithholdingProof({ ...proof, withheld: [forged] })
expect(
  !fabricated.proven,
  `a fabricated event is rejected as a fabrication, not as arithmetic: "${fabricated.proven ? '' : fabricated.reason}"`,
)

const unrelated: NostrEvent = { ...hidden, id: 'd'.repeat(64) }
expect(
  withholdingProof(point, served, [unrelated]) === undefined,
  'an event the relay never committed to does not close the gap, so nothing is emitted',
)

// --- 5. the chain -------------------------------------------------------------

act('5. the chain')

const windows: Checkpoint[] = []
for (const [from, until] of [[to + 1, to + 100], [to + 101, to + 200], [to + 201, to + 300]] as const) {
  windows.push(one(checkpoints([relay.checkpoint(GROUP, { from, to: until })], relay.pubkey)))
}
say('relay', 'closes three more windows, each chaining on the last by event id')
expect(checkChain(windows).ok, 'the chain holds: contiguous windows, every `prev` the one before it')

const severed = checkChain([windows[0]!, windows[2]!])
expect(
  severed.broken.length === 1 && severed.broken[0]!.event.id === windows[2]!.event.id,
  'remove the middle checkpoint from the log and the next one is left pointing at nothing — ' +
    '`prev` is an event id, so it commits to the window bounds and the count, not only to the set',
)

client.close()
await relay.stop()
console.log(failures === 0 ? '\ndone.' : `\n${failures} failed.`)
process.exit(failures === 0 ? 0 : 1)

// --- narration ----------------------------------------------------------------

function one<T>(items: T[]): T {
  if (items.length !== 1) throw new Error(`expected exactly one, got ${items.length}`)
  return items[0]!
}

function act(title: string): void {
  console.log(`\n\x1b[1m${title}\x1b[0m`)
}

function say(who: string, what: string): void {
  console.log(`  ${who.padEnd(8)} ${what}`)
}

function report(label: string, value: unknown, note: string): void {
  const shown = typeof value === 'string' ? value : JSON.stringify(value)
  console.log(`  \x1b[2m→ ${label}:\x1b[0m ${shown}\n  \x1b[2m  ${note}\x1b[0m`)
}

function expect(condition: boolean, what: string): void {
  if (condition) console.log(`  \x1b[32m✔\x1b[0m ${what}`)
  else fail(what)
}

function fail(what: string): void {
  failures += 1
  console.log(`  \x1b[31m✘\x1b[0m ${what}`)
}
