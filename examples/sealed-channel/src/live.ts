/**
 * M9 against the real Go relay: the subtraction, proved.
 *
 *   cd apps/relay && QUORUM_EVENTS_BURST=400 QUORUM_FILTERS_BURST=400 \
 *     QUORUM_CHECKPOINT_EVERY=5 QUORUM_CHECKPOINT_LAG=10 \
 *     QUORUM_CLOCK_SKEW_SECONDS=10 make run
 *   pnpm --filter @quorum/sealed-channel live
 *
 * The three checkpoint variables move together or the relay refuses to boot:
 * the lag must be at least the skew, or an honest late event lands inside a
 * window already signed. They are shortened here only so act 5 does not sit for
 * twenty minutes waiting for the default window to close, and nothing else in
 * this script depends on them. `QUORUM_OWNER_PUBKEYS` is deliberately *not* set:
 * unset means anyone may create a workspace, and Ada's key is minted at startup.
 *
 * `demo.ts` runs against `FakeRelay`, which projects nothing, packs nothing and
 * enforces nothing — so every claim of the form "the relay stops doing X" is
 * vacuous there, and `demo.ts` says so rather than asserting it. This file is
 * where those claims are worth making, because the Go relay really does all
 * four things on a plaintext channel and the point is that it stops.
 *
 * So each act is a **pair**: the same operation in a plaintext group and in an
 * encrypted one, against one relay in one run.
 *
 *   1. it refuses the leak     plaintext into a sealed channel is rejected, both ways round
 *   2. it refuses to over-seal a grant tagged `enc=nip44` is rejected too
 *   3. the projection stops    8109 folds into a signed 38101 here, and not there
 *   4. the packer stops        the DVM answers here, and refuses with a 7000 there
 *   5. checkpoints do not      the same relay commits to sealed events, unchanged
 *
 * Act 5 is the one worth understanding. A checkpoint commits to event **ids**,
 * and an id is a hash of bytes the relay never has to understand — so layer 3
 * of the ordering design survives encryption completely intact, while layers of
 * the product that read bodies do not. That is not luck; it is the reason the
 * merkle commitment was specified over ids in M7 rather than over content.
 *
 * Exits non-zero on the first failed expectation.
 */

import {
  ContextPackRequestBody,
  EncMode,
  Kinds,
  TagName,
  ThreadStateBody,
  isSealed,
  refTo,
  tagValue,
  type EventRef,
  type NostrEvent,
  type UnsignedEvent,
} from '@quorum/protocol'
import {
  ChannelCrypto,
  Counters,
  LocalSigner,
  MemoryStore,
  Publisher,
  RelayClient,
  channelPolicy,
  checkpointFilter,
  contextRequest,
  checkpointFor,
  checkpoints,
  inWindow,
  packContext,
  rotateChannelKey,
  threadFilter,
  threadOp,
  verifyWindow,
} from '@quorum/sdk'

const url = process.env.QUORUM_RELAY ?? 'ws://localhost:3334'
const stamp = Date.now().toString(36)
// Two groups, one relay, one run. A claim about what a relay stops doing is
// only worth anything next to the same relay still doing it — and a second
// process, or a second run, would be a different relay as far as any reader of
// the output can tell.
const open = process.env.QUORUM_GROUP_OPEN ?? `clear-${stamp}`
const shut = process.env.QUORUM_GROUP_SEALED ?? `sealed-${stamp}`
const PATIENCE_MS = Number(process.env.QUORUM_PATIENCE_MS ?? 40_000)
// NIP-90 addresses a packer by pubkey rather than by endpoint, which is the
// property act 4 turns on: "ask someone who holds the keys" is only actionable
// advice if the asking was addressed in the first place.
const packer = process.env.QUORUM_PACKER ?? (await relayPubkey(url))

const NIP29 = { createGroup: 9007, putUser: 9000 } as const

const ada = LocalSigner.generate()
const bob = LocalSigner.generate()
let failures = 0

console.log(`relay     ${url}`)
console.log(`#${open.padEnd(16)} plaintext — the control, and the same relay`)
console.log(`#${shut.padEnd(16)} nip44 — the subject`)
console.log(`packer    ${packer.slice(0, 16)}…   (the relay's own key, from its NIP-11 document)`)
console.log(`ada       ${ada.npub.slice(0, 20)}…   (owner of both)`)
console.log(`bob       ${bob.npub.slice(0, 20)}…   (a member of both)\n`)

const client = new RelayClient({ url, signer: ada })
await client.connect()

for (const group of [open, shut]) {
  await publishRaw(ada, { kind: NIP29.createGroup, tags: [['h', group]], content: '' })
  await publishRaw(ada, {
    kind: NIP29.putUser,
    tags: [
      ['h', group],
      ['p', bob.publicKey],
    ],
    content: '',
  })
}

const counters = await Counters.load(new MemoryStore(), ada.publicKey)
const clearPub = new Publisher({ client, signer: ada, pubkey: ada.publicKey, group: open, counters })
const crypto = new ChannelCrypto({ client, signer: ada, pubkey: ada.publicKey, group: shut })
const sealedPub = new Publisher({
  client,
  signer: ada,
  pubkey: ada.publicKey,
  group: shut,
  channel: crypto,
  counters,
})

// --- 1. it refuses the leak ----------------------------------------------------------------

act('1. the relay refuses a leak it could never have read')

const rotation = await rotateChannelKey({
  publisher: sealedPub,
  client,
  signer: ada,
  group: shut,
  members: [ada.publicKey, bob.publicKey],
  reason: 'M9 live',
})
await crypto.load()
say('ada', `rotated #${shut} to epoch ${rotation.epoch}: ${rotation.wraps.length} wraps, one policy`)

const served = await channelPolicy(client, shut)
expect(
  served.enc === EncMode.Nip44 && served.epoch === rotation.epoch,
  `the relay serves the policy back as ${served.enc} epoch ${served.epoch} — it is readable on ` +
    'purpose, because it is what tells a writer to encrypt at all',
)

const sealed = await sealedPub.publish({ kind: Kinds.ChatMessage, text: 'the key rotated at 04:12' })
expect(isSealed(sealed), 'a sealed kind 9 is accepted, epoch tag and all')

// The accident this closes: one client with encryption misconfigured, or an
// older build that predates the policy. Nobody sees an error without this —
// `openEvent` passes an untagged event straight through, so every reader
// renders it normally and the channel is simply less private than it says.
expect(
  await refused(
    await ada.sign({
      kind: Kinds.ChatMessage,
      pubkey: ada.publicKey,
      created_at: now(),
      tags: [
        ['h', shut],
        ['alt', 'a chat message'],
      ],
      content: 'and here it is in the clear',
    }),
  ),
  'plaintext into the sealed channel: refused, by a relay that cannot read a byte of what it is protecting',
)

expect(
  await refused(
    await ada.sign({
      kind: Kinds.ChatMessage,
      pubkey: ada.publicKey,
      created_at: now(),
      tags: [
        ['h', open],
        ['alt', 'a chat message'],
        ['enc', 'nip44'],
      ],
      content: 'not actually ciphertext',
    }),
  ),
  'and the other way round too: `enc=nip44` on a plaintext channel is refused',
)
report(
  'which is not symmetry for its own sake',
  '`enc` set skips body validation',
  'so without this arm, one tag is a bypass of the entire schema on a channel nobody is even ' +
    'encrypting — and the content would not have to be ciphertext, as that event demonstrates',
)

const control = await clearPub.publish({ kind: Kinds.ChatMessage, text: 'still readable over here' })
expect(
  !isSealed(control) && control.content === 'still readable over here',
  `control: the identical plaintext message into #${open} goes through untouched`,
)

// --- 2. it refuses to over-seal ------------------------------------------------------------

act('2. and refuses to seal what has to stay auditable')

expect(
  await refused(
    await ada.sign({
      kind: Kinds.CapabilityGrant,
      pubkey: ada.publicKey,
      created_at: now(),
      tags: [
        ['h', shut],
        ['d', `deploy-${stamp}`],
        ['alt', 'a capability grant'],
        ['enc', 'nip44'],
        ['epoch', String(rotation.epoch)],
      ],
      content: 'AsYpxbNkEQlOn0iVbmiRMeJlCCjZypOGjqeriM2NOTl+',
    }),
  ),
  'a kind 38102 grant tagged `enc=nip44`: refused even on the encrypted channel',
)
report(
  'because the unsealed list is not a convenience',
  'a capability nobody can audit is not a capability',
  '"who may deploy to production" is a question an encrypted channel still has to answer to a ' +
    'workspace owner, and sealing the grants answers it to nobody. Two of these the relay ' +
    'enforces itself, so sealing them disarms membership control on the channels that care most',
)

// --- 3. the projection stops ---------------------------------------------------------------

act('3. the 8109→38101 projection: works here, stops there')

const clearTask = await task(clearPub, 'the readable one')
await clearPub.publish(threadOp(clearTask, { op: 'set_status', status: 'working' }))
await waitFor(`the relay to fold #${open}`, async () => (await projection(open, clearTask)) !== undefined)
const folded = await projection(open, clearTask)
expect(
  folded?.status === 'working',
  `the relay read the op, folded it and signed a 38101 saying \`${folded?.status}\` — as it has ` +
    'since M2',
)

const sealedTask = await task(sealedPub, 'the sealed one')
const sealedOp = await sealedPub.publish(threadOp(sealedTask, { op: 'set_status', status: 'working' }))
expect(isSealed(sealedOp), 'the same op into the sealed channel is accepted, and is ciphertext')
await settle(6000)
expect(
  (await projection(shut, sealedTask)) === undefined,
  'and no 38101 was ever signed for it: the relay cannot fold a body it cannot read',
)
report(
  'the client is not worse off, which is the whole design',
  '`threads()` projects locally from the same ops',
  'the fold exists twice for exactly this reason, and M8 made the two agree field for field. ' +
    'What is lost is the relay\'s *signature* on the result — a client can no longer check its ' +
    'own projection against one the relay stands behind, so `threads()` reports `local`',
)

// --- 4. the packer stops -------------------------------------------------------------------

act('4. the context DVM: answers here, refuses there')

const clearRoot = await clearPub.publish({
  kind: Kinds.Thread,
  text: 'what happened to the September ledger?',
  tags: [['title', 'the ledger']],
})
for (const line of ['it was archived', 'by the nightly job', 'on the 3rd'])
  await clearPub.publish({ kind: Kinds.Comment, text: line, thread: refTo(clearRoot), parent: refTo(clearRoot) })

const clearRequest = await clearPub.publish(
  contextRequest(packer, ContextPackRequestBody.parse({ thread: clearRoot.id, budget_tokens: 4000 })),
)
await waitFor('the relay to pack the plaintext thread', async () =>
  (await answer(clearRequest.id, Kinds.ContextPackResult)) !== undefined,
)
expect(true, 'the relay packed it: a signed kind 6600, as M6 built')

const sealedRoot = await sealedPub.publish({
  kind: Kinds.Thread,
  text: 'what happened to the September ledger?',
  tags: [['title', 'the ledger']],
})
for (const line of ['it was archived', 'by the nightly job', 'on the 3rd'])
  await sealedPub.publish({ kind: Kinds.Comment, text: line, thread: refTo(sealedRoot), parent: refTo(sealedRoot) })

const sealedRequest = await sealedPub.publish(
  contextRequest(packer, ContextPackRequestBody.parse({ thread: sealedRoot.id, budget_tokens: 4000 })),
)
await waitFor('the relay to refuse the sealed thread', async () =>
  (await answer(sealedRequest.id, Kinds.JobFeedback)) !== undefined,
)
const refusal = await answer(sealedRequest.id, Kinds.JobFeedback)
// NIP-90 puts the reason in the `status` tag's third element, not in `content`.
// That is the right place for it here and not only by convention: `content` is
// what a sealed event encrypts, and a refusal whose text was sealed would be
// unreadable by precisely the client that needs to read it — the one that asked
// the wrong packer because it has no key.
const because = refusal?.tags.find((tag) => tag[0] === 'status' && tag[1] === 'error')?.[2] ?? ''
expect(
  refusal !== undefined && because !== '',
  `refused, out loud: "${because}" — kind 7000, which is on the unsealed list precisely so a ` +
    'refusal can reach somebody with no key',
)
report(
  'silence would have been the wrong answer',
  'an unanswered job looks like a relay that is down',
  'and NIP-90 makes the packer a pubkey rather than an endpoint, so "ask someone who holds the ' +
    'keys" is a thing a client can actually act on',
)

// Opened before packing, and nothing else about the call changes. That is the
// M6 claim collecting interest: the packer is a pure function over events, so
// making a channel private is a matter of what you hand it.
const locally = packContext({
  thread: sealedRoot.id,
  requester: ada.publicKey,
  budget_tokens: 4000,
  events: [sealedRoot, ...(await gather(shut, sealedRoot.id))].map((e) =>
    crypto.unreadable(e) ? e : crypto.opened(e),
  ),
})
expect(
  locally.segments.some((segment) => segment.text.includes('the nightly job')),
  `and the SDK packer, holding the key, produced ${locally.segments.length} segments over the ` +
    'same thread, with the conversation in them — on this channel it is not an optimisation, ' +
    'it is the only packer',
)

// The control, and the reason the refusal has to be explicit. A packer with no
// key does not fail: `packContext` is a pure function over events and will
// happily pack ciphertext into a well-formed 6600 that a model then reads as
// the conversation.
const keyless = packContext({
  thread: sealedRoot.id,
  requester: ada.publicKey,
  budget_tokens: 4000,
  events: [sealedRoot, ...(await gather(shut, sealedRoot.id))],
})
expect(
  keyless.segments.length > 0 && !keyless.segments.some((s) => s.text.includes('the nightly job')),
  `control: the same call without the key still returns ${keyless.segments.length} segments — ` +
    'base64, no error, nothing in the body saying so. A packer that cannot read the thread has ' +
    'to refuse, because succeeding looks identical from the outside',
)

// --- 5. checkpoints do not stop ---------------------------------------------------------------

act('5. checkpoints are untouched, and that was designed in')

await waitFor('a checkpoint covering the sealed channel', async () =>
  checkpoints(await client.query([checkpointFilter(shut)])).some((c) => checkpointFor([c], sealed)),
)
const chain = checkpoints(await client.query([checkpointFilter(shut)]))
const covering = checkpointFor(chain, sealed)!
// Everything the relay will serve for the window, which is what a reader has.
// `verifyWindow` filters out the wrong kinds and the wrong window itself, so
// handing it the whole group is deliberate rather than lazy.
const held = inWindow(await gatherAll(shut), covering)
const verdict = verifyWindow(covering, held)
expect(
  verdict.verdict === 'agrees',
  `the relay signed a checkpoint over ${covering.body.count} events and it verifies as ` +
    `\`${verdict.verdict}\` — over ciphertext it cannot read`,
)
expect(
  held.some((e) => isSealed(e)),
  `and ${held.filter(isSealed).length} of the committed events are sealed, including the message ` +
    'from act 1',
)
report(
  'why this one costs nothing',
  'the commitment is over event ids',
  'an id is a hash of bytes the relay never has to understand, so layer 3 of the ordering design ' +
    'survives encryption completely. That is not luck — M7 specified the merkle tree over ids ' +
    'rather than over content, and this is the milestone that collects on it',
)

client.close()
console.log(failures === 0 ? '\ndone.' : `\n${failures} failed.`)
process.exit(failures === 0 ? 0 : 1)

// --- the workspace ---------------------------------------------------------------------------

function now(): number {
  return Math.floor(Date.now() / 1000)
}

async function task(publisher: Publisher, title: string): Promise<EventRef> {
  const root = await publisher.publish({
    kind: Kinds.Thread,
    text: `${title} — opened by the M9 live script`,
    tags: [['title', title]],
  })
  return refTo(root)
}

/**
 * The relay's own signed projection for a thread, if it made one.
 *
 * The `h` tag is not optional here even though `d` identifies the thread on its
 * own: relay29 refuses a tag-filtered query that does not also name a group, and
 * a refusal arrives as a CLOSED rather than an error — so the filter without it
 * reads as "the relay folded nothing", which is exactly the sentence act 3 is
 * trying to prove about the *other* channel.
 */
async function projection(group: string, thread: EventRef): Promise<ThreadStateBody | undefined> {
  const [found] = await client.query([
    {
      kinds: [Kinds.ThreadState],
      [`#${TagName.Identifier}`]: [thread.id],
      [`#${TagName.Group}`]: [group],
      limit: 1,
    },
  ])
  return found && ThreadStateBody.safeParse(JSON.parse(found.content)).data
}

/** Whatever the relay published in reply to a job request. */
async function answer(requestId: string, kind: number): Promise<NostrEvent | undefined> {
  const [found] = await client.query([{ kinds: [kind], '#e': [requestId], limit: 1 }])
  return found
}

async function gather(group: string, rootId: string): Promise<NostrEvent[]> {
  return client.query([threadFilter({ group, threadId: rootId, limit: 500 })])
}

async function gatherAll(group: string): Promise<NostrEvent[]> {
  return client.query([{ '#h': [group], limit: 1000 }])
}

/** The packer's pubkey, which for the reference relay is the relay's own. */
async function relayPubkey(wsUrl: string): Promise<string> {
  const http = wsUrl.replace(/^ws/, 'http')
  try {
    const response = await fetch(http, { headers: { Accept: 'application/nostr+json' } })
    const info = (await response.json()) as { pubkey?: string }
    if (info.pubkey) return info.pubkey
  } catch (error) {
    console.error(`could not read ${http}: ${String(error)}`)
  }
  console.error('no pubkey in the relay’s NIP-11 document. Is the relay running? Or set QUORUM_PACKER.')
  process.exit(2)
}

async function publishRaw(who: LocalSigner, unsigned: Omit<UnsignedEvent, 'pubkey' | 'created_at'>) {
  await client.publish(
    await who.sign({ ...unsigned, pubkey: who.publicKey, created_at: now() }),
  )
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

/**
 * Wait out a thing that should *not* happen.
 *
 * A negative claim has no event to wait for, so the only honest version is a
 * deadline: long enough that the relay would have projected by now — act 3
 * watched it do so on the plaintext channel in well under a second — and
 * stated as a duration rather than hidden in a poll loop.
 */
function settle(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms))
}

/**
 * Poll until something is true, paced against the relay's own filter limit.
 *
 * `QUORUM_FILTERS_PER_MINUTE` defaults to 120 and *closes the subscription*
 * rather than queueing, so a loop asking twice a second dies two acts later as
 * an unexplained CLOSED.
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
  console.log(`  ${who.padEnd(9)} ${what}`)
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
