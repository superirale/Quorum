/**
 * M10 against the real Go relay: what a delivery service can enforce over
 * ciphertext, and what it cannot.
 *
 *   cd apps/relay && QUORUM_EVENTS_BURST=400 QUORUM_FILTERS_BURST=400 \
 *     QUORUM_CHECKPOINT_EVERY=5 QUORUM_CHECKPOINT_LAG=10 \
 *     QUORUM_CLOCK_SKEW_SECONDS=10 make run
 *   pnpm --filter @quorum/mls-channel live
 *
 * The three checkpoint variables move together or the relay refuses to boot —
 * the lag must be at least the skew — and are shortened here only so act 4 does
 * not wait for the default window. `QUORUM_OWNER_PUBKEYS` is deliberately not
 * set: unset means anyone may create a workspace, and every key here is minted
 * at startup.
 *
 * `demo.ts` runs against `FakeRelay`, which enforces nothing and keeps no
 * membership list, so every claim of the form "the relay refuses X" or "the two
 * membership lists disagree" is vacuous there and `demo.ts` says so instead of
 * asserting it. This is where those claims are worth making. Each act is a
 * **pair**: the same operation in a plaintext group and in an `mls` one, against
 * one relay in one run.
 *
 *   1. it refuses the leak      both directions, plus a policy that states an epoch
 *   2. three honest refusals    the slot, the recipient, the epoch collision
 *   3. the projection stops     8109 folds here and not there
 *   4. checkpoints do not       the same relay commits to MLS ciphertext, unchanged
 *   5. two membership lists     which disagree in both directions, on purpose
 *
 * Act 5 is the one worth understanding, and it is the tension this milestone
 * could not dissolve. The other two — addressing and rate limiting — turned out
 * to be properties of Marmot's transport rather than of MLS, and keeping the
 * Quorum envelope kept them. Membership is different: the relay's NIP-29 list
 * and the ratchet tree answer two different questions, are maintained by two
 * different acts, and neither may be inferred from the other. Removing somebody
 * from a channel therefore takes two operations, and this repo can only perform
 * one of them.
 *
 * Exits non-zero on the first failed expectation.
 */

import {
  EncMode,
  Kinds,
  TagName,
  ThreadStateBody,
  isMlsSealed,
  refTo,
  tagValue,
  type EventRef,
  type NostrEvent,
  type UnsignedEvent,
} from '@quorum/protocol'
import {
  Archive,
  Counters,
  LocalSigner,
  MemoryStore,
  MlsCrypto,
  Publisher,
  RelayClient,
  SealedEnvelopes,
  acceptMlsInvite,
  channelMembers,
  channelPolicy,
  checkpointFilter,
  checkpointFor,
  checkpoints,
  fetchKeyPackages,
  fetchMlsWelcomes,
  inWindow,
  inviteToMls,
  mlsCiphersuite,
  mlsKeyPackage,
  publishKeyPackage,
  threadOp,
  verifyWindow,
} from '@quorum/sdk'
import type { CiphersuiteImpl } from 'ts-mls'

const url = process.env.QUORUM_RELAY ?? 'ws://localhost:3334'
const stamp = Date.now().toString(36)
const open = process.env.QUORUM_GROUP_OPEN ?? `clear-${stamp}`
const shut = process.env.QUORUM_GROUP_MLS ?? `mls-${stamp}`
const PATIENCE_MS = Number(process.env.QUORUM_PATIENCE_MS ?? 60_000)

const NIP29 = { createGroup: 9007, putUser: 9000, removeUser: 9001 } as const

const cs: CiphersuiteImpl = await mlsCiphersuite()
let failures = 0

const ada = LocalSigner.generate()
const bob = LocalSigner.generate()
const cat = LocalSigner.generate()

console.log(`relay     ${url}`)
console.log(`#${open.padEnd(18)} plaintext — the control, and the same relay`)
console.log(`#${shut.padEnd(18)} mls — the subject`)
console.log(`ada       ${ada.npub.slice(0, 20)}…   (owner; founds the ratchet)`)
console.log(`bob       ${bob.npub.slice(0, 20)}…   (a relay member who never joins the ratchet)`)
console.log(`cat       ${cat.npub.slice(0, 20)}…   (joins the ratchet, then loses her relay seat)\n`)

const client = new RelayClient({ url, signer: ada })
await client.connect()

for (const group of [open, shut]) {
  await publishRaw(ada, { kind: NIP29.createGroup, tags: [['h', group]], content: '' })
  for (const member of [bob, cat]) {
    await publishRaw(ada, {
      kind: NIP29.putUser,
      tags: [
        ['h', group],
        ['p', member.publicKey],
      ],
      content: '',
    })
  }
}

const adaMls = await ratchet(ada)
const catMls = await ratchet(cat)
const clearPub = new Publisher({
  client,
  signer: ada,
  pubkey: ada.publicKey,
  group: open,
  counters: await Counters.load(new MemoryStore(), ada.publicKey),
})

// --- 1. it refuses the leak ------------------------------------------------------------------

act('1. the relay refuses a leak it could never have read')

await adaMls.crypto.create(await mlsKeyPackage(ada.publicKey, cs))
await adaMls.publisher.publish({
  kind: Kinds.ChannelPolicy,
  d: shut,
  body: { enc: 'mls', reason: 'M10 live', changed_at: now() },
})
const policy = await channelPolicy(client, shut)
expect(
  policy.enc === EncMode.Mls && policy.epoch === undefined,
  `the relay serves the policy back as \`${policy.enc}\` with no epoch, which is the rule`,
)
expect(
  await refused(
    await ada.sign({
      kind: Kinds.ChannelPolicy,
      pubkey: ada.publicKey,
      created_at: now(),
      tags: [
        ['h', shut],
        ['d', shut],
        ['alt', 'the channel encryption policy'],
      ],
      content: JSON.stringify({ enc: 'mls', epoch: 3, changed_at: now() }),
    }),
  ),
  'and a policy that *does* state one is refused',
)
report(
  'which is not tidiness',
  'the ratchet is the only thing that knows the epoch',
  'any number written into a 38107 is stale the instant somebody commits, and stale in the ' +
    'damaging direction: a client that believes it is sealing to the current epoch is sealing to ' +
    'one the group has left. `nip44` is the opposite — there the policy is the only thing that ' +
    'knows, which is why the epoch floor had to become per-mode rather than simply be lowered',
)

const first = await adaMls.publisher.publish({ kind: Kinds.ChatMessage, text: 'the migration starts at 06:00' })
expect(
  isMlsSealed(first) && Number(tagValue(first.tags, TagName.Epoch)) === 0,
  'a sealed kind 9 at epoch 0 is accepted — the first message of every MLS group is at zero',
)
report(
  'and that number cost two defects to get right',
  '`nip44` mints generation 1 so that zero stays distinguishable from a missing field',
  'MLS has no such choice: RFC 9420 puts a group at epoch 0 from creation until its first ' +
    'commit. A single floor of 1 rejected the opening messages of every MLS channel this relay ' +
    'would ever host, with "epoch must be a positive integer" about a number the spec requires',
)

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
  'plaintext into the mls channel: refused, by a relay that holds not one key of it',
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
        ['enc', 'mls'],
        ['epoch', '0'],
      ],
      content: 'not actually an MLSMessage',
    }),
  ),
  'and `enc=mls` on a plaintext channel is refused too — one tag is otherwise a bypass of body validation',
)
const control = await clearPub.publish({ kind: Kinds.ChatMessage, text: 'still readable over here' })
expect(
  !isMlsSealed(control) && control.content === 'still readable over here',
  `control: the identical plaintext message into #${open} goes through untouched`,
)

// --- 2. three honest refusals -----------------------------------------------------------------

act('2. the three checks a delivery service can make without reading anything')

const offer = await publishKeyPackage({
  publisher: catMls.publisher,
  group: shut,
  identity: catMls.identity,
  ciphersuite: cs,
})
expect(tagValue(offer.tags, TagName.Identifier) === shut, 'cat’s KeyPackage lands in the slot that will retire it')
expect(
  await refused(
    await cat.sign({
      ...offer,
      id: '',
      sig: '',
      created_at: now(),
      tags: offer.tags.map((t) => (t[0] === TagName.Identifier ? [TagName.Identifier, 'somewhere-else'] : t)),
    } as UnsignedEvent),
  ),
  'the same package in a different `d` slot: refused',
)
report(
  'because the failure it prevents is silent at every other layer',
  'a package in the wrong slot is never retired by the one that replaces it',
  'it still answers the `#h` query an inviter makes, so it looks fetchable forever. An inviter ' +
    'takes the spent one, commits an Add against a private half the joiner discarded months ago, ' +
    'and the result is a member sitting in the ratchet tree who can never read a word',
)

const offers = await fetchKeyPackages(client, shut, { ciphersuite: cs })
const invitation = await inviteToMls({
  publisher: adaMls.publisher,
  signer: ada,
  crypto: adaMls.crypto,
  group: shut,
  packages: offers.filter((p) => p.pubkey === cat.publicKey),
})
expect(
  invitation !== undefined && invitation.welcomes.length === 1,
  `ada commits the Add: one 8112 and ${invitation?.welcomes.length} Welcome, and #${shut} is at epoch ${invitation?.epoch}`,
)
const theWelcome = invitation!.welcomes[0]!
expect(
  await refused(
    await ada.sign({
      kind: theWelcome.kind,
      pubkey: ada.publicKey,
      created_at: now(),
      tags: [...theWelcome.tags, [TagName.Pubkey, bob.publicKey, '', 'to']],
      content: theWelcome.content,
    }),
  ),
  'the same Welcome addressed to two members: refused',
)
report(
  'and the refusal is a tag check, never a body check',
  'it has to keep working on a channel whose bodies this relay cannot read',
  'a Welcome carries key material sealed to one member’s KeyPackage, so the second addressee ' +
    'fails to find their own secrets in it and is required by the spec to treat that as "not ' +
    'mine" rather than as an error. They are told nothing, and go on waiting',
)

expect(
  await refused(
    await ada.sign({
      kind: Kinds.MlsCommit,
      pubkey: ada.publicKey,
      created_at: now(),
      tags: [
        ['h', shut],
        ['alt', 'an mls commit'],
      ],
      content: JSON.stringify({ epoch: 0, commit: 'AAEABQ==' }),
    }),
  ),
  `a second commit for epoch 0, which #${shut} already has: refused`,
)
report(
  'first stored wins, arbitrarily, and that is the point',
  'the property is that every member sees the same commit, not which one it is',
  'two members holding one epoch may both commit and MLS allows exactly one to become the next ' +
    'epoch. The loser is stranded at their old epoch by the ordinary missed-commit rule and has ' +
    'to be re-added — the correct outcome, because a committer whose commit was refused has not ' +
    'moved and knows it. On a generic relay, which serialises nothing, receivers fall back to ' +
    'the spec’s tie-break on the lowest event id',
)

// The honest Welcome is the only one cat should be able to find: the forged
// pair above were refused, so an inbox holding two of them is itself a failure
// of the previous assertion and there is nothing to accept.
//
// Joined and *then* narrated, rather than reading `catMls.crypto.epoch` inside
// the message. A template argument is evaluated whether the condition holds or
// not, so a failed join made the epoch getter throw `NotInMlsGroup` and took
// the whole script down three acts early — an assertion that crashes instead of
// printing ✘ hides every claim after it. Found by the mutation run, which is
// the only place this path is ever taken.
const welcomes = await fetchMlsWelcomes(client, cat.publicKey, shut)
const joined =
  welcomes.length === 1 &&
  (await acceptMlsInvite({
    signer: cat,
    crypto: catMls.crypto,
    identity: catMls.identity,
    event: welcomes[0]!,
    ciphersuite: cs,
  }))
expect(
  joined,
  'control: the honest Welcome — one recipient, right slot — got through, and cat is at epoch ' +
    `${joined ? catMls.crypto.epoch : '—'} (of ${welcomes.length} in her inbox)`,
)

// --- 3. the projection stops ------------------------------------------------------------------

act('3. the 8109→38101 projection: works here, stops there')

const clearTask = await task(clearPub, 'the readable one')
await clearPub.publish(threadOp(clearTask, { op: 'set_status', status: 'working' }))
await waitFor(`the relay to fold #${open}`, async () => (await projection(open, clearTask)) !== undefined)
expect(
  (await projection(open, clearTask))?.status === 'working',
  'the relay read the op, folded it and signed a 38101 — as it has since M2',
)

const sealedTask = await task(adaMls.publisher, 'the sealed one')
const sealedOp = await adaMls.publisher.publish(threadOp(sealedTask, { op: 'set_status', status: 'working' }))
expect(isMlsSealed(sealedOp), 'the same op into the mls channel is accepted, and is an MLSMessage')
await settle(6000)
expect(
  (await projection(shut, sealedTask)) === undefined,
  'and no 38101 was ever signed for it: the relay cannot fold a body it cannot read',
)
report(
  'which is the same subtraction `nip44` made, arriving by a different route',
  'there the relay lacks a key; here there is no key it could ever be given',
  'an admin can hand a `nip44` relay an epoch key and turn the projection back on, and choosing ' +
    'not to is a policy. On `mls` the material is deleted as it is used, so the relay-side fold ' +
    'is not switched off — it is unimplementable. `threads()` projects locally either way',
)

// --- 4. checkpoints do not stop ------------------------------------------------------------------

act('4. checkpoints are untouched, and that was designed in')

await waitFor('a checkpoint covering the mls channel', async () =>
  checkpoints(await client.query([checkpointFilter(shut)])).some((c) => checkpointFor([c], first)),
)
const chain = checkpoints(await client.query([checkpointFilter(shut)]))
const covering = checkpointFor(chain, first)!
const held = inWindow(await client.query([{ '#h': [shut], limit: 1000 }]), covering)
const verdict = verifyWindow(covering, held)
expect(
  verdict.verdict === 'agrees',
  `the relay signed a checkpoint over ${covering.body.count} events and it verifies as ` +
    `\`${verdict.verdict}\` — over ciphertext it cannot read`,
)
expect(
  held.some((e) => isMlsSealed(e)),
  `and ${held.filter(isMlsSealed).length} of the committed events are MLSMessages, including the one from act 1`,
)
report(
  'why this one costs nothing',
  'the commitment is over event ids',
  'an id is a hash of bytes the relay never has to understand, so layer 3 of the ordering design ' +
    'survives both encryption modes completely. M7 specified the merkle tree over ids rather ' +
    'than over content and this is the second milestone to collect on it',
)

// --- 5. two membership lists ---------------------------------------------------------------------

act('5. two membership lists, disagreeing in both directions at once')

// Bob is the first direction and needed no setup: he was put in the NIP-29
// group at startup and never published a KeyPackage, which is what an ordinary
// workspace member who has not run `quorum mls keypackage` looks like.
const relayList = await channelMembers(client, shut)
expect(
  relayList.includes(bob.publicKey) && !adaMls.crypto.members.includes(bob.publicKey),
  'bob is on the relay’s list and not in the ratchet tree — he may publish here and nobody can read him',
)
const bobPub = new Publisher({
  client,
  signer: bob,
  pubkey: bob.publicKey,
  group: shut,
  counters: await Counters.load(new MemoryStore(), bob.publicKey),
})
expect(
  await refused(await bobPub.sign({ kind: Kinds.ChatMessage, text: 'can anyone hear me' })),
  'and in practice he cannot publish at all: the only thing he can build is plaintext, which the policy forbids',
)
report(
  'which is the kinder of the two failures, and only by accident',
  'the `enc` policy catches him at the door',
  'had he published ciphertext from a ratchet nobody had committed, the relay would have stored ' +
    'it, every member would have failed to open it, and the symptom would have been a member ' +
    'whose messages arrive as noise. Being refused is the outcome he can act on',
)

// Cat is the other direction, and getting there takes the removal that does not
// remove: she is in the tree, and now loses her seat at the relay.
await publishRaw(ada, {
  kind: NIP29.removeUser,
  tags: [
    ['h', shut],
    ['p', cat.publicKey],
  ],
  content: '',
})
await settle(1500)
const afterRemoval = await channelMembers(client, shut)
expect(
  !afterRemoval.includes(cat.publicKey) && adaMls.crypto.members.includes(cat.publicKey),
  'ada removes cat at the relay: off the NIP-29 list, still in the ratchet tree',
)
const catPub = new Publisher({
  client,
  signer: cat,
  pubkey: cat.publicKey,
  group: shut,
  channel: catMls.crypto,
  counters: await Counters.load(new MemoryStore(), cat.publicKey),
})
expect(
  await refused(await catPub.sign({ kind: Kinds.ChatMessage, text: 'still here' })),
  'she can no longer publish into the channel — the relay refuses her as an unknown member',
)

const afterwards = await adaMls.publisher.publish({
  kind: Kinds.ChatMessage,
  text: 'rotating the production credentials tonight',
})
// Handed over directly rather than fetched, and that *is* the claim. Option A
// says every Quorum event is valid on any generic relay, so the interesting
// question is never whether this relay will serve her the bytes — it is what
// she can do with bytes she obtained anywhere at all.
expect(
  (await read(catMls.crypto, afterwards)) === 'rotating the production credentials tonight',
  'and she reads what ada says next, in full, from a copy of the event obtained anywhere',
)
report(
  'so removing a member is two acts and this repo can perform one',
  '`MlsCrypto` has `create`, `add`, `applyCommit` and `join` — and no `remove`',
  'the relay removal stops her publishing here and stops this relay serving her, and changes ' +
    'nothing about what she can read from any other relay carrying the channel. Only an MLS ' +
    'Remove commit ends that, and it is not built. Stated as a gap rather than demonstrated',
)
report(
  'and the two lists are not a design failure to be unified',
  'they answer different questions',
  '"who may publish here" is a relay’s question and it has to be answerable over ciphertext. ' +
    '"who can read this" is the ratchet’s and no relay can know it. `quorum mls members` prints ' +
    'both side by side for exactly this reason: a command that printed one would be confidently ' +
    'right about a question nobody asked',
)

client.close()
console.log(failures === 0 ? '\ndone.' : `\n${failures} failed.`)
process.exit(failures === 0 ? 0 : 1)

// --- the workspace ---------------------------------------------------------------------------

/** A member with a ratchet: their own store, archive, envelopes and publisher. */
async function ratchet(
  signer: LocalSigner,
): Promise<{ crypto: MlsCrypto; publisher: Publisher; identity: Awaited<ReturnType<typeof mlsKeyPackage>> }> {
  const store = new MemoryStore()
  const crypto = await MlsCrypto.open({
    store,
    pubkey: signer.publicKey,
    group: shut,
    ciphersuite: cs,
    archive: new Archive(store),
    envelopes: new SealedEnvelopes(store),
  })
  const publisher = new Publisher({
    client: new RelayClient({ url, signer }),
    signer,
    pubkey: signer.publicKey,
    group: shut,
    channel: crypto,
    counters: await Counters.load(store, signer.publicKey),
  })
  return { crypto, publisher, identity: await mlsKeyPackage(signer.publicKey, cs) }
}

function now(): number {
  return Math.floor(Date.now() / 1000)
}

/**
 * What a member can read out of an event, or nothing and why.
 *
 * Every failure here throws — a missed commit, a lifted message, no group state
 * at all — so an assertion that simply awaits `open()` does not print ✘ when it
 * is wrong, it takes the process down and silently deletes every claim below
 * it. The reason is printed rather than paraphrased, because "CryptoError:
 * OperationError" is genuinely what a member who missed a commit is told and a
 * friendlier sentence here would be hiding the finding.
 */
async function read(crypto: MlsCrypto, event: NostrEvent): Promise<string | undefined> {
  try {
    return await crypto.open(event)
  } catch (error) {
    const text = error instanceof Error ? `${error.name}: ${error.message}` : String(error)
    report('cannot read it', text.split('\n')[0]!.slice(0, 140), 'the ratchet’s own words')
    return undefined
  }
}

async function task(publisher: Publisher, title: string): Promise<EventRef> {
  const root = await publisher.publish({
    kind: Kinds.Thread,
    text: `${title} — opened by the M10 live script`,
    tags: [['title', title]],
  })
  return refTo(root)
}

/**
 * The relay's own signed projection for a thread, if it made one.
 *
 * The `h` tag is not optional even though `d` identifies the thread: relay29
 * refuses a tag-filtered query that does not also name a group, and the refusal
 * arrives as a CLOSED — so the filter without it reads as "the relay folded
 * nothing", which is exactly the sentence act 3 is trying to prove about the
 * other channel.
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

async function publishRaw(who: LocalSigner, unsigned: Omit<UnsignedEvent, 'pubkey' | 'created_at'>) {
  await client.publish(await who.sign({ ...unsigned, pubkey: who.publicKey, created_at: now() }))
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
 * watched it do so on the plaintext channel in well under a second.
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
