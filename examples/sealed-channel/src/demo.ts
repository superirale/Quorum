/**
 * The M9 demo: a channel the relay cannot read, and what that costs.
 *
 * `pnpm --filter @quorum/sealed-channel demo` — no infrastructure, no keys, no
 * config.
 *
 *   1. the channel goes dark   one message, before and after; and what is still visible
 *   2. the loop, sealed        propose → ask → approve → run, every body ciphertext
 *   3. the auditor needs a key the same events, verified twice, with and without
 *   4. the subtraction         which kinds stay in the clear, and why each one does
 *   5. rotation                a removed member keeps the past and loses the future
 *
 * Every milestone before this one added something. This one mostly *takes away*,
 * and a demo that only showed the encryption working would be advertising rather
 * than documenting. So acts 3 and 4 are the honest half: an encrypted channel
 * cannot be audited by a stranger, the relay stops projecting tasks, stops
 * packing context and stops enforcing approvals, and a removed member can still
 * read every word said before they left. None of that is a defect to be fixed
 * later — it is what encrypting a channel means, and the number of systems that
 * ship end-to-end encryption without saying so is the reason it is act 3 and 4
 * rather than a footnote.
 *
 * Act 1 is the one to read if you only read one, and specifically the second
 * half of it. The bodies are gone and **the graph is not**: who is in the
 * channel, who answered whom, when, how often, and what kind of event it was
 * all stay in the clear, because that is what routing and rate-limiting are
 * made of. If that metadata is the thing you needed to hide, `nip44` is not the
 * mode you want — M10 is.
 */

import {
  Kinds,
  TagName,
  UNSEALED_KINDS,
  enc,
  epoch as epochOf,
  digest,
  isSealed,
  mustSeal,
  tagValue,
  verifyEvent,
  type NostrEvent,
} from '@quorum/protocol'
import {
  ChannelCrypto,
  Counters,
  LocalSigner,
  MemoryStore,
  Publisher,
  RelayClient,
  approvalResponse,
  createAgent,
  rotateChannelKey,
  tallyApprovals,
  verifyActionChains,
  wrapChannelKey,
  type Rotation,
} from '@quorum/sdk'
import { FakeRelay, waitFor, waitForCount } from '@quorum/test-kit'

const GROUP = 'payments'
const quiet = { debug() {}, info() {}, warn() {}, error() {} }

let failures = 0

const relay = await FakeRelay.start()

/** A person in the channel, holding whichever epochs they have been handed. */
class Member {
  // Written out rather than declared as constructor parameters: those are
  // TypeScript syntax with a runtime effect, which `--experimental-strip-types`
  // refuses, and `erasableSyntaxOnly` is set repo-wide so that it fails here
  // rather than at the first `node src/demo.ts`.
  readonly name: string
  readonly signer: LocalSigner
  readonly client: RelayClient
  readonly crypto: ChannelCrypto
  readonly publisher: Publisher

  constructor(
    name: string,
    signer: LocalSigner,
    client: RelayClient,
    crypto: ChannelCrypto,
    publisher: Publisher,
  ) {
    this.name = name
    this.signer = signer
    this.client = client
    this.crypto = crypto
    this.publisher = publisher
  }

  get pubkey(): string {
    return this.signer.publicKey
  }

  static async join(name: string): Promise<Member> {
    const signer = LocalSigner.generate()
    const client = new RelayClient({ url: relay.url, signer, reconnect: false, log: quiet })
    await client.connect()
    const crypto = new ChannelCrypto({
      client,
      signer,
      pubkey: signer.publicKey,
      group: GROUP,
      log: quiet,
    })
    const publisher = new Publisher({
      client,
      signer,
      pubkey: signer.publicKey,
      group: GROUP,
      channel: crypto,
      counters: await Counters.load(new MemoryStore(), signer.publicKey),
    })
    return new Member(name, signer, client, crypto, publisher)
  }

  say(text: string, to: string[] = []): Promise<NostrEvent> {
    return this.publisher.publish({ kind: Kinds.ChatMessage, text, to })
  }

  rotate(members: Member[], reason: string): Promise<Rotation> {
    return rotateChannelKey({
      publisher: this.publisher,
      client: this.client,
      signer: this.signer,
      group: GROUP,
      members: members.map((m) => m.pubkey),
      reason,
    })
  }

  /** What this identity can actually read. `undefined` means "no key for that epoch". */
  read(event: NostrEvent): string | undefined {
    return this.crypto.unreadable(event) ? undefined : this.crypto.opened(event).content
  }
}

const ada = await Member.join('ada')
const bob = await Member.join('bob')
const deployer = LocalSigner.generate()

console.log(`ada       ${ada.pubkey.slice(0, 16)}…   (owner; rotates the key)`)
console.log(`bob       ${bob.pubkey.slice(0, 16)}…   (a member, until act 5)`)
console.log(`deploy    ${deployer.publicKey.slice(0, 16)}…   (an agent that needs consent)`)
console.log(`relay     holds every byte and can read none of the bodies\n`)

// --- 1. the channel goes dark -----------------------------------------------------------

act('1. the channel goes dark')

const before = await ada.say('the staging migration finished at 04:12')
expect(
  !isSealed(before) && stored(before.id).content === before.content,
  'plaintext channel: the relay stores the sentence, and could index, search or summarise it',
)

const rotation = await ada.rotate([ada, bob], 'payments is going private')
for (const m of [ada, bob]) await m.crypto.load()
say('ada', `published ${rotation.wraps.length} key wraps and then one policy — in that order`)
report(
  'the order is the whole of it',
  'wraps first, policy last',
  'the policy is what tells every writer to start sealing. Publish it first and everyone ' +
    'encrypts to an epoch that has not reached anybody yet, which is a much longer outage than ' +
    'the few hundred milliseconds of stale access the other order costs',
)

const after = await ada.say('the production migration starts at 06:00')
const onWire = stored(after.id)
expect(isSealed(onWire), 'encrypted channel: the same author, the same channel, sealed')
report(
  'what the relay now holds',
  `${onWire.content.slice(0, 44)}…`,
  `${onWire.content.length} bytes of NIP-44 v2 payload where the sentence used to be. The relay ` +
    'cannot tell it from base64 noise, and neither can anything it runs',
)
expect(
  ada.read(onWire) === 'the production migration starts at 06:00' &&
    bob.read(onWire) === ada.read(onWire),
  'both members open it to the same sentence, with a key neither of them sent over this relay',
)
expect(verifyEvent(onWire), 'and it verifies — the signature is over the ciphertext, as published')

// The half that matters. Everything the relay needs in order to be a relay is
// still legible, because that is not an oversight: it is what routing is.
report(
  'what is still in the clear',
  `kind ${onWire.kind} · h=${tagValue(onWire.tags, TagName.Group)} · enc=${enc(onWire.tags)} · ` +
    `epoch=${epochOf(onWire.tags)} · counter=${tagValue(onWire.tags, TagName.Counter)}`,
  'plus every `p`, `e` and `E` tag. So the relay still routes, still rate-limits, still enforces ' +
    'NIP-29 membership and still signs checkpoints — and an observer still learns who talks to ' +
    'whom, how often, and about how many things. `nip44` hides payloads, not the social graph',
)
// --- 2. the loop, sealed ----------------------------------------------------------------

act('2. the whole approval loop, sealed end to end')

const input = { service: 'payments-api', version: '2.1.0', replicas: 4 }
const ran: string[] = []
const agent = createAgent({
  relay: relay.url,
  signer: deployer,
  group: GROUP,
  store: new MemoryStore(),
  leases: false,
  log: quiet,
})
agent.on(async (_event, ctx) => {
  const result = await ctx.act({
    name: 'deploy.production',
    summary: 'deploy payments-api 2.1.0 to production',
    input,
    approvers: [ada.pubkey],
    risk: 'high',
    run: () => 'deployed 4 replicas',
  })
  if (result.status === 'succeeded') ran.push(result.output)
})
await agent.start()

// The agent needs the key like everyone else; an admin wraps the current epoch
// for it exactly as for a human. An agent is a member, not an integration.
await wrapChannelKey({
  publisher: ada.publisher,
  signer: ada.signer,
  group: GROUP,
  member: deployer.publicKey,
  epoch: rotation.epoch,
  key: rotation.key,
})
await until('the agent to be handed the channel key', () =>
  agent.channel.epochs.includes(rotation.epoch),
)

const root = await ada.publisher.publish({
  kind: Kinds.Thread,
  text: 'ship 2.1.0 when you are ready',
  to: [deployer.publicKey],
  tags: [['title', 'release 2.1.0']],
})
say('ada', 'opens a task and addresses the agent — the task text is sealed too')

const [request] = await waitForCount(() => relay.storedOfKind(Kinds.ApprovalRequest), 1, {
  describe: 'the approval request',
})
expect(isSealed(request!), 'the agent asks for consent, and even the request to a human is sealed')
report(
  'and its `alt` tag is in the clear, deliberately',
  `"${tagValue(request!.tags, TagName.Alt)}"`,
  'NIP-31 `alt` is required on every Quorum kind so that a reader which has never heard of kind ' +
    '8102 still produces a usable line — which is exactly why a sealed event must not describe ' +
    'itself in one. `build()` writes a generic line for a sealed event rather than the usual ' +
    'summary, because an `alt` saying what was being asked would publish in the clear the very ' +
    'sentence the body was hidden to protect',
)

const opened = ada.crypto.opened(request!)
await ada.publisher.publish(approvalResponse({ request: opened, decision: 'approved' }))
say('ada', 'opens it, reads what is being asked, and signs approval')
report(
  'she had to open it first, and that is not a UI detail',
  'the digest lives in the sealed body, not in a tag',
  '`approvalResponse` reads `input_digest` out of the request body, so a client that handed it ' +
    'the ciphertext would sign consent to nothing. Every reader of an approval needs a key ' +
    'before the word "approved" means anything',
)

await until('the agent to run', () => ran.length === 1)
expect(ran[0] === 'deployed 4 replicas', `and the agent ran: "${ran[0]}"`)

const events = [...relay.stored]
const [response] = relay.storedOfKind(Kinds.ApprovalResponse)
const withKey = tallyApprovals(
  request!,
  [response!],
  { input, inputDigest: digestOf(opened) },
  ada.crypto.opener(),
)
expect(withKey.decision === 'approved', 'the tally, given the key, counts one approval')

// The control, and the bug this milestone was mostly about. It is not that a
// keyless verifier gets a *worse* answer — it is that it gets the opposite one,
// silently, and an action that can never be approved looks exactly like a human
// who has not answered yet.
const blindTally = tallyApprovals(request!, [response!], { input, inputDigest: digestOf(opened) })
expect(
  blindTally.decision !== 'approved',
  `control: the same tally without the key says "${blindTally.decision}" — ` +
    `"${(blindTally.rejected[0]?.reason ?? blindTally.reason ?? '').slice(0, 68)}…"`,
)
report(
  'which is why `open` is a required dependency of `act()`',
  'not an option with a default',
  'a verifier that parses ciphertext rejects every honest approval, so the agent waits forever ' +
    'on consent it is already holding. The rule is one line and it applies everywhere: verify ' +
    'the signature against the sealed bytes, then open for the body',
)

// --- 3. the auditor needs a key ----------------------------------------------------------

act('3. the auditor needs a key, and says so')

const [blind] = verifyActionChains(events)
expect(blind !== undefined, 'a stranger with no key still finds the chain: the tags are in the clear')
expect(
  blind!.issues.some((i) => i.code === 'sealed'),
  `and reports it as sealed: ${blind!.issues.map((i) => i.code).join(', ')}`,
)
expect(
  !blind!.issues.some((i) => i.code === 'bad_signature'),
  'control: a sealed chain must never look like a forged one — every signature verified',
)
report(
  'why `no_proposal` is in that list too, and is the honest answer',
  'a proposal is identified by its body',
  'it carries no `action` tag, because its own id *is* the action id. So a keyless reader ' +
    'cannot even locate the anchor of the chain it can see. "There is a chain here and I cannot ' +
    'see its start" is a truer report than a clean pass or a forgery accusation',
)

const [chain] = verifyActionChains(events, { open: ada.crypto.opener() })
expect(
  chain!.ok && chain!.issues.length === 0 && chain!.status === 'succeeded',
  'the same events, the same function, one key: the whole answer, clean',
)
// `digest` rather than `JSON.stringify`, because the chain's input has been
// through canonicalisation and comes back key-sorted. Comparing the rendered
// strings would fail on an input that is byte-for-byte the one approved, which
// is the comparison every reader of an audit actually means.
expect(
  digest(chain!.input) === digest(input) &&
    chain!.approvals.length === 1 &&
    chain!.approvals.every((a) => a.counted && a.decision === 'approved'),
  `"${chain!.approvals[0]?.pubkey.slice(0, 12)}… approved exactly this, and exactly this ran"`,
)
report(
  'the cost, stated plainly',
  'an encrypted channel cannot be audited by a stranger',
  'M4 sold consent that anyone could check against no server at all. On a `nip44` channel ' +
    '"anyone" now means "anyone holding an epoch key", which is a real subtraction from the ' +
    'pitch and is why the auditor reports `sealed` rather than quietly failing the chain',
)

// --- 4. the subtraction -------------------------------------------------------------------

act('4. what stays in the clear, and what the relay stops doing')

const clear = events.filter((e) => !mustSeal(e.kind))
report(
  'unsealed kinds present here',
  [...new Set(clear.map((e) => e.kind))].sort((a, b) => a - b).join(', '),
  'out of the allowed set ' +
    UNSEALED_KINDS.join(', ') +
    ' — written as exceptions rather than as an allowlist of sealed kinds, so a kind invented ' +
    'in a later milestone is sealed by default. Get that polarity backwards and a new event ' +
    'type is quietly published in plaintext into channels that believe they are private',
)
expect(
  clear.every((e) => !isSealed(e)),
  'the bootstrap really is readable: 8110 key wraps and the 38107 policy',
)
report(
  'why those two can never be sealed',
  'a channel key wrapped under the channel key is a locked box containing its own key',
  'and the policy is what tells a writer to encrypt at all, so it has to be readable by ' +
    'somebody who cannot yet decrypt anything. The 8110 body is still private — it is wrapped ' +
    'with pairwise NIP-44 to one recipient, which is a different key from the channel’s',
)
report(
  'and why grants stay readable on purpose',
  '38102 and 38106 are authorization, not conversation',
  'two of them the relay itself enforces, so sealing them would disarm membership control on ' +
    'exactly the channels that care most. The deeper reason: a capability nobody can audit is ' +
    'not a capability. "Who may deploy to production" must still have an answer for an owner',
)

report(
  'the claim this demo deliberately does not assert',
  'that the relay stopped folding tasks',
  'there is no kind 38101 in this transcript, and it would prove nothing: `FakeRelay` has never ' +
    'projected anything in any milestone, so the assertion would pass against a relay that folds ' +
    'perfectly well. `live.ts` makes it against the Go projector, which really does fold on a ' +
    'plaintext channel and really does stop here',
)
report(
  'so four relay-side services switch off',
  'the 8109→38101 projection, the context DVM, the approval policies, budget enforcement',
  'each of them reads a body. The clients keep all four, because the SDK has always had its ' +
    'own copy — which is exactly why M6 built the packer twice and made the two byte-identical. ' +
    'On this channel the SDK packer is not an optimisation, it is the only one',
)

// --- 5. rotation ---------------------------------------------------------------------------

act('5. rotation: bob keeps the past and loses the future')

say('ada', 'removes bob and rotates — a new epoch, wrapped for everyone still here')
const second = await ada.rotate([ada], 'bob left the team')
for (const m of [ada, bob]) await m.crypto.load()
expect(second.epoch === rotation.epoch + 1, `epoch ${rotation.epoch} → ${second.epoch}`)

const next = await ada.say('the 06:00 window slipped to 09:00')
expect(
  ada.read(stored(next.id)) === 'the 06:00 window slipped to 09:00',
  'ada reads what is said next',
)
expect(bob.read(stored(next.id)) === undefined, 'bob does not, and gets a named epoch, not a crash')
expect(
  bob.read(stored(after.id)) === 'the production migration starts at 06:00',
  'and bob can still read every word said before he left — forever',
)
report(
  'which is not a gap to be closed',
  'rotation does not revoke, it mints',
  'nobody can un-give bytes somebody already holds. What rotation buys is that he cannot read ' +
    'what is said next, and the window between the removal and the rotation is real: until the ' +
    'new policy lands he is still reading the channel. Say so; do not design around a promise ' +
    'no protocol can keep',
)
report(
  'and the new member’s problem is the mirror of it',
  'joining does not hand over history',
  'an admin decides which past epochs a new member may have, one 8110 each. Handing over all ' +
    'of them is the useful answer and handing over only the current one is the conservative ' +
    'answer, and no library should make that call on an admin’s behalf',
)

await agent.stop()
for (const m of [ada, bob]) m.client.close()
await relay.stop()
console.log(failures === 0 ? '\ndone.' : `\n${failures} failed.`)
process.exit(failures === 0 ? 0 : 1)

// --- helpers ---------------------------------------------------------------------------------

/** The bytes the relay kept, which are the only bytes any of these claims are about. */
function stored(id: string): NostrEvent {
  const event = relay.stored.find((e) => e.id === id)
  if (!event) throw new Error(`the relay did not store ${id.slice(0, 12)}`)
  return event
}

function digestOf(openedRequest: NostrEvent): string {
  return JSON.parse(openedRequest.content).input_digest as string
}

/** `waitFor`, but a timeout is a failed demo rather than an unhandled rejection. */
async function until(what: string, done: () => boolean): Promise<void> {
  try {
    await waitFor(done, { describe: what, timeoutMs: 8000 })
  } catch {
    fail(`timed out waiting for ${what}`)
    console.log(`\n${failures} failed.`)
    process.exit(1)
  }
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
