/**
 * The M10 demo: a channel nobody can read twice, and what that costs.
 *
 * `pnpm --filter @quorum/mls-channel demo` — no infrastructure, no keys, no
 * config.
 *
 *   1. joining hands over nothing   a new member reads none of the history
 *   2. each member is the record    the relay holds every byte and serves nobody
 *   3. a retry is replayed          because a ratchet cannot repeat itself
 *   4. a commit is about everybody  and a member who misses one goes dark
 *   5. authorship is the signature  a lifted message, refused without cost
 *
 * M9 mostly took things away and said so. This one takes away the thing every
 * milestone before it assumed: that a message can be read more than once. MLS
 * deletes the material that opens a message as part of opening it, so the
 * relay's copy of this channel is unreadable to the relay, to a new member, to
 * an auditor, and — after one trip through the ratchet — to the member who read
 * it. Everything Quorum does with history (replay on restart, backfill, context
 * packing, the audit trail) therefore runs off a durable archive each member
 * keeps for itself, and the relay is demoted to a transport.
 *
 * Each act has a plaintext control in a second channel on the same relay, in
 * the same run, because "the encrypted one failed" is only interesting beside
 * "the plain one did not". Where a claim is about what the *relay* stopped
 * doing it is not asserted here at all — `FakeRelay` never did it — and lives
 * in `live.ts` against the Go relay instead.
 *
 * Act 1 is the one to read if you only read one. Under `nip44` a new member's
 * lack of history is an admin's decision: they can be handed old epochs, one
 * wrap each. Here there is no such decision to make and no admin who could make
 * it, because the keys are gone. That is not a gap in this implementation. It
 * is what forward secrecy is.
 */

import {
  EncMode,
  Kinds,
  TagName,
  build,
  epoch as epochOf,
  isMlsSealed,
  tagValue,
  verifyEvent,
  type NostrEvent,
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
  catchUpMls,
  fetchKeyPackages,
  fetchMlsWelcomes,
  inviteToMls,
  mlsCiphersuite,
  mlsKeyPackage,
  publishKeyPackage,
  type MlsIdentity,
} from '@quorum/sdk'
import { FakeRelay } from '@quorum/test-kit'
import type { CiphersuiteImpl } from 'ts-mls'

const GROUP = 'payments'
const CLEAR = 'payments-clear'
const quiet = { debug() {}, info() {}, warn() {}, error() {} }

let failures = 0

const relay = await FakeRelay.start()
const cs: CiphersuiteImpl = await mlsCiphersuite()

/**
 * One member: a key, a socket, a ratchet, and the archive that outlives it.
 *
 * The four storage objects are not incidental. `MlsCrypto` cannot be
 * constructed without an `Archive` and a `SealedEnvelopes`, because a ratchet
 * with nowhere to write is a client that loses the channel on its first
 * restart and cannot get it back from anyone.
 */
class Member {
  // Written out rather than declared as constructor parameters: those are
  // TypeScript syntax with a runtime effect, which `--experimental-strip-types`
  // refuses, and `erasableSyntaxOnly` is set repo-wide so that it fails here
  // rather than at the first `node src/demo.ts`.
  readonly name: string
  readonly signer: LocalSigner
  readonly client: RelayClient
  readonly store: MemoryStore
  readonly archive: Archive
  readonly envelopes: SealedEnvelopes
  readonly publisher: Publisher
  /**
   * The ratchet, behind one level of indirection, and that is load-bearing.
   *
   * MLS state is single-writer: two `MlsCrypto` objects over one store each
   * advance a generation the other does not know about, and the loser's
   * messages are unopenable by everybody. The first version of this file gave
   * the `Publisher` the object rather than the box, so {@link restart} swapped
   * the reader and left the writer stale — and three assertions in acts 4 and 5
   * failed with "epoch too old" against a member who was perfectly up to date.
   * A restart has to replace the writer everywhere, not in the one place the
   * caller was looking.
   */
  readonly ratchet: { crypto: MlsCrypto }
  identity: MlsIdentity

  constructor(
    name: string,
    signer: LocalSigner,
    client: RelayClient,
    store: MemoryStore,
    archive: Archive,
    envelopes: SealedEnvelopes,
    publisher: Publisher,
    ratchet: { crypto: MlsCrypto },
    identity: MlsIdentity,
  ) {
    this.name = name
    this.signer = signer
    this.client = client
    this.store = store
    this.archive = archive
    this.envelopes = envelopes
    this.publisher = publisher
    this.ratchet = ratchet
    this.identity = identity
  }

  get pubkey(): string {
    return this.signer.publicKey
  }

  get crypto(): MlsCrypto {
    return this.ratchet.crypto
  }

  static async join(name: string): Promise<Member> {
    const signer = LocalSigner.generate()
    const client = new RelayClient({ url: relay.url, signer, reconnect: false, log: quiet })
    await client.connect()
    const store = new MemoryStore()
    const archive = new Archive(store)
    const envelopes = new SealedEnvelopes(store)
    const crypto = await MlsCrypto.open({
      store,
      pubkey: signer.publicKey,
      group: GROUP,
      ciphersuite: cs,
      archive,
      envelopes,
      log: quiet,
    })
    const ratchet = { crypto }
    const publisher = new Publisher({
      client,
      signer,
      pubkey: signer.publicKey,
      group: GROUP,
      channel: {
        buildOptions: (kind) => ratchet.crypto.buildOptions(kind),
        seal: (unsigned) => ratchet.crypto.seal(unsigned),
      },
      counters: await Counters.load(store, signer.publicKey),
    })
    return new Member(
      name,
      signer,
      client,
      store,
      archive,
      envelopes,
      publisher,
      ratchet,
      await mlsKeyPackage(signer.publicKey, cs),
    )
  }

  say(text: string, options: { counter?: number; at?: number } = {}): Promise<NostrEvent> {
    return this.publisher.publish({
      kind: Kinds.ChatMessage,
      text,
      ...(options.counter !== undefined ? { counter: options.counter } : {}),
      ...(options.at !== undefined ? { created_at: options.at } : {}),
    })
  }

  /** What this member can actually read, or the reason they cannot. */
  async read(event: NostrEvent): Promise<{ text?: string; why?: string }> {
    try {
      return { text: await this.crypto.open(event) }
    } catch (error) {
      return { why: reason(error) }
    }
  }

  /** Drop the in-memory ratchet and rebuild it from this member's own store. */
  async restart(): Promise<number> {
    this.ratchet.crypto = await MlsCrypto.open({
      store: this.store,
      pubkey: this.pubkey,
      group: GROUP,
      ciphersuite: cs,
      archive: this.archive,
      envelopes: this.envelopes,
      log: quiet,
    })
    return this.crypto.warm()
  }
}

const ada = await Member.join('ada')
const bob = await Member.join('bob')
const cat = await Member.join('cat')
const mallory = LocalSigner.generate()

// The plaintext control channel: the same relay, the same run, no encryption at
// all. Every act below that claims a subtraction asks the same question here.
const clearAda = await plainMember()
const clearLate = await plainMember()

console.log(`ada       ${ada.pubkey.slice(0, 16)}…   (founds the group)`)
console.log(`bob       ${bob.pubkey.slice(0, 16)}…   (joins in act 1, goes dark in act 4)`)
console.log(`cat       ${cat.pubkey.slice(0, 16)}…   (joins in act 4, gets no history)`)
console.log(`mallory   ${mallory.publicKey.slice(0, 16)}…   (republishes what is not hers)`)
console.log(`relay     holds every byte of #${GROUP} and can serve it to nobody\n`)

// --- 1. joining hands over nothing ---------------------------------------------------------

act('1. the channel goes dark, and joining hands over nothing')

await ada.crypto.create(ada.identity)
await ada.publisher.publish({
  kind: Kinds.ChannelPolicy,
  d: GROUP,
  body: { enc: 'mls', reason: 'payments is going private', changed_at: now() },
})
say('ada', `founded the ratchet and published the policy — #${GROUP} is mls at epoch ${ada.crypto.epoch}`)
report(
  'the group first, the policy second',
  'and the reverse order is an outage',
  'the policy is what tells every client to seal; publishing it before the ratchet exists ' +
    'leaves a channel every writer refuses to write to in the clear with no group to write to ' +
    'instead. `channel policy` and `mls create` are one act with two events in it',
)

const early = await ada.say('the staging migration finished at 04:12')
const onWire = stored(early.id)
expect(isMlsSealed(onWire), 'the relay holds an MLSMessage where the sentence used to be')
report(
  'what it holds',
  `${onWire.content.slice(0, 40)}… (${onWire.content.length} bytes, epoch ${epochOf(onWire.tags)})`,
  'and the envelope around it is an ordinary Quorum event — same kind, same `h`, same `p`, same ' +
    '`counter`, same signature. Marmot publishes under a per-message ephemeral key with no other ' +
    'tag, which buys metadata privacy and costs addressing, rate limiting and relay-side ' +
    'membership all at once. Quorum keeps the envelope and says so',
)
expect(verifyEvent(onWire), 'and it verifies — the signature is over the ciphertext, as published')

// The author reading her own message is a claim worth making out loud, because
// the ratchet on its own cannot do it.
expect(
  (await ada.read(onWire)).text === 'the staging migration finished at 04:12',
  'ada reads back what ada said',
)
report(
  'which took a fix, and is the one asymmetry nobody expects',
  '`createApplicationMessage` advances the sender past the generation it just used',
  'so feeding the message back answers "Desired gen in the past". Every *other* member reads ' +
    'it; the author is the one member for whom it is already in the past, and no key exists that ' +
    'anyone could hand over. So the sentence is written down beside the sealed envelope, in the ' +
    'same awaited write, which is the last moment anybody holding this state can read it',
)

// Bob joins: an offer, a commit, a Welcome. Three events and three parties,
// where `nip44` needs one wrap and one decision.
await publishKeyPackage({ publisher: bob.publisher, group: GROUP, identity: bob.identity, ciphersuite: cs })
const offers = await fetchKeyPackages(ada.client, GROUP, { ciphersuite: cs })
const invitation = await inviteToMls({
  publisher: ada.publisher,
  signer: ada.signer,
  crypto: ada.crypto,
  group: GROUP,
  packages: offers.filter((p) => p.pubkey === bob.pubkey),
})
expect(invitation !== undefined, `ada commits the Add — #${GROUP} moves to epoch ${invitation?.epoch}`)
const [welcome] = await fetchMlsWelcomes(bob.client, bob.pubkey, GROUP)
expect(
  welcome !== undefined &&
    (await acceptMlsInvite({ signer: bob.signer, crypto: bob.crypto, identity: bob.identity, event: welcome, ciphersuite: cs })),
  `bob opens the Welcome and is in the ratchet at epoch ${bob.crypto.epoch}`,
)

const denied = await bob.read(onWire)
expect(
  denied.text === undefined,
  'and cannot read one word said before he arrived — not the previous sentence, not any of them',
)
report(
  'what the failure actually says',
  denied.why ?? '(nothing, which would be worse)',
  'the event is tagged epoch 0, bob is at epoch 1, and the relay is still serving the bytes. He ' +
    'has the ciphertext, the group and the membership, and is missing only a secret that was ' +
    'deleted by the act of using it',
)

const later = await ada.say('the production window is 06:00')
expect(
  (await bob.read(stored(later.id))).text === 'the production window is 06:00' &&
    (await ada.read(stored(later.id))).text === 'the production window is 06:00',
  'from this epoch forward the two of them read the same channel',
)

// The control. Not "a different relay behaves differently" — the same relay, a
// second channel, a client that has never seen either message being published.
await clearAda.publisher.publish({ kind: Kinds.ChatMessage, group: CLEAR, text: 'staging finished at 04:12' })
await clearAda.publisher.publish({ kind: Kinds.ChatMessage, group: CLEAR, text: 'production window is 06:00' })
const backfilled = await clearLate.client.query([{ kinds: [Kinds.ChatMessage], '#h': [CLEAR], limit: 50 }])
expect(
  backfilled.length === 2 && backfilled.every((e) => !isMlsSealed(e)),
  `control: in #${CLEAR} a client that has just arrived backfills all ${backfilled.length} messages`,
)
report(
  'and the `nip44` cure has no analogue here',
  'there is nothing an admin could choose to hand over',
  'on a `nip44` channel a new member gets whichever past epochs an admin decides to wrap for ' +
    'them — a decision, with a conservative answer and a useful one. On `mls` there is no ' +
    'decision to make and nobody who could make it. Marmot concedes the same thing in its own ' +
    'words: "not a complete offline-message-history guarantee"',
)

// --- 2. each member is the record -----------------------------------------------------------

act('2. the relay is the transport; each member is the record')

const warmed = await ada.restart()
expect(
  warmed >= 2 && (await ada.read(stored(early.id))).text === 'the staging migration finished at 04:12',
  `ada restarts, warms ${warmed} messages out of her own store, and reads the channel back`,
)
report(
  'both halves, from two places',
  'the archive for what she read, the envelope cache for what she said',
  'they are separated by *when* the plaintext is known. An incoming message is archived with its ' +
    'signature the moment it opens. An outgoing one has no signature yet — the `Publisher` signs ' +
    'after sealing — so it is kept with the envelope and gets its signed copy later, when the ' +
    'event comes back off the relay',
)

// Retention, which on this channel is the only way to get any forward secrecy
// back, and is therefore also the only way to lose the history for good.
const dropped = await bob.archive.prune(GROUP, now() + 60)
const relit = await bob.restart()
const gone = await bob.read(stored(later.id))
expect(
  dropped > 0 && relit === 0 && gone.text === undefined,
  `bob prunes his archive (${dropped} events), restarts, and can no longer read a message he read a moment ago`,
)
report(
  'his ratchet is intact and the relay still has every byte',
  gone.why ?? '(nothing)',
  'this is not corruption and there is no repair. The generation that opened that message was ' +
    'spent when he opened it, so the second attempt is refused by the same mechanism that makes ' +
    'the channel private. `prune` is an operator running a retention policy, never a timer: a ' +
    'background thread quietly deleting an audit trail is the incident, not the feature',
)
expect(
  relay.stored.some((e) => e.id === later.id) && verifyEvent(stored(later.id)),
  'control, in the same channel: the relay is still serving that exact event, and it still verifies',
)
const stillThere = await clearLate.client.query([{ kinds: [Kinds.ChatMessage], '#h': [CLEAR], limit: 50 }])
expect(
  stillThere.length === 2,
  `control, in #${CLEAR}: a plaintext client that deleted everything just asks again — ${stillThere.length} back`,
)
report(
  'so four things that were relay-side facts become client-side obligations',
  'replay on restart, backfill, context packing, the audit trail',
  'all four are built on "ask the relay for the history", and on this channel the relay has ' +
    'nothing to give. A Quorum `mls` client that does not keep an archive is not a degraded ' +
    'client; it is a client that forgets the workspace every time it restarts',
)

// --- 3. a retry is replayed ------------------------------------------------------------------

act('3. a retry is replayed, not re-sealed')

const at = now()
const first = await ada.say('rolling the deploy back to 1.4.1', { counter: 40, at })
const retry = await ada.say('rolling the deploy back to 1.4.1', { counter: 40, at })
expect(
  retry.id === first.id && retry.content === first.content,
  'the same body under the same counter at the same second produces byte-identical bytes',
)
expect(
  relay.received.filter((e) => e.id === first.id).length === 2 &&
    relay.stored.filter((e) => e.id === first.id).length === 1,
  'two arrivals, one message — the relay dedupes on the id, which is what `once()` has always bought',
)
expect(
  (await bob.read(stored(retry.id))).text === 'rolling the deploy back to 1.4.1',
  'and exactly one generation was spent: bob opens it once, successfully',
)
report(
  'because sealing twice is not idempotent and cannot be made so',
  'the sealed envelope is persisted before it is published, and the retry replays it',
  'under `nip44` the nonce is derived from the plaintext event, so sealing is a pure function ' +
    'and a retry rebuilds the same bytes for free. A ratchet advances a secret tree per message, ' +
    'so re-encrypting the same sentence yields different bytes and consumes a generation nobody ' +
    'can give back',
)

const twin = await ada.say('rolling the deploy back to 1.4.1', { counter: 41, at })
expect(
  twin.id !== first.id && relay.stored.filter((e) => e.content === twin.content).length === 1,
  'control: the same sentence under a *different* counter is a different message, sealed afresh',
)
report(
  'which is why the counter rule gained a second reading',
  'same counter and same plaintext is a retry that lost its cache',
  'same counter and *different* plaintext is still what it always was — the key is in two ' +
    'places. A crash between the ratchet step and the envelope write produces the first kind, ' +
    'which is visible and harmless. The write order exists to make sure it is never the other',
)

// --- 4. a commit is about everybody -----------------------------------------------------------

act('4. a commit is about everybody, and nothing tells the member who missed it')

say('bob', 'is busy and does not call catchup for the rest of this act')
await publishKeyPackage({ publisher: cat.publisher, group: GROUP, identity: cat.identity, ciphersuite: cs })
const catOffers = await fetchKeyPackages(ada.client, GROUP, { ciphersuite: cs })
const second = await inviteToMls({
  publisher: ada.publisher,
  signer: ada.signer,
  crypto: ada.crypto,
  group: GROUP,
  packages: catOffers.filter((p) => p.pubkey === cat.pubkey),
})
const catWelcome = (await fetchMlsWelcomes(cat.client, cat.pubkey, GROUP))[0]
expect(
  catWelcome !== undefined &&
    (await acceptMlsInvite({ signer: cat.signer, crypto: cat.crypto, identity: cat.identity, event: catWelcome, ciphersuite: cs })),
  `ada adds cat — epoch ${invitation?.epoch} → ${second?.epoch}, and cat is in`,
)

const afterCommit = await ada.say('freezing deploys until the postmortem')
expect(
  (await cat.read(stored(afterCommit.id))).text === 'freezing deploys until the postmortem',
  'cat, who joined at this epoch, reads what is said next',
)
const dark = await bob.read(stored(afterCommit.id))
expect(dark.text === undefined, 'bob, who missed one commit, reads nothing — and will read nothing ever again')
report(
  'and this is what he is told',
  dark.why ?? '(nothing)',
  'from four frames inside a library nobody in this repo wrote, naming no epoch, no group and no ' +
    'member. There is no notification that a commit happened, because a commit is a message in a ' +
    'channel he can no longer read. `quorum mls catchup` exists as a command an operator can run ' +
    'blind for exactly this reason',
)

const applied = await catchUpMls(bob.client, bob.crypto, GROUP)
expect(
  applied === 1 && (await bob.read(stored(afterCommit.id))).text === 'freezing deploys until the postmortem',
  `bob applies ${applied} commit and is back at epoch ${bob.crypto.epoch}`,
)
report(
  'which worked only because the commit was published',
  'kind 8112 exists because `add()` originally kept the new state and dropped the message',
  'every test agreed with it, because a two-member group is added to by its only other member — ' +
    'who applies the commit by producing it. The third member is what makes it visible, and the ' +
    'symptom was that the *first* member silently lost the channel forever',
)
expect(
  (await cat.read(stored(early.id))).text === undefined &&
    (await cat.read(stored(later.id))).text === undefined,
  'control, the other direction: cat reads nothing from either epoch before she joined',
)
const clearAll = await clearLate.client.query([{ kinds: [Kinds.ChatMessage], '#h': [CLEAR], limit: 50 }])
expect(
  clearAll.length === 2,
  `control, in #${CLEAR}: there is no commit to miss, so nobody can be behind — ${clearAll.length} readable`,
)
report(
  'the claim this demo deliberately does not assert',
  'that the relay and the ratchet disagree about who is a member',
  '`FakeRelay` has no NIP-29 member list, so an assertion here would pass against a relay that ' +
    'keeps a perfect one. It belongs in `live.ts`, and the two directions are different problems: ' +
    'in the tree and not at the relay reads everything and can publish nothing; at the relay and ' +
    'not in the tree publishes what nobody can open',
)
report(
  'and removing a member is two acts, one of which this repo cannot do',
  '`MlsCrypto` has `create`, `add`, `applyCommit` and `join` — and no `remove`',
  'removing at the relay stops them publishing here and leaves them reading the channel from any ' +
    'other relay that carries it, because Option A says every Quorum event is valid on a generic ' +
    'relay. Only an MLS Remove commit ends that, and it is not built. Stated as a gap rather ' +
    'than demonstrated, because a demo that acted it out would be claiming it',
)

// --- 5. authorship is the signature ------------------------------------------------------------

act('5. authorship is the Nostr signature, and refusing a forgery costs nothing')

const honest = await ada.say('approving the 1.4.1 rollback')
const lifted = await mallory.sign(
  build({
    kind: Kinds.ChatMessage,
    pubkey: mallory.publicKey,
    group: GROUP,
    text: honest.content,
    counter: 1,
    enc: EncMode.Mls,
    epoch: epochOf(honest.tags)!,
  }),
)
await ada.client.publish(lifted)
expect(
  verifyEvent(lifted) && lifted.content === honest.content && lifted.pubkey === mallory.publicKey,
  'mallory republishes ada’s ciphertext under her own signature, and the relay stores it',
)

// Asserted on the *reason*, not merely on the refusal. An earlier draft of this
// file refused the forgery with "epoch too old" — cat was a whole epoch behind
// because of a bug elsewhere in the demo — and a bare "she refused it" passed
// happily while proving nothing about the binding this act is named after.
const refused = await cat.read(lifted)
expect(
  refused.text === undefined && refused.why?.includes('says its author is') === true,
  'cat refuses it, and refuses it for the right reason',
)
report(
  'on the strength of a field inside the ciphertext',
  refused.why ?? '(nothing)',
  'the author travels in the MLS `authenticated_data`, covered by the AEAD and by the ' +
    '`FramedContent` signature. `ts-mls` will not tell a receiver who sent an application ' +
    'message — RFC 9420 encrypts the sender index on purpose — so the spec’s per-message ' +
    'credential rule was unimplementable as written and this replaced it',
)
expect(
  (await cat.read(stored(honest.id))).text === 'approving the 1.4.1 rollback',
  'and the honest copy still opens afterwards — the refusal discarded the ratchet step that found it',
)
report(
  'which is the whole of that finding',
  'commit the step and the forgery becomes a denial of service',
  'republish every message a moment before its author and the channel goes permanently dark, one ' +
    'unopenable event at a time. Discarding is safe because an MLS transition is a pure function ' +
    'of state and message, and that assertion above is the only thing that proves it',
)
report(
  'and the cost of binding authorship this way, stated',
  'deniability',
  'MLS gives a member cryptographic deniability outside the group; a Nostr signature over the ' +
    'ciphertext takes it away. That is the deliberate trade: an approval nobody can attribute in ' +
    'six months is not an audit record, and this system sells audit records',
)

for (const m of [ada, bob, cat, clearAda, clearLate]) m.client.close()
await relay.stop()
console.log(failures === 0 ? '\ndone.' : `\n${failures} failed.`)
process.exit(failures === 0 ? 0 : 1)

// --- helpers ---------------------------------------------------------------------------------

/** A client in the plaintext control channel: no sealer, no ratchet, no archive. */
async function plainMember(): Promise<{ client: RelayClient; publisher: Publisher }> {
  const signer = LocalSigner.generate()
  const client = new RelayClient({ url: relay.url, signer, reconnect: false, log: quiet })
  await client.connect()
  const store = new MemoryStore()
  return {
    client,
    publisher: new Publisher({
      client,
      signer,
      pubkey: signer.publicKey,
      group: CLEAR,
      counters: await Counters.load(store, signer.publicKey),
    }),
  }
}

/** The bytes the relay kept, which are the only bytes any of these claims are about. */
function stored(id: string): NostrEvent {
  const event = relay.stored.find((e) => e.id === id)
  if (!event) throw new Error(`the relay did not store ${id.slice(0, 12)}`)
  return event
}

function now(): number {
  return Math.floor(Date.now() / 1000)
}

/**
 * The first line of an error, trimmed.
 *
 * Printed rather than paraphrased throughout, because half of what this demo is
 * about is how unhelpful these sentences are: "CryptoError: OperationError" is
 * what a member who missed a commit is actually told, and writing a friendlier
 * version into the narration would be hiding the finding.
 */
function reason(error: unknown): string {
  const text = error instanceof Error ? `${error.name}: ${error.message}` : String(error)
  return text.split('\n')[0]!.slice(0, 140)
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
