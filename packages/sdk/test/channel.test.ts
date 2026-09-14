/**
 * Encrypted channels — the policy, the keyring, and the two rotations.
 *
 * Most of these are written as "what does the person who was removed still
 * hold?", because that is the question an operator actually asks and the one
 * with the uncomfortable answer. Rotation does not un-give anybody the bytes
 * they already have; it only decides what they can read *next*. A test suite
 * that asserted a removed member "can no longer read the channel" would be
 * asserting something the design does not claim and cannot deliver.
 *
 * The other half is ordering. `rotateChannelKey` publishes wraps first and the
 * policy last, and the difference between the two orders is a channel that
 * briefly has stale readers versus a channel that briefly cannot be written to
 * by anyone — so the order is pinned by a test rather than by the comment.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import {
  AddressableKinds,
  BorrowedKinds,
  EncMode,
  Kinds,
  RegularKinds,
  build,
  computeId,
  isSealed,
  randomConversationKey,
  tagValue,
  verifyEvent,
  type NostrEvent,
} from '@quorum/protocol'
import { FakeRelay } from '@quorum/test-kit'
import {
  ChannelCrypto,
  Counters,
  LocalSigner,
  MemoryStore,
  MissingChannelKey,
  PLAINTEXT_POLICY,
  Publisher,
  RelayClient,
  channelKeyToHex,
  channelKeyring,
  channelMembers,
  channelPolicy,
  rotateChannelKey,
  wrapChannelKey,
} from '../src/index.ts'

const group = 'payments'
const silent = { warn() {}, error() {} }

/** One identity with everything it needs to write into the channel. */
interface Member {
  signer: LocalSigner
  pubkey: string
  client: RelayClient
  publisher: Publisher
  crypto: ChannelCrypto
}

async function member(url: string): Promise<Member> {
  const signer = LocalSigner.generate()
  const client = new RelayClient({ url, signer, reconnect: false, log: silent })
  await client.connect()
  const crypto = new ChannelCrypto({
    client,
    signer,
    pubkey: signer.publicKey,
    group,
    log: silent,
  })
  const publisher = new Publisher({
    client,
    signer,
    pubkey: signer.publicKey,
    group,
    counters: await Counters.load(new MemoryStore(), signer.publicKey),
    channel: crypto,
  })
  return { signer, pubkey: signer.publicKey, client, publisher, crypto }
}

interface Channel {
  relay: FakeRelay
  admin: Member
  close: () => Promise<void>
}

async function channel(extra = 0): Promise<Channel & { others: Member[] }> {
  const relay = await FakeRelay.start()
  const admin = await member(relay.url)
  const others: Member[] = []
  for (let i = 0; i < extra; i++) others.push(await member(relay.url))
  return {
    relay,
    admin,
    others,
    close: async () => {
      admin.client.close()
      for (const other of others) other.client.close()
      await relay.stop()
    },
  }
}

/** The relay's own member list. The real one generates it; here it is planted. */
async function publishMemberList(who: Member, members: string[]): Promise<void> {
  await who.client.publish(
    await who.signer.sign({
      pubkey: who.pubkey,
      created_at: Math.floor(Date.now() / 1000),
      kind: BorrowedKinds.GroupMembers,
      tags: [['d', group], ...members.map((p) => ['p', p])],
      content: '',
    }),
  )
}

describe('channelPolicy', () => {
  it('reads a channel with no 38107 as plaintext', async (t) => {
    // The opposite default would let a relay that failed to serve one event
    // turn a working channel into an unreadable one, which is a worse failure
    // than the one it would be protecting against.
    const ch = await channel()
    t.after(ch.close)

    assert.deepEqual(await channelPolicy(ch.admin.client, group), PLAINTEXT_POLICY)
  })

  it('reads back what an admin published, and says who signed it', async (t) => {
    const ch = await channel()
    t.after(ch.close)

    await rotateChannelKey({
      publisher: ch.admin.publisher,
      client: ch.admin.client,
      signer: ch.admin.signer,
      group,
      members: [ch.admin.pubkey],
      reason: 'contains customer PII',
    })

    const policy = await channelPolicy(ch.admin.client, group)
    assert.equal(policy.enc, EncMode.Nip44)
    assert.equal(policy.epoch, 1)
    assert.equal(policy.reason, 'contains customer PII')
    // Not decoration. A policy signed by someone nobody expected is the one
    // change in this system that silently declassifies a channel.
    assert.equal(policy.author, ch.admin.pubkey)
  })
})

describe('rotateChannelKey', () => {
  it('publishes every wrap before the policy that points at it', async (t) => {
    // The order is the whole risk calculation. Policy first would tell every
    // writer to seal under an epoch that has reached nobody — a channel that
    // cannot be read by anyone, for as long as the wraps take. Wraps first
    // leaves a departed member reading for a few hundred milliseconds longer,
    // which they could read anyway until the instant of rotation.
    const ch = await channel(2)
    t.after(ch.close)
    const members = [ch.admin.pubkey, ...ch.others.map((m) => m.pubkey)]

    const rotation = await rotateChannelKey({
      publisher: ch.admin.publisher,
      client: ch.admin.client,
      signer: ch.admin.signer,
      group,
      members,
    })

    assert.equal(rotation.epoch, 1)
    assert.equal(rotation.wraps.length, 3)

    const order = ch.relay.received.map((e) => e.kind)
    const policyAt = order.indexOf(AddressableKinds.ChannelPolicy)
    const lastWrapAt = order.lastIndexOf(RegularKinds.ChannelKey)
    assert.ok(lastWrapAt < policyAt, 'the policy must be the last thing published')
  })

  it('gives every member a key they can unwrap, and strangers nothing', async (t) => {
    const ch = await channel(2)
    t.after(ch.close)
    const [bob, mallory] = ch.others as [Member, Member]

    const rotation = await rotateChannelKey({
      publisher: ch.admin.publisher,
      client: ch.admin.client,
      signer: ch.admin.signer,
      group,
      members: [ch.admin.pubkey, bob.pubkey],
    })

    const bobs = await channelKeyring(bob.client, bob.signer, bob.pubkey, group)
    assert.deepEqual([...bobs.keys()], [1])
    assert.equal(channelKeyToHex(bobs.get(1)!), channelKeyToHex(rotation.key))

    // Mallory is on the relay and can see the wraps go past. That is the
    // metadata leak sealing `content` always has, and it is not a key.
    const hers = await channelKeyring(mallory.client, mallory.signer, mallory.pubkey, group)
    assert.equal(hers.size, 0)
  })

  it('mints the next epoch and says what it supersedes', async (t) => {
    const ch = await channel(1)
    t.after(ch.close)
    const [bob] = ch.others as [Member]

    await rotateChannelKey({
      publisher: ch.admin.publisher,
      client: ch.admin.client,
      signer: ch.admin.signer,
      group,
      members: [ch.admin.pubkey, bob.pubkey],
    })
    const second = await rotateChannelKey({
      publisher: ch.admin.publisher,
      client: ch.admin.client,
      signer: ch.admin.signer,
      group,
      members: [ch.admin.pubkey],
      reason: 'bob left the team',
    })

    assert.equal(second.epoch, 2)
    for (const wrap of second.wraps) {
      assert.equal(JSON.parse(wrap.content).supersedes, 1)
    }
    assert.equal((await channelPolicy(ch.admin.client, group)).epoch, 2)
  })

  it('refuses to rotate a channel with no members', async (t) => {
    // The failure it prevents is a channel sealed under a key nobody holds,
    // which is indistinguishable from a channel that has been destroyed and is
    // reached by one honest mistake: rotating before the member list loads.
    const ch = await channel()
    t.after(ch.close)

    await assert.rejects(
      () =>
        rotateChannelKey({
          publisher: ch.admin.publisher,
          client: ch.admin.client,
          signer: ch.admin.signer,
          group,
        }),
      /nobody would be able to read it/,
    )
  })

  it('defaults its recipients to the relay-signed member list', async (t) => {
    // `channelMembers` asks the relay, and the relay is the only authority on
    // who is in a NIP-29 group. An admin's own idea of the membership is a copy
    // that can be stale in the direction that matters.
    const ch = await channel(1)
    t.after(ch.close)
    const [bob] = ch.others as [Member]
    await publishMemberList(ch.admin, [ch.admin.pubkey, bob.pubkey])

    assert.deepEqual((await channelMembers(ch.admin.client, group)).sort(), [
      ch.admin.pubkey,
      bob.pubkey,
    ].sort())

    const rotation = await rotateChannelKey({
      publisher: ch.admin.publisher,
      client: ch.admin.client,
      signer: ch.admin.signer,
      group,
    })
    assert.equal(rotation.wraps.length, 2)
  })
})

describe('what rotation does and does not take away', () => {
  it('leaves a removed member able to read the past and not the future', async (t) => {
    // The honest claim, asserted in both directions in one test so neither half
    // can be quoted without the other.
    const ch = await channel(1)
    t.after(ch.close)
    const [bob] = ch.others as [Member]

    await rotateChannelKey({
      publisher: ch.admin.publisher,
      client: ch.admin.client,
      signer: ch.admin.signer,
      group,
      members: [ch.admin.pubkey, bob.pubkey],
    })
    await ch.admin.crypto.load()
    await bob.crypto.load()

    const before = await ch.admin.publisher.publish({
      kind: Kinds.ChatMessage,
      text: 'the staging key is rotating on friday',
    })

    await rotateChannelKey({
      publisher: ch.admin.publisher,
      client: ch.admin.client,
      signer: ch.admin.signer,
      group,
      members: [ch.admin.pubkey],
      reason: 'bob left the team',
    })
    await ch.admin.crypto.load()
    await bob.crypto.load()

    const after = await ch.admin.publisher.publish({
      kind: Kinds.ChatMessage,
      text: 'the production key is rotating on monday',
    })

    assert.equal(bob.crypto.open(before), 'the staging key is rotating on friday')
    assert.ok(bob.crypto.unreadable(after))
    assert.throws(() => bob.crypto.open(after), MissingChannelKey)
    assert.equal(ch.admin.crypto.open(after), 'the production key is rotating on monday')
  })

  it('hands one epoch to a joiner without minting a new one', async (t) => {
    const ch = await channel(1)
    t.after(ch.close)
    const [newcomer] = ch.others as [Member]

    const rotation = await rotateChannelKey({
      publisher: ch.admin.publisher,
      client: ch.admin.client,
      signer: ch.admin.signer,
      group,
      members: [ch.admin.pubkey],
    })
    await wrapChannelKey({
      publisher: ch.admin.publisher,
      signer: ch.admin.signer,
      group,
      member: newcomer.pubkey,
      epoch: rotation.epoch,
      key: rotation.key,
    })

    assert.equal((await channelPolicy(ch.admin.client, group)).epoch, 1, 'no new epoch')
    const keys = await channelKeyring(newcomer.client, newcomer.signer, newcomer.pubkey, group)
    assert.equal(channelKeyToHex(keys.get(1)!), channelKeyToHex(rotation.key))
  })
})

describe('channelKeyring', () => {
  it('keeps the good wraps when one is malformed, and says so', async (t) => {
    // One admin using a stale pubkey must not cost a member the other nine
    // epochs. The warning exists because the alternative — a silently short
    // keyring — looks exactly like never having been given the key.
    const ch = await channel(1)
    t.after(ch.close)
    const [bob] = ch.others as [Member]

    const rotation = await rotateChannelKey({
      publisher: ch.admin.publisher,
      client: ch.admin.client,
      signer: ch.admin.signer,
      group,
      members: [ch.admin.pubkey, bob.pubkey],
    })

    // A wrap for an epoch bob has no key for, encrypted to somebody else.
    await ch.admin.publisher.publish({
      kind: RegularKinds.ChannelKey,
      group,
      to: [bob.pubkey],
      body: {
        epoch: 2,
        key: await ch.admin.signer.nip44Encrypt(ch.admin.pubkey, channelKeyToHex(rotation.key)),
        recipient: bob.pubkey,
      },
    })

    const problems: string[] = []
    const keys = await channelKeyring(bob.client, bob.signer, bob.pubkey, group, (m) =>
      problems.push(m),
    )

    assert.deepEqual([...keys.keys()], [1])
    assert.equal(problems.length, 1)
    assert.match(problems[0]!, /could not unwrap epoch 2/)
  })

  it('ignores a wrap that only mentions us', async (t) => {
    // `#p` is a coarse prefilter and matches a mention as readily as an
    // addressing tag. A wrap addressed to somebody else that happens to name us
    // is not a grant of anything.
    const ch = await channel(1)
    t.after(ch.close)
    const [bob] = ch.others as [Member]

    const key = randomConversationKey()
    await ch.admin.publisher.publish({
      kind: RegularKinds.ChannelKey,
      group,
      to: [ch.admin.pubkey],
      tags: [['p', bob.pubkey]],
      body: {
        epoch: 1,
        key: await ch.admin.signer.nip44Encrypt(bob.pubkey, channelKeyToHex(key)),
        recipient: ch.admin.pubkey,
      },
    })

    const keys = await channelKeyring(bob.client, bob.signer, bob.pubkey, group)
    assert.equal(keys.size, 0)
  })
})

describe('ChannelCrypto', () => {
  it('does nothing at all on a plaintext channel', async (t) => {
    // The branch-free promise. A caller that had to ask `if (encrypted)` before
    // every publish would eventually forget once, and once is enough.
    const ch = await channel()
    t.after(ch.close)
    await ch.admin.crypto.load()

    assert.equal(ch.admin.crypto.encrypted, false)
    assert.deepEqual(ch.admin.crypto.buildOptions(Kinds.ChatMessage), {})

    const event = await ch.admin.publisher.publish({ kind: Kinds.ChatMessage, text: 'hello' })
    assert.equal(isSealed(event), false)
    assert.equal(event.content, 'hello')
  })

  it('seals a message and leaves the key management readable', async (t) => {
    const ch = await channel()
    t.after(ch.close)
    await rotateChannelKey({
      publisher: ch.admin.publisher,
      client: ch.admin.client,
      signer: ch.admin.signer,
      group,
      members: [ch.admin.pubkey],
    })
    await ch.admin.crypto.load()

    assert.deepEqual(ch.admin.crypto.buildOptions(Kinds.ChatMessage), {
      enc: EncMode.Nip44,
      epoch: 1,
    })
    // A grant nobody can audit is not a grant, and a policy nobody can read is
    // a channel nobody can join.
    assert.deepEqual(ch.admin.crypto.buildOptions(AddressableKinds.CapabilityGrant), {})
    assert.deepEqual(ch.admin.crypto.buildOptions(AddressableKinds.ChannelPolicy), {})

    const event = await ch.admin.publisher.publish({
      kind: Kinds.ChatMessage,
      text: 'rotate the production key',
    })
    assert.ok(isSealed(event))
    assert.notEqual(event.content, 'rotate the production key')
    assert.equal(tagValue(event.tags, 'epoch'), '1')
    assert.equal(ch.admin.crypto.open(event), 'rotate the production key')
  })

  it('does not summarise the body it just hid', async (t) => {
    // The `alt` tag is never sealed, so a helpful one hands the relay exactly
    // the sentence the encryption was there to withhold.
    const ch = await channel()
    t.after(ch.close)
    await rotateChannelKey({
      publisher: ch.admin.publisher,
      client: ch.admin.client,
      signer: ch.admin.signer,
      group,
      members: [ch.admin.pubkey],
    })
    await ch.admin.crypto.load()

    const event = await ch.admin.publisher.publish({
      kind: Kinds.ChatMessage,
      text: 'the root password is hunter2',
    })
    assert.doesNotMatch(tagValue(event.tags, 'alt') ?? '', /hunter2/)
  })

  it('rebuilds a retried event byte for byte', async (t) => {
    // The deterministic nonce, from the other end. `once()`'s exactly-once
    // property *is* "a retry produces the same id and the relay dedupes it", so
    // a random nonce would make idempotency a property of plaintext channels
    // only — silently, and only under retry.
    const ch = await channel()
    t.after(ch.close)
    await rotateChannelKey({
      publisher: ch.admin.publisher,
      client: ch.admin.client,
      signer: ch.admin.signer,
      group,
      members: [ch.admin.pubkey],
    })
    await ch.admin.crypto.load()

    const draft = {
      kind: Kinds.ChatMessage,
      text: 'deploying api 1.4.2',
      counter: 99,
      createdAt: 1_700_000_000,
    }
    const first = await ch.admin.publisher.sign(draft)
    const retry = await ch.admin.publisher.sign(draft)

    assert.equal(first.id, retry.id)
    assert.equal(first.content, retry.content)
  })

  it('refuses to seal under an epoch it does not hold', async (t) => {
    const ch = await channel(1)
    t.after(ch.close)
    const [bob] = ch.others as [Member]

    await rotateChannelKey({
      publisher: ch.admin.publisher,
      client: ch.admin.client,
      signer: ch.admin.signer,
      group,
      members: [ch.admin.pubkey],
    })
    // Bob reads the policy — it is in the clear, by design — and learns he is
    // expected to write under an epoch he was never handed. `load()` warns
    // rather than throwing, because he can still read history and still publish
    // the unsealed kinds; the refusal happens when he tries to seal.
    await bob.crypto.load()

    assert.equal(bob.crypto.encrypted, true)
    assert.deepEqual(bob.crypto.epochs, [])
    await assert.rejects(
      () => bob.publisher.sign({ kind: Kinds.ChatMessage, text: 'can anyone hear me' }),
      MissingChannelKey,
    )
  })

  it('opens into a thing that is deliberately not a valid event', async (t) => {
    // `opened()` exists for the context packer and nothing else. Its result
    // carries plaintext under an id that commits to the ciphertext, so it must
    // never be re-published — and the property that makes that detectable is
    // asserted here rather than trusted to the doc comment.
    const ch = await channel()
    t.after(ch.close)
    await rotateChannelKey({
      publisher: ch.admin.publisher,
      client: ch.admin.client,
      signer: ch.admin.signer,
      group,
      members: [ch.admin.pubkey],
    })
    await ch.admin.crypto.load()

    const sealedEvent = await ch.admin.publisher.publish({
      kind: Kinds.ChatMessage,
      text: 'the invoice total is 40000',
    })
    const opened = ch.admin.crypto.opened(sealedEvent)

    assert.equal(opened.content, 'the invoice total is 40000')
    assert.equal(opened.id, sealedEvent.id)
    assert.equal(verifyEvent(opened), false)
    assert.notEqual(computeId(opened), opened.id)
  })

  it('calls a sealed event with no epoch tag unreadable rather than guessing', async (t) => {
    // Trying every held key in turn would make a MAC failure — which is what
    // tampering looks like — indistinguishable from a missing key, and the two
    // send an operator to opposite ends of the building.
    const ch = await channel()
    t.after(ch.close)
    await rotateChannelKey({
      publisher: ch.admin.publisher,
      client: ch.admin.client,
      signer: ch.admin.signer,
      group,
      members: [ch.admin.pubkey],
    })
    await ch.admin.crypto.load()

    const sealedEvent = await ch.admin.publisher.publish({
      kind: Kinds.ChatMessage,
      text: 'hello',
    })
    const stripped: NostrEvent = {
      ...sealedEvent,
      tags: sealedEvent.tags.filter((tag) => tag[0] !== 'epoch'),
    }

    assert.ok(ch.admin.crypto.unreadable(stripped))
    assert.throws(() => ch.admin.crypto.open(stripped), /no way to say which key is missing/)
  })

  it('leaves a plaintext event alone when reading an encrypted channel', async (t) => {
    // The mixed case is real: the unsealed kinds are in the same channel, and
    // so is anything published before encryption was turned on.
    const ch = await channel()
    t.after(ch.close)
    await ch.admin.crypto.load()

    const early = build({
      pubkey: ch.admin.pubkey,
      kind: Kinds.ChatMessage,
      group,
      text: 'before we turned this on',
      counter: 1,
    })
    const signed = await ch.admin.signer.sign(early)

    assert.equal(ch.admin.crypto.unreadable(signed), false)
    assert.equal(ch.admin.crypto.open(signed), 'before we turned this on')
    assert.equal(ch.admin.crypto.opened(signed), signed)
  })
})
