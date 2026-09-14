/**
 * Key establishment over the wire: how a pubkey gets into the tree, and the
 * five ways an inviter must refuse to put it there.
 *
 * The positive path is one test — publish, fetch, invite, accept, read a
 * message — and everything else is a refusal, because this is the one moment in
 * an `mls` channel where identity is decided. After it, a receiver never sees a
 * credential again: per-message authorship is the pubkey in `authenticated_data`
 * and it matches the event's own signature by construction, so a leaf committed
 * under the wrong name is never questioned again by anything.
 *
 * Each refusal below is therefore a *silent* failure if it is missing, not a
 * loud one. A credential claiming another member gets that member's name on a
 * second leaf. A ciphersuite mismatch produces a member who reads nothing, found
 * weeks later and looking like a delivery problem. A KeyPackage whose own
 * signature is broken is refused by no other layer, because the relay does not
 * read MLS. And the two that are not refusals at all — a Welcome for a spent
 * package, and a `p` tag that is a mention — are here because turning either of
 * them into an error would break an ordinary thing members do.
 */

import assert from 'node:assert/strict'
import { before, describe, it } from 'node:test'
import { base64 } from '@scure/base'
import { bytesToHex } from '@noble/hashes/utils.js'
import {
  BorrowedKinds,
  Kinds,
  MlsCommitBody,
  MlsWelcomeBody,
  RegularKinds,
  addressees,
  isSealed,
  mentionTag,
  mlsKeyPackageTags,
  parseMlsKeyPackageEvent,
  tagValue,
  type NostrEvent,
} from '@quorum/protocol'
import { FakeRelay } from '@quorum/test-kit'
import {
  decodeMlsMessage,
  encodeMlsMessage,
  type CiphersuiteImpl,
  type CiphersuiteName,
  type KeyPackage,
} from 'ts-mls'
import { makeKeyPackageRef } from 'ts-mls/keyPackage.js'
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
  credentialPubkey,
  fetchKeyPackages,
  fetchMlsCommits,
  fetchMlsWelcomes,
  inviteToMls,
  mlsCiphersuite,
  mlsKeyPackage,
  publishKeyPackage,
  type MlsIdentity,
  type MlsInvitation,
} from '../src/index.ts'

const group = 'ops'
const silent = { warn() {}, error() {} }

let cs: CiphersuiteImpl

before(async () => {
  cs = await mlsCiphersuite()
})

/** One identity with a relay connection, a publisher and a ratchet. */
interface Member {
  pubkey: string
  signer: LocalSigner
  client: RelayClient
  publisher: Publisher
  crypto: MlsCrypto
  identity: MlsIdentity
}

async function member(url: string): Promise<Member> {
  const signer = LocalSigner.generate()
  const client = new RelayClient({ url, signer, reconnect: false, log: silent })
  await client.connect()
  const store = new MemoryStore()
  const crypto = await MlsCrypto.open({
    store,
    pubkey: signer.publicKey,
    group,
    ciphersuite: cs,
    archive: new Archive(store),
    envelopes: new SealedEnvelopes(store),
    log: silent,
  })
  // The sealer is attached from the start, exactly as an agent on an `mls`
  // channel would have it. A KeyPackage is published by somebody who cannot
  // seal yet, and a Welcome by somebody who can and must not.
  const publisher = new Publisher({
    client,
    signer,
    pubkey: signer.publicKey,
    group,
    counters: await Counters.load(new MemoryStore(), signer.publicKey),
    channel: crypto,
  })
  return {
    pubkey: signer.publicKey,
    signer,
    client,
    publisher,
    crypto,
    identity: await mlsKeyPackage(signer.publicKey, cs),
  }
}

interface Channel {
  relay: FakeRelay
  ada: Member
  bob: Member
  close: () => Promise<void>
}

/** Ada has started the group; Bob has not published anything yet. */
async function channel(extra: Member[] = []): Promise<Channel> {
  const relay = await FakeRelay.start()
  const ada = await member(relay.url)
  const bob = await member(relay.url)
  await ada.crypto.create(ada.identity)
  return {
    relay,
    ada,
    bob,
    close: async () => {
      ada.client.close()
      bob.client.close()
      for (const other of extra) other.client.close()
      await relay.stop()
    },
  }
}

/**
 * All four acts, for the tests that need somebody *in* the tree rather than a
 * claim about how they got there.
 *
 * The KeyPackage fetch is filtered to the joiner because a 30443 stays in its
 * addressable slot after it has been spent, so on the third invitation the
 * inviter reads back the packages of members who are already in the group.
 * Re-adding an existing leaf is not what any of these tests mean.
 */
async function join(inviter: Member, joiner: Member): Promise<MlsInvitation> {
  await publishKeyPackage({ publisher: joiner.publisher, group, identity: joiner.identity, ciphersuite: cs })
  const all = await fetchKeyPackages(inviter.client, group, { ciphersuite: cs })
  const packages = all.filter((p) => p.pubkey === joiner.pubkey)
  assert.equal(packages.length, 1, 'the inviter found exactly one package for the joiner')

  const invitation = await inviteToMls({
    publisher: inviter.publisher,
    signer: inviter.signer,
    crypto: inviter.crypto,
    group,
    packages,
  })
  assert.ok(invitation)

  const waiting = await fetchMlsWelcomes(joiner.client, joiner.pubkey, group)
  const accepted = await acceptMlsInvite({
    signer: joiner.signer,
    crypto: joiner.crypto,
    identity: joiner.identity,
    event: waiting[waiting.length - 1]!,
    ciphersuite: cs,
  })
  assert.equal(accepted, true, 'the joiner accepted the Welcome')
  return invitation
}

/**
 * Publish a 30443 by hand, for the two cases a correct publisher cannot produce.
 *
 * The capability lists are constants rather than the package's own, because
 * nothing under test reads them — `parseMlsKeyPackageEvent` has its own suite in
 * `@quorum/protocol` and these only have to be well-formed enough to get past it.
 */
function publishRaw(
  who: Member,
  keyPackage: KeyPackage,
  ref: string,
  slot = group,
): Promise<NostrEvent> {
  return who.publisher.publish({
    kind: BorrowedKinds.MlsKeyPackage,
    d: slot,
    text: base64.encode(
      encodeMlsMessage({ version: 'mls10', wireformat: 'mls_key_package', keyPackage }),
    ),
    tags: mlsKeyPackageTags({
      ref,
      ciphersuites: [1],
      extensions: [1, 2, 3],
      proposals: [1, 2, 3, 4, 5, 6, 7, 8],
    }),
  })
}

describe('publishing a KeyPackage', () => {
  it('frames it as an MLSMessage in an addressable slot named for the channel', async () => {
    const c = await channel()
    try {
      const event = await publishKeyPackage({
        publisher: c.bob.publisher,
        group,
        identity: c.bob.identity,
        ciphersuite: cs,
      })
      assert.equal(event.kind, BorrowedKinds.MlsKeyPackage)
      assert.equal(tagValue(event.tags, 'h'), group)
      assert.equal(tagValue(event.tags, 'd'), group)

      const parsed = parseMlsKeyPackageEvent(event)
      const decoded = decodeMlsMessage(parsed.message, 0)
      assert.ok(decoded)
      assert.equal(decoded[0].wireformat, 'mls_key_package')
      assert.equal(parsed.ref, bytesToHex(await makeKeyPackageRef(c.bob.identity.publicPackage, cs.hash)))
    } finally {
      await c.close()
    }
  })

  it('advertises the capabilities the leaf holds, GREASE values and all', async () => {
    // `Capabilities.ciphersuites` is typed `CiphersuiteName[]` and is not one:
    // `ts-mls` appends GREASE values as decimal strings, at random, so most
    // packages advertise a suite that is in no registry. Mapping those through
    // the name table gives `undefined`, which is how this was found — publishing
    // failed four times in five with a message about 16-bit ids.
    //
    // Carrying them through rather than dropping them is the point of GREASE:
    // the values exist so that somebody's reader meets one and does not choke.
    const c = await channel()
    try {
      const leaf = c.bob.identity.publicPackage.leafNode
      const identity = {
        ...c.bob.identity,
        publicPackage: {
          ...c.bob.identity.publicPackage,
          leafNode: {
            ...leaf,
            capabilities: {
              ...leaf.capabilities,
              // 0x4a4a, one of RFC 9420 §13.2's reserved values. Planted rather
              // than waited for, because `ts-mls` includes each with p=0.1 and
              // a test that is vacuous one run in five is not a test.
              ciphersuites: [...leaf.capabilities.ciphersuites, '19018' as CiphersuiteName],
            },
          },
        },
      }
      const event = await publishKeyPackage({
        publisher: c.bob.publisher,
        group,
        identity,
        ciphersuite: cs,
      })
      const advertised = parseMlsKeyPackageEvent(event).ciphersuites
      assert.ok(advertised.includes(1), 'the suite this workspace speaks')
      assert.ok(advertised.includes(0x4a4a), 'the GREASE value the leaf declares')
      assert.ok(!advertised.includes(0), 'no unknown name collapsed to zero')
    } finally {
      await c.close()
    }
  })

  it('republishing retires the package it replaces, because the slot is the same', async () => {
    // A KeyPackage is single-use: the `init_key` is gone once a Welcome built
    // from it is accepted. An addressable `d` makes the retirement and the next
    // offer one write, rather than a publish plus a NIP-09 deletion a relay may
    // decline to honour.
    const c = await channel()
    try {
      await publishKeyPackage({ publisher: c.bob.publisher, group, identity: c.bob.identity, ciphersuite: cs })
      const next = await mlsKeyPackage(c.bob.pubkey, cs)
      await publishKeyPackage({ publisher: c.bob.publisher, group, identity: next, ciphersuite: cs })

      const found = await fetchKeyPackages(c.ada.client, group, { ciphersuite: cs })
      assert.equal(found.length, 1)
      assert.equal(
        bytesToHex(await makeKeyPackageRef(found[0]!.keyPackage, cs.hash)),
        bytesToHex(await makeKeyPackageRef(next.publicPackage, cs.hash)),
      )
    } finally {
      await c.close()
    }
  })
})

describe('reading KeyPackages back', () => {
  it('gives the inviter the package and the pubkey that the credential agrees on', async () => {
    const c = await channel()
    try {
      await publishKeyPackage({ publisher: c.bob.publisher, group, identity: c.bob.identity, ciphersuite: cs })
      const found = await fetchKeyPackages(c.ada.client, group, { ciphersuite: cs })
      assert.equal(found.length, 1)
      assert.equal(found[0]!.pubkey, c.bob.pubkey)
      assert.equal(found[0]!.event.pubkey, c.bob.pubkey)
      assert.equal(credentialPubkey(found[0]!.keyPackage), c.bob.pubkey)
    } finally {
      await c.close()
    }
  })

  it('gives one package per publisher even from a relay that kept two', async () => {
    // Addressable replacement is what normally does this, and it is not enough
    // to rely on: Option A says every Quorum event is valid on any generic
    // relay, and a publisher who wrote into two different `d` slots — or a
    // client that merged two stores — hands the inviter two live packages for
    // one member. Committing both puts that member in the tree twice, which
    // costs them nothing and costs everybody else a leaf they cannot attribute.
    const c = await channel()
    try {
      const ref = bytesToHex(await makeKeyPackageRef(c.bob.identity.publicPackage, cs.hash))
      await publishRaw(c.bob, c.bob.identity.publicPackage, ref)
      await publishRaw(c.bob, c.bob.identity.publicPackage, ref, 'another-slot')

      const found = await fetchKeyPackages(c.ada.client, group, { ciphersuite: cs })
      assert.deepEqual(
        found.map((p) => p.pubkey),
        [c.bob.pubkey],
      )
    } finally {
      await c.close()
    }
  })

  it('refuses a credential that names somebody other than the signer', async () => {
    // The attack this whole file exists for. Mallory publishes, under her own
    // key, a KeyPackage whose credential says Ada — and if it is committed, the
    // tree holds two leaves for Ada and every message Mallory sends from the
    // second one is attributed correctly by every check downstream.
    const c = await channel()
    try {
      const forged = await mlsKeyPackage(c.ada.pubkey, cs)
      await publishKeyPackage({ publisher: c.bob.publisher, group, identity: forged, ciphersuite: cs })

      const problems: string[] = []
      const found = await fetchKeyPackages(c.ada.client, group, {
        ciphersuite: cs,
        onProblem: (_event, reason) => problems.push(reason),
      })
      assert.deepEqual(found, [])
      assert.equal(problems.length, 1)
      assert.match(problems[0]!, /credential claims/)
      assert.ok(problems[0]!.includes(c.ada.pubkey))
      assert.ok(problems[0]!.includes(c.bob.pubkey))
    } finally {
      await c.close()
    }
  })

  it('refuses an `i` tag computed against different bytes from the ones sent', async () => {
    const c = await channel()
    try {
      await publishRaw(c.bob, c.bob.identity.publicPackage, 'ab'.repeat(32))
      const problems: string[] = []
      const found = await fetchKeyPackages(c.ada.client, group, {
        ciphersuite: cs,
        onProblem: (_event, reason) => problems.push(reason),
      })
      assert.deepEqual(found, [])
      assert.match(problems[0]!, /hashes to/)
    } finally {
      await c.close()
    }
  })

  it('refuses a ciphersuite this workspace does not speak, here and not at join time', async () => {
    // MLS negotiates nothing at the message level, so a member added under
    // another suite is a member who reads nothing — a failure that would
    // otherwise surface long after the commit, as silence.
    //
    // The package is forged rather than generated, and that is not laziness:
    // this repo cannot produce a real one. Every other suite needs an optional
    // `@hpke/*` or curve dependency that is not installed, so `ts-mls` throws
    // while building the ciphersuite. Suite 1 only is therefore enforced by the
    // dependency tree as well as by the spec — but only for *our* publisher,
    // which is exactly why the reader still has to check.
    const c = await channel()
    try {
      const declared = { ...c.bob.identity.publicPackage, cipherSuite: 'MLS_256_XWING_AES256GCM_SHA512_Ed25519' as const }
      await publishRaw(c.bob, declared, bytesToHex(await makeKeyPackageRef(declared, cs.hash)))

      const problems: string[] = []
      const found = await fetchKeyPackages(c.ada.client, group, {
        ciphersuite: cs,
        onProblem: (_event, reason) => problems.push(reason),
      })
      assert.deepEqual(found, [])
      assert.match(problems[0]!, /ciphersuite/)
    } finally {
      await c.close()
    }
  })

  it('refuses a package whose own signature does not verify, which nothing else checks', async () => {
    // The relay reads no MLS, and the Nostr signature covers the base64 rather
    // than what it frames. If the inviter does not verify the KeyPackage, no
    // layer in the system ever does.
    const c = await channel()
    try {
      const real = c.bob.identity.publicPackage
      const signature = Uint8Array.from(real.signature, (byte, i) => (i === 0 ? byte ^ 0xff : byte))
      const broken = { ...real, signature }
      await publishRaw(c.bob, broken, bytesToHex(await makeKeyPackageRef(broken, cs.hash)))

      const problems: string[] = []
      const found = await fetchKeyPackages(c.ada.client, group, {
        ciphersuite: cs,
        onProblem: (_event, reason) => problems.push(reason),
      })
      assert.deepEqual(found, [])
      assert.match(problems[0]!, /signature does not verify/)
    } finally {
      await c.close()
    }
  })

  it('reports a bad package without costing the good ones their invitation', async () => {
    // An inviter adds several members at once. One malformed package must not
    // be four other people's problem — and it must not be nobody's problem
    // either, because a member silently left out of a commit is a member
    // waiting for a Welcome that is never coming.
    //
    // The bad one here fails in `@quorum/protocol`'s parser rather than in any
    // of the checks above, which is the case that would *throw* out of the loop
    // rather than skip an entry.
    const c = await channel()
    const cara = await member(c.relay.url)
    try {
      await c.bob.publisher.publish({
        kind: BorrowedKinds.MlsKeyPackage,
        d: group,
        text: base64.encode(
          encodeMlsMessage({
            version: 'mls10',
            wireformat: 'mls_key_package',
            keyPackage: c.bob.identity.publicPackage,
          }),
        ),
        tags: mlsKeyPackageTags({
          ref: bytesToHex(await makeKeyPackageRef(c.bob.identity.publicPackage, cs.hash)),
          ciphersuites: [1],
          extensions: [],
          proposals: [],
        }).map((tag) => (tag[0] === 'mls_protocol_version' ? ['mls_protocol_version', '2.0'] : tag)),
      })
      await publishKeyPackage({ publisher: cara.publisher, group, identity: cara.identity, ciphersuite: cs })

      const problems: NostrEvent[] = []
      const found = await fetchKeyPackages(c.ada.client, group, {
        ciphersuite: cs,
        onProblem: (event) => problems.push(event),
      })
      assert.deepEqual(
        found.map((p) => p.pubkey),
        [cara.pubkey],
      )
      assert.deepEqual(
        problems.map((e) => e.pubkey),
        [c.bob.pubkey],
      )
    } finally {
      cara.client.close()
      await c.close()
    }
  })
})

describe('the Welcome', () => {
  it('carries the joiner all the way into the ratchet, tree and all', async () => {
    const c = await channel()
    try {
      await publishKeyPackage({ publisher: c.bob.publisher, group, identity: c.bob.identity, ciphersuite: cs })
      const packages = await fetchKeyPackages(c.ada.client, group, { ciphersuite: cs })

      const invitation = await inviteToMls({
        publisher: c.ada.publisher,
        signer: c.ada.signer,
        crypto: c.ada.crypto,
        group,
        packages,
      })
      assert.ok(invitation)
      assert.equal(invitation.epoch, c.ada.crypto.epoch)
      assert.equal(invitation.welcomes.length, 1)

      const waiting = await fetchMlsWelcomes(c.bob.client, c.bob.pubkey, group)
      assert.equal(waiting.length, 1)
      assert.equal(
        await acceptMlsInvite({
          signer: c.bob.signer,
          crypto: c.bob.crypto,
          identity: c.bob.identity,
          event: waiting[0]!,
          ciphersuite: cs,
        }),
        true,
      )
      assert.ok(c.bob.crypto.joined)
      assert.deepEqual(c.bob.crypto.members.sort(), [c.ada.pubkey, c.bob.pubkey].sort())

      // The point of the whole exercise: Ada can now say something and Bob can
      // read it. Nothing above this line proves the ratchet tree arrived — a
      // joiner that decoded the Welcome and got the tree wrong fails here.
      const said = await c.ada.publisher.publish({ kind: Kinds.ChatMessage, text: 'ship it' })
      assert.ok(isSealed(said))
      assert.equal(await c.bob.crypto.open(said), 'ship it')
    } finally {
      await c.close()
    }
  })

  it('stays in the clear on a channel that seals everything else', async () => {
    // 8111 is on `UNSEALED_KINDS` and this is what that entry is for: a Welcome
    // sealed to the group is a Welcome the one person who needs it — who is by
    // definition not in the group yet — cannot open.
    const c = await channel()
    try {
      await publishKeyPackage({ publisher: c.bob.publisher, group, identity: c.bob.identity, ciphersuite: cs })
      const packages = await fetchKeyPackages(c.ada.client, group, { ciphersuite: cs })
      const invitation = await inviteToMls({
        publisher: c.ada.publisher,
        signer: c.ada.signer,
        crypto: c.ada.crypto,
        group,
        packages,
      })
      const welcome = invitation!.welcomes[0]!
      assert.ok(!isSealed(welcome))
      assert.doesNotThrow(() => MlsWelcomeBody.parse(JSON.parse(welcome.content)))
    } finally {
      await c.close()
    }
  })

  it('goes to each recipient separately, naming the exact KeyPackage it answers', async () => {
    // One commit, one Welcome, N events. The bytes are shared — RFC 9420 puts a
    // per-recipient entry inside the Welcome — so what the N events buy is
    // addressing: a five-way broadcast is four members trial-decrypting
    // somebody else's invitation on every invite.
    const c = await channel()
    const cara = await member(c.relay.url)
    try {
      await publishKeyPackage({ publisher: c.bob.publisher, group, identity: c.bob.identity, ciphersuite: cs })
      await publishKeyPackage({ publisher: cara.publisher, group, identity: cara.identity, ciphersuite: cs })
      const packages = await fetchKeyPackages(c.ada.client, group, { ciphersuite: cs })
      assert.equal(packages.length, 2)

      const invitation = await inviteToMls({
        publisher: c.ada.publisher,
        signer: c.ada.signer,
        crypto: c.ada.crypto,
        group,
        packages,
      })
      assert.equal(invitation!.welcomes.length, 2)

      for (const welcome of invitation!.welcomes) {
        const body = MlsWelcomeBody.parse(JSON.parse(welcome.content))
        assert.deepEqual(addressees(welcome.tags), [body.recipient])
        // By event id, not by the addressable coordinate: a KeyPackage is
        // single-use, so by the time the invitee reads this the slot may
        // already hold its replacement.
        const source = packages.find((p) => p.pubkey === body.recipient)
        assert.equal(body.key_package, source!.event.id)
      }

      // And each of them opens only for the member it names.
      const bobs = await fetchMlsWelcomes(c.bob.client, c.bob.pubkey, group)
      assert.equal(bobs.length, 1)
      assert.equal(MlsWelcomeBody.parse(JSON.parse(bobs[0]!.content)).recipient, c.bob.pubkey)
    } finally {
      cara.client.close()
      await c.close()
    }
  })

  it('a `p` tag without the `to` marker is a mention, not an invitation', async () => {
    // `#p` is a relay-side prefilter and matches a mention as readily as an
    // addressing tag, which is the M0 finding the marker exists for: an agent
    // that acts on every `p` acts on things not meant for it.
    const c = await channel()
    try {
      await publishKeyPackage({ publisher: c.bob.publisher, group, identity: c.bob.identity, ciphersuite: cs })
      const packages = await fetchKeyPackages(c.ada.client, group, { ciphersuite: cs })
      const invitation = await inviteToMls({
        publisher: c.ada.publisher,
        signer: c.ada.signer,
        crypto: c.ada.crypto,
        group,
        packages,
      })
      const real = invitation!.welcomes[0]!

      await c.ada.publisher.publish({
        kind: RegularKinds.MlsWelcome,
        body: MlsWelcomeBody.parse(JSON.parse(real.content)),
        tags: [mentionTag(c.bob.pubkey)],
      })

      const waiting = await fetchMlsWelcomes(c.bob.client, c.bob.pubkey, group)
      assert.deepEqual(
        waiting.map((e) => e.id),
        [real.id],
      )
    } finally {
      await c.close()
    }
  })

  it('inviting nobody commits nothing, rather than an empty commit no one is told about', async () => {
    const c = await channel()
    try {
      const before = c.ada.crypto.epoch
      const invitation = await inviteToMls({
        publisher: c.ada.publisher,
        signer: c.ada.signer,
        crypto: c.ada.crypto,
        group,
        packages: [],
      })
      assert.equal(invitation, undefined)
      assert.equal(c.ada.crypto.epoch, before)
    } finally {
      await c.close()
    }
  })

  it('a Welcome for a package this identity no longer holds is false, not a failure', async () => {
    // A member added, removed and re-added has two Welcomes in the channel and
    // only the newer one matches the package they now hold. Throwing on the
    // older one would make an ordinary history an error; joining from it would
    // be a decryption failure reported as tampering.
    const c = await channel()
    try {
      await publishKeyPackage({ publisher: c.bob.publisher, group, identity: c.bob.identity, ciphersuite: cs })
      const packages = await fetchKeyPackages(c.ada.client, group, { ciphersuite: cs })
      const invitation = await inviteToMls({
        publisher: c.ada.publisher,
        signer: c.ada.signer,
        crypto: c.ada.crypto,
        group,
        packages,
      })

      const replacement = await mlsKeyPackage(c.bob.pubkey, cs)
      assert.equal(
        await acceptMlsInvite({
          signer: c.bob.signer,
          crypto: c.bob.crypto,
          identity: replacement,
          event: invitation!.welcomes[0]!,
          ciphersuite: cs,
        }),
        false,
      )
      // And the ratchet was not touched on the way to finding that out.
      assert.equal(c.bob.crypto.joined, false)
    } finally {
      await c.close()
    }
  })
})

/**
 * The commit, which is the transport that was missing until a three-member
 * group was actually built.
 *
 * `add()` used to create the commit, keep the resulting state and drop the
 * message, which every existing test agreed with: a two-member group is added
 * to by its only other member, who applies the commit by producing it. The
 * second person added to any channel silently locked the first one out, and the
 * error was `CryptoError: OperationError` from HPKE four frames inside `ts-mls`
 * — no epoch, no group, no member, nothing naming the cause.
 *
 * So the headline test below is the three-member one, and the control beside it
 * is a Bob who does not catch up. Without the control the test would pass
 * against an `applyCommit` that did nothing, because it cannot tell "the commit
 * was delivered and applied" from "the commit was never needed".
 */
describe('the commit', () => {
  it('keeps the first member readable when a third one is added', async () => {
    const c = await channel()
    const cat = await member(c.relay.url)
    try {
      await join(c.ada, c.bob)
      const first = await c.ada.publisher.publish({ kind: Kinds.ChatMessage, text: 'one' })
      assert.equal(await c.bob.crypto.open(first), 'one')

      await join(c.ada, cat)
      assert.equal(await catchUpMls(c.bob.client, c.bob.crypto, group), 1)
      assert.equal(c.bob.crypto.epoch, c.ada.crypto.epoch)

      const second = await c.ada.publisher.publish({ kind: Kinds.ChatMessage, text: 'two' })
      assert.equal(await cat.crypto.open(second), 'two')
      assert.equal(await c.bob.crypto.open(second), 'two')
      assert.deepEqual(
        c.bob.crypto.members.sort(),
        [c.ada.pubkey, c.bob.pubkey, cat.pubkey].sort(),
      )
    } finally {
      cat.client.close()
      await c.close()
    }
  })

  it('and without that catch-up the first member reads nothing, which is the defect', async () => {
    // The negative control, and the only thing that makes the test above mean
    // anything. This is exactly what shipped before kind 8112 existed: Bob is
    // still in the tree, still a NIP-29 member, still receiving every event,
    // and every one of them fails to decrypt inside a library he did not write.
    const c = await channel()
    const cat = await member(c.relay.url)
    try {
      await join(c.ada, c.bob)
      await join(c.ada, cat)

      const said = await c.ada.publisher.publish({ kind: Kinds.ChatMessage, text: 'two' })
      assert.equal(await cat.crypto.open(said), 'two')
      await assert.rejects(() => c.bob.crypto.open(said))
      assert.equal(c.bob.crypto.epoch, c.ada.crypto.epoch - 1)
    } finally {
      cat.client.close()
      await c.close()
    }
  })

  it('states the epoch it applies to in the clear, so the relay can order commits', async () => {
    // The body is JSON and the epoch is a number in it, deliberately. The relay
    // has to serialise commits — at most one per group per epoch — and doing
    // that from the MLSMessage would mean an MLS wire parser in Go, which is
    // the one thing this milestone is built to avoid.
    const c = await channel()
    try {
      const before = c.ada.crypto.epoch
      const invitation = await join(c.ada, c.bob)

      assert.ok(!isSealed(invitation.commit))
      const body = MlsCommitBody.parse(JSON.parse(invitation.commit.content))
      assert.equal(body.epoch, before, 'the epoch the commit was created at, not the one it leads to')
      assert.equal(c.ada.crypto.epoch, before + 1)
      assert.deepEqual(body.adds, [c.bob.pubkey])
    } finally {
      await c.close()
    }
  })

  it('replays a commit already applied as a no-op rather than an error', async () => {
    // A relay serves the whole history on every backfill, so a member meets
    // every commit it has ever applied each time it reconnects. Throwing on one
    // would make a reconnect an incident.
    const c = await channel()
    const cat = await member(c.relay.url)
    try {
      await join(c.ada, c.bob)
      await join(c.ada, cat)
      assert.equal(await catchUpMls(c.bob.client, c.bob.crypto, group), 1)

      const at = c.bob.crypto.epoch
      assert.equal(await catchUpMls(c.bob.client, c.bob.crypto, group), 0)
      assert.equal(c.bob.crypto.epoch, at)
      // Including the commit that added Bob himself, which he never applied:
      // he arrived at the epoch it produced, by Welcome.
      assert.equal((await fetchMlsCommits(c.bob.client, group)).length, 2)
    } finally {
      cat.client.close()
      await c.close()
    }
  })

  it('orders commits by the epoch in the body, not by when they arrived', async () => {
    // Applying them in arrival order fails on the first one with "a commit was
    // missed", which is a true sentence about a member who missed nothing. NIP-01
    // serves newest first; `FakeRelay` happens to serve oldest first, so an
    // assertion against it alone is vacuous — the old commit is republished here
    // so that arrival order and epoch order genuinely disagree. That is not a
    // contrived case: every Quorum event is valid on any relay, so backfilling
    // from a second relay carrying the channel delivers old commits last.
    const c = await channel()
    const cat = await member(c.relay.url)
    try {
      const first = await join(c.ada, c.bob)
      await join(c.ada, cat)
      const stale = MlsCommitBody.parse(JSON.parse(first.commit.content))
      // Into a later second, deliberately and at the cost of a slow test.
      // `created_at` has one-second resolution and the fake relay breaks a tie
      // on the event id, so without this the arrival order is decided by a hash
      // and the assertion below passes or fails at random — which is worse than
      // not making it, because the mutation it is meant to catch would survive
      // most runs.
      await new Promise((resolve) => setTimeout(resolve, 1100))
      await c.ada.publisher.publish({ kind: RegularKinds.MlsCommit, body: stale })

      const arrived = await c.ada.client.query([
        { kinds: [RegularKinds.MlsCommit], '#h': [group], limit: 100 },
      ])
      const epochs = (events: NostrEvent[]) =>
        events.map((e) => MlsCommitBody.parse(JSON.parse(e.content)).epoch)
      // The relay's own order is asserted as "ends on the stale one", not as a
      // literal array: the two commits published in the same second are tied on
      // `created_at` and separated by a hash, so which of them comes first is
      // not a fact about anything.
      assert.equal(epochs(arrived).at(-1), 0, 'the relay served an old commit last')
      assert.deepEqual(epochs(await fetchMlsCommits(c.ada.client, group)), [0, 0, 1])
    } finally {
      cat.client.close()
      await c.close()
    }
  })

  it('says a member is stranded rather than letting every later message fail', async () => {
    // There is no catching a ratchet up across a commit it never held, so the
    // only honest answer is to say so once, by name, at the moment it is
    // discovered — instead of leaving the member to meet `OperationError` on
    // every message for the rest of the channel's life.
    const c = await channel()
    const cat = await member(c.relay.url)
    const dan = await member(c.relay.url)
    try {
      await join(c.ada, c.bob)
      await join(c.ada, cat)
      await join(c.ada, dan)

      const commits = await fetchMlsCommits(c.bob.client, group)
      const latest = commits[commits.length - 1]!
      await assert.rejects(
        () => c.bob.crypto.applyCommit(latest, MlsCommitBody.parse(JSON.parse(latest.content))),
        /a commit was missed/,
      )
      // And the failed attempt left the ratchet where it was, so catching up
      // properly still works.
      assert.equal(await catchUpMls(c.bob.client, c.bob.crypto, group), 2)
      assert.equal(c.bob.crypto.epoch, c.ada.crypto.epoch)
    } finally {
      dan.client.close()
      cat.client.close()
      await c.close()
    }
  })
})
