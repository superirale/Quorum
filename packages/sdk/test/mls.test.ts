/**
 * The ratchet, written mostly as "what does a second attempt do?"
 *
 * Almost every way `mls` differs from `nip44` is a statefulness question, and
 * statefulness only shows up on the second call. Sealing the same body twice
 * must not ratchet twice. Opening the same event twice must not throw. A restart
 * must not lose the state, and having lost the plaintext it must not be able to
 * get it back. So the suite is built around a real two-member group and asks it
 * to do things again.
 *
 * The other half is adversarial, and the two attacks are the ones the spec's
 * bindings exist for: a member republishing somebody else's message under their
 * own signature, and a member lifting a message out of one channel into another.
 * Both are refused — but the interesting assertion is the one immediately after
 * the refusal, that the honest message still opens. Rejecting a forgery by
 * burning the generation it was forged from turns an impersonation attempt into
 * a way to silence the channel, which is a worse bug than the one being fixed.
 */

import assert from 'node:assert/strict'
import { before, describe, it } from 'node:test'
import { base64 } from '@scure/base'
import {
  BorrowedKinds,
  EncMode,
  build,
  computeId,
  epoch as epochTag,
  type NostrEvent,
  type UnsignedEvent,
} from '@quorum/protocol'
import { hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js'
import {
  createApplicationMessage,
  createGroup,
  decodeMlsMessage,
  encodeMlsMessage,
  makePskIndex,
  processPrivateMessage,
  type CiphersuiteImpl,
} from 'ts-mls'
import {
  Archive,
  MemoryStore,
  MlsCrypto,
  NotInMlsGroup,
  SealedEnvelopes,
  credentialPubkey,
  mlsCiphersuite,
  mlsKeyPackage,
  openReadableMls,
  type MlsIdentity,
  type PublishCommit,
  type Store,
} from '../src/index.ts'

const ADA = 'a'.repeat(64)
const BOB = 'b'.repeat(64)
const MALLORY = 'c'.repeat(64)
const NOW = 1_700_000_000

let cs: CiphersuiteImpl

before(async () => {
  cs = await mlsCiphersuite()
})

/**
 * A `PublishCommit` that drops the commit on the floor.
 *
 * Legitimate here and nowhere else. Every group in this file is built by adding
 * its second member, and the only member who already exists is the committer,
 * who applies the commit itself rather than reading it back off the wire. The
 * moment there is a *third* member the commit has to be delivered, which is
 * what the three-member test in `mls-keys.test.ts` is for — and is the failure
 * kind 8112 exists because of.
 */
const discard: PublishCommit = async () => {}

/** One member: their store, their archive, their ratchet. */
interface Member {
  pubkey: string
  store: Store
  archive: Archive
  envelopes: SealedEnvelopes
  crypto: MlsCrypto
  identity: MlsIdentity
}

async function member(pubkey: string, group = 'ops', store: Store = new MemoryStore()): Promise<Member> {
  const archive = new Archive(store, { now: () => NOW })
  const envelopes = new SealedEnvelopes(store)
  const crypto = await MlsCrypto.open({
    store,
    pubkey,
    group,
    ciphersuite: cs,
    archive,
    envelopes,
  })
  return { pubkey, store, archive, envelopes, crypto, identity: await mlsKeyPackage(pubkey, cs) }
}

/** Ada starts `group`, adds Bob, Bob joins. The shape every test below needs. */
async function pair(group = 'ops'): Promise<{ ada: Member; bob: Member }> {
  const ada = await member(ADA, group)
  const bob = await member(BOB, group)
  await ada.crypto.create(ada.identity)
  const welcome = await ada.crypto.add([bob.identity.publicPackage], discard)
  assert.ok(welcome, 'adding a member produces a Welcome')
  await bob.crypto.join(welcome, bob.identity, ada.crypto.ratchetTree)
  return { ada, bob }
}

/** Build → seal → "sign", which is where the `Publisher` would sit. */
async function say(
  from: Member,
  text: string,
  options: { at?: number; counter?: number; group?: string; kind?: number } = {},
): Promise<NostrEvent> {
  const unsigned = build({
    kind: options.kind ?? BorrowedKinds.ChatMessage,
    pubkey: from.pubkey,
    group: options.group ?? 'ops',
    text,
    counter: options.counter ?? 1,
    created_at: options.at ?? NOW,
    ...from.crypto.buildOptions(options.kind ?? BorrowedKinds.ChatMessage),
  })
  return sign(await from.crypto.seal(unsigned))
}

function sign(unsigned: UnsignedEvent): NostrEvent {
  return { ...unsigned, id: computeId(unsigned), sig: 'f'.repeat(128) }
}

/** A store that remembers the order of its writes, for the two ordering claims. */
function recording(): { store: Store; writes: string[] } {
  const inner = new MemoryStore()
  const writes: string[] = []
  return {
    writes,
    store: {
      get: (key) => inner.get(key),
      set: async (key, value) => {
        writes.push(key)
        return inner.set(key, value)
      },
      delete: (key) => inner.delete(key),
      keys: (prefix) => inner.keys(prefix),
    },
  }
}

describe('mlsKeyPackage', () => {
  it('puts the Nostr pubkey in the credential, which is where the binding starts', async () => {
    // Per-message authorship travels in `authenticated_data`, because a receiver
    // cannot see the credential. The credential is what a committer checks
    // against the signature on the kind 30443 that published this package, so
    // the identity in the tree and the identity on the relay are one principal.
    const identity = await mlsKeyPackage(ADA.toUpperCase(), cs)
    assert.equal(credentialPubkey(identity.publicPackage), ADA)
  })
})

describe('MlsCrypto', () => {
  it('seals a body Ada writes and opens it as Bob', async () => {
    const { ada, bob } = await pair()
    const event = await say(ada, 'deploy api 1.4.2 to production')

    assert.notEqual(event.content, 'deploy api 1.4.2 to production', 'the wire carries ciphertext')
    assert.equal(await bob.crypto.open(event), 'deploy api 1.4.2 to production')
  })

  it('tags the event with the epoch the ciphertext was actually sealed under', async () => {
    // Not a cosmetic tag. It is the only thing that lets a reader who cannot
    // open a message say *why* — "I am missing epoch 4" rather than "I cannot
    // read this" — and `openMlsEvent` rejects an event whose tag disagrees with
    // its own ciphertext.
    const { ada, bob } = await pair()
    const event = await say(ada, 'hello')

    assert.equal(epochTag(event.tags), ada.crypto.epoch)
    const [message] = decodeMlsMessage(base64.decode(event.content), 0) ?? []
    assert.equal(
      Number(message?.wireformat === 'mls_private_message' ? message.privateMessage.epoch : -1),
      epochTag(event.tags),
    )
    assert.equal(await bob.crypto.open(event), 'hello')
  })

  it('uses the channel name as the MLS group_id, so one channel has one identifier', async () => {
    const { ada } = await pair('ops:prod')
    const event = await say(ada, 'hello', { group: 'ops:prod' })
    const [message] = decodeMlsMessage(base64.decode(event.content), 0) ?? []
    assert.ok(message?.wireformat === 'mls_private_message')
    assert.equal(new TextDecoder().decode(message.privateMessage.groupId), 'ops:prod')
  })

  it('refuses to seal before this identity is in the group, rather than sealing to nobody', async () => {
    const ada = await member(ADA)
    assert.equal(ada.crypto.joined, false)
    assert.deepEqual(ada.crypto.buildOptions(BorrowedKinds.ChatMessage), {})
    const unsigned = build({
      kind: BorrowedKinds.ChatMessage,
      pubkey: ADA,
      group: 'ops',
      text: 'hello',
      counter: 1,
      created_at: NOW,
      enc: EncMode.Mls,
      epoch: 0,
    })
    await assert.rejects(() => ada.crypto.seal(unsigned), NotInMlsGroup)
  })

  it('leaves the bootstrap kinds unsealed even once this client is in the group', async () => {
    // The moment that matters is not the one before joining — `buildOptions`
    // returns nothing at all then — it is afterwards. A member rotating their
    // KeyPackage or wrapping a Welcome for somebody new is sealing to a reader
    // who is by definition outside the group.
    const { ada } = await pair()
    assert.deepEqual(ada.crypto.buildOptions(30443), {}, 'MLS KeyPackage')
    assert.deepEqual(ada.crypto.buildOptions(8111), {}, 'MLS Welcome')
    assert.equal(ada.crypto.buildOptions(BorrowedKinds.ChatMessage).enc, EncMode.Mls)
  })

  it('and hands one of them back untouched when it is asked to seal it anyway', async () => {
    // `buildOptions` is advice; this is the enforcement, and they are two
    // different moments. `Publisher.sign()` calls `seal()` on *everything* it
    // signs, so an event built with no `enc` tag — by this SDK, by a caller
    // reaching past `buildOptions`, or by a second implementation — still
    // arrives here. Without the guard the ratchet would run over a KeyPackage
    // and produce ciphertext readable only by the group, published by an agent
    // asking to be let into that group.
    const { ada } = await pair()
    const bootstrap = build({
      kind: 30443,
      pubkey: ADA,
      group: 'ops',
      d: ADA,
      text: base64.encode(Uint8Array.of(0, 1, 2)), // a KeyPackage, as 30443 carries one
      counter: 1,
      created_at: NOW,
      ...ada.crypto.buildOptions(30443),
    })

    assert.equal(await ada.crypto.seal(bootstrap), bootstrap, 'the same object, unratcheted')
  })

  describe('retrying', () => {
    it('republishes the stored envelope rather than ratcheting a second time', async () => {
      // The property `once()` rests on, and the one MLS cannot give for free.
      // Two seals of one body would be two messages in the channel under one
      // counter, and a generation nobody can give back.
      const { ada, bob } = await pair()
      const draft = {
        kind: BorrowedKinds.ChatMessage,
        pubkey: ADA,
        group: 'ops',
        text: 'deploying api 1.4.2',
        counter: 7,
        created_at: NOW,
        ...ada.crypto.buildOptions(BorrowedKinds.ChatMessage),
      }
      const first = await ada.crypto.seal(build(draft))
      const retry = await ada.crypto.seal(build(draft))

      assert.equal(retry.content, first.content, 'byte for byte')
      assert.equal(computeId(retry), computeId(first), 'so the relay discards the second copy')
      // And the generation really was not spent: Bob opens the retry, then the
      // next message, with no gap in between.
      assert.equal(await bob.crypto.open(sign(retry)), 'deploying api 1.4.2')
      assert.equal(await bob.crypto.open(await say(ada, 'and the next one', { counter: 8 })), 'and the next one')
    })

    it('gives two different bodies two different envelopes', async () => {
      // The control for the test above: a cache keyed on nothing would pass it.
      const { ada } = await pair()
      const one = await say(ada, 'first', { counter: 1 })
      const two = await say(ada, 'second', { counter: 2 })
      assert.notEqual(one.content, two.content)
    })

    it('serialises concurrent seals instead of forking the state', async () => {
      // Two ratchet steps in flight both read the same predecessor and one
      // successor is thrown away — which loses a generation with nothing to
      // show for it. The failure is not an error: Bob simply cannot open one of
      // the three.
      const { ada, bob } = await pair()
      const sent = await Promise.all([
        say(ada, 'one', { counter: 1 }),
        say(ada, 'two', { counter: 2 }),
        say(ada, 'three', { counter: 3 }),
      ])
      const read: string[] = []
      for (const event of sent) read.push(await bob.crypto.open(event))
      assert.deepEqual(read.sort(), ['one', 'three', 'two'])
    })
  })

  describe('the bindings', () => {
    it('refuses a message republished under somebody else’s signature', async () => {
      // Ada approves; Mallory lifts the MLSMessage off the wire and publishes it
      // as her own. The group opens it happily — it is Ada's ciphertext — and
      // without this check the body is attributed, by signature, to Mallory.
      const { ada, bob } = await pair()
      const honest = await say(ada, 'approved the production deploy')
      const forged = sign({ ...honest, pubkey: MALLORY })

      await assert.rejects(() => bob.crypto.open(forged), /republishing/)
    })

    it('and the honest message still opens afterwards, which is the whole point', async () => {
      // Reject by spending the generation and Mallory has a denial of service:
      // republish every message a moment before its author does and the channel
      // goes permanently dark, one event at a time. So a binding failure must
      // discard the ratchet step it took to detect it.
      const { ada, bob } = await pair()
      const honest = await say(ada, 'approved the production deploy')
      await assert.rejects(() => bob.crypto.open(sign({ ...honest, pubkey: MALLORY })))

      assert.equal(await bob.crypto.open(honest), 'approved the production deploy')
    })

    it('records the forgery as an event it could not read, rather than dropping it', async () => {
      const { ada, bob } = await pair()
      const honest = await say(ada, 'approved')
      const forged = sign({ ...honest, pubkey: MALLORY })
      await assert.rejects(() => bob.crypto.open(forged))

      assert.deepEqual(await bob.archive.unreadable('ops'), [forged.id])
    })

    it('refuses a message lifted out of another channel', async () => {
      // Ada is in both. The relay routes by `h`, the ratchet opens it because
      // the reader is in both groups, and the body lands in a thread it was
      // never sent to.
      const finance = await pair('finance')
      const ops = await pair('ops')
      const elsewhere = await say(finance.ada, 'the payroll numbers', { group: 'finance' })
      const replayed = sign({
        ...elsewhere,
        tags: elsewhere.tags.map((t) => (t[0] === 'h' ? ['h', 'ops'] : t)),
      })

      await assert.rejects(() => ops.bob.crypto.open(replayed), /another channel/)
    })

    it('refuses a Welcome for a different channel than the one it is joining', async () => {
      const elsewhere = await pair('finance')
      const bob = await member(BOB, 'ops')
      const welcome = await elsewhere.ada.crypto.add([bob.identity.publicPackage], discard)
      assert.ok(welcome)

      await assert.rejects(
        () => bob.crypto.join(welcome, bob.identity, elsewhere.ada.crypto.ratchetTree),
        /another channel/,
      )
    })

    it('refuses a message whose epoch tag disagrees with its ciphertext', async () => {
      const { ada, bob } = await pair()
      const event = await say(ada, 'hello')
      const relabelled = sign({
        ...event,
        tags: event.tags.map((t) => (t[0] === 'epoch' ? ['epoch', '9'] : t)),
      })

      await assert.rejects(() => bob.crypto.open(relabelled), /tagged epoch 9/)
    })

    it('will not open a message whose authenticated author was altered', async () => {
      // This is what makes `authenticated_data` a real binding rather than a
      // claim: it is covered by the AEAD, so changing it does not produce a
      // message attributed to somebody else, it produces one that does not
      // decrypt at all.
      const { ada, bob } = await pair()
      const event = await say(ada, 'approved')
      const [message] = decodeMlsMessage(base64.decode(event.content), 0) ?? []
      assert.ok(message?.wireformat === 'mls_private_message')
      const swapped = encodeMlsMessage({
        version: 'mls10',
        wireformat: 'mls_private_message',
        privateMessage: {
          ...message.privateMessage,
          authenticatedData: Uint8Array.from(Buffer.from(MALLORY, 'hex')),
        },
      })
      const tampered = sign({ ...event, pubkey: MALLORY, content: base64.encode(swapped) })

      await assert.rejects(() => bob.crypto.open(tampered))
      assert.equal(await bob.crypto.open(event), 'approved', 'and the honest copy survives')
    })
  })

  describe('reading twice', () => {
    it('answers a re-seen event from the archive instead of throwing at the ratchet', async () => {
      // The ordinary way this happens is a reconnect, not a bug: restart,
      // backfill, re-see everything. A second trip through the ratchet for one
      // message throws `Desired gen in the past`, so the archive lookup is not
      // an optimisation.
      const { ada, bob } = await pair()
      const event = await say(ada, 'deploy api 1.4.2')
      assert.equal(await bob.crypto.open(event), 'deploy api 1.4.2')

      assert.equal(await bob.crypto.open(event), 'deploy api 1.4.2')
    })

    it('survives a restart with its state, and keeps reading the channel', async () => {
      const { ada, bob } = await pair()
      assert.equal(await bob.crypto.open(await say(ada, 'before the restart', { counter: 1 })), 'before the restart')

      const restarted = await MlsCrypto.open({
        store: bob.store,
        pubkey: BOB,
        group: 'ops',
        ciphersuite: cs,
        archive: bob.archive,
        envelopes: bob.envelopes,
      })
      assert.equal(restarted.joined, true)
      assert.equal(
        await restarted.open(await say(ada, 'after the restart', { counter: 2 })),
        'after the restart',
      )
    })

    it('reads a backfilled event from the archive across a restart', async () => {
      const { ada, bob } = await pair()
      const event = await say(ada, 'said before the restart')
      await bob.crypto.open(event)

      const restarted = await MlsCrypto.open({
        store: bob.store,
        pubkey: BOB,
        group: 'ops',
        ciphersuite: cs,
        archive: bob.archive,
        envelopes: bob.envelopes,
      })
      assert.equal(await restarted.open(event), 'said before the restart')
    })

    it('opens messages that arrive in the wrong order, because relays serve newest first', async () => {
      // A relay answers a filter newest-first, so an agent backfilling reads its
      // channel backwards. An implementation that required generations in order
      // would work in every test written by hand and fail on the first real
      // connection.
      const { ada, bob } = await pair()
      const sent: NostrEvent[] = []
      for (const [i, text] of ['one', 'two', 'three'].entries()) {
        sent.push(await say(ada, text, { counter: i + 1, at: NOW + i }))
      }

      const read: string[] = []
      for (const event of [...sent].reverse()) read.push(await bob.crypto.open(event))
      assert.deepEqual(read, ['three', 'two', 'one'])
    })
  })

  describe('what the author said', () => {
    it('reads back its own message, which the ratchet alone cannot', async () => {
      // The finding this block exists for. `createApplicationMessage` advances
      // the sender's own ratchet past the generation it just used, so the author
      // is the one member of the group for whom the message is already in the
      // past — every other member reads it and its author gets `Desired gen in
      // the past`. There is no key anybody could hand over; the deletion *is*
      // the forward secrecy. So `seal()` remembers, and this is the assertion
      // that it does.
      const { ada } = await pair()
      const event = await say(ada, 'deploying api 1.4.2')

      assert.equal(await ada.crypto.open(event), 'deploying api 1.4.2')
      assert.equal(ada.crypto.opener()(event)?.content, 'deploying api 1.4.2')
      assert.equal(ada.crypto.unreadable(event), false)
    })

    it('files the signed envelope in the archive when the event comes back', async () => {
      // `seal()` never sees a signature — the `Publisher` signs afterwards — so
      // the record is completed on the way past `open()`. Without this the
      // archive holds every message in the channel except the ones this client
      // wrote, and `quorum export` a month later has a conversation with one
      // side of it missing.
      const { ada } = await pair()
      const event = await say(ada, 'deploying api 1.4.2')
      assert.equal(await ada.archive.get('ops', event.id), undefined)

      await ada.crypto.open(event)
      const held = await ada.archive.get('ops', event.id)
      assert.equal(held?.plaintext, 'deploying api 1.4.2')
      assert.equal(held?.event.sig, event.sig, 'the signature, which is what an auditor checks')
    })

    it('survives a restart before the event has ever come back off the relay', async () => {
      // The crash window the envelope cache closes on the reading side too.
      // Publish, die, restart: the archive has nothing, because the event has
      // not been seen yet, and the ratchet has never been able to open it. The
      // envelope cache is the only copy, and it was written before `publish()`
      // was allowed to happen.
      const { ada } = await pair()
      const event = await say(ada, 'deploying api 1.4.2')

      const restarted = await MlsCrypto.open({
        store: ada.store,
        pubkey: ADA,
        group: 'ops',
        ciphersuite: cs,
        archive: ada.archive,
        envelopes: ada.envelopes,
      })
      assert.equal(restarted.opener()(event), undefined, 'nothing is loaded until warm()')

      assert.equal(await restarted.warm(), 1)
      assert.equal(restarted.opener()(event)?.content, 'deploying api 1.4.2')
    })

    it('remembers nothing for an event it declined to seal', async () => {
      // The control for `seal()`'s two early returns. A KeyPackage goes out in
      // the clear on an `mls` channel by design, and an author that filed its
      // own plaintext for one would be building a private record of events that
      // were never private — harmless here, and the kind of thing that stops
      // being harmless when the unsealed list grows.
      const { ada } = await pair()
      const bootstrap = sign(
        build({
          kind: 30443,
          pubkey: ADA,
          group: 'ops',
          d: ADA,
          text: base64.encode(Uint8Array.of(0, 1, 2)),
          counter: 1,
          created_at: NOW,
          ...ada.crypto.buildOptions(30443),
        }),
      )
      await ada.crypto.seal(bootstrap)

      assert.equal((await ada.envelopes.spoken('ops')).size, 0)
      assert.equal(ada.crypto.unreadable(bootstrap), false, 'because it is not sealed at all')
    })

    it('does not remember a retry twice or move the generation to do it', async () => {
      // `seal()` writes to the map after `sealOnce`, so the cached path runs it
      // too. That is deliberate — a restarted author replaying a `once()` retry
      // needs the plaintext in memory as much as the first caller did — and this
      // pins that it costs nothing: one envelope, one entry, one generation.
      const { ada, bob } = await pair()
      const draft = {
        kind: BorrowedKinds.ChatMessage,
        pubkey: ADA,
        group: 'ops',
        text: 'deploying api 1.4.2',
        counter: 7,
        created_at: NOW,
        ...ada.crypto.buildOptions(BorrowedKinds.ChatMessage),
      }
      const first = sign(await ada.crypto.seal(build(draft)))
      const retry = sign(await ada.crypto.seal(build(draft)))

      assert.equal(retry.id, first.id)
      assert.equal((await ada.envelopes.spoken('ops')).size, 1)
      assert.equal(await bob.crypto.open(retry), 'deploying api 1.4.2')
    })
  })

  describe('opener()', () => {
    it('answers for what has been opened and stays silent about the rest', async () => {
      // Deliberately narrow. The verifiers that take this hook are synchronous
      // and walk whole chains; letting one of them reach the ratchet would mean
      // decrypting an event twice, which throws.
      const { ada, bob } = await pair()
      const seen = await say(ada, 'I approve', { counter: 1 })
      const unseen = await say(ada, 'and this one', { counter: 2 })
      await bob.crypto.open(seen)

      const open = bob.crypto.opener()
      assert.equal(open(seen)?.content, 'I approve')
      assert.equal(open(unseen), undefined)
      assert.equal(bob.crypto.unreadable(unseen), true)
      // And the other arm, which is the one that keeps `unreadable()` from
      // meaning "sealed": a feed that marked every sealed event unreadable would
      // report a gap in a conversation this client has read end to end.
      assert.equal(bob.crypto.unreadable(seen), false)
    })

    it('passes an unsealed event straight through', async () => {
      const { bob } = await pair()
      const plain = sign(
        build({
          kind: BorrowedKinds.ChatMessage,
          pubkey: ADA,
          group: 'ops',
          text: 'in the clear',
          counter: 1,
          created_at: NOW,
        }),
      )
      assert.equal(bob.crypto.opener()(plain)?.content, 'in the clear')
    })

    it('is empty after a restart until warm() loads the archive', async () => {
      // The in-memory map is what makes the synchronous hook possible, and a
      // restart empties it while the archive still holds everything. An agent
      // that skipped `warm()` would come back up unable to verify a single
      // approval it had already read, with no error to say why.
      const { ada, bob } = await pair()
      const event = await say(ada, 'I approve')
      await bob.crypto.open(event)

      const restarted = await MlsCrypto.open({
        store: bob.store,
        pubkey: BOB,
        group: 'ops',
        ciphersuite: cs,
        archive: bob.archive,
        envelopes: bob.envelopes,
      })
      assert.equal(restarted.opener()(event), undefined)

      assert.equal(await restarted.warm(), 1)
      assert.equal(restarted.opener()(event)?.content, 'I approve')
    })
  })

  describe('membership', () => {
    it('lists members by the pubkey in their credential', async () => {
      const { ada, bob } = await pair()
      assert.deepEqual(ada.crypto.members.sort(), [ADA, BOB].sort())
      assert.deepEqual(bob.crypto.members.sort(), [ADA, BOB].sort())
    })

    it('produces no Welcome when nobody was added, and does not move the epoch to say so', async () => {
      // Returning `undefined` is the visible half; not committing is the half
      // that matters. An empty commit is a perfectly valid MLS commit: it
      // advances the group to an epoch every other member has to be told about,
      // and there is no Welcome and no commit message here to tell them with. A
      // caller that filters an add list down to nothing would silently take the
      // channel with it.
      const { ada, bob } = await pair()
      const before = ada.crypto.epoch
      let published = 0

      assert.equal(
        await ada.crypto.add([], async () => {
          published += 1
        }),
        undefined,
      )
      assert.equal(published, 0, 'and nothing was broadcast to say it had happened')
      assert.equal(ada.crypto.epoch, before)
      assert.equal(await bob.crypto.open(await say(ada, 'still readable')), 'still readable')
    })

    it('does not advance when the commit could not be published', async () => {
      // The ordering rule, and the one place it is visible. Everywhere else in
      // this file state is written first; a commit is published first, because
      // whether it is the group's next epoch is decided by the delivery service
      // and not by the committer. Advance first and a member whose commit is
      // refused has moved to a state no one else will ever reach — it has
      // removed itself from its own channel and nothing says so.
      const { ada, bob } = await pair()
      const cat = await member(MALLORY)
      const before = ada.crypto.epoch

      await assert.rejects(
        () =>
          ada.crypto.add([cat.identity.publicPackage], async () => {
            throw new Error('the relay refused it')
          }),
        /the relay refused it/,
      )

      assert.equal(ada.crypto.epoch, before)
      assert.equal(await bob.crypto.open(await say(ada, 'still in the group')), 'still in the group')
    })

    it('refuses a commit lifted out of another channel', async () => {
      // Worse than the same attack on an application message, which misfiles a
      // sentence. A commit accepted from elsewhere rewrites this group's
      // membership.
      const ops = await member(ADA, 'ops')
      await ops.crypto.create(ops.identity)
      const finance = await member(ADA, 'finance')
      const joiner = await member(BOB, 'finance')
      await finance.crypto.create(finance.identity)

      let message: Uint8Array | undefined
      await finance.crypto.add([joiner.identity.publicPackage], async (m) => {
        message = m
      })
      assert.ok(message)

      // Only the id is read, and only to name the event in the error.
      const carrier = { id: 'd'.repeat(64) } as NostrEvent
      await assert.rejects(
        () =>
          ops.crypto.applyCommit(carrier, {
            epoch: 0,
            commit: base64.encode(message!),
            adds: [],
          }),
        /arrived in ops/,
      )
      assert.equal(ops.crypto.epoch, 0)
    })

    it('refuses an application message published as a commit', async () => {
      // A member can put anything in an 8112, and the group-id check passes for
      // anything they legitimately sent. What stops it is that processing a
      // `PrivateMessage` says which of the two it was — and the honest message
      // must survive being used this way, or a member can silence the channel
      // one message at a time by republishing each as a commit.
      const { ada, bob } = await pair()
      const said = await say(ada, 'not a commit')

      await assert.rejects(
        () =>
          bob.crypto.applyCommit(said, {
            epoch: bob.crypto.epoch,
            commit: said.content,
            adds: [],
          }),
        /carries a body, not a commit/,
      )
      assert.equal(await bob.crypto.open(said), 'not a commit')
    })

    it('a member added later cannot read what was said before they joined', async () => {
      // Not a gap to fix. Under `nip44` an admin re-wraps the old epoch keys and
      // the new member reads history; MLS has deleted the material, so there is
      // nothing to wrap. A new member starts at the current epoch and the
      // archive of everything before it belongs to whoever was there.
      const { ada, bob } = await pair()
      const earlier = await say(ada, 'said before Mallory joined', { counter: 1 })
      await bob.crypto.open(earlier)

      const mallory = await member(MALLORY)
      const welcome = await ada.crypto.add([mallory.identity.publicPackage], discard)
      assert.ok(welcome)
      await mallory.crypto.join(welcome, mallory.identity, ada.crypto.ratchetTree)

      await assert.rejects(() => mallory.crypto.open(earlier))
      assert.deepEqual(await mallory.archive.unreadable('ops'), [earlier.id])
    })
  })

  describe('the group state on disk', () => {
    it('is written before the sealed event is handed back', async () => {
      // Same argument as `SealedEnvelopes.sealOnce` awaiting its write, one
      // layer down: a generation spent in memory and not on disk is one this
      // process consumed and its replacement will consume again.
      const { store, writes } = recording()
      const ada = await member(ADA, 'ops', store)
      await ada.crypto.create(ada.identity)
      writes.length = 0
      const crypto = ada.crypto
      await crypto.seal(
        build({
          kind: BorrowedKinds.ChatMessage,
          pubkey: ADA,
          group: 'ops',
          text: 'hello',
          counter: 1,
          created_at: NOW,
          ...crypto.buildOptions(BorrowedKinds.ChatMessage),
        }),
      )

      assert.equal(writes.length, 2)
      assert.equal(writes[0], 'mls:ops:state', 'the ratchet is durable before the envelope is')
      assert.match(writes[1] ?? '', /^sealed:[0-9a-f]{64}$/)
    })

    it('writes nothing at all when the seal is refused', async () => {
      // The envelope is built *before* the state is committed for one reason:
      // `sealMlsEvent` re-checks the epoch tag against the epoch the ciphertext
      // was actually produced under, and that check has to be able to fail
      // without costing anything. It fires when a rotation lands between
      // `build()` and `seal()` — an event tagged at an epoch the group has left.
      // Commit first and a refused message permanently burns the generation the
      // next honest one was going to use.
      const { store, writes } = recording()
      const ada = await member(ADA, 'ops', store)
      const bob = await member(BOB)
      await ada.crypto.create(ada.identity)
      const welcome = await ada.crypto.add([bob.identity.publicPackage], discard)
      assert.ok(welcome)
      await bob.crypto.join(welcome, bob.identity, ada.crypto.ratchetTree)

      const built = build({
        kind: BorrowedKinds.ChatMessage,
        pubkey: ADA,
        group: 'ops',
        text: 'sealed against an epoch that has gone',
        counter: 1,
        created_at: NOW,
        ...ada.crypto.buildOptions(BorrowedKinds.ChatMessage),
      })
      const stale = {
        ...built,
        tags: built.tags.map((t) => (t[0] === 'epoch' ? ['epoch', '9'] : t)),
      }
      writes.length = 0

      await assert.rejects(() => ada.crypto.seal(stale), /Rebuild the event at the current epoch/)
      assert.deepEqual(writes, [], 'no state, so no generation spent')
      assert.equal(await bob.crypto.open(await say(ada, 'rebuilt', { counter: 2 })), 'rebuilt')
    })

    it('keeps two channels apart even when one name is a prefix of the other', async () => {
      const store = new MemoryStore()
      const ops = await member(ADA, 'ops', store)
      const prod = await member(ADA, 'ops:prod', store)
      await ops.crypto.create(ops.identity)
      await prod.crypto.create(prod.identity)

      assert.deepEqual((await store.keys('mls:')).sort(), ['mls:ops:state', 'mls:ops%3Aprod:state'].sort())
    })
  })
})

describe('the raw library, pinned', () => {
  it('really does refuse to decrypt the same application message twice', async () => {
    // The premise the archive-first rule rests on, asserted against `ts-mls`
    // rather than assumed from the RFC. If a future version started tolerating a
    // replay, the lookup would become an optimisation and this test would say so.
    const { ada, bob } = await pair()
    const event = await say(ada, 'once')
    assert.equal(await bob.crypto.open(event), 'once')

    const fresh = await MlsCrypto.open({
      store: bob.store,
      pubkey: BOB,
      group: 'ops',
      ciphersuite: cs,
      archive: new Archive(new MemoryStore(), { now: () => NOW }),
      envelopes: new SealedEnvelopes(new MemoryStore()),
    })
    await assert.rejects(() => fresh.open(event), /gen/i)
  })

  it('really does refuse to let a sender decrypt what it just sent', async () => {
    // The control for the whole `what the author said` block, and the reason
    // that block is not a convenience cache. Asserted against `ts-mls` directly
    // so it is a claim about MLS rather than about this file: the sender's own
    // ratchet is advanced by `createApplicationMessage`, so the generation the
    // message was encrypted under is gone before anyone could ask for it back.
    const identity = await mlsKeyPackage(ADA, cs)
    const state = await createGroup(
      utf8ToBytes('ops'),
      identity.publicPackage,
      identity.privatePackage,
      [],
      cs,
    )
    const { newState, privateMessage } = await createApplicationMessage(
      state,
      utf8ToBytes('mine'),
      cs,
      hexToBytes(ADA),
    )

    await assert.rejects(
      () => processPrivateMessage(newState, privateMessage, makePskIndex(newState, {}), cs),
      /gen/i,
    )
  })

  it('carries the author in `authenticated_data`, readable without the group state', async () => {
    // The wire-format claim the second binding rests on. It is deliberately not
    // secret — the event's own `pubkey` field already publishes it — which is
    // what lets a receiver reject a republished message before spending a
    // generation on it, and what a second implementation must reproduce.
    const { ada } = await pair()
    const event = await say(ada, 'approved')
    const [message] = decodeMlsMessage(base64.decode(event.content), 0) ?? []
    assert.ok(message?.wireformat === 'mls_private_message')

    assert.equal(
      Buffer.from(message.privateMessage.authenticatedData).toString('hex'),
      event.pubkey,
    )
  })
})

describe('openReadableMls', () => {
  it('opens what it can and hands back everything else untouched', async () => {
    // Unreadable events stay in the list rather than being filtered out, and
    // that is the same rule the archive follows: a reader shown only what it
    // could decrypt sees a complete-looking conversation with the gaps closed
    // up, which is a worse lie than a line it cannot read.
    const { ada, bob } = await pair()
    const mine = await say(ada, 'ship it')
    const stranger = { ...mine, id: 'd'.repeat(64), content: base64.encode(new Uint8Array([1, 2, 3])) }

    let missing = 0
    const opened = await openReadableMls(bob.crypto, [mine, stranger], (n) => (missing = n))

    assert.equal(opened.length, 1, 'an event it cannot read contributes nothing to open')
    assert.equal(opened[0]?.content, 'ship it')
    assert.equal(missing, 1)
  })

  it('does not call back at all when it read everything', async () => {
    // The banner this drives says "there is traffic here you cannot read".
    // Firing it with a count of zero on a channel the reader is fully caught up
    // on is how a UI teaches its operator to ignore it.
    const { ada, bob } = await pair()
    let called = 0
    await openReadableMls(bob.crypto, [await say(ada, 'one')], () => (called += 1))
    assert.equal(called, 0)
  })

  it('leaves an unsealed event alone rather than counting it as unreadable', async () => {
    // Key material, policies and commits travel unsealed by design on an `mls`
    // channel, and they are the majority of what a command like `quorum audit`
    // reads. Counting them as missing would report a channel full of holes and
    // point at forward secrecy, which is not what happened.
    const { ada, bob } = await pair()
    const policy = sign(
      build({ kind: BorrowedKinds.ChatMessage, pubkey: ADA, group: 'ops', text: 'in the clear', created_at: NOW }),
    )
    let missing = 0
    const opened = await openReadableMls(bob.crypto, [policy], (n) => (missing = n))
    assert.equal(opened[0]?.content, 'in the clear')
    assert.equal(missing, 0)
  })

  it('reads a second pass out of the archive rather than spending a generation twice', async () => {
    // The reason this exists instead of a loop over `ratchetOpen`. A console
    // command that calls `readableEvents()` twice — `audit` warms the opener and
    // then verifies — must not turn the second read into a channel that has gone
    // dark. Asserted by reading the same set twice and requiring the same answer.
    const { ada, bob } = await pair()
    const events = [await say(ada, 'first', { counter: 1 }), await say(ada, 'second', { counter: 2 })]

    const once = await openReadableMls(bob.crypto, events)
    let missing = 0
    const twice = await openReadableMls(bob.crypto, events, (n) => (missing = n))

    assert.deepEqual(
      twice.map((e) => e.content),
      once.map((e) => e.content),
    )
    assert.deepEqual(once.map((e) => e.content), ['first', 'second'])
    assert.equal(missing, 0, 'the second read must not report the channel as unreadable')
  })

  it('reports one count for many failures rather than one callback each', async () => {
    // A per-event warning on a client that joined a busy channel yesterday is
    // several thousand lines saying the same thing, which is indistinguishable
    // from an outage. One line with a number is the whole point.
    const { ada, bob } = await pair()
    const real = await say(ada, 'this one is fine')
    const junk = [1, 2, 3].map((n) => ({
      ...real,
      id: String(n).repeat(64),
      content: base64.encode(new Uint8Array([n, n, n])),
    }))

    const calls: number[] = []
    const opened = await openReadableMls(bob.crypto, junk, (n) => calls.push(n))
    assert.equal(opened.length, 0)
    assert.deepEqual(calls, [3], 'one callback, carrying the total')
  })
})
