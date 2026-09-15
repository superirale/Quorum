/**
 * The private half of a KeyPackage, across a restart.
 *
 * The claim under test is one sentence: the process that publishes a 30443 and
 * the process that opens the Welcome are not the same process. Everything in
 * `mls-keys.test.ts` holds an `MlsIdentity` in a local variable for the length
 * of a test function, which is the one arrangement that cannot fail — and is
 * not an arrangement any deployment has. A joiner waits for a human or an agent
 * to notice its package and commit an Add, and every restart in that window
 * lands here.
 *
 * So the central test is act two of a real join with a restart in the middle,
 * and its control is a Bob who mints a fresh package instead of loading the one
 * he published. That control is not hypothetical: it is exactly what the console
 * did before this module existed, and it fails with an HPKE error several frames
 * inside `ts-mls` that names neither the cause nor the cure.
 */

import assert from 'node:assert/strict'
import { before, describe, it } from 'node:test'
import { base64 } from '@scure/base'
import { BorrowedKinds, build, computeId, type NostrEvent, type UnsignedEvent } from '@quorum/protocol'
import { encodeKeyPackage } from 'ts-mls/keyPackage.js'
import type { CiphersuiteImpl, Welcome } from 'ts-mls'
import {
  Archive,
  MemoryStore,
  MlsCrypto,
  SealedEnvelopes,
  forgetMlsIdentity,
  mlsCiphersuite,
  mlsIdentity,
  mlsKeyPackage,
  renewMlsIdentity,
  saveMlsIdentity,
  loadMlsIdentity,
  type MlsIdentity,
  type PublishCommit,
  type Store,
} from '../src/index.ts'

const ADA = 'a'.repeat(64)
const BOB = 'b'.repeat(64)
const NOW = 1_700_000_000
const group = 'ops'

let cs: CiphersuiteImpl

before(async () => {
  cs = await mlsCiphersuite()
})

/** Every group here is two members, so the committer applies its own commit. */
const discard: PublishCommit = async () => {}

/** A fresh ratchet over an existing store — what a restart produces. */
async function ratchet(store: Store, pubkey: string, channel = group): Promise<MlsCrypto> {
  return MlsCrypto.open({
    store,
    pubkey,
    group: channel,
    ciphersuite: cs,
    archive: new Archive(store, { now: () => NOW }),
    envelopes: new SealedEnvelopes(store),
  })
}

/** Build → seal → "sign", which is where the `Publisher` would sit. */
async function say(from: MlsCrypto, pubkey: string, text: string): Promise<NostrEvent> {
  const unsigned: UnsignedEvent = build({
    kind: BorrowedKinds.ChatMessage,
    pubkey,
    group,
    text,
    counter: 1,
    created_at: NOW,
    ...from.buildOptions(BorrowedKinds.ChatMessage),
  })
  const sealed = await from.seal(unsigned)
  return { ...sealed, id: computeId(sealed), sig: 'f'.repeat(128) }
}

/** The same bytes the 30443 would carry, for comparing two packages. */
function wire(identity: MlsIdentity): string {
  return base64.encode(encodeKeyPackage(identity.publicPackage))
}

describe('the KeyPackage an identity holds for a channel', () => {
  it('is minted once and handed back to every later call', async () => {
    const store = new MemoryStore()
    const first = await mlsIdentity({ store, group, pubkey: BOB, ciphersuite: cs })
    const second = await mlsIdentity({ store, group, pubkey: BOB, ciphersuite: cs })

    assert.equal(wire(second), wire(first))
    assert.deepEqual(second.privatePackage.initPrivateKey, first.privatePackage.initPrivateKey)
    assert.deepEqual(second.privatePackage.hpkePrivateKey, first.privatePackage.hpkePrivateKey)
    assert.deepEqual(
      second.privatePackage.signaturePrivateKey,
      first.privatePackage.signaturePrivateKey,
    )
  })

  it('comes back as bytes, not as the object JSON makes of a Uint8Array', async () => {
    // The failure this pins is not a comparison going wrong; it is
    // `{"0":12,"1":…}` reaching HPKE, which reports a length and not a cause.
    const store = new MemoryStore()
    await mlsIdentity({ store, group, pubkey: BOB, ciphersuite: cs })
    const loaded = await loadMlsIdentity(store, group, BOB)

    assert.ok(loaded)
    assert.ok(loaded.privatePackage.initPrivateKey instanceof Uint8Array)
    assert.ok(loaded.privatePackage.hpkePrivateKey instanceof Uint8Array)
    assert.ok(loaded.privatePackage.signaturePrivateKey instanceof Uint8Array)
  })

  it('is nothing at all before one is minted', async () => {
    assert.equal(await loadMlsIdentity(new MemoryStore(), group, BOB), undefined)
  })

  it('is scoped to one channel', async () => {
    const store = new MemoryStore()
    const ops = await mlsIdentity({ store, group: 'ops', pubkey: BOB, ciphersuite: cs })
    const design = await mlsIdentity({ store, group: 'design', pubkey: BOB, ciphersuite: cs })

    // A member of two channels publishes a 30443 in each, and each is consumed
    // by its own Welcome. One package shared between them is spent by whichever
    // invitation lands first.
    assert.notEqual(wire(design), wire(ops))
  })
})

describe('a join with a restart in the middle', () => {
  it('opens the Welcome with the package the earlier process published', async () => {
    const adaStore = new MemoryStore()
    const bobStore = new MemoryStore()

    // Act one: Bob's first process mints a package and publishes it. Nothing
    // else about that process survives.
    const published = await mlsIdentity({ store: bobStore, group, pubkey: BOB, ciphersuite: cs })

    const ada = await ratchet(adaStore, ADA)
    await ada.create(await mlsIdentity({ store: adaStore, group, pubkey: ADA, ciphersuite: cs }))
    const welcome = await ada.add([published.publicPackage], discard)
    assert.ok(welcome, 'adding a member produces a Welcome')

    // Act two: a different process, holding only the store.
    const bob = await ratchet(bobStore, BOB)
    const restored = await mlsIdentity({ store: bobStore, group, pubkey: BOB, ciphersuite: cs })
    await bob.join(welcome, restored, ada.ratchetTree)

    assert.equal(await bob.open(await say(ada, ADA, 'ship it')), 'ship it')
  })

  it('and a process that mints a fresh one instead reads nothing, ever', async () => {
    // The control. Without it the test above passes against a `mlsIdentity`
    // that ignores the store entirely, because two packages for one pubkey are
    // indistinguishable until HPKE is asked to open something.
    const bobStore = new MemoryStore()
    const published = await mlsIdentity({ store: bobStore, group, pubkey: BOB, ciphersuite: cs })

    const adaStore = new MemoryStore()
    const ada = await ratchet(adaStore, ADA)
    await ada.create(await mlsIdentity({ store: adaStore, group, pubkey: ADA, ciphersuite: cs }))
    const welcome = await ada.add([published.publicPackage], discard)
    assert.ok(welcome)

    const bob = await ratchet(new MemoryStore(), BOB)
    const forgotten = await mlsKeyPackage(BOB, cs)
    await assert.rejects(() => bob.join(welcome as Welcome, forgotten, ada.ratchetTree))
  })
})

describe('the ways a stored package is replaced', () => {
  it('renewing makes a new one and that is what later calls load', async () => {
    const store = new MemoryStore()
    const spent = await mlsIdentity({ store, group, pubkey: BOB, ciphersuite: cs })
    const renewed = await renewMlsIdentity({ store, group, pubkey: BOB, ciphersuite: cs })

    assert.notEqual(wire(renewed), wire(spent))
    assert.equal(wire(await mlsIdentity({ store, group, pubkey: BOB, ciphersuite: cs })), wire(renewed))
  })

  it('forgetting leaves nothing, so the next call mints', async () => {
    const store = new MemoryStore()
    const first = await mlsIdentity({ store, group, pubkey: BOB, ciphersuite: cs })
    await forgetMlsIdentity(store, group)

    assert.equal(await loadMlsIdentity(store, group, BOB), undefined)
    assert.notEqual(wire(await mlsIdentity({ store, group, pubkey: BOB, ciphersuite: cs })), wire(first))
  })
})

describe('a store that is not this identity’s', () => {
  it('is refused by name rather than published under the wrong credential', async () => {
    // Two agents pointed at one state file. Handing Bob Ada's package produces a
    // signed 30443 whose credential says Ada, which an inviter is required to
    // refuse — so the cost lands on Bob, minutes or days later, as a channel
    // that never admits him and a reason he cannot see.
    const store = new MemoryStore()
    await saveMlsIdentity(store, group, await mlsKeyPackage(ADA, cs))

    await assert.rejects(
      () => loadMlsIdentity(store, group, BOB),
      (error: Error) => error.message.includes(ADA) && error.message.includes(BOB),
    )
  })

  it('and a package that is not a package at all is refused too', async () => {
    const store = new MemoryStore()
    await store.set(`mls:${group}:identity`, {
      package: base64.encode(new Uint8Array([1, 2, 3])),
      init: '00',
      hpke: '00',
      signature: '00',
    })

    await assert.rejects(() => loadMlsIdentity(store, group, BOB), /did not decode/)
  })
})
