/**
 * The `mls` envelope: three bindings, and the ways each one fails quietly.
 *
 * There is no RFC 9420 here, because there is none in `mls.ts` either — the
 * ratchet lives in the SDK. What is tested is the seam, and a seam is where
 * this milestone's mistakes will be. Each binding has a failure that produces
 * no error anywhere if it is not checked:
 *
 * - **group id.** A message from another channel, replayed into this one, opens
 *   fine for a reader who is in both groups and lands in a thread it was never
 *   sent to.
 * - **credential.** A member lifts another member's application message off the
 *   wire and re-signs it. The group opens it under the original author's
 *   ratchet; the *signature* — which is what an approval is audited by — says
 *   somebody else wrote it.
 * - **epoch.** A tag that disagrees with the ciphertext turns "I am missing
 *   epoch 4" into a wild goose chase, which is the sentence the tag exists to
 *   make possible.
 *
 * The fourth group of tests is about `isSealed`, which is not an MLS question
 * at all: it answered `false` for an `mls` event until this milestone, and
 * every reader downstream would have treated base64 as a body.
 */

import assert from 'node:assert/strict'
import { describe, test } from 'node:test'
import { base64 } from '@scure/base'
import { utf8ToBytes } from '@noble/hashes/utils.js'
import {
  BorrowedKinds,
  EncMode,
  build,
  epoch,
  isMlsGroupId,
  isMlsSealed,
  isSealed,
  mlsGroupId,
  mlsGroupIdOf,
  mlsMessage,
  openEvent,
  openMlsEvent,
  sealMlsEvent,
  type MlsOpened,
} from '../src/index.ts'

const pubkey = 'a'.repeat(64)
const other = 'b'.repeat(64)

/** Stand-in for an MLSMessage: this layer never looks inside one. */
const CIPHERTEXT = utf8ToBytes('an RFC 9420 MLSMessage would be here')

function message(text: string, at = 3, enc: EncMode = EncMode.Mls) {
  return build({
    kind: BorrowedKinds.ChatMessage,
    pubkey,
    group: 'ops',
    text,
    counter: 7,
    created_at: 1_700_000_000,
    enc,
    epoch: at,
  })
}

/** An opener that agrees with everything, which each test then spoils one way. */
function opener(over: Partial<MlsOpened> = {}) {
  return (): MlsOpened => ({
    plaintext: 'deploy api 1.4.2 to production',
    credential: pubkey,
    epoch: 3,
    ...over,
  })
}

describe('mlsGroupId', () => {
  test('is the group id itself, legible in both places', () => {
    assert.deepEqual(mlsGroupId('ops'), utf8ToBytes('ops'))
    assert.ok(isMlsGroupId(mlsGroupId('ops'), 'ops'))
  })

  test('refuses an empty group rather than producing an empty id every channel shares', () => {
    assert.throws(() => mlsGroupId(''), /group id/)
  })

  test('a message from another channel does not match this one', () => {
    // The replay case. Both ids are valid, the reader may hold both group
    // states, and only this comparison says the message is in the wrong place.
    assert.equal(isMlsGroupId(mlsGroupId('finance'), 'ops'), false)
    assert.equal(isMlsGroupId(mlsGroupId('op'), 'ops'), false, 'a prefix is not a match')
  })

  test('reads the group off an event, and refuses one that names no group', () => {
    assert.deepEqual(mlsGroupIdOf(message('hi')), mlsGroupId('ops'))
    const homeless = { ...message('hi'), tags: [['enc', 'mls']] }
    assert.throws(() => mlsGroupIdOf(homeless), /no `h` tag/)
  })
})

describe('sealMlsEvent', () => {
  test('puts the MLSMessage in content as base64 and leaves every tag alone', () => {
    const unsigned = message('deploy api 1.4.2 to production')
    const sealed = sealMlsEvent(unsigned, CIPHERTEXT, 3)
    assert.deepEqual(base64.decode(sealed.content), CIPHERTEXT)
    assert.deepEqual(sealed.tags, unsigned.tags)
    assert.equal(sealed.kind, unsigned.kind)
    assert.equal(sealed.created_at, unsigned.created_at)
  })

  test('refuses an event that is not tagged mls', () => {
    // The same guard `sealEvent` has, for the same reason: the `alt` text is
    // decided at build time, and an event built as plaintext carries an `alt`
    // that summarises the body it is about to hide.
    assert.throws(
      () => sealMlsEvent(message('x', 3, EncMode.Nip44), CIPHERTEXT, 3),
      /enc=nip44/,
    )
  })

  test('refuses when the group sealed under a different epoch than the event claims', () => {
    // A rotation racing a publish. The tag is already committed to by the id,
    // so relabelling is not available: the event has to be rebuilt.
    assert.throws(() => sealMlsEvent(message('x', 3), CIPHERTEXT, 4), /epoch 3 and the group/)
  })

  test('refuses a sealed event with no epoch tag at all', () => {
    const untagged = { ...message('x'), tags: [['h', 'ops'], ['enc', 'mls']] }
    assert.throws(() => sealMlsEvent(untagged, CIPHERTEXT, 3), /needs an `epoch` tag/)
  })

  test('accepts epoch 0, which is where every MLS group starts', () => {
    const fresh = message('first thing said here', 0)
    assert.equal(epoch(fresh.tags), 0, 'the tag reader must not treat 0 as absent')
    assert.doesNotThrow(() => sealMlsEvent(fresh, CIPHERTEXT, 0))
  })

  test('leaves an empty body alone, and refuses an empty message over a real one', () => {
    const empty = build({
      kind: BorrowedKinds.ChatMessage,
      pubkey,
      group: 'ops',
      text: '',
      enc: EncMode.Mls,
      epoch: 3,
    })
    assert.equal(sealMlsEvent(empty, CIPHERTEXT, 3).content, '')
    assert.throws(() => sealMlsEvent(message('x'), new Uint8Array(), 3), /empty MLSMessage/)
  })
})

describe('openMlsEvent', () => {
  const sealed = () => sealMlsEvent(message('deploy api 1.4.2 to production'), CIPHERTEXT, 3)

  test('hands the ciphertext to the opener and returns the plaintext', () => {
    let seen: Uint8Array | undefined
    const plaintext = openMlsEvent(sealed(), (bytes) => {
      seen = bytes
      return { plaintext: 'deploy api 1.4.2 to production', credential: pubkey, epoch: 3 }
    })
    assert.equal(plaintext, 'deploy api 1.4.2 to production')
    assert.deepEqual(seen, CIPHERTEXT)
  })

  test('rejects a message whose MLS credential is not the event author', () => {
    // Mallory republishing Ada's message under Mallory's signature. The group
    // opens it — the ciphertext is genuine — and only this check notices that
    // the signature and the credential name different people.
    assert.throws(
      () => openMlsEvent(sealed(), opener({ credential: other })),
      /republishing the other's message/,
    )
  })

  test('is case-insensitive about the credential, because hex is written both ways', () => {
    assert.doesNotThrow(() => openMlsEvent(sealed(), opener({ credential: pubkey.toUpperCase() })))
  })

  test('rejects an epoch tag that disagrees with the ciphertext', () => {
    assert.throws(() => openMlsEvent(sealed(), opener({ epoch: 4 })), /tagged epoch 3/)
  })

  test('does not discard a message it has already opened just because the tag is missing', () => {
    // The obligation is asymmetric on purpose: a sender MUST write the tag, and
    // a reader that got the plaintext out MUST NOT throw it away for want of a
    // label. The epoch is authenticated inside the MLSMessage header, so an
    // absent tag costs this reader nothing — only the reader who *cannot* open
    // the message loses anything, and it loses the explanation, not the body.
    const untagged = { ...sealed(), tags: [['h', 'ops'], ['enc', 'mls']] }
    assert.equal(openMlsEvent(untagged, opener({ epoch: 9 })), 'deploy api 1.4.2 to production')
  })

  test('mlsMessage refuses an event that is not mls, rather than base64-decoding a body', () => {
    const nip44 = message('x', 3, EncMode.Nip44)
    assert.throws(() => mlsMessage(nip44), /tagged enc=nip44/)
  })

  test('returns content untouched for an event that is not mls', () => {
    const plain = build({
      kind: BorrowedKinds.ChatMessage,
      pubkey,
      group: 'ops',
      text: 'in the clear',
    })
    assert.equal(
      openMlsEvent(plain, () => assert.fail('the opener must not run on a plaintext event')),
      'in the clear',
    )
  })

  test('returns empty for an empty body without troubling the ratchet', () => {
    const empty = build({
      kind: BorrowedKinds.ChatMessage,
      pubkey,
      group: 'ops',
      text: '',
      enc: EncMode.Mls,
      epoch: 3,
    })
    assert.equal(
      openMlsEvent(empty, () => assert.fail('nothing to open')),
      '',
    )
  })

  test('reports content that is not base64 as this client writing it wrong', () => {
    // Rather than letting it reach the ratchet, where a short read surfaces as
    // a decryption failure and reads as tampering.
    const junk = { ...sealed(), content: 'not base64 !!!' }
    assert.throws(() => mlsMessage(junk), /not base64/)
    assert.throws(() => openMlsEvent(junk, opener()), /not base64/)
  })

  test('refuses to hand an mls event to the nip44 opener', () => {
    // The M9 keyless-packer failure in a new place: returning base64 as a body
    // is not an error, it is a success full of nonsense.
    assert.throws(() => openEvent(sealed(), new Uint8Array(32)), /openMlsEvent/)
  })
})

describe('isSealed', () => {
  test('is true for an mls event, which it was not before M10', () => {
    const sealed = sealMlsEvent(message('x'), CIPHERTEXT, 3)
    assert.ok(isSealed(sealed))
    assert.ok(isMlsSealed(sealed))
  })

  test('is false for an mls event with nothing in it', () => {
    const empty = build({
      kind: BorrowedKinds.ChatMessage,
      pubkey,
      group: 'ops',
      text: '',
      enc: EncMode.Mls,
      epoch: 3,
    })
    assert.equal(isSealed(empty), false)
    assert.equal(isMlsSealed(empty), false)
  })

  test('is false for a plaintext event, and isMlsSealed is false for a nip44 one', () => {
    const nip44 = message('x', 3, EncMode.Nip44)
    assert.ok(isSealed(nip44))
    assert.equal(isMlsSealed(nip44), false, 'two modes, and a reader has to tell them apart')
  })
})
