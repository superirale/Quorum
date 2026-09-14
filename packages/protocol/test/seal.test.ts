/**
 * Sealing, and the one property the whole milestone rests on.
 *
 * `once()` gives exactly-once effects by rebuilding a byte-identical event on a
 * retry and letting the relay dedupe it by id. Encryption is the first thing in
 * eight milestones that could break that silently: a random nonce produces a
 * different ciphertext for the same message, so the retry publishes a *second*
 * copy and nothing anywhere reports it. The first test here is that check, and
 * it is the reason `sealNonce` exists at all.
 */

import assert from 'node:assert/strict'
import { describe, test } from 'node:test'
import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import {
  EncMode,
  UNSEALED_KINDS,
  build,
  computeId,
  isSealed,
  mustSeal,
  nip44Encrypt,
  openEvent,
  randomConversationKey,
  sealEvent,
  sealNonce,
  RegularKinds,
  AddressableKinds,
  BorrowedKinds,
  EphemeralKinds,
} from '../src/index.ts'

const pubkey = 'a'.repeat(64)
const key = hexToBytes('11'.repeat(32))

function comment(text: string, at = 1_700_000_000) {
  const thread = { id: 'b'.repeat(64), pubkey, kind: BorrowedKinds.Thread }
  return build({
    kind: BorrowedKinds.Comment,
    pubkey,
    group: 'ops',
    text,
    thread,
    counter: 7,
    created_at: at,
    enc: EncMode.Nip44,
  })
}

describe('sealEvent', () => {
  test('is deterministic, so a once() retry rebuilds the same event id', () => {
    const unsigned = comment('deploy api 1.4.2 to production')
    const first = sealEvent(unsigned, key)
    const second = sealEvent(unsigned, key)
    assert.equal(first.content, second.content)
    assert.equal(computeId(first), computeId(second))
  })

  test('a random nonce would have broken that, which is what this pins', () => {
    // The negative control. Two encryptions of the same plaintext with NIP-44's
    // own default — fresh random bytes — give two different ids, so a retried
    // handler would say the same thing twice on an encrypted channel and once
    // on a plaintext one. Idempotency would have become a property of
    // unencrypted channels only, reported by nothing.
    const unsigned = comment('deploy api 1.4.2 to production')
    const a = { ...unsigned, content: nip44Encrypt(unsigned.content, key) }
    const b = { ...unsigned, content: nip44Encrypt(unsigned.content, key) }
    assert.notEqual(a.content, b.content)
    assert.notEqual(computeId(a), computeId(b))
  })

  test('different messages get different nonces', () => {
    const one = sealNonce(comment('one'), key)
    const two = sealNonce(comment('two'), key)
    assert.notEqual(bytesToHex(one), bytesToHex(two))
  })

  test('the same message at a different second gets a different nonce', () => {
    // created_at is part of the id, so it is part of the nonce. Two genuinely
    // separate sends of the same sentence must not share a keystream.
    const one = sealNonce(comment('ping', 1_700_000_000), key)
    const two = sealNonce(comment('ping', 1_700_000_001), key)
    assert.notEqual(bytesToHex(one), bytesToHex(two))
  })

  test('the nonce is a MAC under the channel key, not a hash of the plaintext', () => {
    // This is the confirmation-attack defence and it is worth asserting rather
    // than trusting the comment. A relay holding a guess at the plaintext must
    // not be able to rebuild the nonce and compare; only a key holder can.
    const unsigned = comment('approved')
    const plainId = computeId(unsigned)
    assert.equal(bytesToHex(sealNonce(unsigned, key)), bytesToHex(hmac(sha256, key, hexToBytes(plainId))))
    assert.notEqual(bytesToHex(sealNonce(unsigned, key)), plainId)
    assert.notEqual(
      bytesToHex(sealNonce(unsigned, key)),
      bytesToHex(sealNonce(unsigned, randomConversationKey())),
    )
  })

  test('round trips', () => {
    const unsigned = comment('deploy api 1.4.2 to production')
    const sealed = sealEvent(unsigned, key)
    assert.notEqual(sealed.content, unsigned.content)
    assert.ok(isSealed(sealed))
    assert.equal(openEvent(sealed, key), unsigned.content)
  })

  test('leaves every tag in the clear, because routing has to keep working', () => {
    const unsigned = comment('secret')
    const sealed = sealEvent(unsigned, key)
    assert.deepEqual(sealed.tags, unsigned.tags)
  })

  test('the alt says nothing about the body', () => {
    const unsigned = build({
      kind: RegularKinds.Action,
      pubkey,
      group: 'ops',
      thread: { id: 'b'.repeat(64), pubkey, kind: BorrowedKinds.Thread },
      counter: 1,
      enc: EncMode.Nip44,
      body: { name: 'deploy.production', status: 'proposed', summary: 'Deploy api 1.4.2' },
    })
    const altText = unsigned.tags.find((t) => t[0] === 'alt')?.[1]
    assert.equal(altText, 'Encrypted action')
    assert.ok(!altText!.includes('deploy'))
  })

  test('refuses to encrypt an event that is not tagged nip44', () => {
    const plain = build({
      kind: BorrowedKinds.Comment,
      pubkey,
      group: 'ops',
      text: 'hello',
      thread: { id: 'b'.repeat(64), pubkey, kind: BorrowedKinds.Thread },
      counter: 1,
    })
    assert.throws(() => sealEvent(plain, key), /refusing to encrypt/)
  })

  test('the wrong key does not open it', () => {
    const sealed = sealEvent(comment('secret'), key)
    assert.throws(() => openEvent(sealed, randomConversationKey()), /MAC/)
  })

  test('openEvent passes a plaintext event straight through', () => {
    const plain = build({
      kind: BorrowedKinds.Comment,
      pubkey,
      group: 'ops',
      text: 'hello',
      thread: { id: 'b'.repeat(64), pubkey, kind: BorrowedKinds.Thread },
      counter: 1,
    })
    assert.equal(openEvent(plain, key), 'hello')
    assert.ok(!isSealed(plain))
  })
})

describe('mustSeal', () => {
  test('defaults to sealing, so a kind added later is private by accident and not public', () => {
    assert.ok(mustSeal(8199))
    assert.ok(mustSeal(38199))
  })

  test('seals everything a member authors with a body', () => {
    for (const kind of [
      BorrowedKinds.ChatMessage,
      BorrowedKinds.Thread,
      BorrowedKinds.Comment,
      RegularKinds.Action,
      RegularKinds.ApprovalRequest,
      RegularKinds.ApprovalResponse,
      RegularKinds.Summary,
      RegularKinds.Error,
      RegularKinds.Artifact,
      RegularKinds.Handoff,
      RegularKinds.ThreadOp,
      EphemeralKinds.Interrupt,
      EphemeralKinds.Presence,
      AddressableKinds.AgentMemory,
    ]) {
      assert.ok(mustSeal(kind), `kind ${kind}`)
    }
  })

  test('leaves key management, authorization and relay-authored records alone', () => {
    for (const kind of UNSEALED_KINDS) assert.ok(!mustSeal(kind), `kind ${kind}`)
    assert.ok(!mustSeal(RegularKinds.Checkpoint))
    assert.ok(!mustSeal(AddressableKinds.CapabilityGrant))
    assert.ok(!mustSeal(AddressableKinds.ChannelPolicy))
    assert.ok(!mustSeal(RegularKinds.ChannelKey))
    assert.ok(!mustSeal(9021)) // NIP-29 join request
    assert.ok(!mustSeal(BorrowedKinds.GroupMembers))
  })

  test('leaves the `mls` bootstrap alone, or an agent cannot join the channel it is joining', () => {
    // Named individually rather than looped over `UNSEALED_KINDS`, because the
    // test above is vacuous for exactly the failure these two had: the spec
    // listed them and the table did not, and a loop over the table agrees with
    // whatever the table says. A sealed 30443 is a KeyPackage that only the
    // group can read, published by somebody asking to be let into the group; a
    // sealed 8111 is a Welcome the one member who needs it cannot open.
    assert.ok(!mustSeal(BorrowedKinds.MlsKeyPackage))
    assert.ok(!mustSeal(RegularKinds.MlsWelcome))

    // The commit is on the list for a different reason and is named here for
    // the same one. Sealing it would wrap an MLS PrivateMessage in an MLS
    // application message of the group it is advancing — and a member who
    // missed the previous commit could not open the envelope carrying the
    // commit they need, which is the one shape of deadlock this kind exists to
    // avoid.
    assert.ok(!mustSeal(RegularKinds.MlsCommit))

    // And the pair that came off the list when the Welcome stopped being a
    // NIP-59 gift wrap. Quorum publishes neither, so leaving them on would have
    // been the same prose-versus-table drift pointing the other way.
    assert.ok(mustSeal(1059)) // NIP-59 gift wrap — not a kind Quorum emits
    assert.ok(mustSeal(10050)) // NIP-17 inbox relay list — nobody would read one
  })
})
