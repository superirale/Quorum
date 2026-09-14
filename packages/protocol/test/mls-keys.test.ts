/**
 * The `mls` bootstrap event: the tags, and the four ways a KeyPackage goes missing.
 *
 * No RFC 9420 here either — `content` is opaque bytes to this layer. What is
 * tested is the tag contract, and every case below is one where a lenient
 * reader would produce a *quieter* failure than the strict one it replaces:
 *
 * - an id list spelled `0x1` instead of `0x0001` reads as no capability at all,
 *   so the member is left out of the group and nothing says why;
 * - a missing `h` makes the KeyPackage unroutable on a relay that refuses
 *   tag-filtered queries without a group, so it is invisible rather than wrong;
 * - a protocol version that is not `1.0` is a KeyPackage for a different
 *   protocol, and adding it would fail inside the ratchet much later;
 * - content that is not base64 fails as a decode error inside an MLS library,
 *   which reads as tampering rather than as a client writing the field wrong.
 */

import assert from 'node:assert/strict'
import { describe, test } from 'node:test'
import { base64 } from '@scure/base'
import { utf8ToBytes } from '@noble/hashes/utils.js'
import {
  BorrowedKinds,
  MLS_PROTOCOL_VERSION,
  build,
  idListTag,
  mlsKeyPackageTags,
  parseIdList,
  parseMlsKeyPackageEvent,
  type Tag,
} from '../src/index.ts'

const pubkey = 'a'.repeat(64)
const ref = 'c3'.repeat(32)
const PACKAGE = utf8ToBytes('a framed mls_key_package MLSMessage would be here')

const capabilities = {
  ciphersuites: [1],
  extensions: [1, 2, 3],
  proposals: [1, 2, 3, 4, 5, 6, 7, 8],
}

function keyPackageEvent(overrides: { tags?: Tag[]; content?: string; d?: string } = {}) {
  const event = build({
    kind: BorrowedKinds.MlsKeyPackage,
    pubkey,
    group: 'ops',
    d: overrides.d ?? 'ops',
    text: overrides.content ?? base64.encode(PACKAGE),
    counter: 1,
    created_at: 1_700_000_000,
    tags: overrides.tags ?? mlsKeyPackageTags({ ref, ...capabilities }),
  })
  return event
}

describe('id lists', () => {
  test('put every value in one tag, as 0x-prefixed lowercase four-digit hex', () => {
    assert.deepEqual(idListTag('mls_ciphersuite', [1, 0x0a, 0xffff]), [
      'mls_ciphersuite',
      '0x0001',
      '0x000a',
      '0xffff',
    ])
  })

  test('round-trip, because the writer and the reader are the pair that can drift', () => {
    const tag = idListTag('mls_proposals', capabilities.proposals)
    assert.deepEqual(parseIdList([tag], 'mls_proposals'), capabilities.proposals)
  })

  test('accept an empty list, which is a real answer and not a missing tag', () => {
    assert.deepEqual(parseIdList([['mls_extensions']], 'mls_extensions'), [])
  })

  test('refuse a value that is not 16 bits, rather than truncating it', () => {
    assert.throws(() => idListTag('mls_ciphersuite', [0x10000]), /not a 16-bit id/)
    assert.throws(() => idListTag('mls_ciphersuite', [-1]), /not a 16-bit id/)
    assert.throws(() => idListTag('mls_ciphersuite', [1.5]), /not a 16-bit id/)
  })

  test('refuse every other spelling of the same number', () => {
    for (const spelling of ['1', '0x1', '0001', '0X0001', '0x0001 ', '0xAAAA']) {
      assert.throws(
        () => parseIdList([['mls_ciphersuite', spelling]], 'mls_ciphersuite'),
        /not a 0x-prefixed lowercase 4-digit hex id/,
        spelling,
      )
    }
  })

  test('say which tag is missing rather than reading it as empty', () => {
    assert.throws(() => parseIdList([], 'mls_proposals'), /needs a `mls_proposals` tag/)
  })
})

describe('a kind 30443', () => {
  test('carries the version, the ref and the three capability lists', () => {
    const parsed = parseMlsKeyPackageEvent(keyPackageEvent())
    assert.equal(parsed.group, 'ops')
    assert.equal(parsed.slot, 'ops')
    assert.equal(parsed.version, MLS_PROTOCOL_VERSION)
    assert.equal(parsed.ref, ref)
    assert.deepEqual(parsed.message, PACKAGE)
    assert.deepEqual(parsed.ciphersuites, capabilities.ciphersuites)
    assert.deepEqual(parsed.extensions, capabilities.extensions)
    assert.deepEqual(parsed.proposals, capabilities.proposals)
  })

  test('names its channel twice, once for the relay and once for the coordinate', () => {
    // `h` routes and admits; `d` is the addressable slot. Quorum sets both to
    // the group id so that `30443:<pubkey>:<group>` is one member's current
    // KeyPackage for one channel — which is what lets an inviter fetch a
    // specific member instead of scanning the workspace.
    const event = keyPackageEvent()
    assert.deepEqual(
      event.tags.filter((t) => t[0] === 'h' || t[0] === 'd'),
      [
        ['h', 'ops'],
        ['d', 'ops'],
      ],
    )
  })

  test('is not a Quorum kind, so it carries no alt and no version tag', () => {
    // Borrowed kinds are outside the envelope rules on purpose: this event has
    // to be readable by an RFC 9420 tool that has never heard of Quorum.
    const names = keyPackageEvent().tags.map((t) => t[0])
    assert.equal(names.includes('alt'), false)
    assert.equal(names.includes('quorum'), false)
  })

  test('refuses a ref that is not 32 bytes of lowercase hex', () => {
    assert.throws(() => mlsKeyPackageTags({ ref: 'C3'.repeat(32), ...capabilities }), /lowercase hex/)
    assert.throws(() => mlsKeyPackageTags({ ref: 'c3', ...capabilities }), /32 bytes/)
  })

  test('refuses another kind outright, rather than reading its tags hopefully', () => {
    const notAKeyPackage = { ...keyPackageEvent(), kind: BorrowedKinds.ChatMessage }
    assert.throws(() => parseMlsKeyPackageEvent(notAKeyPackage), /is not a KeyPackage event/)
  })

  test('refuses one with no `h` tag, which no relay would serve back anyway', () => {
    const event = keyPackageEvent()
    assert.throws(
      () => parseMlsKeyPackageEvent({ ...event, tags: event.tags.filter((t) => t[0] !== 'h') }),
      /needs an `h` tag/,
    )
  })

  test('refuses one with no `d` tag, because an addressable event without one is unreplaceable', () => {
    const event = keyPackageEvent()
    assert.throws(
      () => parseMlsKeyPackageEvent({ ...event, tags: event.tags.filter((t) => t[0] !== 'd') }),
      /needs a `d` tag/,
    )
  })

  test('refuses one whose `d` is not the channel, because nothing ever retires it', () => {
    // Marmot randomises `d` and Quorum derives it, and this is the check that
    // makes the divergence mean something. A package in another slot still
    // answers the inviter's `#h` query, so it looks perfectly usable; what it
    // never does is get replaced by the next one this member publishes. The
    // spent package stays live, an inviter commits an Add against a private
    // half the joiner has thrown away, and the result is a member in the tree
    // who can never read the channel.
    assert.throws(
      () => parseMlsKeyPackageEvent(keyPackageEvent({ d: '2c7f4b9e' })),
      /`d` must be the channel id, but this one says "2c7f4b9e" in ops/,
    )
  })

  test('refuses a protocol version that is not 1.0, and says both numbers', () => {
    const event = keyPackageEvent({
      tags: mlsKeyPackageTags({ ref, ...capabilities }).map((t) =>
        t[0] === 'mls_protocol_version' ? ['mls_protocol_version', '2.0'] : t,
      ),
    })
    assert.throws(() => parseMlsKeyPackageEvent(event), /says protocol version 2.0 and Quorum speaks 1.0/)
  })

  test('refuses a missing ref, and a ref that is the wrong length', () => {
    const without = keyPackageEvent()
    assert.throws(
      () => parseMlsKeyPackageEvent({ ...without, tags: without.tags.filter((t) => t[0] !== 'i') }),
      /needs an `i` tag/,
    )
    const short = keyPackageEvent()
    assert.throws(
      () =>
        parseMlsKeyPackageEvent({
          ...short,
          tags: short.tags.map((t) => (t[0] === 'i' ? ['i', 'c3'] : t)),
        }),
      /needs an `i` tag/,
    )
  })

  test('refuses content that is not base64, before an MLS library calls it tampering', () => {
    assert.throws(() => parseMlsKeyPackageEvent(keyPackageEvent({ content: '!!!' })), /not base64/)
  })

  test('refuses empty content, which is a KeyPackage-shaped hole', () => {
    assert.throws(() => parseMlsKeyPackageEvent(keyPackageEvent({ content: '' })), /content is empty/)
  })
})
