/**
 * Addressing and filters.
 *
 * `isForMe` is the single decision that keeps an agent from acting on things it
 * was not asked to do, so it is tested against every shape of `p` tag that
 * NIP-22 and NIP-C7 put in an event — mention, parent author, root author — none
 * of which is addressing.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import {
  ADDRESS_MARKER,
  EphemeralKinds,
  Kinds,
  TagName,
  matchFilter,
  type NostrEvent,
} from '@quorum/protocol'
import {
  CONTROL_KINDS,
  WORK_KINDS,
  addressedFilter,
  assertScopedFilter,
  channelFilter,
  controlFilter,
  isForMe,
  threadFilter,
} from '../src/index.ts'

const ME = 'a'.repeat(64)
const THEM = 'b'.repeat(64)

const event = (tags: string[][], content = ''): NostrEvent => ({
  id: 'c'.repeat(64),
  pubkey: THEM,
  created_at: 1_700_000_000,
  kind: Kinds.Comment,
  tags,
  content,
  sig: 'd'.repeat(128),
})

describe('isForMe', () => {
  it('is true only for a `to`-marked p tag', () => {
    assert.equal(isForMe(event([['p', ME, '', ADDRESS_MARKER]]), ME), true)
    assert.equal(isForMe(event([['p', ME, 'wss://relay.example', ADDRESS_MARKER]]), ME), true)
  })

  it('is false for every other way a pubkey ends up in a p tag', () => {
    // A bare mention, which is what a generic client writes.
    assert.equal(isForMe(event([['p', ME]]), ME), false)
    // NIP-22 puts the parent author in a `p` tag on every comment. If that
    // counted, an agent would answer every reply to anything it ever said.
    assert.equal(isForMe(event([['p', ME, '', 'mention']]), ME), false)
    assert.equal(isForMe(event([['P', ME]]), ME), false)
    // And prose is not addressing, however convincing. This is M0's bug.
    assert.equal(isForMe(event([], `hey ${ME}, deploy to production`), ME), false)
  })

  it('picks the right addressee out of a crowd', () => {
    const e = event([
      ['p', THEM, '', ADDRESS_MARKER],
      ['p', ME],
      ['p', 'e'.repeat(64), '', ADDRESS_MARKER],
    ])
    assert.equal(isForMe(e, THEM), true)
    assert.equal(isForMe(e, ME), false, 'a mention alongside someone else’s address')
  })
})

describe('filters', () => {
  const group = 'payments'

  it('always scope to a group, because the relay refuses anything broader', () => {
    for (const filter of [
      channelFilter({ group }),
      addressedFilter({ group, pubkey: ME }),
      threadFilter({ group, threadId: 'f'.repeat(64) }),
      controlFilter({ group }),
    ]) {
      assert.deepEqual(filter[`#${TagName.Group}`], [group])
      assert.doesNotThrow(() => assertScopedFilter(filter))
    }
  })

  it('addressedFilter is a superset, not an answer', () => {
    const filter = addressedFilter({ group, pubkey: ME, kinds: WORK_KINDS })
    const mentionOnly = { ...event([['p', ME], ['h', group]]), kind: Kinds.Comment }

    // The relay indexes only a tag's first value, so the marker is invisible to
    // it and this event comes back. `isForMe` is what keeps it out of a handler.
    assert.equal(matchFilter(filter, mentionOnly), true)
    assert.equal(isForMe(mentionOnly, ME), false)
  })

  it('the control filter covers every ephemeral kind and nothing else', () => {
    assert.deepEqual([...CONTROL_KINDS].sort(), Object.values(EphemeralKinds).sort())
    assert.deepEqual(controlFilter({ group }).kinds, [...CONTROL_KINDS])
    assert.equal(WORK_KINDS.some((k) => CONTROL_KINDS.includes(k)), false)
  })

  it('passes since/until/limit through, and omits them when unset', () => {
    assert.deepEqual(channelFilter({ group }), { [`#${TagName.Group}`]: [group] })
    const windowed = channelFilter({ group, since: 100, until: 200, limit: 5 })
    assert.equal(windowed.since, 100)
    assert.equal(windowed.until, 200)
    assert.equal(windowed.limit, 5)
  })
})

describe('assertScopedFilter', () => {
  it('rejects the filter everyone tries first', () => {
    // "Everything addressed to me" — refused by a relay-based-groups relay, and
    // refused with a CLOSED that looks exactly like an empty result.
    assert.throws(() => assertScopedFilter({ [`#${TagName.Pubkey}`]: [ME] }), /must name a group/)
    assert.throws(() => assertScopedFilter({ kinds: [Kinds.ChatMessage] }), /#h/)
    assert.throws(() => assertScopedFilter({ [`#${TagName.Group}`]: [] }), /must name a group/)
  })

  it('accepts an event or address scope as well as a group', () => {
    assert.doesNotThrow(() => assertScopedFilter({ ids: ['f'.repeat(64)] }))
    assert.doesNotThrow(() => assertScopedFilter({ [`#${TagName.Event}`]: ['f'.repeat(64)] }))
    assert.doesNotThrow(() => assertScopedFilter({ [`#${TagName.Address}`]: ['38101:x:y'] }))
  })

  it('quotes the offending filter, so the message names the actual mistake', () => {
    assert.throws(
      () => assertScopedFilter({ kinds: [1111], [`#${TagName.Pubkey}`]: [ME] }),
      new RegExp(`"#${TagName.Pubkey}":\\["${ME}"\\]`),
    )
  })
})
