/**
 * Saying when something happened without saying anything false.
 *
 * Two of these are about clocks that are not ours. Every timestamp in this
 * client is author-chosen — `created_at` on an event, `expires_at` inside a
 * grant — so "now" is routinely in the past or the future relative to what an
 * event claims, and a formatter that assumes one direction prints nonsense at
 * exactly the moment someone is reading it closely.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'vitest'
import { ago, describe as line, hue, short, until } from '../src/format.ts'

const NOW = 1_800_000_000
const HOUR = 3600

describe('ago', () => {
  it('rounds to the coarsest unit that is still true', () => {
    assert.equal(ago(NOW - 10, NOW), 'just now')
    assert.equal(ago(NOW - 600, NOW), '10m ago')
    assert.equal(ago(NOW - 5 * HOUR, NOW), '5h ago')
    assert.equal(ago(NOW - 3 * 86_400, NOW), '3d ago')
  })

  it('does not report a skewed clock as the future', () => {
    // An author whose clock runs four seconds fast is not a fact about the
    // work, and "in 4 seconds" on a message already on screen reads as a bug.
    assert.equal(ago(NOW + 4, NOW), 'just now')
  })
})

describe('until', () => {
  it('goes both ways across the moment it names', () => {
    // A grant's expiry is in the future until the second it is not, and the row
    // showing it must stay true across that boundary without the caller
    // checking which side it is on.
    assert.equal(until(NOW + 2 * HOUR, NOW), 'in 2h')
    assert.equal(until(NOW - 2 * HOUR, NOW), '2h ago')
    assert.equal(until(NOW, NOW), 'just now')
  })
})

describe('describe', () => {
  it('prefers alt to content, which is the whole point of requiring alt', () => {
    // A reader that has never heard of kind 8102 still gets a usable line. This
    // client knows several kinds and renders all of them this way on purpose:
    // a fallback nothing exercises is a fallback that does not work.
    const event = {
      id: 'a',
      pubkey: 'b',
      created_at: NOW,
      kind: 8102,
      tags: [['alt', 'Approval needed: deploy api 1.4.2']],
      content: '{"risk":"high"}',
      sig: 'c',
    }
    assert.equal(line(event), 'Approval needed: deploy api 1.4.2')
  })

  it('falls back to content, then to the kind number', () => {
    const bare = { id: 'a', pubkey: 'b', created_at: NOW, kind: 9, tags: [], content: 'hi', sig: 'c' }
    assert.equal(line(bare), 'hi')
    assert.equal(line({ ...bare, content: 'x'.repeat(500) }), 'kind 9')
  })
})

describe('hue', () => {
  it('is stable for a key, so an agent looks the same after a reload', () => {
    const key = 'f'.repeat(64)
    assert.equal(hue(key), hue(key))
    assert.ok(hue(key) >= 0 && hue(key) < 360)
  })
})

describe('short', () => {
  it('leaves a name alone and truncates a hex key', () => {
    assert.equal(short('ada'), 'ada')
    assert.equal(short('0'.repeat(64)), '00000000…')
  })
})
