/**
 * Reading an edited field back without changing its type.
 *
 * Worth testing rather than eyeballing, because the failure is invisible on
 * screen: `"3"` and `3` render identically, hash differently, and the human has
 * already signed by the time anything notices.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'vitest'
import { changed, kindOf, parseField, toInput } from '../src/fields.ts'

describe('parseField', () => {
  it('keeps a number a number', () => {
    // The whole reason this module exists. An input yields "3"; the payload the
    // approver signs must contain 3.
    assert.deepEqual(parseField(30, '3'), { ok: true, value: 3 })
  })

  it('keeps a string a string, even when it looks like a number', () => {
    assert.deepEqual(parseField('1.4.2', '2'), { ok: true, value: '2' })
    assert.deepEqual(parseField('api', '7'), { ok: true, value: '7' })
  })

  it('refuses an emptied number rather than reading it as zero', () => {
    // `Number('')` is 0, which is a plausible replica count and a plausible
    // budget. Silently approving zero of something is not an acceptable
    // interpretation of a field someone cleared.
    assert.equal(parseField(30, '').ok, false)
    assert.equal(parseField(30, '   ').ok, false)
  })

  it('reports a non-number instead of signing NaN', () => {
    const parsed = parseField(30, 'three')
    assert.equal(parsed.ok, false)
    assert.match(parsed.ok ? '' : parsed.problem, /not a number/)
  })

  it('parses JSON for arrays and objects', () => {
    assert.deepEqual(parseField(['a'], '["a","b"]'), { ok: true, value: ['a', 'b'] })
    assert.equal(parseField(['a'], '["a",').ok, false)
  })

  it('reads a boolean from the select, not from truthiness', () => {
    assert.deepEqual(parseField(true, 'false'), { ok: true, value: false })
    assert.deepEqual(parseField(false, 'true'), { ok: true, value: true })
  })
})

describe('kindOf and toInput', () => {
  it('round-trips every field kind unchanged when nothing is typed', () => {
    for (const value of ['api', 30, true, null, ['a'], { k: 1 }]) {
      const parsed = parseField(value, toInput(value))
      assert.equal(parsed.ok, true)
      assert.equal(changed(value, parsed.ok ? parsed.value : undefined), false)
    }
  })

  it('treats null as JSON, so it is editable rather than stuck', () => {
    assert.equal(kindOf(null), 'json')
    assert.deepEqual(parseField(null, '"set"'), { ok: true, value: 'set' })
  })
})

describe('changed', () => {
  it('compares by value, not by reference', () => {
    assert.equal(changed({ a: 1 }, { a: 1 }), false)
    assert.equal(changed({ a: 1 }, { a: 2 }), true)
  })
})
