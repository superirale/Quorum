import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { applyEdits, leaves } from '../src/edits.ts'

describe('applyEdits', () => {
  const proposed = { service: 'api', version: '1.4.2', env: 'production', replicas: 30 }

  it('returns the input untouched when there is nothing to edit', () => {
    assert.equal(applyEdits(proposed, {}), proposed)
  })

  it('copies rather than mutating', () => {
    const edited = applyEdits(proposed, { replicas: 3 })
    assert.deepEqual(edited, { ...proposed, replicas: 3 })
    // The chain records both digests and an auditor compares them, so the
    // original has to survive intact.
    assert.equal(proposed.replicas, 30)
  })

  it('reaches nested keys', () => {
    const nested = { limits: { cpu: 1, memory: 512 } }
    assert.deepEqual(applyEdits(nested, { 'limits.cpu': 4 }), { limits: { cpu: 4, memory: 512 } })
  })

  it('refuses to invent a field the agent never proposed', () => {
    // An approver adding an argument the agent did not ask about is either a
    // typo or a way past the agent's own validation. Neither should go through
    // quietly.
    assert.throws(() => applyEdits(proposed, { force: true }), /has no "force"/)
  })

  it('refuses to edit a payload that is not an object', () => {
    assert.throws(() => applyEdits('a string', { x: 1 }), /object payload/)
  })

  it('refuses a path through a non-object', () => {
    assert.throws(() => applyEdits(proposed, { 'service.name': 'x' }), /not an object/)
  })
})

describe('leaves', () => {
  it('lists the top-level fields of a flat payload', () => {
    assert.deepEqual(leaves({ service: 'api', replicas: 30 }), [
      { path: 'service', value: 'api' },
      { path: 'replicas', value: 30 },
    ])
  })

  it('descends into nested objects with dotted paths', () => {
    assert.deepEqual(leaves({ limits: { cpu: 1, memory: 512 } }), [
      { path: 'limits.cpu', value: 1 },
      { path: 'limits.memory', value: 512 },
    ])
  })

  it('treats an array as one value rather than a branch', () => {
    // `tags.0` would let an approver rewrite one element while the length
    // silently stayed the same. Edit the whole array or none of it.
    assert.deepEqual(leaves({ tags: ['a', 'b'] }), [{ path: 'tags', value: ['a', 'b'] }])
  })

  it('keeps an empty object as an editable leaf', () => {
    assert.deepEqual(leaves({ scope: {} }), [{ path: 'scope', value: {} }])
  })

  it('offers nothing to edit for a payload that is not an object', () => {
    // Which is the right answer: `applyEdits` would refuse such a payload, so a
    // form generated from it must offer no fields rather than one nameless one.
    assert.deepEqual(leaves('a string'), [])
    assert.deepEqual(leaves(undefined), [])
  })

  it('produces paths applyEdits accepts, for every field', () => {
    // The property the web form rests on: every path a UI can generate from a
    // payload is a path that round-trips back through the edit check.
    const payload = { service: 'api', limits: { cpu: 1 }, tags: ['x'] }
    for (const leaf of leaves(payload)) {
      assert.doesNotThrow(() => applyEdits(payload, { [leaf.path]: leaf.value }))
    }
  })
})
