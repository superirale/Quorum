/**
 * The cursor: replay window, dedup, and gap detection.
 *
 * `agent.test.ts` proves these end to end through a relay. This file pins the
 * arithmetic, which is where the mistakes are — an off-by-one in the replay
 * floor is the difference between re-running work and losing it, and neither is
 * visible from the outside until it happens.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { Kinds, type NostrEvent } from '@quorum/protocol'
import { Cursor, MemoryStore } from '../src/index.ts'

const ADA = 'a'.repeat(64)
const BOB = 'b'.repeat(64)

let seq = 0
function event(pubkey: string, createdAt: number, counter?: number): NostrEvent {
  const n = (seq++).toString(16).padStart(64, '0')
  return {
    id: n,
    pubkey,
    created_at: createdAt,
    kind: Kinds.ChatMessage,
    tags: counter === undefined ? [] : [['counter', String(counter)]],
    content: '',
    sig: 'f'.repeat(128),
  }
}

describe('replay window', () => {
  it('resumes from the oldest unfinished handler, not from now', async () => {
    const c = await Cursor.load(new MemoryStore(), 'a', { slackSeconds: 0 })
    const early = event(ADA, 1000)
    const late = event(ADA, 2000)
    for (const e of [early, late]) c.observe(e)

    c.begin(early)
    c.begin(late)
    c.complete(late)

    // `late` finished, `early` did not. Resuming at `late` would abandon a
    // handler that was mid-await — the exact failure `replay, not resume`
    // exists to prevent.
    assert.equal(c.since(), 1000)
    assert.deepEqual(c.inFlightIds, [early.id])
  })

  it('falls back to the newest event seen when nothing is in flight', async () => {
    const c = await Cursor.load(new MemoryStore(), 'a', { slackSeconds: 0 })
    const e = event(ADA, 5000)
    c.observe(e)
    c.begin(e)
    c.complete(e)
    assert.equal(c.since(), 5000)
  })

  it('starts at zero, so a first run reads the channel rather than only the future', async () => {
    const c = await Cursor.load(new MemoryStore(), 'a')
    assert.equal(c.since(), 0)
  })

  it('subtracts slack, because created_at is the author’s clock', async () => {
    const c = await Cursor.load(new MemoryStore(), 'a', { slackSeconds: 300 })
    c.observe(event(ADA, 10_000))
    assert.equal(c.since(), 9700)

    // And never below zero, which would be a filter no relay can serve.
    const young = await Cursor.load(new MemoryStore(), 'b', { slackSeconds: 300 })
    young.observe(event(ADA, 10))
    assert.equal(young.since(), 0)
  })

  it('does not re-dispatch a completed event when the window reaches back over it', async () => {
    const store = new MemoryStore()
    const first = await Cursor.load(store, 'a')
    const done = event(ADA, 1000)
    const open = event(ADA, 1001)
    first.observe(done)
    first.begin(done)
    first.complete(done)
    first.observe(open)
    first.begin(open)
    await first.save()

    const second = await Cursor.load(store, 'a')
    assert.equal(second.shouldDispatch(done), false)
    assert.equal(second.shouldDispatch(open), true, 'an unfinished handler must replay')
  })

  it('forgets completed ids the window can no longer reach', async () => {
    const store = new MemoryStore()
    const c = await Cursor.load(store, 'a', { slackSeconds: 0 })
    const old = event(ADA, 1000)
    c.observe(old)
    c.begin(old)
    c.complete(old)
    await c.save()

    // Time moves on. Without pruning, `completed_ahead` is a list of every
    // event this agent has ever handled — fine for a week, a problem after a
    // year.
    c.observe(event(ADA, 90_000))
    await c.save()
    assert.equal(c.shouldDispatch(old), true)
  })
})

describe('gaps', () => {
  it('reports a hole in an author’s sequence, bounded by what came after', async () => {
    const c = await Cursor.load(new MemoryStore(), 'a')
    c.observe(event(ADA, 1, 1))
    c.observe(event(ADA, 2, 2))
    assert.deepEqual(c.gaps(), [])

    c.observe(event(ADA, 4, 4))
    assert.deepEqual(c.gaps(), [{ pubkey: ADA, expected: 3, seen: [4] }])

    // The missing event arrives late; the gap closes and the watermark jumps
    // past everything that was waiting on it.
    c.observe(event(ADA, 3, 3))
    assert.deepEqual(c.gaps(), [])
  })

  it('starts an author at their first counter, not at zero', async () => {
    // Joining a channel where Ada is on message 4,000 is not missing 3,999
    // events. Reporting it as one would make the gap report useless on day one.
    const c = await Cursor.load(new MemoryStore(), 'a')
    c.observe(event(ADA, 1, 4000))
    assert.deepEqual(c.gaps(), [])
    c.observe(event(ADA, 2, 4002))
    assert.deepEqual(c.gaps(), [{ pubkey: ADA, expected: 4001, seen: [4002] }])
  })

  it('tracks authors independently', async () => {
    const c = await Cursor.load(new MemoryStore(), 'a')
    c.observe(event(ADA, 1, 1))
    c.observe(event(BOB, 1, 1))
    c.observe(event(ADA, 2, 3))
    c.observe(event(BOB, 2, 2))
    assert.deepEqual(c.gaps(), [{ pubkey: ADA, expected: 2, seen: [3] }])
  })

  it('ignores events with no counter instead of counting them as a gap', async () => {
    // Kind 9 from a generic client carries no `counter`, and that is legal —
    // interop is the whole point of borrowing the kind.
    const c = await Cursor.load(new MemoryStore(), 'a')
    c.observe(event(ADA, 1, 1))
    c.observe(event(ADA, 2))
    c.observe(event(ADA, 3, 2))
    assert.deepEqual(c.gaps(), [])
  })

  it('survives a restart with its watermarks intact', async () => {
    const store = new MemoryStore()
    const first = await Cursor.load(store, 'a')
    first.observe(event(ADA, 1, 1))
    first.observe(event(ADA, 2, 2))
    await first.save()

    const second = await Cursor.load(store, 'a')
    second.observe(event(ADA, 3, 4))
    assert.deepEqual(second.gaps(), [{ pubkey: ADA, expected: 3, seen: [4] }])
  })
})
