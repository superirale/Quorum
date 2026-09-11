/**
 * `once()`, the store beneath it, and the counter allocator.
 *
 * The test that matters most is "a crash between the effect and the record" —
 * the window a naive `once()` leaves open. It is reproduced here by throwing
 * away the process's in-memory state and building a fresh `once` over the same
 * store, which is exactly what a restart is.
 */

import assert from 'node:assert/strict'
import { after, describe, it } from 'node:test'
import { computeId, type UnsignedEvent } from '@quorum/protocol'
import {
  Counters,
  FileStore,
  MemoryStore,
  createOnce,
  hasRun,
  incompleteEffects,
  namespaced,
} from '../src/index.ts'
import { tempDir } from './harness.ts'

const EVENT = 'a'.repeat(64)

/** A fresh `once` over an existing store: the same agent, one restart later. */
const restart = (store: MemoryStore | FileStore) => createOnce(store, EVENT, new Map())

describe('once', () => {
  it('runs an effect once and returns the recorded value afterwards', async () => {
    const store = new MemoryStore()
    let runs = 0
    const once = createOnce(store, EVENT, new Map())

    assert.equal(await once('deploy', async () => ++runs), 1)
    assert.equal(await once('deploy', async () => ++runs), 1)
    assert.equal(runs, 1)
    assert.equal(await hasRun(store, EVENT, 'deploy'), true)
  })

  it('survives a restart without re-running a completed effect', async () => {
    const store = new MemoryStore()
    let runs = 0
    await createOnce(store, EVENT, new Map())('deploy', async () => ++runs)
    await restart(store)('deploy', async () => ++runs)
    assert.equal(runs, 1)
  })

  it('hands a retry the same timestamp, so a republished event has the same id', async () => {
    const store = new MemoryStore()
    const pubkey = 'b'.repeat(64)
    const ids: string[] = []
    const attempts: number[] = []

    const build = (createdAt: number): UnsignedEvent => ({
      pubkey,
      created_at: createdAt,
      kind: 9,
      tags: [['h', 'payments']],
      content: 'shipped',
    })

    // Life one: the effect runs and the process dies before the record is
    // written. Simulated by throwing after the id exists — from the ledger's
    // point of view that is indistinguishable from a kill -9 one line later.
    await assert.rejects(() =>
      createOnce(store, EVENT, new Map())('announce', ({ createdAt, attempt }) => {
        attempts.push(attempt)
        ids.push(computeId(build(createdAt)))
        throw new Error('process died here')
      }),
    )

    // Life two, some seconds later on the wall clock.
    await restart(store)('announce', ({ createdAt, attempt }) => {
      attempts.push(attempt)
      ids.push(computeId(build(createdAt)))
    })

    assert.deepEqual(attempts, [1, 2], 'the second run should know it is a retry')
    assert.equal(
      ids[0],
      ids[1],
      'the rebuilt event has a different id, so the relay would store it twice',
    )
  })

  it('reports an effect that was started and never finished', async () => {
    const store = new MemoryStore()
    const once = createOnce(store, EVENT, new Map())

    await assert.rejects(() => once('charge-the-card', () => Promise.reject(new Error('502'))))
    assert.deepEqual(await incompleteEffects(store), [`${EVENT}:charge-the-card`])

    // A non-Nostr effect stays honestly at-least-once: the reservation says an
    // attempt happened, not that it did not take effect. All the SDK can do is
    // make sure nobody has to guess.
    await once('charge-the-card', () => 'ok')
    assert.deepEqual(await incompleteEffects(store), [])
  })

  it('shares an in-flight effect between concurrent callers', async () => {
    const store = new MemoryStore()
    const once = createOnce(store, EVENT, new Map())
    let runs = 0
    const slow = async () => {
      await new Promise((r) => setTimeout(r, 20))
      return ++runs
    }

    // Neither call has written to the ledger yet when the other starts, so the
    // ledger alone cannot stop the second one.
    const [a, b] = await Promise.all([once('x', slow), once('x', slow)])
    assert.equal(runs, 1)
    assert.equal(a, b)
  })

  it('keys on the label, so two different effects both happen', async () => {
    const store = new MemoryStore()
    const once = createOnce(store, EVENT, new Map())
    const done: string[] = []
    await once('notify-ops', () => done.push('ops'))
    await once('notify-security', () => done.push('security'))
    assert.deepEqual(done, ['ops', 'security'])
  })

  it('insists on a label', async () => {
    const once = createOnce(new MemoryStore(), EVENT, new Map())
    await assert.rejects(() => once('', () => 1), /needs a label/)
  })
})

describe('FileStore', () => {
  it('is readable by a second process', async () => {
    const dir = await tempDir()
    after(() => dir.remove())

    const first = FileStore.in(dir.path)
    await first.set('once:x:deploy', { at: 7, attempts: 1, done: true })
    await first.set('counter:me', 4)

    const second = FileStore.in(dir.path)
    assert.deepEqual(await second.get('once:x:deploy'), { at: 7, attempts: 1, done: true })
    assert.deepEqual((await second.keys('once:')).sort(), ['once:x:deploy'])

    await second.delete('counter:me')
    assert.equal(await FileStore.in(dir.path).get('counter:me'), undefined)
  })

  it('serialises concurrent writes instead of interleaving renames', async () => {
    const dir = await tempDir()
    after(() => dir.remove())

    const store = FileStore.in(dir.path)
    await Promise.all(Array.from({ length: 50 }, (_, i) => store.set(`k${i}`, i)))

    const reread = FileStore.in(dir.path)
    assert.equal((await reread.keys()).length, 50)
    assert.equal(await reread.get('k49'), 49)
  })

  it('an unwritten store reads as empty rather than throwing', async () => {
    const dir = await tempDir()
    after(() => dir.remove())
    const store = FileStore.in(dir.path, 'never-written')
    assert.equal(await store.get('anything'), undefined)
    assert.deepEqual(await store.keys(), [])
  })
})

describe('MemoryStore', () => {
  it('does not hand back a reference the caller can mutate', async () => {
    const store = new MemoryStore()
    const value = { spend: 0 }
    await store.set('thread', value)
    value.spend = 999
    assert.deepEqual(await store.get('thread'), { spend: 0 })
  })
})

describe('namespaced', () => {
  it('keeps two concerns from colliding, and strips the prefix on the way out', async () => {
    const store = new MemoryStore()
    const a = namespaced(store, 'agent-a')
    const b = namespaced(store, 'agent-b')

    await a.set('counter:me', 1)
    await b.set('counter:me', 99)

    assert.equal(await a.get('counter:me'), 1)
    assert.deepEqual(await a.keys('counter:'), ['counter:me'])
    assert.equal(store.size, 2)
  })
})

describe('Counters', () => {
  it('never hands out the same number twice, even called concurrently', async () => {
    const counters = await Counters.load(new MemoryStore(), 'me')
    const issued = await Promise.all(Array.from({ length: 20 }, () => counters.next()))
    assert.deepEqual(issued, Array.from({ length: 20 }, (_, i) => i + 1))
    assert.equal(counters.current, 20)
  })

  it('resumes from disk rather than restarting the sequence', async () => {
    const store = new MemoryStore()
    const first = await Counters.load(store, 'me')
    await first.next()
    await first.next()

    const second = await Counters.load(store, 'me')
    assert.equal(await second.next(), 3)
  })

  it('catches up to a counter this key has already published', async () => {
    // The state directory was lost; the channel's memory was not. Restarting at
    // 1 would look like the key is in two places at once.
    const counters = await Counters.load(new MemoryStore(), 'me')
    await counters.observeOwn(40)
    assert.equal(await counters.next(), 41)
    await counters.observeOwn(3)
    assert.equal(await counters.next(), 42, 'observeOwn must never move a counter backwards')
  })
})
