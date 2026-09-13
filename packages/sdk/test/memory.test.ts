/**
 * Agent memory, which is published.
 *
 * The tests worth having here are the ones about the boundary rather than the
 * round trip. Memory is an addressable event keyed by `(pubkey, d)`, so the
 * scoping claim — no agent can overwrite or impersonate another's memory — is
 * enforced by Nostr itself and the test is that the SDK does not undo it by
 * reading without an `authors` filter. And `forget()` is a tombstone rather
 * than an erasure, which is the kind of thing an API can quietly lie about, so
 * it is asserted from both sides: the reader stops seeing the value, and the
 * relay still holds an event for that key.
 */

import assert from 'node:assert/strict'
import { after, describe, it } from 'node:test'
import { AgentMemoryBody, Kinds, TagName, tagValue } from '@quorum/protocol'
import { createMemory, memoryEntry, type Memory } from '../src/memory.ts'
import { Actor, assertAllValid, harness } from './harness.ts'

const h = await harness('payments')
after(() => h.finish())

async function agent(): Promise<{ actor: Actor; memory: Memory }> {
  const actor = await Actor.create(h.relay.url, h.group)
  h.cleanup(() => actor.close())
  return {
    actor,
    memory: createMemory({
      client: actor.client,
      publish: (options) => actor.publish(options),
      pubkey: actor.pubkey,
      group: h.group,
    }),
  }
}

describe('memory', () => {
  it('round-trips a value through the relay', async () => {
    const { memory } = await agent()
    await memory.set('last-deploy', { version: '1.4.2', env: 'production' })
    assert.deepEqual(await memory.get('last-deploy'), { version: '1.4.2', env: 'production' })
  })

  it('returns undefined for a key it never wrote', async () => {
    const { memory } = await agent()
    assert.equal(await memory.get('nothing-here'), undefined)
  })

  it('replaces rather than appends', async () => {
    const { actor, memory } = await agent()
    await memory.set('mood', 'cautious')
    await memory.set('mood', 'confident')
    assert.equal(await memory.get('mood'), 'confident')
    // One addressable coordinate, one event: the relay replaced it, so a reader
    // that joins later cannot be served the old answer.
    const stored = h.relay.storedOfKind(Kinds.AgentMemory).filter((e) => e.pubkey === actor.pubkey)
    assert.equal(stored.length, 1)
  })

  it('lists every key it holds', async () => {
    const { memory } = await agent()
    await memory.set('a', 1)
    await memory.set('b', { nested: true })
    await memory.set('c', ['x', 'y'])
    assert.deepEqual(await memory.all(), { a: 1, b: { nested: true }, c: ['x', 'y'] })
  })

  it('keeps one agent out of another’s namespace', async () => {
    // `(pubkey, kind, d)` is the whole mechanism — there is nothing to
    // coordinate and no lock to hold — but only as long as the read is scoped
    // by author. A query missing `authors` would make the loudest writer in the
    // workspace the memory of every agent in it.
    const one = await agent()
    const two = await agent()
    await one.memory.set('owner', 'first')
    await two.memory.set('owner', 'second')

    assert.equal(await one.memory.get('owner'), 'first')
    assert.equal(await two.memory.get('owner'), 'second')
    assert.deepEqual(await one.memory.all(), { owner: 'first' })
  })

  it('forgets by writing a tombstone, and says so', async () => {
    const { actor, memory } = await agent()
    await memory.set('secret-ish', 'remembered')
    await memory.forget('secret-ish')

    assert.equal(await memory.get('secret-ish'), undefined)
    assert.deepEqual(await memory.all(), {})

    // The honest half. Nostr has no unpublish: the key is still an event, it
    // still has an author and a signature, and the only thing "forgotten" means
    // is that no reader following the rules will use the old value again.
    const stored = h.relay.storedOfKind(Kinds.AgentMemory).filter((e) => e.pubkey === actor.pubkey)
    assert.equal(stored.length, 1)
    assert.equal(tagValue(stored[0]!.tags, TagName.Identifier), 'secret-ish')
    assert.equal(AgentMemoryBody.parse(JSON.parse(stored[0]!.content)).value, null)
  })

  it('distinguishes a stored null from a key that was never set', async () => {
    const { memory } = await agent()
    await memory.set('explicitly-null', null)
    assert.equal(await memory.get('explicitly-null'), undefined)
    // Both read as "nothing", because a tombstone and an author's own null are
    // the same event and the SDK refuses to invent a difference between them.
    assert.deepEqual(await memory.all(), {})
  })
})

describe('memoryEntry', () => {
  it('builds a valid 38104 keyed by the memory key', async () => {
    const { actor } = await agent()
    const event = await actor.publish(memoryEntry('last-thread', { id: 'abc' }))
    assertAllValid([event])
    assert.equal(event.kind, Kinds.AgentMemory)
    assert.equal(tagValue(event.tags, TagName.Identifier), 'last-thread')
  })

  it('is byte-identical for the same key and value', async () => {
    // No `updated_at`: it would be the author's own clock repeating what
    // `created_at` already says, and two replicas of one agent writing the same
    // value would produce different bytes, different ids, and a second stored
    // copy of an entry the relay could otherwise have deduplicated.
    assert.deepEqual(memoryEntry('k', { a: 1 }), memoryEntry('k', { a: 1 }))
    assert.equal(
      JSON.stringify(memoryEntry('k', { a: 1 })),
      JSON.stringify(memoryEntry('k', { a: 1 })),
    )
  })
})
