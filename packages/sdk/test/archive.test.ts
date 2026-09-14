/**
 * The archive — written mostly as "what does a restart destroy?"
 *
 * Under `nip44` this file would not need to exist: the relay keeps the bytes,
 * the keyring keeps opening them, and history is a query. Under `mls` the keys
 * are deleted on a schedule, so the only copy of last month's conversation that
 * anyone can read is the one this client wrote down — and the ordinary way to
 * lose it is not a bug in a delete path, it is a reconnect. An agent restarts,
 * backfills, re-sees every event it archived in June, cannot open any of them,
 * and writes each one back. No error, no warning, and the audit trail is gone.
 *
 * So the central test here is the boring-sounding one: re-recording an event you
 * can no longer read must not erase the plaintext you already have.
 *
 * The rest is about not lying. An archive that quietly held only the events it
 * could read would present a complete-looking thread with three messages missing
 * from it, which is worse than a gap somebody can see.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { BorrowedKinds, build, computeId, type NostrEvent } from '@quorum/protocol'
import { Archive, MemoryStore, SealedEnvelopes, type Store } from '../src/index.ts'

const ADA = 'a'.repeat(64)
const NOW = 1_700_000_000

/** A published event, sealed or not — the archive never looks inside `content`. */
function event(options: { at?: number; content?: string; group?: string } = {}): NostrEvent {
  const unsigned = build({
    kind: BorrowedKinds.ChatMessage,
    pubkey: ADA,
    group: options.group ?? 'ops',
    text: options.content ?? 'c2VhbGVkIGJ5dGVz',
    created_at: options.at ?? NOW,
    counter: options.at ?? NOW,
  })
  return { ...unsigned, id: computeId(unsigned), sig: 'f'.repeat(128) }
}

function archive(): Archive {
  return new Archive(new MemoryStore(), { now: () => NOW })
}

describe('Archive', () => {
  it('keeps the event as published alongside the plaintext read out of it', async () => {
    // The whole event, not only the body: a record that needs the relay to still
    // be serving the envelope is not a record, and the signature an auditor
    // checks is over the sealed bytes.
    const a = archive()
    const sealed = event({ content: 'c2VhbGVk' })
    await a.record(sealed, 'deploy api 1.4.2 to production')

    const held = await a.get('ops', sealed.id)
    assert.equal(held?.plaintext, 'deploy api 1.4.2 to production')
    assert.equal(held?.event.content, 'c2VhbGVk', 'the published bytes survive')
    assert.equal(held?.event.sig, sealed.sig)
    assert.equal(held?.archived_at, NOW)
  })

  it('does not erase a plaintext when the same event is re-seen unreadable', async () => {
    // This is the whole file. The sequence is one reconnect: archived in June
    // with the epoch in hand, re-seen in August after the epoch was deleted.
    const a = archive()
    const june = event()
    await a.record(june, 'approved the production deploy')

    await a.record(june)

    const held = await a.get('ops', june.id)
    assert.equal(held?.plaintext, 'approved the production deploy')
  })

  it('fills in a plaintext for an event it first saw sealed', async () => {
    // The other direction has to work too: an event archived before the wrap for
    // its epoch arrived becomes readable later, and the archive must take it.
    const a = archive()
    const e = event()
    await a.record(e)
    assert.equal((await a.get('ops', e.id))?.plaintext, undefined)

    await a.record(e, 'the wrap turned up')
    assert.equal((await a.get('ops', e.id))?.plaintext, 'the wrap turned up')
  })

  it('keeps the first archived_at, because a re-record is not a new sighting', async () => {
    const store = new MemoryStore()
    let clock = NOW
    const a = new Archive(store, { now: () => clock })
    const e = event()
    await a.record(e, 'said once')

    clock = NOW + 86_400
    await a.record(e, 'said once')

    assert.equal((await a.get('ops', e.id))?.archived_at, NOW)
  })

  it('records what it could not read, so a gap is visible rather than absent', async () => {
    const a = archive()
    const readable = event({ at: NOW })
    const before = event({ at: NOW - 10 })
    await a.record(readable, 'I can read this')
    await a.record(before)

    assert.deepEqual(await a.unreadable('ops'), [before.id])
    assert.equal((await a.all('ops')).length, 2, 'both are held')
  })

  it('returns a timeline oldest-first whatever order the store hands back', async () => {
    const a = archive()
    const third = event({ at: NOW + 2, content: 'c' })
    const first = event({ at: NOW, content: 'a' })
    const second = event({ at: NOW + 1, content: 'b' })
    await a.recordAll([
      { event: third, plaintext: 'third' },
      { event: first, plaintext: 'first' },
      { event: second, plaintext: 'second' },
    ])

    assert.deepEqual(
      (await a.all('ops')).map((r) => r.plaintext),
      ['first', 'second', 'third'],
    )
  })

  it('keeps two channels apart even when one group id is a prefix of the other', async () => {
    // `ops` and `ops:prod` share a prefix, and with a raw separator the scan for
    // one would match the other. The failure is not an error — it is a reader
    // shown messages from a channel they were looking at the name of.
    const a = archive()
    await a.record(event({ group: 'ops' }), 'from ops')
    await a.record(event({ group: 'ops:prod' }), 'from ops:prod')

    assert.deepEqual(
      (await a.all('ops')).map((r) => r.plaintext),
      ['from ops'],
    )
    assert.deepEqual(
      (await a.all('ops:prod')).map((r) => r.plaintext),
      ['from ops:prod'],
    )
  })

  it('files nothing at all for an event that names no channel', async () => {
    // Not "files it somewhere harmless": a key built from an absent group id is
    // a phantom channel called `undefined` that accumulates every stray event
    // forever and that nothing will ever read or prune. Checked against the
    // store rather than against `all()`, because `all('ops')` is empty either
    // way and an assertion that cannot fail is not one.
    const store = new MemoryStore()
    const a = new Archive(store, { now: () => NOW })
    await a.record({ ...event(), tags: [] }, 'nowhere')
    assert.deepEqual(await store.keys(), [])
  })

  describe('opened()', () => {
    it('substitutes the plaintext back in, ready for the packer', async () => {
      const a = archive()
      const e = event({ content: 'c2VhbGVk' })
      await a.record(e, 'deploy api 1.4.2')

      const [opened] = await a.opened('ops')
      assert.equal(opened?.content, 'deploy api 1.4.2')
      assert.equal(opened?.id, e.id, 'the id still commits to the ciphertext; do not republish it')
    })

    it('drops what it cannot read and says how much, rather than handing back base64', async () => {
      // Returning the sealed event would put base64 in front of a model as
      // though it were the conversation — the M9 keyless-packer failure. Saying
      // nothing at all would be the same lie by omission `openReadable` names.
      const a = archive()
      await a.record(event({ at: NOW, content: 'c2VhbGVk' }))
      await a.record(event({ at: NOW + 1 }), 'the one I have')

      let reported: [number, number] | undefined
      const opened = await a.opened('ops', (missing, held) => {
        reported = [missing, held]
      })
      assert.equal(opened.length, 1)
      assert.deepEqual(reported, [1, 1])
    })

    it('does not call onMissing when it holds everything', async () => {
      const a = archive()
      await a.record(event(), 'all present')
      let called = false
      await a.opened('ops', () => {
        called = true
      })
      assert.equal(called, false, 'a warning that fires every time is a warning nobody reads')
    })
  })

  describe('prune()', () => {
    it('drops by when the event was sent, not by when this replica saw it', async () => {
      // Otherwise two agents that joined a month apart hold different windows of
      // the same channel and neither is wrong, which makes "we keep six weeks"
      // untrue of the workspace while being true of every agent in it.
      const store = new MemoryStore()
      let clock = NOW + 100_000
      const a = new Archive(store, { now: () => clock })
      const old = event({ at: NOW - 86_400 })
      const recent = event({ at: NOW })
      await a.record(old, 'last month')
      clock = NOW + 200_000
      await a.record(recent, 'today')

      assert.equal(await a.prune('ops', NOW), 1)
      assert.deepEqual(
        (await a.all('ops')).map((r) => r.plaintext),
        ['today'],
      )
    })

    it('leaves other channels alone', async () => {
      const a = archive()
      await a.record(event({ at: NOW - 86_400, group: 'ops' }), 'old ops')
      await a.record(event({ at: NOW - 86_400, group: 'finance' }), 'old finance')

      await a.prune('ops', NOW)
      assert.equal((await a.all('finance')).length, 1)
    })
  })
})

describe('SealedEnvelopes', () => {
  it('seals once and returns the same bytes on every retry', async () => {
    // The property `once()` rests on. Under `nip44` re-sealing is a pure
    // function and this cache would be an optimisation; under `mls` the ratchet
    // advances per message, so a second seal is a second message in the channel
    // and a consumed generation nobody can give back.
    const envelopes = new SealedEnvelopes(new MemoryStore())
    let seals = 0
    const seal = () => {
      seals += 1
      return { ...event(), content: `ratchet-output-${seals}` }
    }

    const first = await envelopes.sealOnce('plaintext-id', seal)
    const retry = await envelopes.sealOnce('plaintext-id', seal)

    assert.equal(seals, 1, 'the ratchet advanced once')
    assert.deepEqual(retry, first)
  })

  it('does not hand the envelope back until the write has completed', async () => {
    // The ordering *is* the mechanism, so it is asserted as an ordering rather
    // than by reading the store afterwards — against an in-memory store a
    // fire-and-forget write lands before the next line either way, and the test
    // would pass over the version of this code that publishes first and records
    // whenever. The failure it guards against is a crash in that gap: the relay
    // has the event, the cache does not, and the retry seals again.
    let release = (): void => {}
    const gate = new Promise<void>((resolve) => {
      release = resolve
    })
    const store = new MemoryStore()
    const slow: Store = {
      get: (key) => store.get(key),
      set: async (key, value) => {
        await gate
        return store.set(key, value)
      },
      delete: (key) => store.delete(key),
      keys: (prefix) => store.keys(prefix),
    }

    const envelopes = new SealedEnvelopes(slow)
    let settled = false
    const pending = envelopes.sealOnce('plaintext-id', () => event()).then((e) => {
      settled = true
      return e
    })

    await new Promise((resolve) => setImmediate(resolve))
    assert.equal(settled, false, 'the caller must not be able to publish before the write lands')

    release()
    const sealed = await pending
    assert.deepEqual(await store.get('sealed:plaintext-id'), sealed)
  })

  it('keys on the plaintext id, so two different bodies get two envelopes', async () => {
    const envelopes = new SealedEnvelopes(new MemoryStore())
    const a = await envelopes.sealOnce('one', () => ({ ...event(), content: 'A' }))
    const b = await envelopes.sealOnce('two', () => ({ ...event(), content: 'B' }))
    assert.notEqual(a.content, b.content)
  })

  it('forgets on request, and the next call seals again', async () => {
    const envelopes = new SealedEnvelopes(new MemoryStore())
    await envelopes.sealOnce('one', () => ({ ...event(), content: 'A' }))
    await envelopes.forget('one')
    const again = await envelopes.sealOnce('one', () => ({ ...event(), content: 'B' }))
    assert.equal(again.content, 'B')
  })
})
