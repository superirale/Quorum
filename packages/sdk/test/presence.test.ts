/**
 * Presence, written as the two ways it could lie.
 *
 * A liveness indicator has exactly one job and two ways to fail at it: claiming
 * someone is there who is not, and hiding someone who is. The first gets a human
 * waiting on an agent that died an hour ago; the second gets them restarting one
 * that was working. Every test here is one of those two.
 */

import assert from 'node:assert/strict'
import { after, describe, it } from 'node:test'
import { EphemeralKinds, Kinds, type NostrEvent } from '@quorum/protocol'
import { settle, waitFor } from '@quorum/test-kit'
import {
  Counters,
  LocalSigner,
  MemoryStore,
  PresenceReporter,
  Publisher,
  RelayClient,
  presence,
} from '../src/index.ts'
import { Keyholder, assertAllValid, harness, type Harness } from './harness.ts'

const NOW = 1_800_000_000
const agent = new Keyholder()
const other = new Keyholder()

const beat = (who: Keyholder, body: Record<string, unknown>, created_at = NOW) =>
  who.sign({ kind: EphemeralKinds.Presence, created_at, body })

describe('presence', () => {
  it('reads a heartbeat as one live agent', async () => {
    const list = presence([await beat(agent, { status: 'online', ttl_seconds: 90 })], NOW)

    assert.equal(list.length, 1)
    assert.equal(list[0]?.pubkey, agent.pubkey)
    assert.equal(list[0]?.status, 'online')
    assert.equal(list[0]?.live, true)
    assert.equal(list[0]?.until, NOW + 90)
  })

  it('stops believing a heartbeat once its ttl has passed', async () => {
    // The failure that matters. A badge that stays green because the process
    // that set it is gone is worse than no badge: it is the reason the human
    // sits and waits instead of investigating.
    const stale = await beat(agent, { status: 'online', ttl_seconds: 90 }, NOW - 91)
    const list = presence([stale], NOW)

    assert.equal(list.length, 1, 'still listed — "was here, has gone quiet" is worth knowing')
    assert.equal(list[0]?.live, false)
    assert.equal(list[0]?.at, NOW - 91)
  })

  it('believes the newest beat from each key and no others', async () => {
    const events = [
      await beat(agent, { status: 'online', ttl_seconds: 90 }, NOW - 60),
      await beat(agent, { status: 'busy', activity: 'deploying', ttl_seconds: 90 }, NOW - 5),
      await beat(other, { status: 'online', ttl_seconds: 90 }, NOW - 5),
    ]

    const list = presence(events, NOW)
    assert.equal(list.length, 2, 'one row per key, not one per beat')
    const mine = list.find((p) => p.pubkey === agent.pubkey)
    assert.equal(mine?.status, 'busy')
    assert.equal(mine?.activity, 'deploying')
  })

  it('settles two beats in one second on arrival order, not on a hash', async () => {
    // An agent that finishes a job inside a second publishes `busy` then
    // `online` with the same `created_at`. NIP-01's tiebreak is the lower id, so
    // a reader using it shows whichever the hash happens to favour — half the
    // time a working agent stuck on `busy` until the next beat.
    //
    // Asserted over twenty fresh pairs because one pair passes by luck.
    for (let i = 0; i < 20; i++) {
      const key = new Keyholder()
      const busy = await beat(key, { status: 'busy', activity: 'deploying', ttl_seconds: 90 })
      const idle = await beat(key, { status: 'online', ttl_seconds: 90 })
      assert.equal(presence([busy, idle], NOW)[0]?.status, 'online', 'the later arrival wins')
      assert.equal(presence([idle, busy], NOW)[0]?.status, 'busy', 'and so does the other way')
    }
  })

  it('shows an explicit offline rather than waiting out the ttl', async () => {
    const events = [
      await beat(agent, { status: 'online', ttl_seconds: 90 }, NOW - 10),
      await beat(agent, { status: 'offline', ttl_seconds: 90 }, NOW - 1),
    ]

    const [only] = presence(events, NOW)
    assert.equal(only?.status, 'offline')
    assert.equal(only?.live, true, 'the beat is fresh; what it says is that the process is gone')
  })

  it('puts the live ones first', async () => {
    const events = [
      await beat(agent, { status: 'online', ttl_seconds: 30 }, NOW - 100),
      await beat(other, { status: 'online', ttl_seconds: 30 }, NOW - 5),
    ]

    assert.deepEqual(
      presence(events, NOW).map((p) => p.live),
      [true, false],
    )
  })

  it('ignores junk published at a presence kind, and everything else', async () => {
    const junk = await agent.signer.sign({
      kind: EphemeralKinds.Presence,
      pubkey: agent.pubkey,
      created_at: NOW,
      tags: [['h', 'payments'], ['alt', 'online']],
      content: 'not json',
    })
    const chat = await other.sign({ kind: Kinds.ChatMessage, text: 'morning' })

    assert.deepEqual(presence([junk, chat], NOW), [])
  })
})

describe('PresenceReporter', () => {
  /** A reporter on its own relay, and a view of what it published. */
  async function reporter(h: Harness): Promise<{
    it: PresenceReporter
    beats: () => NostrEvent[]
  }> {
    const signer = LocalSigner.generate()
    const client = new RelayClient({
      url: h.relay.url,
      signer,
      reconnect: false,
      // Short, because one test here deliberately publishes into a dead socket
      // and the assertion is about what the reporter does with the failure.
      publishTimeoutMs: 200,
    })
    await client.connect()
    h.cleanup(() => client.close())
    const publisher = new Publisher({
      client,
      signer,
      pubkey: signer.publicKey,
      group: h.group,
      counters: await Counters.load(new MemoryStore(), signer.publicKey),
    })
    return {
      it: new PresenceReporter(publisher, { ttlSeconds: 90 }),
      beats: () =>
        h.relay.received.filter(
          (e) => e.kind === EphemeralKinds.Presence && e.pubkey === signer.publicKey,
        ),
    }
  }

  it('beats on start and says offline on stop', async () => {
    const h = await harness()
    after(() => h.finish())
    const r = await reporter(h)

    await r.it.start()
    assert.equal(presence(r.beats())[0]?.status, 'online')

    await r.it.stop()
    assert.equal(
      presence(r.beats())[0]?.status,
      'offline',
      'a clean shutdown knows the answer, so it should not leave a badge to time out',
    )
    assert.equal(r.beats().length, 2)
    assertAllValid(r.beats())
  })

  it('publishes a status change at once and an activity change at leisure', async () => {
    // Both halves matter. online→busy is the thing being watched, so it cannot
    // wait for the next beat; a caption change must not cost an event, or an
    // agent draining a backfill publishes one heartbeat per message it reads.
    const h = await harness()
    after(() => h.finish())
    const r = await reporter(h)
    await r.it.start()

    r.it.set('busy', 'deploying')
    await waitFor(() => r.beats().length === 2, { describe: 'the busy beat' })
    assert.equal(presence(r.beats())[0]?.status, 'busy')

    r.it.set('busy', 'deploying something else')
    await settle(50)
    assert.equal(r.beats().length, 2, 'a caption is not worth an event of its own')
  })

  it('does not take the agent down with it when the relay is gone', async () => {
    // A heartbeat that can throw is a liveness reporter causing the outage it
    // reports. That `start()` resolves at all is the whole assertion.
    const h = await harness()
    after(() => h.finish())
    const r = await reporter(h)
    await h.relay.stop()

    await r.it.start()
    assert.deepEqual(r.beats(), [])
  })
})
