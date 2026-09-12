/**
 * The M3 demo, as tests.
 *
 *   1. the agent responds only when it is `p`-tagged
 *   2. it survives a restart mid-handler without repeating itself
 *   3. two replicas do not both answer
 *
 * Each has a negative control somewhere in the file: a test that the mechanism
 * is *load-bearing*, not merely present. M1 taught that the hard way — seven of
 * its eight tamper cases would have passed against an implementation that only
 * checked a hash.
 */

import assert from 'node:assert/strict'
import { after, describe, it } from 'node:test'
import { Kinds, digest, refTo, threadRef } from '@quorum/protocol'
import { settle, waitFor, waitForCount } from '@quorum/test-kit'
import {
  Cursor,
  FileStore,
  LocalSigner,
  MemoryStore,
  createAgent,
  hasRun,
  type Store,
} from '../src/index.ts'
import { Actor, assertAllValid, deferred, harness, tempDir, text } from './harness.ts'

describe('addressing', () => {
  it('answers when p-tagged and stays quiet when merely talked about', async () => {
    const h = await harness()
    after(() => h.finish())

    const signer = LocalSigner.generate()
    const agent = createAgent({
      relay: h.relay.url,
      signer,
      group: h.group,
      store: new MemoryStore(),
      leases: false,
    })
    h.cleanup(() => agent.stop())

    const seen: string[] = []
    agent.on(async (event, ctx) => {
      seen.push(event.content)
      await ctx.say(`echo: ${event.content}`)
    })
    await agent.start()

    const ada = await Actor.create(h.relay.url, h.group)
    h.cleanup(() => ada.close())

    // Prose that names the agent every way a human might. None of it is
    // addressing, and the M0 spike fired on exactly this kind of message.
    const root = await ada.thread('deploy', `to reach the bot, p-tag ${signer.publicKey}`)
    await settle()
    assert.deepEqual(seen, [], 'an agent must never infer addressing from body text')

    // The same words, this time with a `to`-marked p tag.
    await ada.comment(refTo(root), 'ping', [signer.publicKey])
    await waitFor(() => seen.length === 1, { describe: 'the addressed message' })

    const replies = await waitForCount(
      () => h.relay.eventsOfKind(Kinds.Comment).filter((e) => e.pubkey === signer.publicKey),
      1,
      { describe: 'a reply' },
    )
    assert.equal(replies[0]!.content, 'echo: ping')
    assert.ok(
      threadRef(replies[0]!)?.id === root.id,
      'the reply must sit in the thread it answers',
    )
    assertAllValid(h.relay.received)
  })

  it('does not answer its own events, which is how a loop starts', async () => {
    const h = await harness()
    after(() => h.finish())

    const signer = LocalSigner.generate()
    const agent = createAgent({
      relay: h.relay.url,
      signer,
      group: h.group,
      store: new MemoryStore(),
      leases: false,
    })
    h.cleanup(() => agent.stop())

    let calls = 0
    agent.on(async (event, ctx) => {
      calls++
      // Addressed to itself: the shape of every runaway agent conversation.
      await ctx.say('again', { to: [signer.publicKey], label: `again:${calls}` })
    })
    await agent.start()

    const ada = await Actor.create(h.relay.url, h.group)
    h.cleanup(() => ada.close())
    const root = await ada.thread('loop', 'start')
    await ada.comment(refTo(root), 'go', [signer.publicKey])

    await waitFor(() => calls >= 1, { describe: 'the first dispatch' })
    await settle(200)
    assert.equal(calls, 1, 'the agent answered itself')
  })
})

/** The `once()` label `ctx.say('working on it')` derives, computed the same way. */
const PROGRESS = `say:${digest('working on it').slice(0, 16)}`

describe('restart', () => {
  it('replays an unfinished handler without repeating what it already did', async () => {
    const h = await harness()
    const dir = await tempDir()
    after(async () => {
      await h.finish()
      await dir.remove()
    })

    const signer = LocalSigner.generate()
    const ada = await Actor.create(h.relay.url, h.group)
    h.cleanup(() => ada.close())

    // --- first life: gets halfway, then the process dies ---------------------
    const first = createAgent({
      relay: h.relay.url,
      signer,
      group: h.group,
      store: FileStore.in(dir.path),
      leases: false,
    })
    const stuck = deferred()
    let firstRuns = 0
    first.on(async (event, ctx) => {
      firstRuns++
      await ctx.say('working on it')
      await stuck.promise // never resolves: this handler dies here
      await ctx.say('done')
    })
    await first.start()

    const root = await ada.thread('deploy', 'please deploy', [signer.publicKey])
    await waitFor(() => firstRuns === 1, { describe: 'the first handler to start' })

    // Wait for the *ledger*, not for the relay. The relay logs the arrival
    // before the publisher has its OK back, so killing the agent on the arrival
    // is a race against the completion write — and which side wins decides
    // whether the replay re-sends the message, which is the thing this test is
    // asserting. `hasRun` is the same fact the replay will read.
    await waitFor(() => hasRun(FileStore.in(dir.path), root.id, PROGRESS), {
      describe: 'the send to be recorded in the ledger',
    })
    await first.stop()

    // --- second life: same key, same state directory -------------------------
    const second = createAgent({
      relay: h.relay.url,
      signer,
      group: h.group,
      store: FileStore.in(dir.path),
      leases: false,
    })
    h.cleanup(() => second.stop())
    let secondRuns = 0
    second.on(async (event, ctx) => {
      secondRuns++
      await ctx.say('working on it')
      await ctx.say('done')
    })
    await second.start()

    await waitFor(() => secondRuns === 1, {
      describe: 'the interrupted handler to be replayed',
    })
    await waitForCount(() => h.relay.eventsOfKind(Kinds.Comment), 2, { describe: 'the finish' })
    await settle(150)

    assert.deepEqual(
      text(h.relay.stored, Kinds.Comment, signer.publicKey),
      ['working on it', 'done'],
      'the work finished, and neither message was said twice',
    )

    // The handler ran twice — whole, from the top, because the SDK cannot know
    // how far the last life got inside it — and yet the relay was sent the
    // progress message only once. The ledger had recorded it, so `once()`
    // short-circuited on the replay and returned the recorded value.
    const arrivals = h.relay
      .eventsOfKind(Kinds.Comment)
      .filter((e) => e.pubkey === signer.publicKey)
    assert.equal(arrivals.length, 2, 'a recorded effect must not run again')
    assert.equal(threadRef(arrivals[0]!)?.id, root.id)
  })

  it('rebuilds the same event when it died before the ledger recorded the send', async () => {
    const h = await harness()
    const dir = await tempDir()
    after(async () => {
      await h.finish()
      await dir.remove()
    })

    const signer = LocalSigner.generate()
    const ada = await Actor.create(h.relay.url, h.group)
    h.cleanup(() => ada.close())

    // The window the two-phase reservation exists for, and the only one that is
    // genuinely dangerous: the effect happened, the record of it did not. The
    // test above cannot reach it — there the ledger write lands and the replay
    // skips the effect. Here the completion write is dropped, which is what a
    // process dying between the two looks like from the next life's side.
    //
    // `endsWith`, not `includes`: `say` nests a second reservation at
    // `<label>/counter` so a retry reuses the counter it already spent. Lose
    // that one too and the rebuilt event carries a fresh counter and hashes to
    // a new id — which is precisely the failure being ruled out, arriving by
    // the back door and passing as a success.
    const losesCompletion = (inner: FileStore): Store => ({
      get: (key) => inner.get(key),
      delete: (key) => inner.delete(key),
      keys: (prefix) => inner.keys(prefix),
      async set(key, value) {
        if (key.endsWith(`:${PROGRESS}`) && (value as { done?: boolean }).done) return
        await inner.set(key, value)
      },
    })

    const stuck = deferred()
    const first = createAgent({
      relay: h.relay.url,
      signer,
      group: h.group,
      store: losesCompletion(FileStore.in(dir.path)),
      leases: false,
    })
    first.on(async (_event, ctx) => {
      await ctx.say('working on it')
      await stuck.promise
    })
    await first.start()

    const root = await ada.thread('deploy', 'please deploy', [signer.publicKey])
    await waitForCount(() => h.relay.eventsOfKind(Kinds.Comment), 1, {
      describe: 'the progress message',
    })
    await first.stop()

    const second = createAgent({
      relay: h.relay.url,
      signer,
      group: h.group,
      store: FileStore.in(dir.path),
      leases: false,
    })
    h.cleanup(() => second.stop())
    let replays = 0
    second.on(async (_event, ctx) => {
      replays++
      await ctx.say('working on it')
      await ctx.say('done')
    })
    await second.start()
    await waitFor(() => replays === 1, { describe: 'the replay' })
    await waitForCount(() => h.relay.eventsOfKind(Kinds.Comment), 3, { describe: 'the finish' })
    await settle(150)

    const arrivals = h.relay
      .eventsOfKind(Kinds.Comment)
      .filter((e) => e.pubkey === signer.publicKey)
    assert.equal(arrivals.length, 3, 'the replay re-sent a message it had no record of sending')
    assert.equal(
      arrivals[1]!.id,
      arrivals[0]!.id,
      'the rebuilt event must hash to the id the relay already holds',
    )
    assert.deepEqual(
      text(h.relay.stored, Kinds.Comment, signer.publicKey),
      ['working on it', 'done'],
      'so a reader sees the same thread as if nothing had gone wrong',
    )
    assert.equal(threadRef(arrivals[0]!)?.id, root.id)
  })

  it('replays only what did not finish', async () => {
    const h = await harness()
    const dir = await tempDir()
    after(async () => {
      await h.finish()
      await dir.remove()
    })

    const signer = LocalSigner.generate()
    const ada = await Actor.create(h.relay.url, h.group)
    h.cleanup(() => ada.close())
    const root = await ada.thread('work', 'kickoff', [signer.publicKey])

    const runs: string[] = []
    const build = () => {
      const agent = createAgent({
        relay: h.relay.url,
        signer,
        group: h.group,
        store: FileStore.in(dir.path),
        leases: false,
      })
      agent.on(async (event) => {
        runs.push(event.content)
      })
      return agent
    }

    const first = build()
    await first.start()
    // A handler is finished when the *cursor* says so, not when its last line
    // ran: killing the agent in between is the case the replay exists for, so
    // stopping on `runs.length` would be testing the race, not the rule.
    await waitFor(() => runs.length === 1, { describe: 'the kickoff' })
    await waitFor(
      async () => (await Cursor.load(FileStore.in(dir.path), 'default')).inFlightIds.length === 0,
      { describe: 'the handler to be recorded as finished' },
    )
    await first.stop()

    const second = build()
    h.cleanup(() => second.stop())
    await second.start()
    await settle(200)

    assert.deepEqual(runs, ['kickoff'], 'a completed handler was replayed after a restart')
  })

  it('resumes the interrupted handler before it takes on anything new', async () => {
    // The queue is serial, so the order of the backfill decides what gets to
    // block on a human first. Left to the relay that order is `created_at` — a
    // wall clock the *other* clients set. An agent parked on an approval is the
    // ordinary case from M4 onwards, so an event that sorts ahead of the replay
    // does not merely go first, it goes first *forever*.
    const h = await harness()
    const dir = await tempDir()
    after(async () => {
      await h.finish()
      await dir.remove()
    })

    const signer = LocalSigner.generate()
    const ada = await Actor.create(h.relay.url, h.group)
    h.cleanup(() => ada.close())

    const order: string[] = []
    const build = (block?: Promise<void>) => {
      const agent = createAgent({
        relay: h.relay.url,
        signer,
        group: h.group,
        store: FileStore.in(dir.path),
        leases: false,
      })
      agent.on(async (event) => {
        order.push(event.content)
        if (block) await block
      })
      return agent
    }

    const stuck = deferred()
    const first = build(stuck.promise)
    await first.start()
    const root = await ada.thread('deploy', 'the interrupted one', [signer.publicKey])
    await waitFor(() => order.length === 1, { describe: 'the first handler to start' })
    await first.stop()

    // Backdated, so the relay hands it over first in the replay window. Nothing
    // exotic: two clients with clocks a minute apart produce exactly this.
    await ada.publish({
      kind: Kinds.ChatMessage,
      text: 'something newer that looks older',
      to: [signer.publicKey],
      created_at: root.created_at - 60,
    })

    const second = build()
    h.cleanup(() => second.stop())
    await second.start()
    await waitFor(() => order.length === 3, { describe: 'both events to be handled' })

    assert.deepEqual(order, [
      'the interrupted one',
      'the interrupted one',
      'something newer that looks older',
    ])
  })
})

describe('replicas', () => {
  /**
   * Two processes, one agent key, separate state directories — the ordinary way
   * anyone runs two of something. `once()` cannot help across processes: each
   * has its own ledger and neither can see the other's.
   */
  const twoReplicas = async (useLease: boolean) => {
    const h = await harness()
    const signer = LocalSigner.generate()
    const ada = await Actor.create(h.relay.url, h.group)
    h.cleanup(() => ada.close())

    const replicas = ['a', 'b'].map((name) => {
      const agent = createAgent({
        relay: h.relay.url,
        signer,
        group: h.group,
        name,
        store: new MemoryStore(),
        leases: { settleMs: 120, ttlSeconds: 5 },
      })
      agent.on(async (event, ctx) => {
        if (useLease) {
          const lease = await ctx.lease('echo')
          if (!lease.held) return
        }
        await ctx.say(`handled by one of us`, { label: `handled:${name}` })
      })
      h.cleanup(() => agent.stop())
      return agent
    })

    await Promise.all(replicas.map((r) => r.start()))
    await ada.thread('deploy', 'who is taking this?', [signer.publicKey])
    await settle(700)

    const answers = h.relay.eventsOfKind(Kinds.Comment).filter((e) => e.pubkey === signer.publicKey)
    await h.finish()
    return answers.length
  }

  it('only one replica answers', async () => {
    assert.equal(await twoReplicas(true), 1)
  })

  it('and without the lease both of them do — so the lease is what stopped it', async () => {
    assert.equal(await twoReplicas(false), 2)
  })
})

describe('gap detection', () => {
  it('reports an author whose counter sequence skipped, using no help from the relay', async () => {
    const h = await harness()
    after(() => h.finish())

    const signer = LocalSigner.generate()
    const agent = createAgent({
      relay: h.relay.url,
      signer,
      group: h.group,
      store: new MemoryStore(),
      leases: false,
    })
    h.cleanup(() => agent.stop())

    const gaps: unknown[] = []
    agent.on((event, ctx) => {
      gaps.push(ctx.gaps())
    })
    await agent.start()

    const ada = await Actor.create(h.relay.url, h.group)
    h.cleanup(() => ada.close())
    const root = await ada.thread('t', 'one', [signer.publicKey]) // counter 1
    await ada.comment(refTo(root), 'two', [signer.publicKey]) // counter 2
    await waitFor(() => gaps.length === 2, { describe: 'the first two messages' })

    // The relay accepts the third, tells Ada it did, and never mentions it to
    // anyone. Nothing in Nostr forbids this, which is the entire reason the
    // counter tag exists.
    h.relay.withholdMatching((e) => e.content === 'three')
    await ada.comment(refTo(root), 'three', [signer.publicKey]) // counter 3
    h.relay.withholdMatching(() => false)
    await ada.comment(refTo(root), 'four', [signer.publicKey]) // counter 4

    await waitFor(() => gaps.length === 3, { describe: 'the fourth message' })
    assert.deepEqual(gaps.at(-1), [{ pubkey: ada.pubkey, expected: 3, seen: [4] }])
  })
})
