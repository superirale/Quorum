/**
 * The two controls that apply while an agent is already running.
 *
 * Everything else in this SDK decides whether work may start: a capability, an
 * approval, a manifest. These two are what a human reaches for when those
 * decisions turn out to have been wrong — a budget that stops an agent nobody
 * is watching, and a Stop button that stops one somebody is.
 *
 * Both are tested end to end through `Agent`, not against `runAction` directly,
 * because the interesting failures are in the wiring rather than the logic. A
 * budget checked with a number fetched when the handler started is a budget
 * that never bites. An abort controller armed after the effect began is a Stop
 * that lands in the gap and is dropped. Neither shows up in a unit test of the
 * function that does the arithmetic.
 */

import assert from 'node:assert/strict'
import { after, describe, it } from 'node:test'
import {
  ActionBody,
  Kinds,
  TagName,
  ThreadOpBody,
  refTo,
  tagValue,
  type NostrEvent,
} from '@quorum/protocol'
import { waitFor, waitForCount } from '@quorum/test-kit'
import {
  LocalSigner,
  createAgent,
  interrupt,
  threadOp,
  threadState,
  type ActResult,
  type Agent,
} from '../src/index.ts'
import { Actor, assertAllValid, deferred, harness, type Harness } from './harness.ts'

/** Quiet: these tests deliberately provoke warnings the runtime should log. */
const quiet = { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} }

interface World {
  h: Harness
  ada: Actor
  agent: Agent
  /** The thread everything happens in. Not addressed to the agent. */
  root: NostrEvent
  results: ActResult<string>[]
  /** Wakes the agent up by addressing it in the thread. */
  poke(): Promise<NostrEvent>
  op(body: unknown): Promise<NostrEvent>
  actions(status: string): NostrEvent[]
  spends(): { cost: Record<string, number>; note?: string }[]
}

/**
 * A thread, an agent watching it, and an effect the test controls.
 *
 * The thread root is deliberately *not* addressed to the agent: the ops that
 * set the budget have to be in the channel before the handler runs, and an
 * addressed root would start it first.
 */
async function world(run: (signal: AbortSignal) => Promise<string>, cost?: unknown): Promise<World> {
  const h = await harness()
  const ada = await Actor.create(h.relay.url, h.group)
  h.cleanup(() => ada.close())

  const results: ActResult<string>[] = []
  const agent = createAgent({
    relay: h.relay.url,
    signer: LocalSigner.generate(),
    group: h.group,
    leases: false,
    log: quiet,
  })
  agent.on(async (_event, ctx) => {
    results.push(
      await ctx.act({
        name: 'deploy.production',
        summary: 'deploy api 1.4.2 to production',
        input: { service: 'api' },
        run: async (_input, r) => {
          if (cost) Object.assign(r, { cost })
          return run(r.signal)
        },
      }),
    )
  })
  h.cleanup(() => agent.stop())
  await agent.start()

  const root = await ada.thread('deploy', 'ship 1.4.2 when you can')
  const thread = refTo(root)

  return {
    h,
    ada,
    agent,
    root,
    results,
    poke: () => ada.comment(thread, 'go ahead', [agent.me]),
    op: (body) => ada.publish(threadOp(thread, body as never)),
    actions: (status) =>
      h.relay
        .storedOfKind(Kinds.Action)
        .filter((e) => ActionBody.safeParse(JSON.parse(e.content)).data?.status === status),
    spends: () =>
      h.relay
        .storedOfKind(Kinds.ThreadOp)
        .map((e) => ThreadOpBody.safeParse(JSON.parse(e.content)).data)
        .filter((b): b is Extract<ThreadOpBody, { op: 'add_spend' }> => b?.op === 'add_spend')
        .map((b) => ({ cost: b.cost as Record<string, number>, ...(b.note ? { note: b.note } : {}) })),
  }
}

describe('the budget', () => {
  it('refuses to propose anything once the thread has spent it', async () => {
    const w = await world(async () => 'deployed')
    after(() => w.h.finish())

    await w.op({ op: 'set_budget', budget: { usd: 1 } })
    await w.op({ op: 'add_spend', cost: { usd: 2 } })
    await w.poke()

    await waitForCount(() => w.results, 1, { describe: 'the action to be decided' })
    const [result] = w.results
    assert.equal(result?.status, 'cancelled')
    assert.match(result?.status === 'cancelled' ? result.reason : '', /spent its budget/)

    // Nothing was proposed, and that is the point: the relay refuses a
    // `proposed` in a paused thread, a rejected publish throws inside a
    // handler, and a throw inside a handler is replayed — so proposing it would
    // turn a budget stop into a loop against a relay that will refuse it every
    // time.
    assert.deepEqual(w.h.relay.storedOfKind(Kinds.Action), [])
    assert.equal(result?.status === 'cancelled' ? result.actionId : 'x', '')
  })

  it('lets work through while there is budget left', async () => {
    // The control that stops the test above passing against an agent that
    // refuses everything.
    const w = await world(async () => 'deployed')
    after(() => w.h.finish())

    await w.op({ op: 'set_budget', budget: { usd: 10 } })
    await w.op({ op: 'add_spend', cost: { usd: 2 } })
    await w.poke()

    await waitForCount(() => w.results, 1, { describe: 'the action to be decided' })
    assert.equal(w.results[0]?.status, 'succeeded')
  })

  it('reports what the action cost as an op the thread folds', async () => {
    const w = await world(async () => 'deployed', { tokens_in: 900, tokens_out: 300 })
    after(() => w.h.finish())

    await w.op({ op: 'set_budget', budget: { tokens: 1000 } })
    await w.poke()
    await waitForCount(() => w.results, 1, { describe: 'the action to be decided' })
    await waitFor(() => w.spends().length === 1, { describe: 'the spend op' })

    assert.deepEqual(w.spends()[0], {
      cost: { tokens_in: 900, tokens_out: 300 },
      // Named, because a thread that ran out of money is read to find out which
      // part of it was expensive, and six bare amounts answer nothing.
      note: 'deploy.production',
    })

    // And the thread is now over its ceiling, which is what the next `act()`
    // will refuse on. Folded locally here because the fake relay projects
    // nothing — that is `apps/relay`'s job, and `budget_test.go` proves it.
    const state = threadState(w.h.relay.stored, w.root.id)
    assert.deepEqual(state.spent, { tokens_in: 900, tokens_out: 300 })
    assert.equal(state.status, 'paused')
  })

  it('records the cost once, on the op, not twice', async () => {
    // The action's own `cost` field is audit detail: it says what this turn
    // cost. `spent` is a sum of ops. Counting the action body as well would
    // double every number in the workspace.
    const w = await world(async () => 'deployed', { usd: 0.5 })
    after(() => w.h.finish())

    await w.poke()
    await waitForCount(() => w.results, 1, { describe: 'the action to be decided' })
    await waitFor(() => w.spends().length === 1, { describe: 'the spend op' })

    const succeeded = w.actions('succeeded')[0]
    assert.deepEqual(ActionBody.safeParse(JSON.parse(succeeded!.content)).data?.cost, { usd: 0.5 })
    assert.equal(w.spends().length, 1)
    assert.deepEqual(threadState(w.h.relay.stored, w.root.id).spent, { usd: 0.5 })
  })

  it('publishes nothing when the effect reported no cost', async () => {
    const w = await world(async () => 'deployed')
    after(() => w.h.finish())

    await w.poke()
    await waitForCount(() => w.results, 1, { describe: 'the action to be decided' })
    assert.deepEqual(w.spends(), [])
  })
})

describe('Stop', () => {
  it('aborts the effect and records the action as cancelled, not failed', async () => {
    const started = deferred()
    const w = await world(
      (signal) =>
        new Promise<string>((_resolve, reject) => {
          started.resolve()
          signal.addEventListener('abort', () => reject(signal.reason))
        }),
    )
    after(() => w.h.finish())

    await w.poke()
    await started.promise

    const [proposed] = await waitForCount(() => w.actions('proposed'), 1, {
      describe: 'the proposed action',
    })
    await w.ada.publish(
      interrupt({ thread: refTo(w.root), action: proposed!.id, reason: 'wrong version' }),
    )

    await waitForCount(() => w.results, 1, { describe: 'the action to be decided' })
    const [result] = w.results
    assert.equal(result?.status, 'cancelled')
    assert.match(result?.status === 'cancelled' ? result.reason : '', /cancelled by .*wrong version/)

    // The distinction the protocol has to carry: a deploy that broke and a
    // deploy a human stopped send very different people to very different
    // screens.
    assert.deepEqual(w.actions('failed'), [])
    assert.equal(w.actions('cancelled').length, 1)
    assertAllValid(w.h.relay.stored)
  })

  it('stops everything in the thread when the interrupt names no action', async () => {
    const started = deferred()
    const w = await world(
      (signal) =>
        new Promise<string>((_resolve, reject) => {
          started.resolve()
          signal.addEventListener('abort', () => reject(signal.reason))
        }),
    )
    after(() => w.h.finish())

    await w.poke()
    await started.promise
    await w.ada.publish(interrupt({ thread: refTo(w.root), reason: 'stop everything' }))

    await waitForCount(() => w.results, 1, { describe: 'the action to be decided' })
    assert.equal(w.results[0]?.status, 'cancelled')
  })

  it('ignores an interrupt naming an action this agent is not running', async () => {
    const started = deferred()
    const release = deferred()
    const w = await world(async (signal) => {
      started.resolve()
      await release.promise
      return signal.aborted ? 'aborted' : 'deployed'
    })
    after(() => w.h.finish())

    await w.poke()
    await started.promise
    await w.ada.publish(
      interrupt({ thread: refTo(w.root), action: 'f'.repeat(64), reason: 'someone else' }),
    )
    // Give the interrupt a chance to arrive and be wrong about what it matched.
    await new Promise((r) => setTimeout(r, 50))
    release.resolve()

    await waitForCount(() => w.results, 1, { describe: 'the action to be decided' })
    assert.equal(w.results[0]?.status, 'succeeded')
  })

  it('keeps the terminal event in the chain the auditor can follow', async () => {
    const started = deferred()
    const w = await world(
      (signal) =>
        new Promise<string>((_resolve, reject) => {
          started.resolve()
          signal.addEventListener('abort', () => reject(signal.reason))
        }),
    )
    after(() => w.h.finish())

    await w.poke()
    await started.promise
    const [proposed] = await waitForCount(() => w.actions('proposed'), 1, {
      describe: 'the proposed action',
    })
    await w.ada.publish(interrupt({ thread: refTo(w.root), action: proposed!.id }))
    await waitForCount(() => w.results, 1, { describe: 'the action to be decided' })

    const cancelled = w.actions('cancelled')[0]
    assert.ok(cancelled)
    assert.equal(tagValue(cancelled.tags, TagName.Action), proposed!.id)
    assert.equal(tagValue(cancelled.tags, TagName.Event), w.actions('running')[0]?.id)
  })
})
