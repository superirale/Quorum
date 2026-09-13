/**
 * The task list, and the part of it that is a security claim rather than a view.
 *
 * Most of what `threads()` does is arithmetic over events. One thing it does is
 * decide whether to believe the relay: kind 38101 is signed by the relay, the
 * relay is the only party positioned to misstate what a task says, and
 * `folded_from` is the list that makes the claim checkable. So the tests below
 * are mostly attempts to get a wrong status onto the screen — by signing a
 * projection that does not match its own ops, by folding in a different order,
 * and by forging a 38101 as an ordinary member on a relay that does not stop
 * you.
 *
 * The rest guard the boring failure: a thread that shows as `open` because a
 * `set_status` arrived a second ago and the relay has not folded it yet is a
 * client people stop trusting for a reason that has nothing to do with trust.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import {
  Kinds,
  TagName,
  build,
  tagValue,
  type NostrEvent,
  type ThreadStatus,
} from '@quorum/protocol'
import type { PublishOptions } from '../src/publish.ts'
import { LocalSigner } from '../src/signer.ts'
import { foldOps, thread as findThread, threadOp, threads } from '../src/threads.ts'

const GROUP = 'payments'
const NOW = 1_800_000_000

const ada = LocalSigner.generate()
const bot = LocalSigner.generate()
const relay = LocalSigner.generate()

const root = await ada.sign(
  build({
    kind: Kinds.Thread,
    pubkey: ada.publicKey,
    group: GROUP,
    text: 'deploy api 1.4.2 to production',
    created_at: NOW - 300,
    tags: [['title', 'deploy api']],
  }),
)
const threadRef = { id: root.id, kind: root.kind, pubkey: root.pubkey }

let clock = NOW - 200

/** A thread op from whoever signs it. `created_at` advances so order is stable. */
async function op(signer: LocalSigner, body: unknown): Promise<NostrEvent> {
  return signer.sign(
    build({
      kind: Kinds.ThreadOp,
      pubkey: signer.publicKey,
      group: GROUP,
      thread: threadRef,
      body,
      created_at: clock++,
    }),
  )
}

/**
 * A projection, as the relay would sign it — including the `folded_from` order,
 * which is the whole point of the exercise and therefore takes it as an argument
 * rather than deriving it.
 */
async function projection(options: {
  status: ThreadStatus
  title?: string
  assignee?: string
  budget?: { usd?: number }
  foldedFrom: readonly NostrEvent[]
  signer?: LocalSigner
}): Promise<NostrEvent> {
  const signer = options.signer ?? relay
  return signer.sign(
    build({
      kind: Kinds.ThreadState,
      pubkey: signer.publicKey,
      group: GROUP,
      d: root.id,
      created_at: clock++,
      body: {
        status: options.status,
        ...(options.title !== undefined ? { title: options.title } : {}),
        ...(options.assignee !== undefined ? { assignee: options.assignee } : {}),
        ...(options.budget !== undefined ? { budget: options.budget } : {}),
        folded_from: options.foldedFrom.map((e) => e.id),
        updated_at: NOW,
      },
    }),
  )
}

function one(events: NostrEvent[]) {
  const [found, ...rest] = threads(events)
  assert.equal(rest.length, 0, 'expected exactly one thread')
  assert.ok(found)
  return found
}

describe('threads', () => {
  it('reads a thread with no state at all as open', async () => {
    const found = one([root])
    assert.equal(found.status, 'open')
    assert.equal(found.title, 'deploy api')
    assert.deepEqual(found.check, { verdict: 'local' })
  })

  it('folds ops itself when no relay has projected them', async () => {
    // The generic-relay case, and it has to work: nothing about a task is lost
    // by moving a workspace to a relay that has never heard of Quorum, only the
    // cross-check.
    const events = [
      root,
      await op(ada, { op: 'assign', assignee: bot.publicKey }),
      await op(bot, { op: 'set_status', status: 'working' }),
    ]
    const found = one(events)
    assert.equal(found.status, 'working')
    assert.equal(found.assignee, bot.publicKey)
    assert.deepEqual(found.check, { verdict: 'local' })
    assert.equal(found.unfolded.length, 2)
  })

  it('agrees with a projection that matches the ops it names', async () => {
    const assign = await op(ada, { op: 'assign', assignee: bot.publicKey })
    const working = await op(bot, { op: 'set_status', status: 'working' })
    const found = one([
      root,
      assign,
      working,
      await projection({
        status: 'working',
        assignee: bot.publicKey,
        foldedFrom: [assign, working],
      }),
    ])

    assert.deepEqual(found.check, { verdict: 'agrees' })
    assert.equal(found.status, 'working')
    assert.equal(found.unfolded.length, 0)
  })

  it('catches a projection whose state its own ops do not produce', async () => {
    // The relay signs `done` over a thread whose only op said `blocked`. There
    // is no innocent version of this: it named the op itself.
    const blocked = await op(ada, { op: 'set_status', status: 'blocked' })
    const found = one([root, blocked, await projection({ status: 'done', foldedFrom: [blocked] })])

    assert.deepEqual(found.check, { verdict: 'disagrees', fields: ['status'] })
    assert.equal(found.status, 'blocked', 'our fold is what gets shown, not the relay’s')
  })

  it('names every field that disagrees, not just the first', async () => {
    const ops = [
      await op(ada, { op: 'set_status', status: 'blocked' }),
      await op(ada, { op: 'set_title', title: 'what ada asked for' }),
      await op(ada, { op: 'set_budget', budget: { usd: 10 } }),
    ]
    const found = one([
      root,
      ...ops,
      await projection({
        status: 'done',
        title: 'something else',
        budget: { usd: 5000 },
        foldedFrom: ops,
      }),
    ])

    assert.deepEqual(found.check, {
      verdict: 'disagrees',
      fields: ['status', 'title', 'budget'],
    })
    assert.equal(found.title, 'what ada asked for')
    assert.deepEqual(found.budget, { usd: 10 })
  })

  it('replays in the relay’s order rather than its own', async () => {
    // Both ops are legitimate and the relay saw them in the opposite order to
    // the one their timestamps imply — which is ordinary, since arrival order is
    // not `created_at` order. Folding by timestamp would call this a forgery.
    const done = await op(ada, { op: 'set_status', status: 'done' })
    const blocked = await op(bot, { op: 'set_status', status: 'blocked' })
    const found = one([
      root,
      done,
      blocked,
      await projection({ status: 'done', foldedFrom: [blocked, done] }),
    ])

    assert.deepEqual(found.check, { verdict: 'agrees' })
    assert.equal(found.status, 'done')
  })

  it('says so rather than accusing when it cannot see every op folded', async () => {
    // A thread older than the backfill window. The relay folded ops we were
    // never served, so there is nothing to check it against — and an
    // unverifiable projection is the normal state of a long-lived task, not a
    // sign of anything.
    const held = await op(ada, { op: 'set_status', status: 'working' })
    const found = one([
      root,
      held,
      await projection({
        status: 'done',
        foldedFrom: [held, { ...held, id: 'f'.repeat(64) } as NostrEvent],
      }),
    ])

    assert.deepEqual(found.check, { verdict: 'unverifiable', missing: 1 })
    assert.equal(found.status, 'done', 'the relay’s state is used, and labelled')
  })

  it('applies an op the projection has not caught up with yet', async () => {
    const working = await op(bot, { op: 'set_status', status: 'working' })
    const state = await projection({ status: 'working', foldedFrom: [working] })
    const justNow = await op(bot, { op: 'set_status', status: 'done' })

    const found = one([root, working, state, justNow])
    assert.equal(found.status, 'done')
    assert.deepEqual(found.check, { verdict: 'agrees' }, 'lag is not disagreement')
    assert.deepEqual(
      found.unfolded.map((e) => e.id),
      [justNow.id],
    )
  })

  it('turns a member’s forged projection into a warning, not a status', async () => {
    // On our relay `RejectRelaySignedForgeries` stops this at the door. On a
    // generic relay nothing does, so the client must not be the only thing that
    // believes it — and it does not, because the forger has to name ops that
    // produce the state it claims.
    const blocked = await op(ada, { op: 'set_status', status: 'blocked' })
    const forged = await projection({
      status: 'done',
      foldedFrom: [blocked],
      signer: bot,
    })

    const found = one([root, blocked, forged])
    assert.equal(found.check.verdict, 'disagrees')
    assert.equal(found.status, 'blocked')
  })

  it('prefers the newest projection when the relay has rewritten it', async () => {
    const first = await op(ada, { op: 'set_status', status: 'working' })
    const second = await op(ada, { op: 'set_status', status: 'done' })
    const stale = await projection({ status: 'working', foldedFrom: [first] })
    const current = await projection({ status: 'done', foldedFrom: [first, second] })

    const found = one([root, first, second, stale, current])
    assert.equal(found.projection?.id, current.id)
    assert.deepEqual(found.check, { verdict: 'agrees' })
  })

  it('counts replies and participants, and sorts by last activity', async () => {
    const other = await ada.sign(
      build({
        kind: Kinds.Thread,
        pubkey: ada.publicKey,
        group: GROUP,
        text: 'something older',
        created_at: NOW - 400,
        tags: [['title', 'older']],
      }),
    )
    const reply = await bot.sign(
      build({
        kind: Kinds.Comment,
        pubkey: bot.publicKey,
        group: GROUP,
        thread: threadRef,
        text: 'on it',
        created_at: NOW - 10,
      }),
    )

    const list = threads([other, root, reply])
    assert.deepEqual(
      list.map((t) => t.id),
      [root.id, other.id],
      'the thread touched most recently comes first',
    )
    assert.equal(list[0]?.replies, 1)
    assert.deepEqual(list[0]?.participants, [ada.publicKey, bot.publicKey])
    assert.equal(list[0]?.lastActivity, reply.created_at)
  })

  it('ignores a reply whose thread root it does not hold', async () => {
    // A hole in the backfill, not a task. Synthesising a thread from an orphan
    // reply puts a row on the screen with no title, no author and no state,
    // which reads as a broken workspace rather than an incomplete query.
    const orphan = await bot.sign(
      build({
        kind: Kinds.Comment,
        pubkey: bot.publicKey,
        group: GROUP,
        thread: { id: 'a'.repeat(64), kind: Kinds.Thread, pubkey: ada.publicKey },
        text: 'about a thread you cannot see',
        created_at: NOW,
      }),
    )
    assert.deepEqual(threads([orphan]), [])
  })

  it('filters by status and assignee', async () => {
    const events = [
      root,
      await op(ada, { op: 'assign', assignee: bot.publicKey }),
      await op(bot, { op: 'set_status', status: 'working' }),
    ]
    assert.equal(threads(events, { status: ['working'] }).length, 1)
    assert.equal(threads(events, { status: ['done'] }).length, 0)
    assert.equal(threads(events, { assignee: bot.publicKey }).length, 1)
    assert.equal(threads(events, { assignee: ada.publicKey }).length, 0)
  })

  it('finds one thread by id', async () => {
    assert.equal(findThread([root], root.id)?.title, 'deploy api')
    assert.equal(findThread([root], 'b'.repeat(64)), undefined)
  })

  it('falls back to the first line when a thread has no title tag', async () => {
    const untitled = await ada.sign(
      build({
        kind: Kinds.Thread,
        pubkey: ada.publicKey,
        group: GROUP,
        text: 'no title tag\nand a second line nobody should see',
        created_at: NOW,
      }),
    )
    assert.equal(one([untitled]).title, 'no title tag')
  })
})

describe('foldOps', () => {
  it('ignores an op it does not understand rather than stopping', async () => {
    // Adding an op is a MINOR bump, so an older reader must survive a newer
    // writer. The unknown one is skipped and the next one still applies.
    const unknown = { ...(await op(ada, { op: 'set_status', status: 'working' })) }
    unknown.content = JSON.stringify({ op: 'set_priority', priority: 'high' })

    const state = foldOps([unknown, await op(ada, { op: 'set_status', status: 'done' })])
    assert.equal(state.status, 'done')
  })

  it('ignores an op whose body is not JSON at all', async () => {
    const junk = { ...(await op(ada, { op: 'set_status', status: 'working' })) }
    junk.content = 'not json'
    assert.equal(foldOps([junk]).status, 'open')
  })

  it('unassigns on a null assignee', async () => {
    const state = foldOps([
      await op(ada, { op: 'assign', assignee: bot.publicKey }),
      await op(ada, { op: 'assign', assignee: null }),
    ])
    assert.equal(state.assignee, undefined)
  })
})

/**
 * The producer side, which until now did not exist.
 *
 * The relay has folded 8109 into 38101 since M2 and `threads()` reads the
 * result, but nothing in TypeScript had ever *published* an op — so every task
 * in every TS client was `open` forever, and the projection was exercised only
 * by Go tests constructing events by hand. These check the two things that make
 * an op findable rather than the body, which the protocol package already
 * validates: the `E` tag the relay locates the thread by, and the `alt` a
 * client that has never heard of kind 8109 renders instead.
 */
describe('threadOp', () => {
  it('produces an op the reader folds straight back', async () => {
    const event = await sign(
      threadOp(threadRef, { op: 'set_status', status: 'blocked', reason: 'needs a human' }),
    )
    const found = one([root, event])
    assert.equal(found.status, 'blocked')
    assert.deepEqual(found.check, { verdict: 'local' })
  })

  it('scopes the op to its thread, which is how the relay finds it', async () => {
    const event = await sign(threadOp(threadRef, { op: 'assign', assignee: bot.publicKey }))
    assert.equal(tagValue(event.tags, TagName.RootEvent), root.id)
    assert.equal(tagValue(event.tags, TagName.RootKind), String(Kinds.Thread))
    assert.equal(tagValue(event.tags, TagName.RootPubkey), root.pubkey)
  })

  it('carries the alt that every Quorum kind requires', async () => {
    // Generated by `@quorum/protocol` rather than composed here. A second copy
    // of this sentence is how the console's audit verdict came to be wrong in
    // both of the places it was written.
    const event = await sign(threadOp(threadRef, { op: 'set_status', status: 'done' }))
    assert.match(tagValue(event.tags, TagName.Alt) ?? '', /done/i)
  })

  it('does not number itself — an op is stored, so it takes a counter', async () => {
    // Not ephemeral: the sequence of ops is the audit trail for how a task got
    // where it is, so it belongs in the counter sequence like any other stored
    // event. The builder leaves the number to the publisher, which is the only
    // thing that knows what has already been used.
    const options = threadOp(threadRef, { op: 'set_title', title: 'deploy api 1.4.3' })
    assert.equal(options.counter, undefined)
    const event = await sign({ ...options, counter: 7 })
    assert.equal(tagValue(event.tags, TagName.Counter), '7')
  })
})

/** Sign what `threadOp` returns, the way a `Publisher` would. */
async function sign(options: PublishOptions): Promise<NostrEvent> {
  return ada.sign(build({ ...options, pubkey: ada.publicKey, group: GROUP, created_at: clock++ }))
}
