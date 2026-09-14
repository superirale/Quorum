/**
 * Stop, and the four ways a Stop button becomes a lie.
 *
 * It can stop the wrong thing (another agent's action, in a channel where three
 * of them are running). It can stop nothing, silently, because the interrupt
 * named an action by an id nobody registered. It can keep stopping things after
 * they finished, because a controller was never released. And it can *look*
 * like it stopped something when what it delivered was a `steer` — a sentence
 * from whoever felt like publishing one, which must reach the handler as data
 * and never as control.
 *
 * All four are tested here, because the failure mode of this file is not an
 * exception: it is a button somebody presses and walks away from.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { EphemeralKinds, Kinds, TagName, build, tagValue, type NostrEvent } from '@quorum/protocol'
import {
  Interrupts,
  InterruptedError,
  interrupt,
  type InterruptOptions,
} from '../src/interrupt.ts'
import { LocalSigner } from '../src/signer.ts'

const GROUP = 'payments'
const NOW = 1_800_000_000

const ada = LocalSigner.generate()
const bot = LocalSigner.generate()

const root = await ada.sign(
  build({
    kind: Kinds.Thread,
    pubkey: ada.publicKey,
    group: GROUP,
    text: 'deploy api 1.4.2',
    created_at: NOW,
  }),
)
const threadRef = { id: root.id, kind: root.kind, pubkey: root.pubkey }

let clock = NOW

/** The event a human's client publishes when they press Stop. */
async function stop(options: Omit<InterruptOptions, 'thread'>): Promise<NostrEvent> {
  return ada.sign(
    build({
      ...interrupt({ thread: threadRef, ...options }),
      pubkey: ada.publicKey,
      group: GROUP,
      created_at: clock++,
    }),
  )
}

describe('interrupt()', () => {
  it('infers action scope from naming an action', () => {
    const options = interrupt({ thread: threadRef, action: 'abc123' })
    assert.equal((options.body as { scope: string }).scope, 'action')
    assert.equal((options.body as { mode: string }).mode, 'cancel')
  })

  it('infers thread scope when no action is named', () => {
    const options = interrupt({ thread: threadRef, reason: 'wrong branch' })
    assert.equal((options.body as { scope: string }).scope, 'thread')
  })

  it('refuses an action-scoped interrupt with no action to stop', () => {
    // It would validate at the relay and abort nothing, which is the worst
    // available outcome: a Stop that reports success and does nothing.
    assert.throws(
      () => interrupt({ thread: threadRef, scope: 'action' }),
      /must name the action it stops/,
    )
  })

  it('is ephemeral and carries the tags the registry matches on', async () => {
    const event = await stop({ action: 'abc123', reason: 'wrong version' })
    assert.equal(event.kind, EphemeralKinds.Interrupt)
    assert.equal(tagValue(event.tags, TagName.Action), 'abc123')
    assert.equal(tagValue(event.tags, TagName.RootEvent), root.id)
    assert.ok(tagValue(event.tags, TagName.Alt))
  })

  it('carries no counter, because an ephemeral event is not in the sequence', async () => {
    const event = await stop({ action: 'abc123' })
    assert.equal(tagValue(event.tags, TagName.Counter), undefined)
  })
})

describe('Interrupts', () => {
  it('aborts the action an interrupt names', async () => {
    const interrupts = new Interrupts()
    const armed = interrupts.register('action-1', root.id)

    const stopped = interrupts.deliver(await stop({ action: 'action-1', reason: 'wrong version' }))
    assert.equal(stopped.length, 1)
    assert.equal(armed.signal.aborted, true)
    assert.ok(armed.signal.reason instanceof InterruptedError)
    assert.match(String(armed.signal.reason.message), /cancelled by .*wrong version/)
  })

  it('leaves another agent’s action alone', async () => {
    // The normal case in a busy channel, and the reason nothing is logged for
    // it: every agent hears every interrupt.
    const interrupts = new Interrupts()
    const mine = interrupts.register('action-mine', root.id)

    const stopped = interrupts.deliver(await stop({ action: 'action-theirs' }))
    assert.deepEqual(stopped, [])
    assert.equal(mine.signal.aborted, false)
  })

  it('stops everything in a thread when the interrupt is thread-scoped', async () => {
    const interrupts = new Interrupts()
    const first = interrupts.register('action-1', root.id)
    const second = interrupts.register('action-2', root.id)
    const elsewhere = interrupts.register('action-3', 'a-different-thread')

    const stopped = interrupts.deliver(await stop({ reason: 'stop everything' }))
    assert.equal(stopped.length, 2)
    assert.equal(first.signal.aborted, true)
    assert.equal(second.signal.aborted, true)
    assert.equal(elsewhere.signal.aborted, false)
  })

  it('does not abort on a steer, and hands the instruction over as data', async () => {
    // The instruction came from a group member with no particular authority. An
    // interrupt that applied it would be prompt injection with a protocol kind.
    const interrupts = new Interrupts()
    const armed = interrupts.register('action-1', root.id)

    const stopped = interrupts.deliver(
      await stop({ action: 'action-1', mode: 'steer', instruction: 'deploy to staging instead' }),
    )
    assert.equal(armed.signal.aborted, false)
    assert.equal(stopped[0]?.mode, 'steer')
    assert.equal(stopped[0]?.instruction, 'deploy to staging instead')
    assert.equal(armed.interruptions().length, 1)
  })

  it('aborts on a pause exactly as it does on a cancel', async () => {
    // The difference between the two is a thread status a human sets and clears.
    // There is no in-memory half-finished effect waiting to be told to continue,
    // because that state does not survive the restart that is coming for it.
    const interrupts = new Interrupts()
    const armed = interrupts.register('action-1', root.id)
    interrupts.deliver(await stop({ action: 'action-1', mode: 'pause' }))
    assert.equal(armed.signal.aborted, true)
    assert.equal((armed.signal.reason as InterruptedError).mode, 'pause')
  })

  it('stops matching a released action', async () => {
    // A controller left behind is an interrupt delivered to nobody, and a
    // registry that grows for the life of the process.
    const interrupts = new Interrupts()
    const armed = interrupts.register('action-1', root.id)
    armed.release()
    assert.equal(interrupts.size, 0)
    assert.deepEqual(interrupts.deliver(await stop({ action: 'action-1' })), [])
  })

  it('ignores an event that is not an interrupt at all', async () => {
    const interrupts = new Interrupts()
    interrupts.register('action-1', root.id)
    assert.deepEqual(interrupts.deliver(root), [])
  })

  it('ignores an interrupt whose body is not a valid one', async () => {
    // A junk 28101 from a member must not throw inside `ingest`, which is not
    // in a try: the control plane is dispatched off the queue and an exception
    // there takes the subscription callback with it.
    const interrupts = new Interrupts()
    const armed = interrupts.register('action-1', root.id)
    // Built valid and then corrupted, because `build()` validates its own body
    // — which is exactly why the junk has to come from somewhere else. On a
    // generic relay it comes from a client that is not this SDK.
    const valid = build({
      ...interrupt({ thread: threadRef, action: 'action-1' }),
      pubkey: ada.publicKey,
      group: GROUP,
      created_at: clock++,
    })
    const junk = await ada.sign({ ...valid, content: JSON.stringify({ mode: 'demolish' }) })
    assert.deepEqual(interrupts.deliver(junk), [])
    assert.equal(armed.signal.aborted, false)
  })

  it('aborts everything on shutdown', () => {
    const interrupts = new Interrupts()
    const first = interrupts.register('action-1', root.id)
    const second = interrupts.register('action-2', undefined)
    interrupts.abortAll(new Error('going down'))
    assert.equal(first.signal.aborted, true)
    assert.equal(second.signal.aborted, true)
    assert.equal(interrupts.size, 0)
  })

  it('does not match a thread-scoped interrupt against an unthreaded action', async () => {
    const interrupts = new Interrupts()
    const armed = interrupts.register('action-1', undefined)
    assert.deepEqual(interrupts.deliver(await stop({})), [])
    assert.equal(armed.signal.aborted, false)
  })

  it('names who stopped it, because that is the first question asked', async () => {
    const interrupts = new Interrupts()
    interrupts.register('action-1', root.id)
    const event = await bot.sign(
      build({
        ...interrupt({ thread: threadRef, action: 'action-1' }),
        pubkey: bot.publicKey,
        group: GROUP,
        created_at: clock++,
      }),
    )
    const [stopped] = interrupts.deliver(event)
    assert.equal(stopped?.from, bot.publicKey)
  })
})
