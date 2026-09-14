/**
 * Stopping the right thread.
 *
 * The budget arithmetic is the protocol's and the thread projection is the
 * SDK's; both are tested where they live. What is tested here is the one
 * decision this console makes on its own: turning `4b2f` typed in a hurry into
 * exactly one thread, or refusing to guess.
 *
 * It matters more for `stop` than for anything else in the tool. Every other
 * command that takes an id is recoverable — approve the wrong request and you
 * can deny the next one — but an interrupt aimed at the wrong thread cancels a
 * deploy somebody was depending on, and there is no undo for work that stopped
 * halfway.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { Kinds, build } from '@quorum/protocol'
import { LocalSigner, threads, type Thread } from '@quorum/sdk'
import { findTask } from '../src/commands/tasks.ts'

const GROUP = 'payments'
const ada = LocalSigner.generate()

let clock = 1_800_000_000

/** A thread root, so the ids are real hashes rather than chosen strings. */
async function root(title: string) {
  return ada.sign(
    build({
      kind: Kinds.Thread,
      pubkey: ada.publicKey,
      group: GROUP,
      text: title,
      created_at: clock++,
      tags: [['title', title]],
    }),
  )
}

const one = await root('deploy api')
const two = await root('rotate keys')
const list: Thread[] = threads([one, two])

describe('findTask', () => {
  it('finds a thread by its full id', () => {
    assert.equal(findTask(list, one.id).id, one.id)
  })

  it('finds a thread by the prefix the list printed', () => {
    assert.equal(findTask(list, one.id.slice(0, 8)).id, one.id)
  })

  it('accepts the ellipsis the list printed with it', () => {
    // `quorum tasks` prints `4b2f91a8…`; pasting that back must work, because
    // that is what a person will actually do.
    assert.equal(findTask(list, `${one.id.slice(0, 8)}…`).id, one.id)
  })

  it('is case-insensitive, because a pasted id may be either', () => {
    assert.equal(findTask(list, one.id.slice(0, 8).toUpperCase()).id, one.id)
  })

  it('refuses rather than guessing when a prefix matches two threads', () => {
    // The ids are overridden rather than fished for: two real hashes share a
    // prefix only by luck, and a test that depends on luck is a test that
    // reports this rule working on the days it does not run.
    const ambiguous: Thread[] = [
      { ...list[0]!, id: `abc111${one.id.slice(6)}` },
      { ...list[1]!, id: `abc222${two.id.slice(6)}` },
    ]
    assert.throws(() => findTask(ambiguous, 'abc'), /matches 2 threads/)
  })

  it('refuses an id that matches nothing', () => {
    assert.throws(() => findTask(list, 'ffffffffff'), /no thread in this group/)
  })

  it('refuses an empty id rather than matching everything', () => {
    // `startsWith('')` is true for every thread, so without this the operator
    // types `quorum stop` with a missing argument and stops a random one.
    assert.throws(() => findTask(list, '…'), /give a thread id/)
  })
})
