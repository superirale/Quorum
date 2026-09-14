/**
 * Shapes for the screens, built by hand rather than signed.
 *
 * Nothing here is a real event: the ids are not hashes and the signatures are
 * not signatures. That is correct for these tests and would be wrong anywhere
 * else. A component is handed a `Thread` or a `GrantSummary` that some other
 * layer has already verified — `threads()`, `summariseGrants()`,
 * `verifyActionChains()` — and those layers have their own suites in the SDK.
 * Signing fixtures here would test the SDK a second time and the rendering
 * not at all, while making every one of these tests slow enough that nobody
 * runs them.
 *
 * The constructors take overrides so each test can name the one field it is
 * about, and every other field stays a boring default the reader can ignore.
 */

import assert from 'node:assert/strict'
import { PLAINTEXT_POLICY } from '@quorum/sdk'
import type { NostrEvent } from '@quorum/protocol'
import type { Thread } from '@quorum/sdk'
import type { Workspace } from '../src/useWorkspace.ts'

export const NOW = 1_800_000_000

export const ADA = 'a'.repeat(64)
export const BOT = 'b'.repeat(64)

let seq = 0

/** An event with a unique id, so React keys and `e`-tag lookups behave. */
export function event(over: Partial<NostrEvent> = {}): NostrEvent {
  seq += 1
  return {
    id: String(seq).padStart(64, '0'),
    pubkey: ADA,
    created_at: NOW,
    kind: 9,
    tags: [],
    content: '',
    sig: 'f'.repeat(128),
    ...over,
  }
}

export function thread(over: Partial<Thread> = {}): Thread {
  const root = over.root ?? event({ kind: 11, tags: [['title', 'Ship the API']] })
  return {
    id: root.id,
    root,
    title: 'Ship the API',
    status: 'open',
    check: { verdict: 'local' },
    unfolded: [],
    replies: 0,
    lastActivity: NOW,
    participants: [root.pubkey],
    ...over,
  }
}

/**
 * A workspace with nothing in it.
 *
 * `publish` rejects by default. A screen that publishes without the test
 * saying it should is the interesting failure — a control that fires on
 * render, say — and a silent no-op would hide it.
 */
export function workspace(over: Partial<Workspace> = {}): Workspace {
  return {
    status: 'live',
    events: [],
    raw: [],
    policy: PLAINTEXT_POLICY,
    sealed: () => false,
    unreadable: 0,
    pending: [],
    chains: [],
    threads: [],
    agents: [],
    grants: [],
    feed: [],
    publish: () => Promise.reject(new Error('this test did not expect a publish')),
    now: NOW,
    ...over,
  }
}

/**
 * Assert that a `queryBy*` found nothing — without handing the node to assert.
 *
 * `assert.equal(node, null)` is the obvious spelling and it is a trap. When it
 * *passes* nothing happens; when it fails, `node:assert` builds a diff by
 * running `util.inspect` over a jsdom element, which walks a graph containing
 * its document, its window and every other node in the tree. Discovered by a
 * mutation check: the mutation was caught, and the run then spent 277 seconds
 * before the worker was SIGKILLed, so the report said only that a worker had
 * died. A test whose failure is unreadable is barely better than one that does
 * not fail.
 */
export function absent(node: unknown, what: string): void {
  assert.equal(node === null, true, `expected no ${what} on the screen`)
}

/** A `publish` that records what it was asked to send. */
export function recorder(): {
  publish: Workspace['publish']
  sent: Parameters<Workspace['publish']>[0][]
} {
  const sent: Parameters<Workspace['publish']>[0][] = []
  return {
    sent,
    publish: (options) => {
      sent.push(options)
      return Promise.resolve(event({ kind: options.kind }))
    },
  }
}
