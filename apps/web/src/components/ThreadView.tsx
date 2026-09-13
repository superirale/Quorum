/**
 * One task, with everything that happened to it in the order it happened.
 *
 * The timeline is the whole thread oldest-first, rendered through `alt` like
 * the channel feed. Reading it top to bottom should answer "why is this thing
 * in this state" — which is the question a task list can only ever raise.
 *
 * Actions are drawn from `verifyActionChains`, so the approvals shown here have
 * been checked in this browser against their signatures rather than taken from
 * the relay's word. A chain's own events are already in causal order, by `e`-tag
 * parent links and never by `created_at`: the whole propose → ask → approve →
 * run loop completes inside one second, and sorting a chain by a one-second
 * clock shuffles it.
 *
 * The controls publish kind 8109 ops. They are requests, not writes — the relay
 * folds them into the 38101 it signs, a generic relay folds nothing and every
 * reader folds them locally, and both arrive at the same answer. `set_budget` is
 * deliberately not here: a spending ceiling is authority rather than
 * coordination, the relay gates it on a `thread:budget` grant, and offering a
 * control that most members' requests will be refused for is worse than not
 * offering it.
 */

import { useState } from 'react'
import {
  Kinds,
  TagName,
  tagValue,
  type Budget,
  type Cost,
  type NostrEvent,
  type ThreadStatus,
} from '@quorum/protocol'
import { threadOp, type ActionChain, type Thread } from '@quorum/sdk'
import { describe, hue, short, when } from '../format.ts'
import type { Workspace } from '../useWorkspace.ts'
import { Check } from './Tasks.tsx'
import { Chains } from './Chains.tsx'

const STATUSES: ThreadStatus[] = ['open', 'working', 'blocked', 'paused', 'done']

export function ThreadView({
  workspace,
  thread,
  me,
  onBack,
}: {
  workspace: Workspace
  thread: Thread
  me: string
  onBack: () => void
}) {
  const inThread = timeline(workspace.events, thread.id)
  const chains = workspace.chains.filter((chain) => belongsTo(chain, thread.id))

  return (
    <div className="thread">
      <button className="link" onClick={onBack}>
        ← all tasks
      </button>

      <h3>{thread.title}</h3>
      <div className="row wrap">
        <span className={`pill status-${thread.status}`}>{thread.status}</span>
        <Check check={thread.check} />
        {thread.assignee && <span className="dim">assigned to {short(thread.assignee)}</span>}
        {thread.budget && (
          <span className="dim">
            budget {budget(thread.budget)}
            {thread.spent ? ` · spent ${budget(thread.spent)}` : ''}
          </span>
        )}
      </div>

      {thread.check.verdict === 'disagrees' && (
        <div className="banner error">
          The relay's projection of this task disagrees with a replay of the ops it says it folded
          ({thread.check.fields.join(', ')}). The state above is this browser's own fold of the
          signed ops, not the relay's.
        </div>
      )}
      {thread.unfolded.length > 0 && (
        <p className="dim">
          {thread.unfolded.length} op(s) published since the relay last projected this task,
          applied here on top of it.
        </p>
      )}

      <Controls workspace={workspace} thread={thread} />

      <h2>Actions</h2>
      <Chains chains={chains} />

      <h2>Timeline</h2>
      <ol className="timeline">
        {inThread.map((event) => (
          <li key={event.id} className={event.pubkey === me ? 'mine' : undefined}>
            <span className="at dim">{when(event.created_at)}</span>
            <span className="who" style={{ color: `hsl(${hue(event.pubkey)} 60% 70%)` }}>
              {short(event.pubkey)}
            </span>
            <span className="kind dim">{event.kind}</span>
            <span className="text">{describe(event)}</span>
          </li>
        ))}
      </ol>
    </div>
  )
}

/**
 * Change the task's state, by asking.
 *
 * The select does not move until the op comes back through the subscription,
 * so what is on screen is always a state some signed event supports. An
 * optimistic control here would show `done` for a request the relay refused.
 */
function Controls({ workspace, thread }: { workspace: Workspace; thread: Thread }) {
  const [busy, setBusy] = useState(false)
  const [problem, setProblem] = useState<string | undefined>()

  const ref = { id: thread.root.id, kind: thread.root.kind, pubkey: thread.root.pubkey }
  const assignees = [...new Set(workspace.events.map((e) => e.pubkey))].sort()

  const send = async (body: Parameters<typeof threadOp>[1]) => {
    setBusy(true)
    setProblem(undefined)
    try {
      await workspace.publish(threadOp(ref, body))
    } catch (error) {
      setProblem((error as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="controls">
      <label>
        status
        <select
          value={thread.status}
          disabled={busy}
          onChange={(e) => void send({ op: 'set_status', status: e.target.value as ThreadStatus })}
        >
          {STATUSES.map((status) => (
            <option key={status} value={status}>
              {status}
            </option>
          ))}
        </select>
      </label>

      <label>
        assignee
        <select
          value={thread.assignee ?? ''}
          disabled={busy}
          onChange={(e) => void send({ op: 'assign', assignee: e.target.value || null })}
        >
          <option value="">nobody</option>
          {assignees.map((pubkey) => (
            <option key={pubkey} value={pubkey}>
              {short(pubkey)}
            </option>
          ))}
        </select>
      </label>

      {problem && <span className="bad">{problem}</span>}
    </div>
  )
}

/**
 * Everything in this thread, oldest first.
 *
 * `(created_at, id)` — NIP-01's order, which is the right one here and the
 * wrong one inside a chain. A timeline is a record of what a relay served and
 * when its authors claim it happened; a chain is a causal argument about which
 * event answered which, and it carries its own links for that.
 */
function timeline(events: readonly NostrEvent[], id: string): NostrEvent[] {
  return events
    .filter((e) => e.id === id || inThisThread(e, id))
    .sort((a, b) => a.created_at - b.created_at || (a.id < b.id ? -1 : 1))
}

function belongsTo(chain: ActionChain, id: string): boolean {
  return chain.events.some((e) => inThisThread(e, id))
}

function inThisThread(event: NostrEvent, id: string): boolean {
  return event.kind === Kinds.ThreadState
    ? tagValue(event.tags, TagName.Identifier) === id
    : tagValue(event.tags, TagName.RootEvent) === id
}

/**
 * A budget or a spend in one line.
 *
 * Both shapes at once because they are nearly the same object and differ in the
 * one place that matters: a budget has `tokens`, a spend has `tokens_in` and
 * `tokens_out`. A function taking the union of the *keys* would quietly drop
 * the two it had not been told about, and a spend line reading `$0.02` beside a
 * budget of `40000 tokens` is how an overspend hides.
 */
function budget(cost: Budget | Cost): string {
  const tokens =
    'tokens' in cost && cost.tokens !== undefined
      ? `${cost.tokens} tokens`
      : 'tokens_in' in cost && (cost.tokens_in !== undefined || cost.tokens_out !== undefined)
        ? `${(cost.tokens_in ?? 0) + (cost.tokens_out ?? 0)} tokens`
        : undefined

  const parts = [
    cost.usd !== undefined ? `$${cost.usd}` : undefined,
    cost.msat !== undefined ? `${cost.msat} msat` : undefined,
    tokens,
  ].filter(Boolean)
  return parts.length ? parts.join(' · ') : '—'
}
