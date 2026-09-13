/**
 * The task list — every thread, with its state and with the relay checked.
 *
 * A thread in Quorum is a unit of work, not a conversation, so this is the
 * screen that answers "what is being worked on" without anyone reading prose.
 * Status, assignee and budget come from kind 38101, which the relay folds and
 * signs.
 *
 * The badge next to each task is the part worth explaining. `threads()` in the
 * SDK replays the ops the relay says it folded — in the order the relay says it
 * folded them, which is what `folded_from` is for — and compares the result
 * with the body the relay signed. So the badge is not decoration: `agrees`
 * means this browser recomputed the status from signed ops and got the same
 * answer, and `disagrees` means it did not, which has no innocent explanation.
 *
 * `local` is the ordinary state on a generic relay, which projects nothing and
 * is supposed to work anyway. It is shown rather than hidden because "nobody
 * has checked this" and "someone checked this and it was fine" are different
 * things to know about a task that says `done`.
 */

import type { ProjectionCheck, Thread } from '@quorum/sdk'
import { ago, short } from '../format.ts'

export function Tasks({
  threads,
  now,
  selected,
  onSelect,
}: {
  threads: Thread[]
  now: number
  selected?: string
  onSelect: (id: string) => void
}) {
  if (!threads.length) return <p className="dim empty">no threads yet</p>

  return (
    <ul className="tasks">
      {threads.map((thread) => (
        <li key={thread.id} className={thread.id === selected ? 'selected' : undefined}>
          <button className="task" onClick={() => onSelect(thread.id)}>
            <span className={`pill status-${thread.status}`}>{thread.status}</span>
            <span className="title">{thread.title}</span>
            <Check check={thread.check} />
            <span className="meta dim">
              {thread.assignee ? `→ ${short(thread.assignee)} · ` : ''}
              {thread.replies} {thread.replies === 1 ? 'reply' : 'replies'} ·{' '}
              {ago(thread.lastActivity, now)}
            </span>
          </button>
        </li>
      ))}
    </ul>
  )
}

/** One word for what happened when we recomputed the relay's projection. */
export function Check({ check }: { check: ProjectionCheck }) {
  switch (check.verdict) {
    case 'agrees':
      return (
        <span className="pill checked" title="this browser replayed the ops the relay folded and got the same state">
          checked
        </span>
      )
    case 'disagrees':
      return (
        <span
          className="pill disagrees"
          title={`the relay's projection does not match a replay of the ops it says it folded: ${check.fields.join(', ')}`}
        >
          disagrees: {check.fields.join(', ')}
        </span>
      )
    case 'unverifiable':
      return (
        <span
          className="pill unverified"
          title={`the relay folded ${check.missing} op(s) this client has not been served, so its projection cannot be replayed`}
        >
          unverified
        </span>
      )
    case 'local':
      return (
        <span className="pill local" title="no relay projection; this state was folded here from the ops">
          local
        </span>
      )
  }
}
