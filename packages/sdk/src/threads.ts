/**
 * The task list: every thread in a workspace, with its state, and with the
 * relay's projection of that state checked rather than believed.
 *
 * Pure, and in the SDK for the same reason `inbox()` is: the console and the
 * reference client both show "what is being worked on", and two implementations
 * of a status projection drift in ways nobody notices until a task is `done` on
 * one screen and `blocked` on another.
 *
 * ## Why this recomputes what the relay already computed
 *
 * Kind 38101 is signed by the relay, and the relay is the one party with both
 * the motive and the position to misstate it. `folded_from` is what makes that
 * checkable — it lists the op ids the relay folded, **in the order it folded
 * them** — so a client holding those ops can replay them and compare. That list
 * has been in the projection since M2 and nothing has ever read it. This does.
 *
 * The order matters and is the reason `folded_from` has to exist at all. The
 * relay folds ops as they arrive, which is not an order any client can
 * reconstruct: `(created_at, id)` is a different sequence, and folding
 * `set_status: done` before or after `set_status: blocked` gives different
 * answers. Without the list, "the relay is lying" and "the relay saw these in a
 * different order" would be indistinguishable, and a check that cannot tell
 * those apart is a check nobody can act on.
 *
 * So each thread reports one of four verdicts:
 *
 * - `local` — no projection at all. That is the generic-relay case, and it is
 *   supposed to work: we fold every op ourselves and lose nothing but the
 *   cross-check.
 * - `agrees` — replaying `folded_from` reproduces the body the relay signed.
 * - `unverifiable` — the relay folded ops we do not hold, so we cannot replay
 *   it. Its state is used, and labelled. Ordinary rather than sinister: a long
 *   thread's early ops fall outside a client's backfill window.
 * - `disagrees` — we hold every op it claims to have folded, replayed them in
 *   its own order, and got something else. There is no innocent version of
 *   this. Our fold is what gets displayed.
 *
 * A forged 38101 on a generic relay — where nothing stops a member signing one
 * — therefore produces a warning rather than a lie, provided the ops are there
 * to check it against.
 *
 * ## What this does not do
 *
 * It does not check whether the author of an op was *allowed* to publish it.
 * Authority is the relay's job at write time (`RequireGrantToSetBudget`) and the
 * resource's job at use time. A client folding ops it was served is computing
 * what the relay would compute, not deciding who may do what — and on a generic
 * relay, which enforces nothing, no amount of local folding would make the
 * answer safe.
 */

import {
  Kinds,
  TagName,
  ThreadOpBody,
  ThreadStateBody,
  tagValue,
  type Budget,
  type Cost,
  type EventRef,
  type NostrEvent,
  type ThreadStatus,
} from '@quorum/protocol'
import type { PublishOptions } from './publish.ts'

/** What replaying `folded_from` said about the relay's projection. */
export type ProjectionCheck =
  | { verdict: 'local' }
  | { verdict: 'agrees' }
  | { verdict: 'unverifiable'; missing: number }
  | { verdict: 'disagrees'; fields: string[] }

export interface Thread {
  /** The thread id, which is the id of its immutable kind 11 root. */
  id: string
  root: NostrEvent
  title: string
  status: ThreadStatus
  assignee?: string
  budget?: Budget
  spent?: Cost

  /** The relay's kind 38101, if one has been served. */
  projection?: NostrEvent
  check: ProjectionCheck
  /** Ops the projection does not claim to have folded. Applied on top of it. */
  unfolded: NostrEvent[]

  /** Kind 1111 comments in this thread. */
  replies: number
  /** Newest `created_at` anywhere in the thread, including the root. */
  lastActivity: number
  /** Distinct pubkeys that have published in it, the root author first. */
  participants: string[]
}

export interface ThreadsOptions {
  /** Keep only these statuses. */
  status?: readonly ThreadStatus[]
  /** Keep only threads assigned to this pubkey. */
  assignee?: string
}

/**
 * Every thread in `events`, newest activity first.
 *
 * Threads with no root are skipped rather than synthesised. A comment whose
 * root we have not fetched is a hole in the backfill, and inventing a thread
 * from it would put a task on the screen with no title, no author and no state
 * — which reads as a bug in the workspace rather than a gap in the query.
 */
export function threads(events: readonly NostrEvent[], options: ThreadsOptions = {}): Thread[] {
  const roots = events.filter((e) => e.kind === Kinds.Thread)
  const byThread = groupByRoot(events)

  const out: Thread[] = []
  for (const root of roots) {
    const inThread = byThread.get(root.id) ?? []
    const thread = derive(root, inThread)

    if (options.status && !options.status.includes(thread.status)) continue
    if (options.assignee && thread.assignee !== options.assignee) continue
    out.push(thread)
  }

  return out.sort((a, b) => b.lastActivity - a.lastActivity || (a.id < b.id ? -1 : 1))
}

/** One thread, by id, or `undefined` if its root is not in `events`. */
export function thread(events: readonly NostrEvent[], id: string): Thread | undefined {
  return threads(events).find((t) => t.id === id)
}

/**
 * Ask for a change to a thread's state.
 *
 * A request and not a write: the op is a kind 8109 the author signs, and what
 * it means is decided by whoever folds it. The reference relay folds it into
 * 38101 and signs that; a generic relay folds nothing and every reader folds it
 * for themselves via {@link threads}. Both give the same answer, which is the
 * property that lets this system run on a relay that has never heard of Quorum.
 *
 * The `E` tag is how the op finds its thread, so the root must be passed whole
 * rather than by id: NIP-22 wants `E`/`K`/`P` together, and a root scope with
 * the kind or author missing is not a comment on anything.
 *
 * Authority is not checked here and could not be. `set_budget` is gated by the
 * relay (`RequireGrantToSetBudget`) because a spending ceiling is authority
 * rather than coordination; the other three are coordination, and anyone in the
 * group may publish them. A client that pre-checked would only be guessing at a
 * decision the relay makes.
 */
export function threadOp(root: EventRef, op: ThreadOpBody): PublishOptions {
  return { kind: Kinds.ThreadOp, thread: root, body: op }
}

/** The mutable half of a thread: what ops fold into. */
export interface Folded {
  status: ThreadStatus
  title?: string
  assignee?: string
  budget?: Budget
  spent?: Cost
}

/**
 * Apply thread ops to a state, in the order given.
 *
 * The same rules as `apply()` in the relay's projector, including that an op
 * changing nothing is not an op: the relay does not record those in
 * `folded_from`, so a replay that applied them would drift from the list it is
 * checking. Unknown ops are ignored rather than rejected — adding one is a
 * MINOR version bump, and an older client must not be broken by a newer one.
 */
export function foldOps(ops: readonly NostrEvent[], from?: Folded): Folded {
  const state: Folded = { status: 'open', ...from }

  for (const event of ops) {
    const parsed = ThreadOpBody.safeParse(parse(event.content))
    if (!parsed.success) continue
    const op = parsed.data

    switch (op.op) {
      case 'set_status':
        state.status = op.status
        break
      case 'assign':
        state.assignee = op.assignee ?? undefined
        break
      case 'set_title':
        state.title = op.title
        break
      case 'set_budget':
        state.budget = op.budget
        break
    }
  }

  return state
}

function derive(root: NostrEvent, inThread: readonly NostrEvent[]): Thread {
  const ops = inThread
    .filter((e) => e.kind === Kinds.ThreadOp)
    .sort((a, b) => a.created_at - b.created_at || (a.id < b.id ? -1 : 1))
  const projection = latestProjection(inThread, root.id)

  const body = projection && ThreadStateBody.safeParse(parse(projection.content))
  const claimed = body?.success ? body.data : undefined

  const { check, base, folded } = reconcile(claimed, ops)
  // Whatever the relay has not folded yet goes on top. A thread op published a
  // moment ago must show up immediately; waiting for the projection to catch up
  // would make the client feel broken in the one place it is fastest.
  const unfolded = ops.filter((e) => !folded.has(e.id))
  const state = foldOps(unfolded, base)

  const activity = [root, ...inThread]
  return {
    id: root.id,
    root,
    title: state.title ?? tagValue(root.tags, TagName.Title) ?? firstLine(root.content),
    status: state.status,
    assignee: state.assignee,
    budget: state.budget,
    spent: state.spent,
    projection,
    check,
    unfolded,
    replies: inThread.filter((e) => e.kind === Kinds.Comment).length,
    lastActivity: Math.max(...activity.map((e) => e.created_at)),
    participants: [...new Set([root.pubkey, ...activity.map((e) => e.pubkey)])],
  }
}

/**
 * Replay what the relay says it folded, and decide whether to believe the rest.
 *
 * `base` is the state to apply unfolded ops on top of: our own replay when we
 * could do one, the relay's word when we could not.
 */
function reconcile(
  claimed: ThreadStateBody | undefined,
  ops: readonly NostrEvent[],
): { check: ProjectionCheck; base: Folded | undefined; folded: Set<string> } {
  if (!claimed) return { check: { verdict: 'local' }, base: undefined, folded: new Set() }

  const byId = new Map(ops.map((e) => [e.id, e]))
  const replayed = claimed.folded_from.map((id) => byId.get(id))
  const missing = replayed.filter((e) => e === undefined).length
  const folded = new Set(claimed.folded_from)

  if (missing > 0) {
    return { check: { verdict: 'unverifiable', missing }, base: asFolded(claimed), folded }
  }

  const ours = foldOps(replayed as NostrEvent[])
  const fields = differences(ours, claimed)
  return {
    check: fields.length === 0 ? { verdict: 'agrees' } : { verdict: 'disagrees', fields },
    base: ours,
    folded,
  }
}

/**
 * Which fields the relay and the replay disagree about.
 *
 * `updated_at` is excluded deliberately: it is the relay's own clock at fold
 * time, so no replay can reproduce it and comparing it would make every
 * projection look forged. `spent` is excluded because nothing folds into it —
 * it is written by the relay from usage the ops do not carry, so a replay has
 * nothing to say about it.
 */
function differences(ours: Folded, theirs: ThreadStateBody): string[] {
  const out: string[] = []
  if (ours.status !== theirs.status) out.push('status')
  if ((ours.title ?? '') !== (theirs.title ?? '')) out.push('title')
  if ((ours.assignee ?? '') !== (theirs.assignee ?? '')) out.push('assignee')
  if (JSON.stringify(ours.budget ?? null) !== JSON.stringify(theirs.budget ?? null)) {
    out.push('budget')
  }
  return out
}

function asFolded(state: ThreadStateBody): Folded {
  return {
    status: state.status,
    title: state.title,
    assignee: state.assignee ?? undefined,
    budget: state.budget,
    spent: state.spent,
  }
}

/**
 * The current 38101 for a thread.
 *
 * NIP-01's addressable rule — newest `created_at`, lowest id on a tie — and no
 * check of who signed it. On our relay nobody else can: `RejectRelaySignedForgeries`
 * refuses a 38101 from anyone but the relay. On a generic relay anyone can, and
 * that is exactly the case the `folded_from` replay is here to catch. Filtering
 * by a pubkey the client would have to be told out of band would trade a
 * detectable problem for an undetectable one.
 */
function latestProjection(inThread: readonly NostrEvent[], id: string): NostrEvent | undefined {
  return inThread
    .filter((e) => e.kind === Kinds.ThreadState && tagValue(e.tags, TagName.Identifier) === id)
    .sort((a, b) => b.created_at - a.created_at || (a.id < b.id ? -1 : 1))[0]
}

/**
 * Index every event by the thread it belongs to.
 *
 * Threads are identified by the NIP-22 root scope `E` for conversation, and by
 * `d` for the addressable state, which carries no `E` — it is not *in* the
 * thread, it is *about* it.
 */
function groupByRoot(events: readonly NostrEvent[]): Map<string, NostrEvent[]> {
  const out = new Map<string, NostrEvent[]>()
  for (const event of events) {
    const id =
      event.kind === Kinds.ThreadState
        ? tagValue(event.tags, TagName.Identifier)
        : tagValue(event.tags, TagName.RootEvent)
    if (!id) continue
    const list = out.get(id)
    if (list) list.push(event)
    else out.set(id, [event])
  }
  return out
}

function firstLine(content: string): string {
  const line = content.split('\n', 1)[0] ?? ''
  return line.length > 80 ? `${line.slice(0, 79)}…` : line
}

function parse(content: string): unknown {
  try {
    return JSON.parse(content)
  } catch {
    return undefined
  }
}
