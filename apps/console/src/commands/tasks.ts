/**
 * What is being worked on, what it is costing, and how to stop it.
 *
 * Three commands that are really one screen: `tasks` is the list, `budget` is
 * the ceiling on one of them, and `stop` is the button. They live together
 * because in practice they are used in that order, at speed, by someone who has
 * just noticed a number going up.
 *
 * `stop` is the only command in this console that is time-critical. Kind 28101
 * is ephemeral — no relay stores it — so it reaches whatever is running right
 * now and nothing else. If the agent is down, the interrupt is missed, and that
 * is correct: the action it was stopping is not running either, and the agent
 * replays its handler from the top on restart, where a fresh interrupt can
 * catch it.
 */

import { checkBudget, describeBudget } from '@quorum/protocol'
import { interrupt, threadOp, threads, type Thread } from '@quorum/sdk'
import { flag, type ParsedArgs } from '../args.ts'
import { bold, cyan, dim, green, red, short, yellow } from '../format.ts'
import { groupEvents, open, resolvePubkey, type Session } from '../session.ts'

export async function tasks(args: ParsedArgs): Promise<void> {
  const session = await open(flag(args, 'as'))
  try {
    const found = threads(await groupEvents(session))
    if (!found.length) {
      console.log(dim('no threads in this group yet'))
      return
    }
    for (const task of found) console.log(line(task))
  } finally {
    session.close()
  }
}

/**
 * Set, raise or clear a thread's ceiling.
 *
 * `--tokens 0` is a freeze rather than a special verb: `checkBudget` treats "at
 * the ceiling" as exhausted, so a budget of zero stops the thread immediately
 * using a capability that already exists. Clearing it needs `--none`, which is
 * deliberately not spelt `--tokens ''` — removing a ceiling is a different
 * decision from lowering one and should not be one keystroke away from it.
 */
export async function budget(args: ParsedArgs): Promise<void> {
  const id = args.words[1]
  if (!id) throw new Error('usage: quorum budget <thread-id> [--tokens n] [--usd n] [--none]')

  const session = await open(flag(args, 'as'))
  try {
    const task = await find(session, id)
    const spec = {
      ...(flag(args, 'tokens') !== undefined ? { tokens: number(args, 'tokens') } : {}),
      ...(flag(args, 'usd') !== undefined ? { usd: number(args, 'usd') } : {}),
      ...(flag(args, 'msat') !== undefined ? { msat: number(args, 'msat') } : {}),
    }

    if (!Object.keys(spec).length && flag(args, 'none') === undefined) {
      console.log(`${bold(task.title)} ${dim(short(task.id))}`)
      console.log(`  ${describeBudget(task.spent, task.budget)}`)
      return
    }

    await session.publisher.publish(
      threadOp(task.root, { op: 'set_budget', budget: flag(args, 'none') !== undefined ? {} : spec }),
    )
    // Said rather than shown: the relay folds this into 38101 and may pause the
    // thread as it does, so re-reading it here would race its own write. The
    // next `quorum tasks` is the honest place to look.
    console.log(`${green('✓')} asked for a budget of ${describeBudget(task.spent, spec)}`)
    if (checkBudget(task.spent, spec).exhausted) {
      console.log(yellow('  already spent — the thread will pause when this is folded'))
    }
  } finally {
    session.close()
  }
}

export async function stop(args: ParsedArgs): Promise<void> {
  const id = args.words[1]
  if (!id) throw new Error('usage: quorum stop <thread-id> [--action <id>] [--reason r]')

  const session = await open(flag(args, 'as'))
  try {
    const task = await find(session, id)
    const action = flag(args, 'action')
    const mode = flag(args, 'pause') !== undefined ? 'pause' : 'cancel'
    const steer = flag(args, 'steer')
    const to = flag(args, 'to')

    await session.publisher.publish(
      interrupt({
        thread: task.root,
        ...(action ? { action } : {}),
        mode: steer ? 'steer' : mode,
        ...(steer ? { instruction: steer } : {}),
        ...(flag(args, 'reason') ? { reason: flag(args, 'reason') } : {}),
        ...(to ? { to: [await resolvePubkey(to)] } : {}),
      }),
    )

    const what = action ? `action ${short(action)}` : 'everything in the thread'
    console.log(`${green('✓')} asked to ${steer ? 'steer' : mode} ${what}`)
    // The honest caveat, printed every time. An ephemeral event has no receipt:
    // there is no OK from the relay that means an agent heard it, and a human
    // who thinks there is will walk away from a deploy that is still running.
    console.log(
      dim('  nothing stores an interrupt. If no agent was running, nothing was stopped.'),
    )
    if (steer) {
      console.log(
        dim('  a steer is delivered as untrusted text; the agent decides whether to act on it.'),
      )
    }
  } finally {
    session.close()
  }
}

function line(task: Thread): string {
  const status = colour(task.status)
  const cost = task.budget || task.spent ? ` ${dim(describeBudget(task.spent, task.budget))}` : ''
  const warning =
    task.check.verdict === 'disagrees'
      ? ` ${red(`⚠ the relay's projection disagrees about ${task.check.fields.join(', ')}`)}`
      : ''
  return `${dim(short(task.id))} ${status.padEnd(18)} ${task.title}${cost}${warning}`
}

function colour(status: string): string {
  if (status === 'paused') return yellow(status)
  if (status === 'blocked') return red(status)
  if (status === 'done') return dim(status)
  if (status === 'working') return cyan(status)
  return status
}

async function find(session: Session, id: string): Promise<Thread> {
  return findTask(threads(await groupEvents(session)), id)
}

/**
 * A thread by full id or by the prefix `quorum tasks` prints.
 *
 * Ambiguity is an error rather than a first match, and that is the whole reason
 * this is a named function with tests: `quorum stop 4b` picking one of two
 * candidates would stop the wrong deploy, silently, in the one command where
 * the operator is not reading carefully.
 */
export function findTask(found: readonly Thread[], id: string): Thread {
  const prefix = id.replace(/…$/, '').toLowerCase()
  if (!prefix) throw new Error('give a thread id, or enough of one to be unambiguous')
  const matches = found.filter((t) => t.id.startsWith(prefix))
  if (!matches.length) throw new Error(`no thread in this group starts with "${id}"`)
  if (matches.length > 1) {
    throw new Error(
      `"${id}" matches ${matches.length} threads. Use more of the id: ` +
        matches.map((t) => short(t.id)).join(', '),
    )
  }
  return matches[0]!
}

function number(args: ParsedArgs, name: string): number {
  const raw = flag(args, name)
  const value = Number(raw)
  if (!Number.isFinite(value) || value < 0) {
    throw new Error(`--${name} needs a number that is not negative, got "${raw}"`)
  }
  return value
}
