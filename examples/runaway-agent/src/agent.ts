/**
 * An agent that does not know when to stop.
 *
 * It reads pages out of an archive, one `act()` per page, and it will keep
 * going until it runs out of pages. Nothing in the handler checks a budget,
 * counts its turns, or looks at the thread's status — which is the point. Every
 * real runaway is a loop somebody wrote that looked terminating, and a safety
 * mechanism that only works when the agent cooperates is a safety mechanism for
 * the agents that were never the problem.
 *
 * So the two controls in this example are both outside the loop:
 *
 * **The budget.** `ctx.act()` reads the thread's spend against its ceiling
 * before it publishes anything, and returns `cancelled` instead of proposing.
 * The relay does the same check on its own side, refusing a kind 8101 in a
 * paused thread. The agent's only obligation is to report what it spent — and
 * even that it cannot dodge usefully, because a thread whose spend never moves
 * is a thread its operator can see is lying.
 *
 * **The interrupt.** `run.signal` aborts when somebody publishes a kind 28101
 * for this action or its thread. The effect below passes it to the work, which
 * is the whole contract: an effect that ignores the signal turns Stop into a
 * button that says "stop" and does nothing.
 *
 * ## Why the cost is reported before the work, not after
 *
 * `run.cost` is set on the way in. A page that is interrupted halfway still
 * burned the tokens the model was paid for, and an agent that reported nothing
 * for cancelled work would make Stop a way to get work for free — which is
 * exactly the wrong incentive to build into the accounting of a system whose
 * budget is the backstop.
 */

import type { Cost } from '@quorum/protocol'
import {
  createAgent,
  type ActResult,
  type Agent,
  type Logger,
  type RelayClient,
  type Signer,
  type Store,
} from '@quorum/sdk'

export interface RunawayOptions {
  relay: string | RelayClient
  signer: Signer
  group: string
  /** How many pages it will read before it decides the job is done. */
  pages?: number
  /** What one page costs. Stated by the effect; folded onto the thread. */
  perPage?: Cost
  /** What deciding what to read next costs. Reported through `ctx.spend`. */
  perThought?: Cost
  /** The work. Must honour the signal — see the note above. */
  read?: (page: number, signal: AbortSignal) => Promise<string>
  store?: Store
  log?: Logger
}

/**
 * Twelve thousand tokens a page, fifteen hundred to think between them.
 *
 * A budget states `tokens`; a spend states `tokens_in` and `tokens_out`. Both
 * halves count against the one ceiling, which is why the split is here rather
 * than in a single number — a thread capped at 30,000 that has spent 29,000 in
 * and 28,000 out is nearly twice over and looks fine from either column.
 */
const PER_PAGE: Cost = { tokens_in: 9000, tokens_out: 3000 }
const PER_THOUGHT: Cost = { tokens_in: 1000, tokens_out: 500 }

export function createRunawayAgent(options: RunawayOptions): Agent {
  const pages = options.pages ?? 6
  const perPage = options.perPage ?? PER_PAGE
  const perThought = options.perThought ?? PER_THOUGHT
  const read = options.read ?? instantly

  const agent = createAgent({
    relay: options.relay,
    signer: options.signer,
    group: options.group,
    leases: false,
    ...(options.store ? { store: options.store } : {}),
    ...(options.log ? { log: options.log } : {}),
  })

  agent.on(async (_event, ctx) => {
    for (let page = 1; page <= pages; page += 1) {
      const result = await ctx.act({
        name: 'crawl.page',
        title: `Read page ${page}`,
        summary: `read page ${page} of the archive`,
        input: { page },
        describe: (found: string) => `page ${page}: ${found}`,
        run: async (approved, run) => {
          run.cost = perPage
          return read(approved.page, run.signal)
        },
      })

      // Any non-success ends the loop, and the human hears why. Three different
      // people are on the other end of these three sentences: an operator who
      // has to raise a ceiling, whoever pressed Stop, and whoever owns the
      // archive. A handler that logged the difference and said "something went
      // wrong" sends all three to the wrong screen.
      if (result.status !== 'succeeded') {
        await ctx.say(explain(page, result), { label: `stopped:${result.status}:${page}` })
        return
      }

      await ctx.say(`page ${page}: ${result.output}`, { label: `read:${page}` })
      // The cost `act()` does not cover: deciding what to read next. In a real
      // agent this is the model call, and it is usually where the money goes.
      await ctx.spend(perThought, {
        note: `deciding what to read after page ${page}`,
        label: `think:${page}`,
      })
    }

    await ctx.say(`done — all ${pages} pages read.`, { label: 'finished' })
  })

  return agent
}

/** The stand-in archive. Deterministic, so the demo's output is too. */
async function instantly(page: number): Promise<string> {
  return `entry ${page * 37} of the September ledger`
}

function explain(page: number, result: Exclude<ActResult<string>, { status: 'succeeded' }>): string {
  switch (result.status) {
    case 'cancelled':
      return `stopping at page ${page} — ${result.reason}`
    case 'denied':
      return `not reading page ${page} — ${result.reason}`
    default:
      return `page ${page} failed — ${result.error.message}`
  }
}
