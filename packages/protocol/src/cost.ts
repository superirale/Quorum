/**
 * Adding up what a task cost, and deciding when it has cost enough.
 *
 * Four lines of arithmetic that are in the protocol package rather than the SDK
 * for one reason: the relay does this too. A thread's `spent` is folded by the
 * relay on plaintext channels and by the client everywhere else, and the two
 * have to reach the same number or the projection check in `threads()` reports
 * a relay that is telling the truth. Same argument as `extractive-v1`, at a
 * tenth of the size.
 *
 * The interesting decisions here are not in the addition.
 */

import type { Cost } from './bodies/common.ts'
import type { Budget } from './bodies/thread.ts'

/**
 * Sum two costs, dimension by dimension, keeping only what is present.
 *
 * An absent dimension stays absent rather than becoming zero. `{}` and
 * `{usd: 0}` are different claims — "nobody said" and "it was free" — and a
 * thread whose spend is reported in tokens should not grow a `usd: 0` that
 * reads as a priced total.
 */
export function addCost(a: Cost | undefined, b: Cost | undefined): Cost {
  const sum: Cost = {}
  for (const key of ['tokens_in', 'tokens_out', 'usd', 'msat'] as const) {
    const left = a?.[key]
    const right = b?.[key]
    if (left === undefined && right === undefined) continue
    sum[key] = (left ?? 0) + (right ?? 0)
  }
  return sum
}

/**
 * Tokens spent, in the one unit a budget states them in.
 *
 * A budget has `tokens`; a spend has `tokens_in` and `tokens_out`. Comparing
 * either half against the ceiling on its own is how an overspend hides — a
 * thread capped at 40,000 tokens that has spent 39,000 in and 38,000 out is
 * nearly twice over and looks fine from either column.
 */
export function tokensSpent(cost: Cost | undefined): number {
  return (cost?.tokens_in ?? 0) + (cost?.tokens_out ?? 0)
}

export type BudgetDimension = 'tokens' | 'usd' | 'msat'

export interface BudgetCheck {
  /** True when any stated ceiling has been reached. */
  exhausted: boolean
  /** Which ceilings, so a human is told the one that actually bit. */
  over: BudgetDimension[]
  /** What is left under each stated ceiling; negative when overspent. */
  remaining: Partial<Record<BudgetDimension, number>>
}

/**
 * Has this thread spent its budget?
 *
 * Three rules worth stating, because each one is a decision:
 *
 * **A budget with no dimensions set is not a budget.** An empty object means
 * nobody has capped this thread, and it must not read as a cap of zero — that
 * would pause every thread in the workspace the moment budgets shipped.
 *
 * **Any dimension is enough.** A thread capped at both $5 and 100,000 tokens is
 * done when it hits either, because whoever set two ceilings meant both.
 *
 * **At the ceiling is exhausted, not under it.** `>=`, so a budget of zero
 * stops work immediately — which makes `set_budget {usd: 0}` a usable freeze
 * for a thread somebody wants stopped now, using a capability that already
 * exists rather than a new verb.
 */
export function checkBudget(spent: Cost | undefined, budget: Budget | undefined): BudgetCheck {
  const over: BudgetDimension[] = []
  const remaining: Partial<Record<BudgetDimension, number>> = {}
  if (!budget) return { exhausted: false, over, remaining }

  const dimensions: [BudgetDimension, number | undefined, number][] = [
    ['tokens', budget.tokens, tokensSpent(spent)],
    ['usd', budget.usd, spent?.usd ?? 0],
    ['msat', budget.msat, spent?.msat ?? 0],
  ]

  for (const [name, ceiling, used] of dimensions) {
    if (ceiling === undefined) continue
    remaining[name] = ceiling - used
    if (used >= ceiling) over.push(name)
  }

  return { exhausted: over.length > 0, over, remaining }
}

/** One line for a human: what was spent against what was allowed. */
export function describeBudget(spent: Cost | undefined, budget: Budget | undefined): string {
  const parts: string[] = []
  if (budget?.tokens !== undefined) parts.push(`${tokensSpent(spent)}/${budget.tokens} tokens`)
  if (budget?.usd !== undefined) parts.push(`$${(spent?.usd ?? 0).toFixed(4)}/$${budget.usd}`)
  if (budget?.msat !== undefined) parts.push(`${spent?.msat ?? 0}/${budget.msat} msat`)
  if (parts.length) return parts.join(', ')

  const spentParts: string[] = []
  if (tokensSpent(spent)) spentParts.push(`${tokensSpent(spent)} tokens`)
  if (spent?.usd) spentParts.push(`$${spent.usd.toFixed(4)}`)
  if (spent?.msat) spentParts.push(`${spent.msat} msat`)
  return spentParts.length ? `${spentParts.join(', ')}, no ceiling` : 'nothing spent, no ceiling'
}
