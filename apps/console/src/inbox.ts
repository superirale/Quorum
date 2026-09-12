/**
 * Picking one item out of the queue, by typing part of its id.
 *
 * The queue itself lives in `@quorum/sdk` — every client asks "what is waiting
 * on me" and they must all answer it identically. This bit is genuinely
 * terminal-specific: a web client offers a button, and only a CLI needs to turn
 * `a91f` into exactly one request.
 */

import type { Pending } from '@quorum/sdk'

/**
 * Find one pending item by an id prefix.
 *
 * An ambiguous prefix is an error rather than a guess. Approving the wrong
 * action because two ids shared four characters is not a mistake a signature
 * can be taken back from.
 */
export function findByPrefix(items: readonly Pending[], prefix: string): Pending {
  const lower = prefix.toLowerCase()
  const matches = items.filter(
    (i) => i.request.id.startsWith(lower) || i.body.title.toLowerCase() === lower,
  )
  if (matches.length === 1) return matches[0]!
  if (matches.length === 0) {
    throw new Error(`nothing pending matches "${prefix}" — run \`quorum inbox\``)
  }
  throw new Error(
    `"${prefix}" matches ${matches.length} requests: ` +
      `${matches.map((m) => m.request.id.slice(0, 12)).join(', ')}. Use more characters.`,
  )
}
