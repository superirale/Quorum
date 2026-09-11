/**
 * NIP-01 filters.
 *
 * This lives beside `build.ts` for the same reason `build.ts` lives here: the
 * matching rules are part of the wire protocol, so there should be exactly one
 * definition of them. A client that decides locally whether an event matches a
 * subscription and a relay that decides the same thing server-side must agree,
 * or an agent silently drops work it was sent.
 *
 * Our production relay is khatru, which has its own implementation in Go — that
 * is the point of publishing the rules rather than hiding them in a client. The
 * consumers here are the SDK's local matching and `@quorum/test-kit`'s
 * in-process relay, and those two agreeing is what makes a test meaningful.
 */

import type { NostrEvent } from './event.ts'

/**
 * A NIP-01 filter.
 *
 * `#<single-letter>` entries are tag filters and match the tag's *first value*
 * only. That restriction is not ours: relays index one value per tag, which is
 * exactly why Quorum's `to` marker sits in position 4 and cannot be filtered on
 * server-side. See `ADDRESS_MARKER`.
 */
export interface Filter {
  ids?: string[]
  authors?: string[]
  kinds?: number[]
  since?: number
  until?: number
  limit?: number
  search?: string
  [tag: `#${string}`]: unknown
}

/** The `#x` keys of a filter, with their values, ignoring the scalar fields. */
export function tagFilters(filter: Filter): [letter: string, values: string[]][] {
  const out: [string, string[]][] = []
  for (const [key, value] of Object.entries(filter)) {
    if (!key.startsWith('#') || key.length !== 2) continue
    if (Array.isArray(value)) out.push([key.slice(1), value as string[]])
  }
  return out
}

/** True if the event satisfies every clause of the filter. */
export function matchFilter(filter: Filter, event: NostrEvent): boolean {
  if (filter.ids && !filter.ids.includes(event.id)) return false
  if (filter.authors && !filter.authors.includes(event.pubkey)) return false
  if (filter.kinds && !filter.kinds.includes(event.kind)) return false
  if (filter.since !== undefined && event.created_at < filter.since) return false
  if (filter.until !== undefined && event.created_at > filter.until) return false

  for (const [letter, values] of tagFilters(filter)) {
    const present = event.tags.some((t) => t[0] === letter && t[1] !== undefined && values.includes(t[1]))
    if (!present) return false
  }
  return true
}

/** True if any filter matches. A subscription is the union of its filters. */
export function matchFilters(filters: readonly Filter[], event: NostrEvent): boolean {
  return filters.some((f) => matchFilter(f, event))
}
