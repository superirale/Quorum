/**
 * What is waiting for me to decide.
 *
 * Pure, so the rules below can be tested without a relay. Each of them is a
 * judgement about whose attention is genuinely required, and getting any of
 * them wrong produces the same bad outcome from opposite directions: an
 * approval queue that cries wolf is one a human learns to clear without
 * reading, which is exactly the failure the whole project is trying to prevent.
 */

import { ApprovalRequestBody, Kinds, TagName, tagValues, type NostrEvent } from '@quorum/protocol'
import { isForMe } from '@quorum/sdk'

export interface Pending {
  request: NostrEvent
  body: ApprovalRequestBody
  /** Approvers this request actually names, in order. */
  approvers: string[]
  /** True when this identity has already answered it. */
  answered: boolean
  expired: boolean
}

export interface InboxOptions {
  me: string
  now: number
  /** Include requests already answered or expired. */
  all?: boolean
}

export function inbox(events: readonly NostrEvent[], options: InboxOptions): Pending[] {
  const responses = events.filter((e) => e.kind === Kinds.ApprovalResponse)

  const out: Pending[] = []
  for (const request of events) {
    if (request.kind !== Kinds.ApprovalRequest) continue

    // Addressed to me, by the `to` marker and nothing else. A request that
    // merely mentions this key is not a request to this key, and prose naming
    // me is not addressing at all.
    if (!isForMe(request, options.me)) continue

    const body = ApprovalRequestBody.safeParse(parse(request.content))
    if (!body.success) continue

    const answered = responses.some(
      (r) => r.pubkey === options.me && tagValues(r.tags, TagName.Event).includes(request.id),
    )
    const expired = body.data.expires_at !== undefined && body.data.expires_at < options.now

    if (!options.all && (answered || expired)) continue

    out.push({
      request,
      body: body.data,
      approvers: addressees(request),
      answered,
      expired,
    })
  }

  // Oldest first: the thing that has been waiting longest is the thing someone
  // is most likely blocked on.
  return out.sort((a, b) => a.request.created_at - b.request.created_at)
}

/** The `to`-marked `p` tags — the approvers this request names. */
export function addressees(request: NostrEvent): string[] {
  return request.tags
    .filter((t) => t[0] === TagName.Pubkey && t[3] === 'to' && t[1])
    .map((t) => t[1]!)
}

/**
 * Find one pending item by an id prefix.
 *
 * Prefixes are how anyone actually uses this — `quorum approve a91f` — and an
 * ambiguous prefix must be an error rather than a guess. Approving the wrong
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

function parse(content: string): unknown {
  try {
    return JSON.parse(content)
  } catch {
    return undefined
  }
}
