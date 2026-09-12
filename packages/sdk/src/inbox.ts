/**
 * What is waiting for me to decide.
 *
 * Pure, and in the SDK rather than in a client because every client asks the
 * same question and must get the same answer. The console and the reference
 * client both show an approval queue; two implementations of "is this waiting
 * on me" would eventually disagree, and the direction they disagree in decides
 * whether a human sees a production deploy or not.
 *
 * Each rule below is a judgement about whose attention is genuinely required,
 * and getting any of them wrong produces the same bad outcome from opposite
 * directions: an approval queue that cries wolf is one a human learns to clear
 * without reading, which is exactly the failure this project exists to prevent.
 */

import { ApprovalRequestBody, Kinds, TagName, tagValues, type NostrEvent } from '@quorum/protocol'
import { isForMe } from './addressing.ts'

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

function parse(content: string): unknown {
  try {
    return JSON.parse(content)
  } catch {
    return undefined
  }
}
