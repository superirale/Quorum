/**
 * Finding the payload an approval request is asking about.
 *
 * An approval request carries only a digest, on purpose — the request is a
 * commitment to exact bytes, not a copy of them. So a client that wants to show
 * a human *what* they are approving has to go and get the proposal.
 *
 * That lookup is exact rather than a search: the action id IS the id of the
 * `proposed` event, because an event id is the hash of its own contents. There
 * is no allocator and no ambiguity about which of several candidate proposals
 * is the real one. If the proposal is missing, this returns `undefined` and the
 * UI must say so rather than showing an empty payload — an approver looking at
 * `{}` would reasonably conclude the action does nothing.
 */

import { ActionBody, Kinds, TagName, tagValue, type NostrEvent } from '@quorum/protocol'

export function proposedInput(
  events: readonly NostrEvent[],
  request: NostrEvent,
): { found: true; input: unknown } | { found: false } {
  const actionId = tagValue(request.tags, TagName.Action)
  if (!actionId) return { found: false }

  const proposal = events.find((e) => e.id === actionId && e.kind === Kinds.Action)
  if (!proposal) return { found: false }

  try {
    return { found: true, input: ActionBody.parse(JSON.parse(proposal.content)).input }
  } catch {
    return { found: false }
  }
}
