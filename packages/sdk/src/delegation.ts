/**
 * Delegation — acting on a human's behalf, and never gaining anything by it.
 *
 * A delegation (38106) is a human saying "this agent may act as me". The rule
 * that makes it safe is one word: the effective permission of a delegated
 * action is the **intersection** of the agent's own grant and the delegation,
 * never the union.
 *
 * Without that rule the only workable pattern is "give the agent admin so it
 * can help", which is how a product becomes unsellable to anyone with a
 * security team. With it, handing an agent your authority can only ever narrow
 * what it is already allowed to do — so the worst case of a delegation being
 * stolen, forged or simply mis-scoped is that some work does not happen.
 *
 * {@link intersect} is the whole idea in one function, and the property worth
 * asserting about it is not that it computes the right answer for a given pair
 * but that **its output is never wider than either input**. The test suite
 * checks that direction explicitly, because "narrower" is the invariant and a
 * specific expected value is only an example of it.
 */

import { DelegationBody, Kinds, digest, type GrantSpec, type NostrEvent } from '@quorum/protocol'
import type { PublishOptions } from './publish.ts'

/**
 * Narrow a grant by a delegation. Returns undefined when nothing survives.
 *
 * Each dimension narrows independently:
 *
 *   resource   must be in the delegation's whitelist, if it has one
 *   actions    untouched — a delegation does not speak about verbs
 *   scope      union of constraints; a contradiction empties the set
 *   expiry     the earlier of the two
 *   max_uses   from the grant; a delegation does not extend a use budget
 *
 * The scope rule is the one that repays a second read. Both sides are sets of
 * *constraints* on the request, so combining them means taking both — which
 * makes the result narrower, not wider. Two constraints on the same key with
 * different values can never both hold, so the intersection is empty and this
 * returns undefined rather than silently preferring one of them.
 */
export function intersect(grant: GrantSpec, delegation: DelegationBody): GrantSpec | undefined {
  if (delegation.revoked) return undefined
  if (delegation.resources && !delegation.resources.includes(grant.resource)) return undefined

  const scope: Record<string, unknown> = { ...(grant.scope ?? {}) }
  for (const [key, value] of Object.entries(delegation.scope ?? {})) {
    if (key in scope && !deepEqual(scope[key], value)) return undefined
    scope[key] = value
  }

  const expiresAt = earliest(grant.expires_at, delegation.expires_at)

  return {
    resource: grant.resource,
    actions: [...grant.actions],
    ...(Object.keys(scope).length ? { scope } : {}),
    ...(expiresAt !== undefined ? { expires_at: expiresAt } : {}),
    ...(grant.max_uses !== undefined ? { max_uses: grant.max_uses } : {}),
  }
}

/** Is this a live delegation from this human to this agent? */
export function verifyDelegation(
  event: NostrEvent,
  options: { delegate: string; now?: number },
): { ok: boolean; reason?: string; body?: DelegationBody } {
  if (event.kind !== Kinds.Delegation) {
    return { ok: false, reason: `kind ${event.kind} is not a delegation` }
  }
  let body: DelegationBody
  try {
    const parsed = DelegationBody.safeParse(JSON.parse(event.content))
    if (!parsed.success) return { ok: false, reason: 'the delegation body is not valid' }
    body = parsed.data
  } catch {
    return { ok: false, reason: 'the delegation body is not JSON' }
  }

  if (body.revoked) return { ok: false, reason: 'revoked', body }
  if (body.delegate !== options.delegate) {
    return { ok: false, reason: 'delegates to a different pubkey', body }
  }
  const now = options.now ?? Math.floor(Date.now() / 1000)
  if (body.expires_at !== undefined && body.expires_at < now) {
    return { ok: false, reason: 'expired', body }
  }
  return { ok: true, body }
}

export interface DelegationOptions {
  /** The agent principal permitted to act on my behalf. */
  delegate: string
  /** A stable id for this delegation. `d` on the addressable event. */
  id: string
  resources?: string[]
  scope?: Record<string, unknown>
  expiresAt?: number
  revoked?: boolean
  thread?: PublishOptions['thread']
}

/** Build the 38106 a human publishes to delegate. Republish with `revoked` to withdraw. */
export function delegation(options: DelegationOptions): PublishOptions {
  return {
    kind: Kinds.Delegation,
    d: options.id,
    ...(options.thread ? { thread: options.thread } : {}),
    to: [options.delegate],
    body: {
      delegate: options.delegate,
      ...(options.resources ? { resources: options.resources } : {}),
      ...(options.scope ? { scope: options.scope } : {}),
      ...(options.expiresAt !== undefined ? { expires_at: options.expiresAt } : {}),
      revoked: options.revoked ?? false,
    },
  }
}

// --- helpers -----------------------------------------------------------------

/**
 * Structural equality by canonical JSON.
 *
 * The same function that produces `input_digest`, reused here so that "these
 * two scopes are the same" means exactly what "these two inputs are the same"
 * means everywhere else in the protocol.
 */
function deepEqual(a: unknown, b: unknown): boolean {
  try {
    return digest(a) === digest(b)
  } catch {
    return false
  }
}

function earliest(a: number | undefined, b: number | undefined): number | undefined {
  if (a === undefined) return b
  if (b === undefined) return a
  return Math.min(a, b)
}
