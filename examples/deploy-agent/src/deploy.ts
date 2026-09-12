/**
 * The resource.
 *
 * This is not part of the agent, and the separation is the point of the whole
 * milestone. The agent asked a human, got a signature and decided it was
 * allowed to proceed — but the agent is the party with an interest in the
 * answer, so its decision is worth nothing here. The deploy tool re-derives
 * everything from signed events it was handed, with no relay, no session, no
 * bearer token and no call back to whoever is running the agent.
 *
 * Concretely, it refuses unless all three hold:
 *
 *   1. **A capability.** Somebody this tool trusts signed a grant of
 *      `action:deploy` to this exact pubkey, scoped to this exact
 *      environment, unexpired, unrevoked and within its use count.
 *   2. **Consent.** The action chain verifies, and at least one person the
 *      agent actually asked signed an approval that counts.
 *   3. **The same bytes.** What is about to run hashes to the digest the chain
 *      says was approved. A yes to one payload is not a yes to another.
 *
 * Any of the three alone is a hole. A grant with no approval is an agent doing
 * consequential work unsupervised; an approval with no grant is a human's yes
 * standing in for authority they may not have; and either without the digest
 * check is consent to a payload nobody ever saw.
 *
 * `trustedIssuers` is configuration — it arrives from this tool's own config,
 * never from the event stream. A resource that learned who to trust from the
 * same log it is trying to authorise has no root at all.
 *
 * One naming decision worth stating, because the obvious alternative is a trap.
 * The resource is `action:deploy` and the environment lives in the *scope*, not
 * in a resource named `action:deploy.production`. Resource strings are matched
 * exactly and are never narrowed; scopes intersect. Encode the environment in
 * the name and a delegation reading "this agent may act as me, but only in
 * staging" has nothing to narrow — it would have to whitelist a different
 * resource string, which is a decision about identity rather than about
 * authority, and it silently does nothing if the string is misspelt. A scope
 * that does not match refuses; a whitelist entry that does not match a resource
 * nobody requested is invisible.
 */

import { digest, type GrantSpec, type NostrEvent } from '@quorum/protocol'
import { authorize, verifyActionChain } from '@quorum/sdk'

export const RESOURCE = 'action:deploy'

export interface DeployInput {
  service: string
  version: string
  env: string
  replicas: number
}

export interface Attempt {
  /** The pubkey asking. Not a name, not a token: a key. */
  agent: string
  input: DeployInput
  /** The id of the `proposed` event, which is the id of the whole chain. */
  actionId: string
  /** Everything the caller offers as evidence: grants, delegations, the chain. */
  evidence: readonly NostrEvent[]
  /** The coordinate of a 38106 the agent claims to be acting under. */
  onBehalfOf?: string
  now?: number
}

export type Outcome =
  | { ok: true; ref: string; approvedBy: string[]; effective: GrantSpec; via?: string }
  | { ok: false; refused: string; detail: string[] }

export class Deploys {
  private readonly trustedIssuers: readonly string[]
  /** Per-grant use counts. Only the resource can know these. */
  private readonly uses = new Map<string, number>()
  /** What actually got deployed, so a demo can show the absence of an effect. */
  readonly deployed: { ref: string; input: DeployInput }[] = []

  constructor(options: { trustedIssuers: readonly string[] }) {
    this.trustedIssuers = options.trustedIssuers
  }

  attempt(request: Attempt): Outcome {
    const now = request.now ?? Math.floor(Date.now() / 1000)

    // 1. Is this key allowed to deploy to this environment at all?
    const permission = authorize({
      agent: request.agent,
      resource: RESOURCE,
      action: 'invoke',
      scope: { env: request.input.env },
      trustedIssuers: this.trustedIssuers,
      events: request.evidence,
      ...(request.onBehalfOf ? { onBehalfOf: request.onBehalfOf } : {}),
      uses: this.usesOf(request.evidence),
      now,
    })
    if (!permission.allowed || !permission.grant || !permission.effective) {
      return { ok: false, refused: 'no capability', detail: permission.reasons }
    }

    // 2. Does the log say a human agreed, and 3. to this?
    const chain = verifyActionChain(request.actionId, request.evidence, { now })
    if (!chain.ok) {
      return {
        ok: false,
        refused: 'the action chain does not verify',
        detail: chain.issues.filter((i) => i.severity === 'error').map((i) => i.message),
      }
    }
    const approvers = chain.approvals.filter((a) => a.counted && a.decision === 'approved')
    if (!approvers.length) {
      return {
        ok: false,
        refused: 'nobody approved this',
        detail: chain.issues.map((i) => i.message),
      }
    }
    const wanted = digest(request.input)
    if (chain.executedDigest !== wanted) {
      // The seam every other check exists to make visible.
      return {
        ok: false,
        refused: 'the approved payload is not the one being deployed',
        detail: [`the chain approved ${chain.executedDigest}`, `this call passes ${wanted}`],
      }
    }

    this.uses.set(permission.grant.id, (this.uses.get(permission.grant.id) ?? 0) + 1)
    const ref = `${request.input.service}@${request.input.version}#${this.deployed.length + 1}`
    this.deployed.push({ ref, input: request.input })

    return {
      ok: true,
      ref,
      approvedBy: approvers.map((a) => a.pubkey),
      effective: permission.effective,
      ...(permission.delegation ? { via: permission.delegation.id } : {}),
    }
  }

  /**
   * The highest use count among the grants offered.
   *
   * `authorize` will not honour a `max_uses` grant unless the caller supplies a
   * count — silence there would be a limit nobody checked — and the caller is
   * always this tool, because a count the agent reported would be a count the
   * agent could choose.
   */
  private usesOf(evidence: readonly NostrEvent[]): number {
    let most = 0
    for (const event of evidence) {
      most = Math.max(most, this.uses.get(event.id) ?? 0)
    }
    return most
  }
}
