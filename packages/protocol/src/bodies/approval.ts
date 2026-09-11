/**
 * Approvals — the thesis of the whole project, in two kinds.
 *
 * An approval is a signed event that binds a named human to an exact set of
 * arguments. Verification needs no server, survives relay migration, and cannot
 * be forged or retroactively edited by whoever runs the infrastructure. This is
 * the one place where "built on Nostr" is not a wire-format detail: on a
 * conventional platform, "Ada approved this deploy" is a row that the operator
 * can rewrite.
 */

import { z } from 'zod'
import { Digest, GrantSpec, Risk, UnixSeconds } from './common.ts'

export const ApprovalRequestBody = z.object({
  title: z.string().min(1),
  summary: z.string().min(1).describe('enough for a human to decide without opening anything'),
  risk: Risk,

  /**
   * The `input_digest` of the action being authorised. REQUIRED whenever this
   * request has an `action` tag.
   *
   * Without this the approval authorises a *name* ("deploy.production") rather
   * than a *payload*, and approving once would authorise every future deploy.
   */
  input_digest: Digest.optional(),

  /** A capability the agent wants granted as part of saying yes. */
  requested_grant: GrantSpec.optional(),

  expires_at: UnixSeconds.optional(),

  /**
   * How many distinct approvers are required. Default 1.
   *
   * The approvers themselves are the `p` tags carrying the `to` marker, so
   * n-of-m is expressible without a new kind: publish one request addressed to
   * m people with `required: n`, and count distinct signed responses.
   */
  required: z.int().positive().default(1),
})
export type ApprovalRequestBody = z.infer<typeof ApprovalRequestBody>

export const Decision = z.enum(['approved', 'denied', 'expired'])
export type Decision = z.infer<typeof Decision>

export const ApprovalResponseBody = z.object({
  decision: Decision,
  reason: z.string().optional(),

  /**
   * Echo of the request's `input_digest`. REQUIRED when the request carried one.
   *
   * The agent MUST compare this against what it proposed and refuse to act on a
   * mismatch. An approval that does not name what it approved is not an
   * approval.
   */
  input_digest: Digest.optional(),

  /**
   * Set when the human edited the parameters before approving. The agent MUST
   * then execute `modified_input`, not its original proposal, and MUST verify
   * that `modified_input_digest` is the digest of `modified_input` before
   * doing so — a mismatch here is an attempt to have an agent run one thing
   * while the log records another.
   */
  modified_input: z.unknown().optional(),
  modified_input_digest: Digest.optional(),

  /** Address of the `capability_grant` (38102) issued alongside this approval. */
  grant: z.string().optional().describe('addressable coordinate 38102:<pubkey>:<d>'),
})
export type ApprovalResponseBody = z.infer<typeof ApprovalResponseBody>
