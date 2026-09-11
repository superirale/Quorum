/**
 * `action` (8101) — the kind that does the heavy lifting.
 *
 * There is deliberately no tool_call/tool_result pair. The relay does not run
 * tools, so such a pair would be log lines in a wire protocol; it would
 * re-specify MCP's tool shape inside a chat protocol, leaving two schemas to
 * keep in sync forever; and it would hardcode one agent architecture, when a
 * workflow agent or a CI bot has no tool calls at all.
 *
 * Instead: one kind, one chain, a status lifecycle.
 *
 *   proposed → awaiting_approval → running → succeeded | failed | denied | cancelled
 *
 * Every transition is a new signed event carrying an `action` tag holding the
 * id of the `proposed` event. The action id is therefore content-addressed and
 * needs no allocator: it is the hash of the proposal itself.
 *
 * This unifies four subsystems that all key off "a discrete unit of
 * consequential work": the capability resource is literally
 * `action:deploy.production`; the approval binds to this action's
 * `input_digest`; cost accounting attaches to the terminal event; and the audit
 * trail is just the signature chain over these events.
 */

import { z } from 'zod'
import { Cost, Digest, ErrorDetail } from './common.ts'

export const ActionStatus = z.enum([
  'proposed',
  'awaiting_approval',
  'running',
  'succeeded',
  'failed',
  'denied',
  'cancelled',
])
export type ActionStatus = z.infer<typeof ActionStatus>

export const TERMINAL_STATUSES: readonly ActionStatus[] = Object.freeze([
  'succeeded',
  'failed',
  'denied',
  'cancelled',
])

export function isTerminal(status: ActionStatus): boolean {
  return TERMINAL_STATUSES.includes(status)
}

/**
 * Legal transitions. A reader folding an action chain uses this to reject
 * out-of-order or forged transitions rather than trusting arrival order —
 * which matters because Nostr gives no total order and `created_at` is a
 * client clock.
 */
export const ACTION_TRANSITIONS: Readonly<Record<ActionStatus, readonly ActionStatus[]>> =
  Object.freeze({
    proposed: ['awaiting_approval', 'running', 'cancelled', 'denied', 'failed'],
    awaiting_approval: ['running', 'denied', 'cancelled', 'failed'],
    running: ['succeeded', 'failed', 'cancelled'],
    succeeded: [],
    failed: [],
    denied: [],
    cancelled: [],
  })

export function canTransition(from: ActionStatus, to: ActionStatus): boolean {
  return ACTION_TRANSITIONS[from].includes(to)
}

export const ActionBody = z.object({
  name: z.string().min(1).describe('stable dotted identifier, e.g. "deploy.production"'),
  status: ActionStatus,
  summary: z.string().min(1).describe('what this action does, in human words'),

  /**
   * The full input. Present on `proposed`; omitted afterwards so the chain does
   * not repeat a potentially large payload.
   */
  input: z.unknown().optional(),

  /**
   * sha256 over the canonical JSON of `input`. REQUIRED on `proposed`.
   *
   * This is the value an approval binds to, and the reason an approval cannot
   * be replayed onto different arguments. An agent that proposes `{env: "dev"}`,
   * gets it approved, and then runs `{env: "prod"}` produces a digest mismatch
   * that any observer can detect from the log alone.
   */
  input_digest: Digest.optional(),

  output: z.unknown().optional(),
  output_summary: z.string().optional().describe('what happened, in human words'),
  error: ErrorDetail.optional(),
  cost: Cost.optional().describe('present on terminal events when known'),

  /**
   * Address of the `delegation` (38106) this action is performed under, as
   * `38106:<human-pubkey>:<d>`. Effective permission is the intersection of the
   * agent's own grants and that human's permissions — never the union.
   */
  on_behalf_of: z.string().optional(),
})
export type ActionBody = z.infer<typeof ActionBody>

/** `error` (8105) — a failure that is not an action failure. */
export const ErrorBody = z.object({
  code: z.string().min(1),
  message: z.string().min(1),
  retryable: z.boolean().default(false),
  detail: z.unknown().optional(),
})
export type ErrorBody = z.infer<typeof ErrorBody>

/**
 * `interrupt` (28101) — ephemeral, because a cancel is only meaningful to a
 * process that is running right now. Storing it would mean an agent resuming
 * from history could re-apply last Tuesday's cancel to today's work.
 */
export const InterruptBody = z.object({
  mode: z.enum(['cancel', 'pause', 'steer']),
  scope: z.enum(['action', 'thread']).default('action'),
  reason: z.string().optional(),
  instruction: z.string().optional().describe('required in practice when mode is "steer"'),
})
export type InterruptBody = z.infer<typeof InterruptBody>
