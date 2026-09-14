/**
 * A thread is a task, not a conversation.
 *
 * The thread splits into two events, and the split is the interesting part:
 *
 * - The **root** is a plain NIP-7D `kind:11` with a `title`. Immutable,
 *   content-addressed, and renderable by any generic forum client that has
 *   never heard of Quorum. Its id is the thread id.
 * - The **state** is an addressable `38101` keyed by `d = <thread id>`, holding
 *   status, assignee and budget. Mutable, and ignorable by clients that only
 *   want to read the conversation.
 *
 * Keeping them apart means the task layer is additive: strip 38101 and you
 * still have a valid NIP-7D thread. Merging them would have forced the thread
 * root to be addressable, which would have made the thread id a mutable
 * coordinate — and every `E` tag in the channel points at it.
 *
 * Who signs the state? The relay, following NIP-29's precedent for kinds
 * 39000–39003. Members publish `thread_op` (8109) requests; the relay folds the
 * canonical sequence into 38101. On a generic relay with no Quorum logic, no
 * 38101 appears and clients fold the ops themselves — degraded but not broken.
 */

import { z } from 'zod'
import { Cost, Pubkey, UnixSeconds } from './common.ts'

export const ThreadStatus = z.enum(['open', 'working', 'blocked', 'paused', 'done'])
export type ThreadStatus = z.infer<typeof ThreadStatus>

export const Budget = z.object({
  usd: z.number().nonnegative().optional(),
  msat: z.int().nonnegative().optional(),
  tokens: z.int().nonnegative().optional(),
})
export type Budget = z.infer<typeof Budget>

/**
 * `thread_op` (8109) — a request to change task state.
 *
 * Regular (stored) rather than ephemeral because the sequence of ops is the
 * audit trail for how a task got where it is, and because a client on a generic
 * relay has nothing else to fold.
 */
export const ThreadOpBody = z.discriminatedUnion('op', [
  z.object({ op: z.literal('set_status'), status: ThreadStatus, reason: z.string().optional() }),
  z.object({ op: z.literal('assign'), assignee: Pubkey.nullable() }),
  z.object({ op: z.literal('set_title'), title: z.string().min(1) }),
  z.object({ op: z.literal('set_budget'), budget: Budget }),

  /**
   * Report what has just been spent on this thread. Added to `spent`, never
   * assigned — an op says what this turn cost, not what the total now is.
   *
   * This is the only path into `spent`, and an action's `cost` field does not
   * feed it. The two would otherwise be a running total computed two ways from
   * overlapping evidence, and a client that emitted both would double-count.
   * The SDK publishes one of these after a terminal action, which is how the
   * action's cost reaches the total: through the same op every other spend uses.
   *
   * An agent reporting its own spend can under-report it, and nothing here
   * prevents that. What it buys is that spending is *stated* rather than
   * estimated by a relay, so the total is auditable by replay like every other
   * part of the projection, and it works unchanged on a channel the relay
   * cannot read. The dishonest-agent case is what capabilities and revocation
   * are for; an agent nobody should trust with a budget should not hold one.
   */
  z.object({ op: z.literal('add_spend'), cost: Cost, note: z.string().optional() }),
])
export type ThreadOpBody = z.infer<typeof ThreadOpBody>

/** `thread_state` (38101) — the relay's projection. `d` is the thread id. */
export const ThreadStateBody = z.object({
  status: ThreadStatus,
  title: z.string().optional(),
  assignee: Pubkey.nullish(),
  budget: Budget.optional(),
  spent: Cost.optional(),

  /**
   * Ids of the `thread_op` events folded into this state, oldest first.
   *
   * This is what makes the projection auditable rather than asserted: a client
   * can fetch those ops, replay them itself, and check the relay computed the
   * same answer. Without it, 38101 would be the relay telling you a fact you
   * have no way to check — and the whole point of building on Nostr is not
   * having to take the relay's word for things.
   */
  folded_from: z.array(z.string()).default([]),

  updated_at: UnixSeconds.optional(),
})
export type ThreadStateBody = z.infer<typeof ThreadStateBody>

/** `handoff` (8107) — explicit transfer of a thread to another actor. */
export const HandoffBody = z.object({
  to: Pubkey,
  reason: z.string().min(1),
  state: z.unknown().optional().describe('anything the receiver needs that is not in the log'),
})
export type HandoffBody = z.infer<typeof HandoffBody>
