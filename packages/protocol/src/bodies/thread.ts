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
