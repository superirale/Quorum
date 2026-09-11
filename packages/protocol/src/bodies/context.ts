/**
 * The context API, as a NIP-90 data vending machine (5600 → 6600).
 *
 * A DVM rather than a privileged relay endpoint, so the packer is addressed by
 * pubkey and is therefore swappable. That is not architectural neatness: on
 * encrypted channels the relay *cannot* pack context, so the packer has to be
 * relocatable or the feature dies at M9. Making it a DVM from the start means
 * the SDK-side packer and the relay-side packer are the same interface with
 * different pubkeys.
 *
 * **No summarizer agent.** The reason is security, not tidiness. If one
 * designated agent produces the summaries fed to every other agent, a single
 * prompt-injected summarizer rewrites the working memory of the whole
 * workspace: one malicious message becomes persistent, laundered instructions
 * delivered to agents that never saw the original. That is structural and not
 * patchable, so compaction is deterministic and extractive, and model-written
 * summaries are opt-in, provenance-tagged and refusable.
 */

import { z } from 'zod'
import { Provenance, UnixSeconds } from './common.ts'

/** `context_pack_request` (5600). */
export const ContextPackRequestBody = z.object({
  thread: z.string().describe('thread id — the kind:11 root event id'),

  /**
   * Advisory, not a guarantee.
   *
   * The mandatory-keep set — thread root, every approval and its outcome — is
   * never dropped, so a small budget can be exceeded. M0 measured 44 tokens
   * against a 30-token budget and that was the correct answer: silently
   * dropping the approval that gates the work would have been worse than
   * overshooting. Callers must read `used_tokens` and react.
   */
  budget_tokens: z.int().positive().default(2000),

  /** Refuse model-written summaries; pay tokens for verbatim history instead. */
  verbatim_only: z.boolean().default(false),

  include_kinds: z.array(z.int()).optional(),
  exclude_kinds: z.array(z.int()).optional(),
  since: UnixSeconds.optional(),
})
export type ContextPackRequestBody = z.infer<typeof ContextPackRequestBody>

export const ContextSegment = z.object({
  event_id: z.string(),
  kind: z.int(),
  created_at: UnixSeconds,
  text: z.string(),

  /** Who said it and how far to trust it. Never omitted; see `Trust`. */
  provenance: Provenance,

  /** True when `text` was cut at a documented boundary rather than dropped. */
  truncated: z.boolean().default(false),

  /** True when the packer would have dropped this but the rules forbid it. */
  mandatory: z.boolean().default(false),
})
export type ContextSegment = z.infer<typeof ContextSegment>

/** `context_pack_result` (6600). */
export const ContextPackResultBody = z.object({
  thread: z.string(),
  segments: z.array(ContextSegment),
  used_tokens: z.int().nonnegative(),
  budget_tokens: z.int().nonnegative(),
  dropped_events: z.int().nonnegative(),

  /**
   * Identifier of the compaction algorithm, e.g. "extractive-v1".
   *
   * Two packers exist — relay-side for plaintext channels, SDK-side for
   * encrypted ones — and the conformance suite requires them to produce
   * byte-identical output for the same algorithm and input. Naming the
   * algorithm in the result is what makes that check possible, and what lets
   * the algorithm change later without ambiguity about which one ran.
   */
  algorithm: z.string().default('extractive-v1'),
})
export type ContextPackResultBody = z.infer<typeof ContextPackResultBody>

/**
 * `summary` (8104) — opt-in, written by whoever signs it.
 *
 * Returned by the packer tagged with its author's provenance and trust, so a
 * caller can see that a summary came from another agent and treat it as
 * untrusted input, or demand `verbatim_only` and skip it entirely.
 */
export const SummaryBody = z.object({
  text: z.string().min(1),
  from_event: z.string().describe('first event id covered'),
  to_event: z.string().describe('last event id covered'),
  covers: z.int().nonnegative().describe('how many events were summarised'),
  method: z.enum(['extractive', 'model']),
  model: z.string().optional(),
})
export type SummaryBody = z.infer<typeof SummaryBody>
