/**
 * Agent-side state: what an agent is, what it remembers, where it got to, and
 * whether it is alive.
 */

import { z } from 'zod'
import { GrantSpec, Pubkey, UnixSeconds } from './common.ts'

/** `agent_manifest` (38103). `d` is a stable slug. Self-published, so: a claim. */
export const AgentManifestBody = z.object({
  name: z.string().min(1),
  description: z.string().min(1),
  operator: Pubkey.optional().describe('the human accountable for this agent'),
  homepage: z.string().optional(),
  model: z.string().optional().describe('informational, e.g. "claude-opus-5"'),

  /** Capabilities the agent is asking for. A request, never a grant. */
  wants: z
    .array(GrantSpec.extend({ why: z.string().min(1) }))
    .default([])
    .describe('shown to a human at install time, with the stated reason'),

  /**
   * Pubkeys of running instances. Listing them lets an operator revoke one
   * replica without rotating the principal key that holds every grant.
   */
  instances: z.array(Pubkey).default([]),
})
export type AgentManifestBody = z.infer<typeof AgentManifestBody>

/** `agent_memory` (38104). `d` is a scoped key. Freeform by design. */
export const AgentMemoryBody = z.object({
  value: z.unknown(),
  updated_at: UnixSeconds.optional(),
})
export type AgentMemoryBody = z.infer<typeof AgentMemoryBody>

/**
 * `agent_cursor` (38105) — resume state. `d` is a subscription id.
 *
 * This replaces M0's contiguous-prefix `acked_seq`, which cannot survive the
 * move to Nostr: there is no total order to take a prefix of. The three
 * mechanisms M0 actually validated survive intact — `once()`, replay rather
 * than resume, and stable ids — only the representation changes.
 *
 * The rule that carries over unchanged is the important one: an event is
 * removed from `in_flight` only when its handler has *completed*. A handler
 * blocked on a human has not completed, so its event replays after a restart.
 * Advancing past it would silently abandon the work.
 */
export const AgentCursorBody = z.object({
  /**
   * Highest contiguous `counter` seen per author pubkey. A gap here means
   * "I have definitely missed something from this author" — detectable on any
   * relay, with no cooperation from it.
   */
  watermarks: z.record(Pubkey, z.int().nonnegative()).default({}),

  /** Events delivered to a handler that has not finished. These replay. */
  in_flight: z.array(z.string()).default([]),

  /**
   * Events completed but ahead of a gap. Kept so that replaying a gap does not
   * re-run work already done — the dedup set that a fresh process would
   * otherwise lose, which is precisely what duplicated every step in M0's first
   * failed restart test.
   */
  completed_ahead: z.array(z.string()).default([]),

  last_seen_at: UnixSeconds.optional(),
})
export type AgentCursorBody = z.infer<typeof AgentCursorBody>

/**
 * `lease` (28102) — a single-holder claim on a thread, so two replicas of the
 * same agent do not both answer.
 *
 * Ephemeral and advisory. A lease cannot be made authoritative without a
 * consensus mechanism nobody wants in a chat relay, so it is a coordination
 * hint that removes the common case of duplicate work; correctness against
 * double-execution comes from `once()` and content-addressed action ids, not
 * from this.
 */
export const LeaseBody = z.object({
  epoch: z.int().nonnegative().describe('monotonic per holder; higher wins ties'),
  ttl_seconds: z.int().positive().default(60),
  purpose: z.string().optional(),
})
export type LeaseBody = z.infer<typeof LeaseBody>

/** `presence` (28103) — liveness and current activity. */
export const PresenceBody = z.object({
  status: z.enum(['online', 'busy', 'offline']),
  activity: z.string().optional().describe('what it is doing right now, in human words'),
  ttl_seconds: z.int().positive().default(90),
})
export type PresenceBody = z.infer<typeof PresenceBody>
