/**
 * Primitives shared across bodies.
 *
 * A note on style that applies to every schema in this directory: none of them
 * use `.refine()`, `.transform()` or `.superRefine()`. Those are invisible to
 * `z.toJSONSchema()`, so a rule expressed that way would silently fail to reach
 * the committed JSON Schema — and the JSON Schema is what a Rust or Python
 * implementation validates against. Cross-field rules live in `validate.ts` as
 * explicit, documented checks instead, so that the gap between the two is
 * something we write down rather than something we discover.
 */

import { z } from 'zod'
import { hex32 } from '../event.ts'

export const Pubkey = hex32.describe('lowercase hex secp256k1 x-only public key')
export const EventId = hex32.describe('lowercase hex event id')

/** A sha256 over canonical JSON. What approvals actually bind to. */
export const Digest = hex32.describe('sha256 of the canonical JSON encoding')

export const UnixSeconds = z.int().nonnegative().describe('seconds since the unix epoch')

export const Risk = z.enum(['low', 'medium', 'high'])
export type Risk = z.infer<typeof Risk>

/**
 * What a unit of work cost.
 *
 * Deliberately coarse and attached to terminal action events rather than
 * streamed as its own event type. The pre-Nostr design kept usage in a sidecar
 * table on the principle that anything an LLM should never read is not an
 * event; on encrypted channels there is no sidecar, so the compromise is that
 * cost is one small object on an event that already exists, not a firehose.
 */
export const Cost = z.object({
  tokens_in: z.int().nonnegative().optional(),
  tokens_out: z.int().nonnegative().optional(),
  usd: z.number().nonnegative().optional(),
  msat: z.int().nonnegative().optional(),
})
export type Cost = z.infer<typeof Cost>

export const ErrorDetail = z.object({
  code: z.string().min(1).describe('stable machine-readable code, e.g. "permission_denied"'),
  message: z.string().min(1),
  retryable: z.boolean().default(false),
})
export type ErrorDetail = z.infer<typeof ErrorDetail>

/**
 * How much an agent should trust a piece of context.
 *
 * `self` is this agent's own prior output; `operator` is a human who controls
 * this agent; `member` is any other authenticated channel member; `untrusted`
 * is everything else, including other agents' output and anything quoted in
 * from outside. The SDK delimits `untrusted` segments before they reach a
 * model. Making this a protocol field rather than an SDK heuristic is the point
 * — an agent reading another agent's output is the normal case here, not the
 * exception, so the boundary has to survive crossing process lines.
 */
export const Trust = z.enum(['self', 'operator', 'member', 'untrusted'])
export type Trust = z.infer<typeof Trust>

export const ActorKind = z.enum(['human', 'agent', 'relay'])
export type ActorKind = z.infer<typeof ActorKind>

export const Provenance = z.object({
  pubkey: Pubkey,
  kind: ActorKind,
  trust: Trust,
  display_name: z.string().optional(),
})
export type Provenance = z.infer<typeof Provenance>

/** A capability being asked for or handed out. */
export const GrantSpec = z.object({
  resource: z.string().min(1).describe('e.g. "action:deploy.production"'),
  actions: z.array(z.string().min(1)).min(1).describe('e.g. ["invoke"]'),
  scope: z
    .record(z.string(), z.unknown())
    .optional()
    .describe('narrowing constraints, e.g. {"env": "production"}'),
  expires_at: UnixSeconds.optional(),
  max_uses: z.int().positive().optional(),
})
export type GrantSpec = z.infer<typeof GrantSpec>
