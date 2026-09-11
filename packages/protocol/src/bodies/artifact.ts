/**
 * Artifacts and checkpoints — two kinds with nothing in common except that both
 * are about committing to something outside the event body.
 */

import { z } from 'zod'
import { Digest, UnixSeconds } from './common.ts'

/** `artifact` (8106) — a file or blob an agent produced. */
export const ArtifactBody = z.object({
  name: z.string().min(1),
  mime: z.string().min(1),
  url: z.string().optional().describe('e.g. a Blossom or HTTP URL'),
  sha256: Digest.optional(),
  size: z.int().nonnegative().optional(),
  description: z.string().optional(),
})
export type ArtifactBody = z.infer<typeof ArtifactBody>

/**
 * `checkpoint` (8108) — ordering integrity, layer 3.
 *
 * Nostr has no total order. `created_at` is a client wall clock, and a relay
 * withholding events is not detectable from the protocol — that is by design,
 * not a flaw. Layers 1 and 2 (per-author `counter` tags and causal `e` tags)
 * catch gaps you can see from the events you already hold. Neither catches a
 * relay that quietly serves you a smaller world.
 *
 * A checkpoint is the relay signing a commitment to the set of event ids it
 * holds for a group up to `to`. If it later serves a set missing an event
 * covered by a checkpoint it signed, that is cryptographic proof of
 * misbehaviour rather than a suspicion.
 *
 * Note what this does *not* do: it does not make the relay a trust anchor for
 * authenticity — authorship is still the author's signature. It only makes
 * omission provable. A generic relay publishes no checkpoints and readers
 * degrade to layers 1 and 2, which is why this is an addition rather than a
 * requirement.
 */
export const CheckpointBody = z.object({
  from: UnixSeconds.describe('start of the covered window, inclusive'),
  to: UnixSeconds.describe('end of the covered window, inclusive'),
  count: z.int().nonnegative().describe('number of events covered'),

  /** Merkle root over the covered event ids, sorted ascending as hex strings. */
  merkle_root: Digest,

  /**
   * Named so a verifier never has to guess how the root was built. Sorting the
   * ids rather than using arrival order is what makes the root reproducible by
   * someone who holds the same set but received it in a different sequence.
   */
  algorithm: z.literal('sha256-merkle-sorted-v1').default('sha256-merkle-sorted-v1'),

  /** Root of the previous checkpoint, chaining them into a transparency log. */
  prev: Digest.optional(),
})
export type CheckpointBody = z.infer<typeof CheckpointBody>
