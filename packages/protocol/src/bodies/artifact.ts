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
  merkle_root: Digest.describe('Merkle root over the covered event ids, by `algorithm`'),

  /**
   * Named so a verifier never has to guess how the root was built. Sorting the
   * ids rather than using arrival order is what makes the root reproducible by
   * someone who holds the same set but received it in a different sequence.
   *
   * See `merkle.ts` for the construction. The two properties worth knowing are
   * that leaves and internal nodes are domain-separated, and that an odd node
   * is promoted rather than duplicated — the Bitcoin padding rule would let
   * `[a,b,c]` and `[a,b,c,c]` share a root, so a relay could commit to one set
   * and later claim it meant the other.
   */
  algorithm: z.literal('sha256-merkle-sorted-v1').default('sha256-merkle-sorted-v1'),

  /**
   * The previous checkpoint's **event id**, chaining them into a log.
   *
   * The id rather than the previous root, which is what an earlier draft said.
   * A root commits only to the set; an id commits to the window bounds and the
   * count as well, so a relay cannot re-cut the same events into different
   * windows and present either version as the one it signed. It also keeps two
   * quiet windows distinguishable — consecutive empty windows have identical
   * roots and would otherwise chain ambiguously.
   *
   * Absent on the first checkpoint for a group, and only on that one: a reader
   * walking back from the newest checkpoint reaches the first and stops, and a
   * chain that ends anywhere else has had a link removed.
   */
  prev: Digest.optional().describe('event id of the previous checkpoint for this group'),
})
export type CheckpointBody = z.infer<typeof CheckpointBody>
