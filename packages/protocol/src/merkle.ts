/**
 * `sha256-merkle-sorted-v1` — the tree a kind 8108 checkpoint commits to.
 *
 * A checkpoint is a relay signing "this is the set of event ids I hold for this
 * group in this window". The set has to be reducible to 32 bytes that anyone
 * holding the same events can recompute, and the reduction has to be specified
 * tightly enough that a Go relay and a TypeScript client never disagree about
 * it — a root that differs by one byte is indistinguishable from a relay caught
 * lying, which is the worst possible failure mode for a mechanism whose entire
 * output is an accusation.
 *
 * So the rules are few and all of them are load-bearing:
 *
 * **Sorted and deduplicated.** The relay's storage order is its own business
 * and a client receives events in whatever order a subscription delivers them.
 * Sorting is what makes the root a function of the *set*. Ids are compared as
 * lowercase hex strings, which is the same ordering as on the underlying bytes.
 *
 * **Leaves and internal nodes are hashed with different prefixes** — `0x00` for
 * a leaf, `0x01` for a pair. Without that separation an internal node can be
 * presented as a leaf: an attacker who controls two ids can offer their
 * concatenation as a single "event id" and produce a valid-looking inclusion
 * proof for an event nobody published. This is RFC 6962's construction and the
 * reason is the same there.
 *
 * **An odd node is promoted, never duplicated.** Duplicating the last node to
 * pad a level is the Bitcoin construction, and it is broken: a set of three
 * leaves `[a, b, c]` and a set of four `[a, b, c, c]` produce the same root, so
 * a relay could commit to one set and later claim it meant the other. Promotion
 * makes the tree shape a function of the leaf count alone.
 *
 * **The empty set is `sha256("")`.** A quiet window is a real case — a
 * workspace overnight — and the checkpoint chain must not break for it. Picking
 * an arbitrary sentinel like 32 zero bytes would be equally valid and less
 * checkable; this one is a value anyone can reproduce from the name.
 */

import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'

/** The algorithm name carried in a checkpoint body, so a verifier never guesses. */
export const MERKLE_ALGORITHM = 'sha256-merkle-sorted-v1'

/** `sha256("")` — the root of an empty window. */
export const EMPTY_ROOT = bytesToHex(sha256(new Uint8Array(0)))

const LEAF = 0x00
const NODE = 0x01

/**
 * One step of an inclusion proof: a sibling hash and which side it sat on.
 *
 * A promoted node contributes no step, which is why a path can be shorter than
 * `ceil(log2(n))` and why the verifier must not assume a length.
 */
export interface MerkleStep {
  hash: string
  side: 'left' | 'right'
}

/** Sorted, deduplicated, lowercased leaves — the canonical form of a set of ids. */
export function merkleLeaves(ids: readonly string[]): string[] {
  return [...new Set(ids.map((id) => id.toLowerCase()))].sort()
}

/**
 * The root over a set of event ids.
 *
 * Order and duplicates in `ids` are irrelevant by construction; pass whatever a
 * query returned.
 */
export function merkleRoot(ids: readonly string[]): string {
  const leaves = merkleLeaves(ids)
  if (leaves.length === 0) return EMPTY_ROOT

  let level = leaves.map((id) => hashLeaf(id))
  while (level.length > 1) {
    const next: Uint8Array[] = []
    for (let i = 0; i < level.length; i += 2) {
      // The odd one out moves up untouched. Hashing it with itself would make
      // [a,b,c] and [a,b,c,c] the same tree.
      next.push(i + 1 < level.length ? hashNode(level[i]!, level[i + 1]!) : level[i]!)
    }
    level = next
  }
  return bytesToHex(level[0]!)
}

/**
 * The audit path proving `id` is one of `ids`, or `undefined` if it is not.
 *
 * The point of a path is that a client holding one event can check it against a
 * committed root without refetching the window — O(log n) hashes instead of
 * however many events a busy day produced.
 */
export function merkleProof(ids: readonly string[], id: string): MerkleStep[] | undefined {
  const leaves = merkleLeaves(ids)
  let index = leaves.indexOf(id.toLowerCase())
  if (index === -1) return undefined

  const path: MerkleStep[] = []
  let level = leaves.map((leaf) => hashLeaf(leaf))
  while (level.length > 1) {
    const next: Uint8Array[] = []
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 >= level.length) {
        next.push(level[i]!)
        continue
      }
      if (i === index) path.push({ hash: bytesToHex(level[i + 1]!), side: 'right' })
      else if (i + 1 === index) path.push({ hash: bytesToHex(level[i]!), side: 'left' })
      next.push(hashNode(level[i]!, level[i + 1]!))
    }
    index = Math.floor(index / 2)
    level = next
  }
  return path
}

/** True if `path` carries `id` up to `root`. */
export function verifyMerkleProof(id: string, path: readonly MerkleStep[], root: string): boolean {
  let hash = hashLeaf(id.toLowerCase())
  for (const step of path) {
    const sibling = hexToBytes(step.hash)
    hash = step.side === 'left' ? hashNode(sibling, hash) : hashNode(hash, sibling)
  }
  return bytesToHex(hash) === root.toLowerCase()
}

function hashLeaf(id: string): Uint8Array {
  return sha256(prefixed(LEAF, hexToBytes(id)))
}

function hashNode(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(prefixed(NODE, left, right))
}

function prefixed(tag: number, ...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 1)
  const out = new Uint8Array(total)
  out[0] = tag
  let at = 1
  for (const part of parts) {
    out.set(part, at)
    at += part.length
  }
  return out
}
