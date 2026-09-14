/**
 * Generate `fixtures/merkle-v1.json` — the vectors both Merkle trees are held to.
 *
 * `sha256-merkle-sorted-v1` exists twice, in `src/merkle.ts` and in Go at
 * `apps/relay/internal/checkpoint`. The relay computes the root it signs; a
 * client recomputes it from the events it was served and compares. So the two
 * implementations are never in the same process and never compare notes — the
 * only thing they share is this file. If they disagree by one byte, an honest
 * relay is indistinguishable from a caught one, which is the worst failure
 * available to a mechanism whose entire output is an accusation.
 *
 * The vectors are chosen so a plausible misreading of the prose fails at least
 * one of them:
 *
 *   - every size from 0 to 17, which walks the tree through every shape where
 *     a level goes odd — an implementation that pads instead of promoting
 *     matches at 1, 2 and 4 and diverges at 3;
 *   - the three normalisations (order, duplicates, case), each given as a
 *     mangled input with the same expected root as its canonical form, so a
 *     reader who skipped one gets a diff rather than a subtly different tree;
 *   - inclusion proofs including a promoted leaf, whose path is *shorter* than
 *     the others at the same size — a verifier that derives the path length
 *     from the leaf count rather than walking what it was given passes every
 *     power-of-two case and fails here;
 *   - a non-member, which must produce no path at all.
 *
 * Ids are sha256 of a label, so they are 32-byte hex and obviously fake, and a
 * diff in `fixtures/` means the algorithm changed.
 *
 * Run: pnpm --filter @quorum/protocol fixtures
 */

import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  EMPTY_ROOT,
  MERKLE_ALGORITHM,
  merkleLeaves,
  merkleProof,
  merkleRoot,
  type MerkleStep,
} from '../src/merkle.ts'

const here = dirname(fileURLToPath(import.meta.url))
const outDir = join(here, '..', 'fixtures')
mkdirSync(outDir, { recursive: true })

/** A fake but well-formed event id. */
const id = (label: string): string => bytesToHex(sha256(new TextEncoder().encode(label)))
const ids = (n: number): string[] => Array.from({ length: n }, (_, i) => id(`event-${i}`))

interface RootCase {
  name: string
  ids: string[]
  root: string
}

interface ProofCase {
  name: string
  ids: string[]
  id: string
  /** `null` when the id is not in the set — the implementation must say so. */
  path: MerkleStep[] | null
  root: string
}

const roots: RootCase[] = []

for (let n = 0; n <= 17; n++) {
  roots.push({
    name: `${n} event${n === 1 ? '' : 's'}`,
    ids: ids(n),
    root: merkleRoot(ids(n)),
  })
}

// The normalisations, each as a mangled input whose root must equal the
// canonical one above. Recomputed rather than copied so this file cannot claim
// a normalisation the implementation does not perform.
const five = ids(5)
roots.push({
  name: 'reversed — the root is a function of the set, not the order',
  ids: [...five].reverse(),
  root: merkleRoot([...five].reverse()),
})
roots.push({
  name: 'duplicated — a relay may serve one event twice',
  ids: [...five, five[2]!, five[0]!, five[2]!],
  root: merkleRoot([...five, five[2]!, five[0]!, five[2]!]),
})
roots.push({
  name: 'uppercase — ids are compared and emitted lowercase',
  ids: five.map((x) => x.toUpperCase()),
  root: merkleRoot(five.map((x) => x.toUpperCase())),
})

const proofs: ProofCase[] = []

// Size 3 is the smallest tree with a promoted leaf: the last leaf rides up one
// level untouched, so its path is one step where its siblings' are two.
for (const n of [1, 2, 3, 5, 8, 11]) {
  const set = ids(n)
  const root = merkleRoot(set)
  for (const [index, leaf] of merkleLeaves(set).entries()) {
    proofs.push({
      name: `leaf ${index} of ${n}`,
      ids: set,
      id: leaf,
      path: merkleProof(set, leaf) ?? null,
      root,
    })
  }
}

const nine = ids(9)
proofs.push({
  name: 'a non-member has no path',
  ids: nine,
  id: id('never-published'),
  path: merkleProof(nine, id('never-published')) ?? null,
  root: merkleRoot(nine),
})

writeFileSync(
  join(outDir, 'merkle-v1.json'),
  `${JSON.stringify(
    {
      description:
        'Vectors for sha256-merkle-sorted-v1, the tree a kind 8108 checkpoint commits to. ' +
        'Leaves are sorted, deduplicated, lowercase hex ids; leaf = sha256(0x00 || id_bytes); ' +
        'node = sha256(0x01 || left || right); an odd node is promoted, never duplicated; ' +
        'the empty set hashes to sha256("").',
      algorithm: MERKLE_ALGORITHM,
      empty_root: EMPTY_ROOT,
      roots,
      proofs,
    },
    null,
    2,
  )}\n`,
)

console.log(`wrote fixtures/merkle-v1.json — ${roots.length} roots, ${proofs.length} proofs`)
console.log(`  empty root ${EMPTY_ROOT}`)
