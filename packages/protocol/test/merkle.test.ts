/**
 * The tree a checkpoint commits to.
 *
 * Two of these tests are about attacks rather than arithmetic, and they are the
 * reason the construction is not the obvious one. A Merkle root whose shape can
 * be forged turns layer 3 from a proof into a suggestion.
 */

import assert from 'node:assert/strict'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import { readFileSync } from 'node:fs'
import { describe, test } from 'node:test'
import {
  EMPTY_ROOT,
  MERKLE_ALGORITHM,
  type MerkleStep,
  merkleLeaves,
  merkleProof,
  merkleRoot,
  verifyMerkleProof,
} from '../src/index.ts'

/** Deterministic 32-byte hex ids, so a diff here means the algorithm changed. */
const id = (label: string): string => bytesToHex(sha256(new TextEncoder().encode(label)))
const ids = (n: number): string[] => Array.from({ length: n }, (_, i) => id(`event-${i}`))

describe('merkleRoot', () => {
  test('is a function of the set, not of the order it arrived in', () => {
    const set = ids(7)
    const shuffled = [set[4]!, set[0]!, set[6]!, set[2]!, set[1]!, set[5]!, set[3]!]
    assert.equal(merkleRoot(shuffled), merkleRoot(set))
  })

  test('ignores duplicates, because a relay may serve one event twice', () => {
    const set = ids(5)
    assert.equal(merkleRoot([...set, set[2]!, set[0]!]), merkleRoot(set))
  })

  test('is case-insensitive on the way in and lowercase on the way out', () => {
    const set = ids(4)
    assert.equal(merkleRoot(set.map((x) => x.toUpperCase())), merkleRoot(set))
    assert.match(merkleRoot(set), /^[0-9a-f]{64}$/)
  })

  test('an empty window has a root anyone can reproduce from the name', () => {
    assert.equal(merkleRoot([]), EMPTY_ROOT)
    assert.equal(EMPTY_ROOT, bytesToHex(sha256(new Uint8Array(0))))
  })

  test('a single event is its own leaf hash, not a pair with itself', () => {
    const one = id('only')
    const leaf = bytesToHex(sha256(concat(0x00, hex(one))))
    assert.equal(merkleRoot([one]), leaf, 'the root of a one-event window is the leaf itself')
    assert.notEqual(
      merkleRoot([one]),
      bytesToHex(sha256(concat(0x01, hex(leaf), hex(leaf)))),
      'a self-pair would be the Bitcoin rule applied at the root',
    )
    assert.equal(merkleRoot([one, one]), merkleRoot([one]), 'deduplication happens first')
  })

  test('every size from 0 to 32 produces a distinct root', () => {
    const roots = new Set<string>()
    for (let n = 0; n <= 32; n++) roots.add(merkleRoot(ids(n)))
    assert.equal(roots.size, 33, 'two different sets must not share a root')
  })
})

describe('the two attacks the construction exists to stop', () => {
  test('an odd node is promoted, so [a,b,c] and [a,b,c,c] cannot collide', () => {
    // Bitcoin pads a short level by duplicating its last node, and the
    // consequence is CVE-2012-2459: the two sets below have the same tree. A
    // relay could commit to three events and later insist it meant four, or the
    // reverse, and both stories would check out against one signature.
    //
    // Both trees below start from canonical leaves, so the padding rule is the
    // only thing that differs. The duplicate is appended *after* sorting
    // because the attack is "the last node repeated" — a set literally
    // containing an id twice is a different thing, and `merkleLeaves` would
    // collapse it back to three before the tree was ever built.
    const leaves = merkleLeaves([id('a'), id('b'), id('c')])
    const three = merkleRoot(leaves)

    // Recomputed the Bitcoin way, by hand, to show the collision is real and
    // that we do not have it.
    const bitcoinStyle = (ordered: readonly string[]): string => {
      let level = ordered.map((x) => sha256(concat(0x00, hex(x))))
      while (level.length > 1) {
        if (level.length % 2 === 1) level.push(level[level.length - 1]!)
        const next: Uint8Array[] = []
        for (let i = 0; i < level.length; i += 2)
          next.push(sha256(concat(0x01, level[i]!, level[i + 1]!)))
        level = next
      }
      return bytesToHex(level[0]!)
    }
    assert.equal(
      bitcoinStyle(leaves),
      bitcoinStyle([...leaves, leaves[2]!]),
      'the padding rule really does collide — if this fails the attack changed, not our defence',
    )
    assert.notEqual(three, bitcoinStyle(leaves), 'we must not be building that tree')
  })

  test('leaves and internal nodes are domain-separated, so a node is not a leaf', () => {
    // Without the 0x00/0x01 prefixes, the hash of an internal node is
    // indistinguishable from the hash of a leaf, and anyone who can choose two
    // ids can present their parent as a single event that was never published.
    const [a, b] = [id('a'), id('b')].sort() as [string, string]
    const leafHash = (x: string) => sha256(concat(0x00, hex(x)))
    const nodeHash = (l: Uint8Array, r: Uint8Array) => sha256(concat(0x01, l, r))

    const pair = nodeHash(leafHash(a), leafHash(b))
    const undivided = sha256(concat2(sha256(hex(a)), sha256(hex(b))))
    assert.notEqual(bytesToHex(pair), bytesToHex(undivided))
    assert.equal(merkleRoot([a, b]), bytesToHex(pair), 'the root is the domain-separated one')
  })
})

describe('inclusion proofs', () => {
  test('every member of a set proves in, at every size up to 20', () => {
    for (let n = 1; n <= 20; n++) {
      const set = ids(n)
      const root = merkleRoot(set)
      for (const one of set) {
        const path = merkleProof(set, one)
        assert.ok(path, `no path for a member of a ${n}-event set`)
        assert.ok(verifyMerkleProof(one, path, root), `path failed at n=${n}`)
      }
    }
  })

  test('a non-member gets no path, and a forged one does not verify', () => {
    const set = ids(9)
    const outsider = id('never-published')
    assert.equal(merkleProof(set, outsider), undefined)

    // The interesting case: borrow a real member's path. It authenticates the
    // member, so using it for anything else has to fail at the leaf.
    const borrowed = merkleProof(set, set[3]!)!
    assert.equal(verifyMerkleProof(outsider, borrowed, merkleRoot(set)), false)
  })

  test('a path is short when the leaf was promoted, and the verifier must not assume a length', () => {
    // Three leaves: the last one rides up a level untouched, so its path has
    // one step where a balanced tree would give it two.
    const set = ids(3)
    const lengths = set.map((one) => merkleProof(set, one)!.length)
    assert.deepEqual([...lengths].sort(), [1, 2, 2])
    for (const one of set) {
      assert.ok(verifyMerkleProof(one, merkleProof(set, one)!, merkleRoot(set)))
    }
  })

  test('a single-event window has an empty path', () => {
    const one = id('only')
    assert.deepEqual(merkleProof([one], one), [])
    assert.ok(verifyMerkleProof(one, [], merkleRoot([one])))
  })
})

describe('merkleLeaves', () => {
  test('is the canonical form: sorted, deduplicated, lowercase', () => {
    const leaves = merkleLeaves([id('b').toUpperCase(), id('a'), id('b')])
    assert.deepEqual(leaves, [id('a'), id('b')].sort())
  })
})

test('the algorithm name is the one the body schema requires', () => {
  assert.equal(MERKLE_ALGORITHM, 'sha256-merkle-sorted-v1')
})

describe('the golden fixture', () => {
  // `fixtures/merkle-v1.json` is what holds the Go tree to this one. The Go
  // test reads it and requires equality; this is the other end of that rope.
  // Without it the fixture could drift out of date with the source beside it
  // and the Go suite would go on proving conformance to last month's tree.
  const fixture = JSON.parse(
    readFileSync(new URL('../fixtures/merkle-v1.json', import.meta.url), 'utf8'),
  ) as {
    algorithm: string
    empty_root: string
    roots: { name: string; ids: string[]; root: string }[]
    proofs: { name: string; ids: string[]; id: string; path: MerkleStep[] | null; root: string }[]
  }

  test('was generated by this algorithm', () => {
    assert.equal(fixture.algorithm, MERKLE_ALGORITHM)
    assert.equal(fixture.empty_root, EMPTY_ROOT)
    assert.ok(fixture.roots.length > 0 && fixture.proofs.length > 0, 'an empty fixture proves nothing')
  })

  for (const { name, ids: set, root } of fixture.roots) {
    test(`root: ${name}`, () => {
      assert.equal(merkleRoot(set), root)
    })
  }

  for (const { name, ids: set, id: one, path, root } of fixture.proofs) {
    test(`proof: ${name}`, () => {
      assert.deepEqual(merkleProof(set, one) ?? null, path)
      // A committed path that no longer verifies is the same bug as one that no
      // longer matches, and it is the half a relay would actually notice.
      if (path) assert.ok(verifyMerkleProof(one, path, root))
    })
  }
})

function hex(s: string): Uint8Array {
  return Uint8Array.from(s.match(/../g)!.map((b) => parseInt(b, 16)))
}

function concat(tag: number, ...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 1))
  out[0] = tag
  let at = 1
  for (const p of parts) {
    out.set(p, at)
    at += p.length
  }
  return out
}

function concat2(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length)
  out.set(a, 0)
  out.set(b, a.length)
  return out
}
