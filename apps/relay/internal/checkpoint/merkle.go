// Package checkpoint implements ordering integrity layer 3: the relay signing a
// commitment to the set of events it holds for a group in a window.
//
// Layers 1 and 2 — per-author `counter` tags and causal `e` tags — let a reader
// notice gaps in what it already holds. Neither can see an event that was never
// served, and a relay quietly serving a smaller world is not detectable from
// NIP-01 at all. That is by design: nothing in Nostr obliges a relay to admit
// what it has.
//
// A checkpoint does not change that obligation; it makes the relay's own claim
// checkable. Having signed "these are the ids I held for this group up to T",
// the relay cannot later serve a set missing one of them without producing, in
// the reader's hands, a signed contradiction. The honest limit, stated here
// because it belongs beside the mechanism rather than in a footnote: a relay
// that publishes no checkpoints is not caught by any of this. Its silence is at
// least visible, which silent withholding is not.
//
// This file is the tree. `checkpoint.go` is the thing that cuts windows and
// signs.
package checkpoint

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// Algorithm is the name a checkpoint body carries, so a verifier never guesses.
const Algorithm = "sha256-merkle-sorted-v1"

const (
	leafTag = 0x00
	nodeTag = 0x01
)

// EmptyRoot is sha256(""), the root of a window in which nothing happened.
//
// A quiet window is a real case — a workspace overnight — and the chain must
// not break for it. An arbitrary sentinel like 32 zero bytes would be equally
// valid and less checkable; this one anybody can reproduce from the name.
var EmptyRoot = hex.EncodeToString(sha256.New().Sum(nil))

// Step is one hop of an inclusion proof: a sibling hash and the side it sat on.
type Step struct {
	Hash string `json:"hash"`
	Side string `json:"side"` // "left" or "right"
}

// Leaves is the canonical form of a set of ids: sorted, deduplicated, lowercase.
//
// Sorting is what makes the root a function of the *set* rather than of the
// order a query happened to return. Deduplicating matters because a relay may
// legitimately serve one event twice across overlapping filters, and a reader
// recomputing the root from what it received must land in the same place.
func Leaves(ids []string) []string {
	seen := make(map[string]struct{}, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		lower := strings.ToLower(id)
		if _, dup := seen[lower]; dup {
			continue
		}
		seen[lower] = struct{}{}
		out = append(out, lower)
	}
	sort.Strings(out)
	return out
}

// Root reduces a set of event ids to the 32 bytes a checkpoint commits to.
//
// Two rules here are load-bearing and neither is the obvious choice:
//
// Leaves and internal nodes are hashed under different prefixes (RFC 6962's
// construction). Without that separation an internal node can be presented as a
// leaf — an attacker who controls two ids offers their parent as a single
// "event id" and produces a valid-looking inclusion proof for an event nobody
// published.
//
// An odd node is promoted, never duplicated. Padding a short level by repeating
// its last node is Bitcoin's rule and it is broken (CVE-2012-2459): [a,b,c] and
// [a,b,c,c] produce the same root, so a relay could commit to one set and later
// insist it meant the other, with one signature backing both stories.
func Root(ids []string) string {
	leaves := Leaves(ids)
	if len(leaves) == 0 {
		return EmptyRoot
	}

	level := make([][]byte, len(leaves))
	for i, leaf := range leaves {
		level[i] = hashLeaf(leaf)
	}

	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				next = append(next, hashNode(level[i], level[i+1]))
			} else {
				next = append(next, level[i]) // promoted, untouched
			}
		}
		level = next
	}
	return hex.EncodeToString(level[0])
}

// Proof is the audit path showing id is one of ids, or nil with ok=false.
//
// The point is that a client holding one event can check it against a committed
// root without refetching the window — O(log n) hashes rather than however many
// events a busy day produced.
//
// A promoted node contributes no step, so a path can be shorter than
// ceil(log2(n)). A verifier that derives the expected length from the leaf count
// rather than walking what it was given passes every power-of-two case and
// fails on the first odd one.
func Proof(ids []string, id string) ([]Step, bool) {
	leaves := Leaves(ids)
	index := sort.SearchStrings(leaves, strings.ToLower(id))
	if index == len(leaves) || leaves[index] != strings.ToLower(id) {
		return nil, false
	}

	path := []Step{}
	level := make([][]byte, len(leaves))
	for i, leaf := range leaves {
		level[i] = hashLeaf(leaf)
	}

	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 >= len(level) {
				next = append(next, level[i])
				continue
			}
			switch index {
			case i:
				path = append(path, Step{Hash: hex.EncodeToString(level[i+1]), Side: "right"})
			case i + 1:
				path = append(path, Step{Hash: hex.EncodeToString(level[i]), Side: "left"})
			}
			next = append(next, hashNode(level[i], level[i+1]))
		}
		index /= 2
		level = next
	}
	return path, true
}

// VerifyProof reports whether path carries id up to root.
func VerifyProof(id string, path []Step, root string) bool {
	hash := hashLeaf(strings.ToLower(id))
	for _, step := range path {
		sibling, err := hex.DecodeString(step.Hash)
		if err != nil {
			return false
		}
		if step.Side == "left" {
			hash = hashNode(sibling, hash)
		} else {
			hash = hashNode(hash, sibling)
		}
	}
	return hex.EncodeToString(hash) == strings.ToLower(root)
}

func hashLeaf(id string) []byte {
	raw, err := hex.DecodeString(id)
	if err != nil {
		// An id that is not hex cannot be a Nostr event id. Hashing the bytes
		// as given keeps the function total rather than panicking on input a
		// caller should never have produced; it will simply not match anything.
		raw = []byte(id)
	}
	return prefixed(leafTag, raw)
}

func hashNode(left, right []byte) []byte {
	return prefixed(nodeTag, left, right)
}

func prefixed(tag byte, parts ...[]byte) []byte {
	hasher := sha256.New()
	hasher.Write([]byte{tag})
	for _, part := range parts {
		hasher.Write(part)
	}
	return hasher.Sum(nil)
}
