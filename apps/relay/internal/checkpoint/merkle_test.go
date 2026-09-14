package checkpoint

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

// The fixture is the only thing this tree and the TypeScript one share. They
// never run in the same process: the relay computes the root it signs, a client
// recomputes it from the events it was served, and they compare across a
// socket. A one-byte disagreement makes an honest relay indistinguishable from
// a caught one, which is the worst failure available to a mechanism whose whole
// output is an accusation.
const fixturePath = "../../../../packages/protocol/fixtures/merkle-v1.json"

type fixture struct {
	Algorithm string `json:"algorithm"`
	EmptyRoot string `json:"empty_root"`
	Roots     []struct {
		Name string   `json:"name"`
		IDs  []string `json:"ids"`
		Root string   `json:"root"`
	} `json:"roots"`
	Proofs []struct {
		Name string   `json:"name"`
		IDs  []string `json:"ids"`
		ID   string   `json:"id"`
		Path []Step   `json:"path"`
		Root string   `json:"root"`
	} `json:"proofs"`
}

func loadFixture(t *testing.T) fixture {
	t.Helper()
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("reading %s: %v\n\nRun `pnpm --filter @quorum/protocol fixtures`.", fixturePath, err)
	}
	var f fixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parsing %s: %v", fixturePath, err)
	}
	if len(f.Roots) == 0 || len(f.Proofs) == 0 {
		t.Fatal("a fixture with no cases proves nothing")
	}
	return f
}

func TestFixtureRoots(t *testing.T) {
	f := loadFixture(t)
	if f.Algorithm != Algorithm {
		t.Fatalf("fixture algorithm %q, this package implements %q", f.Algorithm, Algorithm)
	}
	if f.EmptyRoot != EmptyRoot {
		t.Fatalf("empty root: got %s, fixture says %s", EmptyRoot, f.EmptyRoot)
	}
	for _, c := range f.Roots {
		if got := Root(c.IDs); got != c.Root {
			t.Errorf("%s: got %s, want %s", c.Name, got, c.Root)
		}
	}
}

func TestFixtureProofs(t *testing.T) {
	f := loadFixture(t)
	for _, c := range f.Proofs {
		path, ok := Proof(c.IDs, c.ID)
		if c.Path == nil {
			if ok {
				t.Errorf("%s: got a path for an id that is not in the set", c.Name)
			}
			continue
		}
		if !ok {
			t.Errorf("%s: no path for a member", c.Name)
			continue
		}
		if len(path) != len(c.Path) {
			t.Errorf("%s: path of %d steps, fixture has %d", c.Name, len(path), len(c.Path))
			continue
		}
		for i, step := range path {
			if step != c.Path[i] {
				t.Errorf("%s: step %d is %+v, fixture has %+v", c.Name, i, step, c.Path[i])
			}
		}
		// A committed path that no longer verifies is the same bug as one that
		// no longer matches, and it is the half a relay would actually notice.
		if !VerifyProof(c.ID, c.Path, c.Root) {
			t.Errorf("%s: the committed path does not verify", c.Name)
		}
	}
}

// --- the two attacks the construction exists to stop -------------------------

func TestOddNodeIsPromotedNotDuplicated(t *testing.T) {
	// Both trees start from canonical leaves, so the padding rule is the only
	// thing that differs. The duplicate is appended *after* sorting because the
	// attack is "the last node repeated" — a set literally containing an id
	// twice is a different thing, and Leaves would collapse it back to three.
	leaves := Leaves([]string{id("a"), id("b"), id("c")})
	three := Root(leaves)

	padded := bitcoinStyle(leaves)
	if padded != bitcoinStyle(append(append([]string{}, leaves...), leaves[2])) {
		t.Fatal("the padding rule no longer collides — the attack changed, not our defence")
	}
	if three == padded {
		t.Fatal("we are building the Bitcoin tree: [a,b,c] and [a,b,c,c] would share a root")
	}
}

func TestLeavesAndNodesAreDomainSeparated(t *testing.T) {
	// Without the prefixes an internal node is indistinguishable from a leaf,
	// and anyone who can choose two ids can present their parent as a single
	// event that was never published.
	leaves := Leaves([]string{id("a"), id("b")})
	a, _ := hex.DecodeString(leaves[0])
	b, _ := hex.DecodeString(leaves[1])

	separated := hex.EncodeToString(hashNode(prefixed(leafTag, a), prefixed(leafTag, b)))
	undivided := sha256.Sum256(append(hashOf(a), hashOf(b)...))

	if separated == hex.EncodeToString(undivided[:]) {
		t.Fatal("the prefixes are not being applied")
	}
	if got := Root(leaves); got != separated {
		t.Fatalf("root is %s, the domain-separated pair is %s", got, separated)
	}
}

// --- properties the fixture cannot state -------------------------------------

func TestRootIsAFunctionOfTheSet(t *testing.T) {
	set := ids(7)
	shuffled := []string{set[4], set[0], set[6], set[2], set[1], set[5], set[3]}
	if Root(shuffled) != Root(set) {
		t.Error("order changed the root")
	}
	if Root(append(append([]string{}, set...), set[2], set[0])) != Root(set) {
		t.Error("duplicates changed the root")
	}
}

func TestEverySizeHasADistinctRoot(t *testing.T) {
	seen := map[string]int{}
	for n := 0; n <= 32; n++ {
		root := Root(ids(n))
		if before, clash := seen[root]; clash {
			t.Fatalf("sets of %d and %d events share a root", before, n)
		}
		seen[root] = n
	}
}

func TestForgedProofDoesNotVerify(t *testing.T) {
	set := ids(9)
	outsider := id("never-published")
	if _, ok := Proof(set, outsider); ok {
		t.Fatal("a non-member got a path")
	}
	// Borrowing a real member's path is the interesting case: it authenticates
	// that member, so using it for anything else has to fail at the leaf.
	borrowed, ok := Proof(set, Leaves(set)[3])
	if !ok {
		t.Fatal("no path for a member")
	}
	if VerifyProof(outsider, borrowed, Root(set)) {
		t.Fatal("a borrowed path proved an event that was never published")
	}
}

// --- helpers -----------------------------------------------------------------

func id(label string) string {
	sum := sha256.Sum256([]byte(label))
	return hex.EncodeToString(sum[:])
}

func ids(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = id(fmt.Sprintf("event-%d", i))
	}
	return out
}

func hashOf(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// bitcoinStyle is the broken construction, recomputed by hand so the collision
// is demonstrated here rather than cited.
func bitcoinStyle(ordered []string) string {
	level := make([][]byte, len(ordered))
	for i, leaf := range ordered {
		level[i] = hashLeaf(leaf)
	}
	for len(level) > 1 {
		if len(level)%2 == 1 {
			level = append(level, level[len(level)-1])
		}
		next := make([][]byte, 0, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			next = append(next, hashNode(level[i], level[i+1]))
		}
		level = next
	}
	return hex.EncodeToString(level[0])
}
