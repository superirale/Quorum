package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nbd-wtf/go-nostr"
)

// These tests read the artifacts @quorum/protocol publishes, not a Go copy of
// them. That is the claim under test: the same schemas and the same requirement
// table drive the TypeScript validator, scripts/validate.py, and this relay. If
// the three ever disagree, one of them is not reading what it says it reads.

const (
	schemaDir  = "../../../../packages/protocol/schemas"
	fixtureDir = "../../../../packages/protocol/fixtures"
)

func load(t *testing.T) *Index {
	t.Helper()
	index, err := Load(schemaDir)
	if err != nil {
		t.Fatalf("loading the protocol index: %v", err)
	}
	return index
}

type fixture struct {
	Group  string         `json:"group"`
	Thread string         `json:"thread"`
	Action string         `json:"action"`
	Events []*nostr.Event `json:"events"`
}

func loadFixture(t *testing.T, name string) fixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fixtureDir, name))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	var f fixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parsing fixture: %v", err)
	}
	if len(f.Events) == 0 {
		t.Fatal("fixture has no events")
	}
	return f
}

func TestIndexLoads(t *testing.T) {
	index := load(t)

	if index.Version == "" {
		t.Error("index has no version")
	}
	if index.Envelope.AddressMarker != "to" {
		t.Errorf("address marker is %q, want \"to\"", index.Envelope.AddressMarker)
	}

	// Every kind the index says has a body must have compiled. loadBodySchema
	// errors are fatal at Load time, so reaching here means they all did — but
	// assert the count so a silently-empty bodies map cannot pass.
	withBody := 0
	for _, kind := range index.Kinds {
		if kind.Body != "" {
			withBody++
		}
	}
	if len(index.bodies) != withBody {
		t.Errorf("compiled %d body schemas, index names %d", len(index.bodies), withBody)
	}
	if withBody == 0 {
		t.Error("no body schemas were loaded")
	}
}

func TestGoldenTranscriptIsAccepted(t *testing.T) {
	index := load(t)
	f := loadFixture(t, "deploy-approval.json")

	for _, event := range f.Events {
		// The relay's own gate: does the id match the content it claims to
		// cover? go-nostr recomputes the NIP-01 serialisation, which is an
		// independent implementation of what the TypeScript generator did.
		if event.GetID() != event.ID {
			t.Errorf("kind %d: id mismatch, recomputed %s", event.Kind, event.GetID())
		}
		ok, err := event.CheckSignature()
		if err != nil || !ok {
			t.Errorf("kind %d: signature does not verify (%v)", event.Kind, err)
		}

		if err := index.ValidateEnvelope(event); err != nil {
			t.Errorf("kind %d: envelope rejected: %v", event.Kind, err)
		}
		if EncMode(event) == EncPlaintext {
			if err := index.ValidateBody(event); err != nil {
				t.Errorf("kind %d: body rejected: %v", event.Kind, err)
			}
		}
	}
}

// The mirror of scripts/validate.py --self-test. Each case must be rejected, and
// each must be rejected for its own reason: a suite where every case trips the
// same check proves only that one check exists.
func TestTamperedEventsAreRejected(t *testing.T) {
	index := load(t)
	f := loadFixture(t, "deploy-approval.json")

	find := func(kind int) *nostr.Event {
		t.Helper()
		for _, event := range f.Events {
			if event.Kind == kind {
				copied := *event
				copied.Tags = append(nostr.Tags{}, event.Tags...)
				for i, tag := range copied.Tags {
					copied.Tags[i] = append(nostr.Tag{}, tag...)
				}
				return &copied
			}
		}
		t.Fatalf("fixture has no kind %d event", kind)
		return nil
	}

	dropTag := func(event *nostr.Event, name string) *nostr.Event {
		kept := nostr.Tags{}
		for _, tag := range event.Tags {
			if tag[0] != name {
				kept = append(kept, tag)
			}
		}
		event.Tags = kept
		return event
	}

	cases := []struct {
		name  string
		event *nostr.Event
		want  string
	}{
		{"missing group", dropTag(find(8101), TagGroup), `"h" tag`},
		{"missing alt", dropTag(find(8102), TagAlt), `"alt" tag`},
		{"unaddressed approval request", func() *nostr.Event {
			event := find(8102)
			kept := nostr.Tags{}
			for _, tag := range event.Tags {
				if !(len(tag) > 3 && tag[0] == TagPubkey && tag[3] == "to") {
					kept = append(kept, tag)
				}
			}
			event.Tags = kept
			return event
		}(), "must address someone"},
		{"response parented to the thread", func() *nostr.Event {
			event := find(8103)
			for _, tag := range event.Tags {
				if tag[0] == TagParentKind {
					tag[1] = "11"
				}
			}
			return event
		}(), "`k` tag says 11"},
		{"unthreaded action", dropTag(find(8101), TagRootEvent), "`E` tag"},
		{"unknown enc mode", func() *nostr.Event {
			event := find(8101)
			event.Tags = append(event.Tags, nostr.Tag{TagEnc, "rot13"})
			return event
		}(), "unknown enc mode"},
		{"addressable without d", dropTag(find(38101), TagIdentifier), "`d` tag"},
		{"alt spanning lines", func() *nostr.Event {
			event := find(8101)
			for _, tag := range event.Tags {
				if tag[0] == TagAlt {
					tag[1] = "deployed\nthen did something else"
				}
			}
			return event
		}(), "single line"},
	}

	seen := map[string]bool{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := index.ValidateEnvelope(tc.event)
			if err == nil {
				t.Fatal("accepted a tampered event")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("rejected for the wrong reason:\n got: %v\nwant substring: %s", err, tc.want)
			}
			if seen[err.Error()] {
				t.Errorf("this case trips the same check as an earlier one: %v", err)
			}
			seen[err.Error()] = true
		})
	}
}

func TestTamperedBodiesAreRejected(t *testing.T) {
	index := load(t)
	f := loadFixture(t, "deploy-approval.json")

	find := func(kind int) nostr.Event {
		for _, event := range f.Events {
			if event.Kind == kind {
				return *event
			}
		}
		t.Fatalf("fixture has no kind %d event", kind)
		return nostr.Event{}
	}

	cases := []struct {
		name    string
		kind    int
		content string
	}{
		{"not JSON at all", 8101, "just some text"},
		{"missing a required field", 8102, `{"summary":"deploy","risk":"high"}`},
		{"wrong type for a field", 8101, `{"name":"deploy.production","status":42}`},
		{"status outside the enum", 8101, `{"name":"deploy.production","status":"vibing"}`},
		{"trailing data after the body", 8101, `{"name":"x","status":"proposed"} {"and":"more"}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			event := find(tc.kind)
			event.Content = tc.content
			if err := index.ValidateBody(&event); err == nil {
				t.Fatal("accepted an invalid body")
			}
		})
	}
}

// Encrypted events cannot have their bodies checked, and the envelope rules must
// still apply. This is why the two are separate functions rather than one.
func TestEncryptedEventsStillValidateTheirEnvelope(t *testing.T) {
	index := load(t)
	f := loadFixture(t, "deploy-approval.json")

	var event nostr.Event
	for _, candidate := range f.Events {
		if candidate.Kind == 8101 {
			event = *candidate
			break
		}
	}

	event.Tags = append(append(nostr.Tags{}, event.Tags...), nostr.Tag{TagEnc, "nip44"})
	event.Content = "AqDS3ZBcNotRealCiphertextButNotJSONEither=="

	if err := index.ValidateEnvelope(&event); err != nil {
		t.Errorf("envelope should still pass on an encrypted event: %v", err)
	}
	if EncMode(&event) != "nip44" {
		t.Errorf("enc mode is %q, want nip44", EncMode(&event))
	}
	// And the body check, if a caller wrongly ran it, would fail — which is
	// exactly why callers must gate on EncMode.
	if err := index.ValidateBody(&event); err == nil {
		t.Error("ciphertext somehow passed body validation")
	}
}

func TestBorrowedKindsAreLeftAlone(t *testing.T) {
	index := load(t)

	// A bare NIP-C7 chat message from a generic client: no alt, no h, no
	// Quorum tags whatsoever. Rejecting it would break the interop promise
	// this whole design rests on.
	chat := &nostr.Event{Kind: 9, Content: "hello", Tags: nostr.Tags{}}
	if err := index.ValidateEnvelope(chat); err != nil {
		t.Errorf("a generic kind 9 event was rejected: %v", err)
	}
	if _, isQuorum := index.Kind(9); isQuorum {
		t.Error("kind 9 should not be a Quorum-defined kind")
	}
	if !index.Supported(9) {
		t.Error("kind 9 should still be supported by the relay")
	}
}
