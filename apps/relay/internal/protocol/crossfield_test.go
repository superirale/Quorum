package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nbd-wtf/go-nostr"
)

// The table is executed, not merely read.
//
// `cross_field_rules` in schemas/index.json is a claim that this relay enforces
// every rule on it, and ConfirmCrossFieldRules only checks that a function with
// the right name exists. A rule whose body was accidentally gutted — an early
// `return nil`, a condition inverted — would still satisfy the boot guard and
// still leave the relay storing events every TypeScript client refuses, which
// is the exact failure the table was added to close. So there is one violating
// event per published code, and the loop is over the *published* list: a rule
// added to the protocol with nothing here to violate it fails this test.
//
// Mirrors `the cross-field rules are published, not only enforced` in
// packages/protocol/test/protocol.test.ts, event for event.

const (
	member = "b0b0000000000000000000000000000000000000000000000000000000000000"
	other  = "cacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacaca"
	digest = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
)

func event(kind int, content string, tags ...nostr.Tag) *nostr.Event {
	return &nostr.Event{Kind: kind, Content: content, Tags: nostr.Tags(tags)}
}

func addressed(to string) nostr.Tag { return nostr.Tag{"p", to, "", "to"} }

// One event per code, built the way a confused client would build it: valid
// against the kind's JSON Schema and valid in its envelope, wrong only in the
// relationship the schema cannot describe.
var crossFieldViolations = map[string]*nostr.Event{
	"missing_input_digest": event(8101,
		`{"name":"deploy.production","status":"proposed","summary":"ship it"}`),

	"missing_action_tag": event(8101,
		`{"name":"deploy.production","status":"running","summary":"ship it","input_digest":"`+digest+`"}`),

	"unreachable_quorum": event(8102,
		`{"title":"Deploy","summary":"to production","risk":"high","required":2}`,
		addressed(member)),

	"missing_modified_digest": event(8103,
		`{"decision":"approved","input_digest":"`+digest+`","modified_input":{"replicas":2}}`),

	"many_recipients": event(8110,
		`{"epoch":2,"key":"`+strings.Repeat("A", 140)+`","recipient":"`+member+`"}`,
		addressed(member), addressed(other)),

	"recipient_mismatch": event(8110,
		`{"epoch":2,"key":"`+strings.Repeat("A", 140)+`","recipient":"`+member+`"}`,
		addressed(other)),

	"mls_policy_epoch": event(38107, `{"enc":"mls","epoch":1}`, nostr.Tag{"d", "engineering"}),

	"missing_epoch": event(38107, `{"enc":"nip44"}`, nostr.Tag{"d", "engineering"}),

	"bad_thread_d": event(38101, `{"status":"open"}`, nostr.Tag{"d", "the-deploy-thread"}),
}

func TestEveryPublishedCrossFieldRuleRefusesSomething(t *testing.T) {
	index := load(t)

	if len(index.CrossFieldRules) == 0 {
		t.Fatal("the index publishes no cross-field rules; is the schema directory stale?")
	}

	for _, rule := range index.CrossFieldRules {
		t.Run(rule.Code, func(t *testing.T) {
			violation, ok := crossFieldViolations[rule.Code]
			if !ok {
				t.Fatalf("%s is published (%s) and nothing here violates it", rule.Code, rule.What)
			}
			// Through ValidateBody rather than the check directly, because the
			// wiring is half the claim: a rule implemented and never called is
			// the same relay as a rule not implemented.
			if err := index.ValidateBody(violation); err == nil {
				t.Fatalf("%s is published but this event was accepted: %s", rule.Code, violation.Content)
			}
		})
	}
}

// And the honest versions go through. Without this the suite would pass against
// a ValidateBody that refused every event of these kinds — which would be a
// workspace where nobody can propose anything, discovered in production.
func TestTheHonestVersionsOfEachViolationAreAccepted(t *testing.T) {
	index := load(t)

	honest := []*nostr.Event{
		event(8101, `{"name":"deploy.production","status":"proposed","summary":"ship it","input_digest":"`+digest+`"}`),
		event(8101,
			`{"name":"deploy.production","status":"running","summary":"ship it","input_digest":"`+digest+`"}`,
			nostr.Tag{"action", digest}),
		event(8102, `{"title":"Deploy","summary":"to production","risk":"high","required":2}`,
			addressed(member), addressed(other)),
		event(8103, `{"decision":"approved","input_digest":"`+digest+`","modified_input":{"replicas":2},"modified_input_digest":"`+digest+`"}`),
		event(8110, `{"epoch":2,"key":"`+strings.Repeat("A", 140)+`","recipient":"`+member+`"}`,
			addressed(member)),
		event(38107, `{"enc":"mls"}`, nostr.Tag{"d", "engineering"}),
		event(38107, `{"enc":"nip44","epoch":3}`, nostr.Tag{"d", "engineering"}),
		event(38101, `{"status":"open"}`, nostr.Tag{"d", digest}),
		// An interrupt that names what to stop, and one that stops the thread.
		event(28101, `{"mode":"cancel","reason":"enough"}`, nostr.Tag{"action", digest}),
		event(28101, `{"mode":"cancel","scope":"thread","reason":"enough"}`),
	}

	for _, honest := range honest {
		if err := index.ValidateBody(honest); err != nil {
			t.Errorf("kind %d %s was refused: %v", honest.Kind, honest.Content, err)
		}
	}
}

// The interrupt half of `missing_action_tag`, separately, because `scope`
// defaults to `action` and a default is the easiest thing in this file to read
// the wrong way round: an interrupt naming nothing is the shape you get by
// forgetting, and it is the ambiguous one.
func TestAnActionScopedInterruptMustNameItsAction(t *testing.T) {
	index := load(t)

	for _, body := range []string{
		`{"mode":"cancel","reason":"enough"}`,
		`{"mode":"cancel","scope":"action","reason":"enough"}`,
	} {
		err := index.ValidateBody(event(28101, body))
		if err == nil {
			t.Fatalf("an interrupt naming nothing was accepted: %s", body)
		}
		if !strings.Contains(err.Error(), "scope \"thread\"") {
			t.Errorf("refused without saying how to stop everything: %v", err)
		}
	}
}

// The boot guard, in both directions. A published rule with no implementation
// is a relay quietly storing what the spec says it refuses; an implemented rule
// published nowhere is a relay refusing what every other implementation
// accepts, with no document saying why.
func TestTheRelayRefusesToStartOnACrossFieldRuleItDoesNotImplement(t *testing.T) {
	index := load(t)

	index.CrossFieldRules = append(index.CrossFieldRules, CrossFieldRule{
		Code:  "approver_is_not_the_proposer",
		Kinds: []string{"8102"},
		What:  "a rule from a later version of the protocol",
	})
	err := index.ConfirmCrossFieldRules()
	if err == nil {
		t.Fatal("started against a protocol publishing a rule this relay has never heard of")
	}
	if !strings.Contains(err.Error(), "approver_is_not_the_proposer") {
		t.Errorf("refused without naming the rule: %v", err)
	}
}

// And through Load, because the guard above is only a guard if something calls
// it. Removing the call from Load is invisible to every other test here — they
// hold an *Index and ask it directly — which is the same shape of hole the
// whole table exists to close, one layer up.
func TestLoadIsWhatRefuses(t *testing.T) {
	dir := t.TempDir()

	entries, err := os.ReadDir(schemaDir)
	if err != nil {
		t.Fatalf("reading the schema directory: %v", err)
	}
	for _, entry := range entries {
		raw, err := os.ReadFile(filepath.Join(schemaDir, entry.Name()))
		if err != nil {
			t.Fatalf("reading %s: %v", entry.Name(), err)
		}
		if err := os.WriteFile(filepath.Join(dir, entry.Name()), raw, 0o600); err != nil {
			t.Fatalf("writing %s: %v", entry.Name(), err)
		}
	}

	raw, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		t.Fatalf("reading the copied index: %v", err)
	}
	var index map[string]any
	if err := json.Unmarshal(raw, &index); err != nil {
		t.Fatalf("parsing the copied index: %v", err)
	}
	rules, ok := index["cross_field_rules"].([]any)
	if !ok || len(rules) == 0 {
		t.Fatal("the committed index publishes no cross_field_rules")
	}
	index["cross_field_rules"] = append(rules, map[string]any{
		"code":  "approver_is_not_the_proposer",
		"kinds": []any{"8102"},
		"what":  "a rule from a later version of the protocol",
	})
	edited, err := json.Marshal(index)
	if err != nil {
		t.Fatalf("re-encoding the index: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.json"), edited, 0o600); err != nil {
		t.Fatalf("writing the edited index: %v", err)
	}

	if _, err := Load(dir); err == nil {
		t.Fatal("Load accepted a protocol publishing a rule this relay does not implement")
	} else if !strings.Contains(err.Error(), "approver_is_not_the_proposer") {
		t.Errorf("Load failed for the wrong reason: %v", err)
	}
}

func TestTheRelayRefusesToStartWhenARuleIsPublishedForOtherKinds(t *testing.T) {
	index := load(t)

	for at := range index.CrossFieldRules {
		if index.CrossFieldRules[at].Code != "many_recipients" {
			continue
		}
		// Published for 8110 and 8111; if the protocol narrows it to one, this
		// relay is refusing Welcomes nobody else refuses.
		index.CrossFieldRules[at].Kinds = []string{"8110"}
	}

	err := index.ConfirmCrossFieldRules()
	if err == nil {
		t.Fatal("started with a rule implemented for kinds it is not published for")
	}
	if !strings.Contains(err.Error(), "many_recipients") {
		t.Errorf("refused without naming the rule: %v", err)
	}
}

func TestTheRelayRefusesToStartWhenItEnforcesAnUnpublishedRule(t *testing.T) {
	index := load(t)

	index.CrossFieldRules = nil
	err := index.ConfirmCrossFieldRules()
	if err == nil {
		t.Fatal("started against a protocol that publishes none of the rules this relay enforces")
	}
	if !strings.Contains(err.Error(), "does not publish") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

// The rules run only where a body can be read, which is the same trade every
// other body check makes. Asserted rather than assumed, because the alternative
// reading — that a sealed event is silently exempt from a rule somebody thinks
// is enforced — is exactly what the spec section on `enc` has to be clear about.
func TestASealedEventReachesNoCrossFieldRule(t *testing.T) {
	index := load(t)

	sealed := event(38107, "base64-looking-nonsense", nostr.Tag{"d", "engineering"}, nostr.Tag{"enc", "nip44"})
	if EncMode(sealed) == EncPlaintext {
		t.Fatal("the fixture is not sealed")
	}
	// The caller — policy.ValidateQuorumEvent — is what skips it, so this test
	// pins the contract ValidateBody's doc comment states rather than a branch
	// inside it.
	if err := index.ValidateBody(sealed); err == nil {
		t.Error("ValidateBody parsed a sealed body; its callers must skip it, and one stopping doing so must fail here")
	}
}
