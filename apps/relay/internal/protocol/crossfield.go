package protocol

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/nbd-wtf/go-nostr"
)

// The rules a JSON Schema cannot carry.
//
// Every other validation in this package is read from schemas/index.json: the
// required tags, the alt limit, the enc modes, the seal table, the per-kind
// requirements, the body schemas themselves. The rules here cannot be, and the
// reason is a property of the tool rather than a shortcut. They span two fields,
// or a field and a tag — "a `nip44` policy states an epoch and an `mls` one must
// not", "an approval request may not require more approvals than it addresses" —
// and `z.toJSONSchema()` emits nothing for a Zod refinement. So a rule written
// as a refinement is enforced by the TypeScript package and by nothing else,
// with no error anywhere to say so.
//
// That has now happened often enough to have a shape. ConfirmResourceNames,
// the UNSEALED_KINDS table and RejectMlsPolicyEpoch each closed one instance.
// The one that produced this file was found by `@quorum/conformance`, which
// publishes a proposed action with no `input_digest` and asks whether the relay
// refuses it: the TypeScript validator does, this relay stored it, and an action
// whose digest is absent is precisely the one a forger wants stored — an
// approval signed over nothing can be checked against nothing.
//
// # How the two implementations are kept in step
//
// The *codes* are published, in `cross_field_rules`. Not the rules: each is a
// few lines of ordinary code, and a schema language expressive enough for them
// would be a second protocol to keep in sync. Just the names and the kinds they
// apply to — which is enough to ask this relay whether it implements all of
// them, and enough for it to refuse to start when it does not. ConfirmCrossField
// does that at boot, because a missing rule here is invisible at runtime: events
// that should be refused are simply stored, which looks exactly like a quiet
// relay doing its job.
type crossFieldCheck struct {
	// The published `Issue.code` from packages/protocol/src/validate.ts.
	code string
	// The kinds it applies to, checked against the published table at boot.
	kinds []int
	// Reports the refusal, or nil. `body` is the already-parsed content, and is
	// never nil: a body that would not parse was refused by the schema layer
	// before this runs.
	check func(i *Index, event *nostr.Event, body map[string]any) error
}

// Kinds this file branches on by number.
//
// The index is the authority for which kinds exist; these are the ones the code
// below names, and the boot check confirms each published rule applies to
// exactly the kinds its implementation claims. Same stance as the Enc
// constants: a branch keyed on a number the protocol has moved is not an error,
// it is a check that never fires.
const (
	kindAction           = 8101
	kindApprovalRequest  = 8102
	kindApprovalResponse = 8103
	kindChannelKey       = 8110
	kindMlsWelcome       = 8111
	kindInterrupt        = 28101
	kindThreadState      = 38101
	kindChannelPolicy    = 38107
)

var threadIdentifier = regexp.MustCompile(`^[0-9a-f]{64}$`)

// crossFieldChecks mirrors crossFieldIssues() in packages/protocol/src/validate.ts,
// rule for rule and in the same order, so the two can be diffed by eye.
//
// Warnings are not here. They change nothing about whether an event is stored,
// so an implementation that omits one is not a relay with a hole in it — and the
// published table carries only the errors for the same reason.
var crossFieldChecks = []crossFieldCheck{
	{
		code:  "missing_input_digest",
		kinds: []int{kindAction, kindApprovalRequest},
		check: func(i *Index, event *nostr.Event, body map[string]any) error {
			// The field an approval binds to. Without it, "Ada approved this"
			// names an action *type* and not a set of arguments, so one yes to
			// deploy.production is a standing yes to every future deploy —
			// which is the difference between consent and a role.
			if text(body, "input_digest") != "" {
				return nil
			}
			switch event.Kind {
			case kindAction:
				if text(body, "status") != "proposed" {
					return nil
				}
				return fmt.Errorf(
					"a proposed action must carry input_digest; an approval that cannot name " +
						"its arguments authorises the action name forever")
			default:
				if firstTagValue(event, TagAction) == "" {
					return nil
				}
				return fmt.Errorf("an approval request tied to an action must bind to its input_digest")
			}
		},
	},
	{
		code:  "missing_action_tag",
		kinds: []int{kindAction, kindInterrupt},
		check: func(i *Index, event *nostr.Event, body map[string]any) error {
			if firstTagValue(event, TagAction) != "" {
				return nil
			}
			if event.Kind == kindAction {
				if text(body, "status") == "proposed" {
					return nil
				}
				return fmt.Errorf(
					"only a `proposed` action opens a chain; every later status needs an " +
						"`action` tag naming it")
			}
			// `scope` defaults to `action`, so an interrupt naming nothing is
			// the shape you get by forgetting — and the ambiguous one, because
			// an agent reading it cannot tell whether "stop" meant this action
			// or everything in the thread.
			scope := text(body, "scope")
			if scope != "" && scope != "action" {
				return nil
			}
			return fmt.Errorf(
				"an action-scoped interrupt must carry an `action` tag naming what to stop; " +
					"use scope \"thread\" to stop everything")
		},
	},
	{
		code:  "unreachable_quorum",
		kinds: []int{kindApprovalRequest},
		check: func(i *Index, event *nostr.Event, body map[string]any) error {
			required, ok := number(body, "required")
			if !ok {
				required = 1
			}
			if approvers := len(i.Addressees(event)); required > float64(approvers) {
				return fmt.Errorf(
					"required is %d but only %d approvers are addressed",
					int(required), approvers)
			}
			return nil
		},
	},
	{
		code:  "missing_modified_digest",
		kinds: []int{kindApprovalResponse},
		check: func(i *Index, event *nostr.Event, body map[string]any) error {
			if _, edited := body["modified_input"]; !edited {
				return nil
			}
			if text(body, "modified_input_digest") != "" {
				return nil
			}
			return fmt.Errorf(
				"modified_input requires modified_input_digest, or the log records one thing " +
					"and the agent runs another")
		},
	},
	{
		// A wrapped key and a Welcome are each for exactly one member. One
		// commit produces one Welcome and the sender publishes it once per
		// recipient, so a second addressee is always a mistake, and a quiet
		// one: the payload is sealed to a single member's key, so the other
		// fetches it, fails to find their own secret in it, and is required by
		// the spec to read that as "not mine" rather than as an error. They are
		// told nothing, and the member who was owed one waits forever.
		code:  "many_recipients",
		kinds: []int{kindChannelKey, kindMlsWelcome},
		check: func(i *Index, event *nostr.Event, body map[string]any) error {
			if to := i.Addressees(event); len(to) > 1 {
				return fmt.Errorf(
					"a wrapped key is for one member; this one is addressed to %d. "+
						"Publish one event per recipient, or the others cannot tell "+
						"\"not mine\" from \"tampered with\"", len(to))
			}
			return nil
		},
	},
	{
		// The tag routes it and the body authorises it, so they must agree. An
		// 8110 addressed to Bob with `recipient: cat` hands Bob a payload he
		// cannot open, and the failure surfaces as a NIP-44 MAC error — which
		// is what tampering looks like.
		code:  "recipient_mismatch",
		kinds: []int{kindChannelKey, kindMlsWelcome},
		check: func(i *Index, event *nostr.Event, body map[string]any) error {
			to := i.Addressees(event)
			recipient := text(body, "recipient")
			if len(to) != 1 || recipient == "" || to[0] == recipient {
				return nil
			}
			return fmt.Errorf(
				"addressed to %s… but the body says %s…; the reader who finds it is not "+
					"the one who can open it", short(to[0]), short(recipient))
		},
	},
	{
		// The MLS epoch is a property of the ratchet, advanced by every commit
		// any member makes, and this relay stores commits it cannot read. A
		// number written into a policy is stale the instant somebody adds a
		// member, and stale in the damaging direction: a client believing it
		// seals at the current epoch is sealing at one the group has left.
		//
		// Found by act 1 of examples/mls-channel/src/live.ts, which published
		// one and watched it stored. Every TypeScript client in the repo refuses
		// to parse that event, so an admin could brick a channel with a policy
		// that reads to every client as no policy at all.
		code:  "mls_policy_epoch",
		kinds: []int{kindChannelPolicy},
		check: func(i *Index, event *nostr.Event, body map[string]any) error {
			if text(body, "enc") != EncMls {
				return nil
			}
			epoch, stated := number(body, "epoch")
			if !stated {
				return nil
			}
			return fmt.Errorf(
				"an mls channel policy must not state an epoch, and this one says %d; "+
					"the ratchet is the only thing that knows the epoch, and a commit from "+
					"any member makes this number wrong", int(epoch))
		},
	},
	{
		code:  "missing_epoch",
		kinds: []int{kindChannelPolicy},
		check: func(i *Index, event *nostr.Event, body map[string]any) error {
			if text(body, "enc") != EncNip44 {
				return nil
			}
			if _, stated := number(body, "epoch"); stated {
				return nil
			}
			return fmt.Errorf(
				"a nip44 channel policy must state the epoch writers should seal under, " +
					"or nobody can tell a rotation from a missing key")
		},
	},
	{
		// Thread state is addressed by the id of its kind 11 root, which is what
		// makes `a`-tag and `#d` lookups from a thread work at all. This relay
		// signs its own 38101s and a member-authored one is refused upstream, so
		// the rule guards the projection rather than inbound traffic — kept
		// because the published table is a claim about what this relay enforces,
		// and an unimplemented rule would make the claim false.
		code:  "bad_thread_d",
		kinds: []int{kindThreadState},
		check: func(i *Index, event *nostr.Event, body map[string]any) error {
			d := firstTagValue(event, TagIdentifier)
			if d == "" || threadIdentifier.MatchString(d) {
				return nil
			}
			return fmt.Errorf("thread_state `d` must be the 64-hex id of the kind:11 root")
		},
	},
}

// validateCrossFields runs every rule that applies to this event's kind.
//
// Called from ValidateBody, and therefore only on plaintext channels: every
// rule here reads a body field, so on a sealed event there is nothing to read.
// That is the same trade every body-layer check makes, and the reason the
// address marker and epoch tags stay in the clear.
func (i *Index) validateCrossFields(event *nostr.Event, content string) error {
	var body map[string]any
	if err := json.Unmarshal([]byte(content), &body); err != nil || body == nil {
		// Unreachable through ValidateBody, which schema-checks first. Reported
		// as no issue rather than as a refusal so that a caller reaching here
		// another way does not attribute the schema layer's rejection to a rule
		// with a name.
		return nil
	}
	for _, rule := range crossFieldChecks {
		if !containsKind(rule.kinds, event.Kind) {
			continue
		}
		if err := rule.check(i, event, body); err != nil {
			return err
		}
	}
	return nil
}

// ConfirmCrossFieldRules refuses to start when the protocol publishes a
// cross-field rule this relay does not implement, or implements for different
// kinds than it is published for.
//
// The same stance as ConfirmResourceNames and the enc-mode check at load: a
// rule this relay does not have is not an error at runtime. Events that should
// be refused are stored, which is indistinguishable from a quiet workspace —
// while the relay goes on advertising that it validates Quorum events.
func (i *Index) ConfirmCrossFieldRules() error {
	implemented := make(map[string][]int, len(crossFieldChecks))
	for _, rule := range crossFieldChecks {
		implemented[rule.code] = rule.kinds
	}

	for _, published := range i.CrossFieldRules {
		kinds, ok := implemented[published.Code]
		if !ok {
			return fmt.Errorf(
				"the protocol publishes cross-field rule %q (%s) and this relay does not "+
					"implement it; see internal/protocol/crossfield.go",
				published.Code, published.What)
		}
		wanted, err := published.KindNumbers()
		if err != nil {
			return err
		}
		if !sameKinds(kinds, wanted) {
			return fmt.Errorf(
				"cross-field rule %q is published for kinds %v and implemented here for %v",
				published.Code, wanted, kinds)
		}
		delete(implemented, published.Code)
	}

	// The other direction. A rule enforced here and published nowhere is the
	// original problem with the polarity flipped: this relay refuses events
	// every other implementation accepts, and the spec does not say why.
	for code := range implemented {
		return fmt.Errorf(
			"this relay enforces cross-field rule %q, which the protocol does not publish; "+
				"add it to CROSS_FIELD_RULES or remove it here", code)
	}
	return nil
}

func containsKind(kinds []int, kind int) bool {
	for _, k := range kinds {
		if k == kind {
			return true
		}
	}
	return false
}

func sameKinds(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for _, kind := range a {
		if !containsKind(b, kind) {
			return false
		}
	}
	return true
}

// text reads a string field, answering "" for absent and for any other type.
// A wrong type was already refused by the schema layer.
func text(body map[string]any, field string) string {
	value, _ := body[field].(string)
	return value
}

// number reads a numeric field, reporting whether it was there at all. The two
// answers are different for `epoch`, where absent is the rule on one mode and a
// violation on another.
func number(body map[string]any, field string) (float64, bool) {
	value, ok := body[field].(float64)
	return value, ok
}

func short(pubkey string) string {
	if len(pubkey) <= 8 {
		return pubkey
	}
	return pubkey[:8]
}
