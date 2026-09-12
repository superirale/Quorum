package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nbd-wtf/go-nostr"
)

// M4's relay-side half: the approval gate and the action chain, enforced at the
// door as well as at the resource.
//
// These are deliberately written as attacks rather than as feature tests. Every
// check in internal/policy/approvals.go exists because of a specific way one
// member of a workspace can manufacture a document that reads as somebody
// else's consent, and a test that only publishes correct events would pass
// against a relay with no policies at all.

// approvalRequest builds the 8102 an agent publishes when it hits a gate.
func approvalRequest(root, actionID, digest string, approvers ...string) *nostr.Event {
	body, _ := json.Marshal(map[string]any{
		"title":        "deploy.production",
		"summary":      "deploy api 1.4.2 to production",
		"risk":         "high",
		"input_digest": digest,
		"required":     1,
	})
	tags := nostr.Tags{
		{"h", group},
		{"E", root},
		{"K", "11"},
		{"action", actionID},
		{"alt", "approval needed: deploy api 1.4.2 to production"},
	}
	for _, pubkey := range approvers {
		tags = append(tags, nostr.Tag{"p", pubkey, "", "to"})
	}
	return &nostr.Event{Kind: 8102, Content: string(body), Tags: tags}
}

// approvalResponse builds the 8103 an approver signs.
func approvalResponse(root, requestID, actionID, digest, decision string) *nostr.Event {
	body, _ := json.Marshal(map[string]any{"decision": decision, "input_digest": digest})
	return &nostr.Event{
		Kind:    8103,
		Content: string(body),
		Tags: nostr.Tags{
			{"h", group},
			{"E", root},
			{"K", "11"},
			{"e", requestID},
			{"k", "8102"},
			{"action", actionID},
			{"alt", decision + ": deploy api 1.4.2 to production"},
		},
	}
}

// transition builds a non-proposal event in an existing action chain.
func transition(root, actionID, status string) *nostr.Event {
	event := action(root, map[string]any{
		"name":    "deploy.production",
		"status":  status,
		"summary": "deploy api 1.4.2 to production",
	})
	event.Tags = append(event.Tags, nostr.Tag{"action", actionID})
	return event
}

const inputDigestHex = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

// gate stands up a workspace where an agent has proposed a deploy and asked Ada
// to approve it. Returns the thread root, the action id and the request id.
func gate(t *testing.T, r testRelay, agent, ada actor) (root, actionID, requestID string) {
	t.Helper()

	agentConn := r.connect(t, agent)
	createGroup(t, agentConn, agent)
	admit(t, agentConn, agent, ada)

	rootEvent := mustPublish(t, agentConn, agent, thread("deploy"))
	proposed := mustPublish(t, agentConn, agent, action(rootEvent.ID, map[string]any{
		"name":         "deploy.production",
		"status":       "proposed",
		"summary":      "deploy api 1.4.2 to production",
		"input":        map[string]any{"version": "1.4.2"},
		"input_digest": inputDigestHex,
	}))
	request := mustPublish(t, agentConn, agent,
		approvalRequest(rootEvent.ID, proposed.ID, inputDigestHex, ada.pubkey))

	return rootEvent.ID, proposed.ID, request.ID
}

func TestAnApproverWhoWasAskedIsAccepted(t *testing.T) {
	agent, ada := newActor(t, "agent"), newActor(t, "ada")
	relay := start(t, agent.pubkey)
	root, actionID, requestID := gate(t, relay, agent, ada)

	mustPublish(t, relay.connect(t, ada), ada,
		approvalResponse(root, requestID, actionID, inputDigestHex, "approved"))
}

func TestAnApprovalFromSomeoneWhoWasNeverAskedIsRefused(t *testing.T) {
	// Mallory is a member of the workspace — she can read the request and she
	// can sign. Membership is not standing.
	agent, ada, mallory := newActor(t, "agent"), newActor(t, "ada"), newActor(t, "mallory")
	relay := start(t, agent.pubkey)
	root, actionID, requestID := gate(t, relay, agent, ada)

	malloryConn := relay.connect(t, mallory)
	admit(t, relay.connect(t, agent), agent, mallory)

	msg := publish(t, malloryConn, mallory,
		approvalResponse(root, requestID, actionID, inputDigestHex, "approved"))
	assertRejected(t, msg, "did not ask you")
}

func TestAnApprovalOfADifferentPayloadIsRefused(t *testing.T) {
	// Ada was asked, and Ada signed — but over a digest that is not the one the
	// request named. An approval that does not say what it approved would make
	// one yes to deploy.production a standing yes to every future deploy.
	agent, ada := newActor(t, "agent"), newActor(t, "ada")
	relay := start(t, agent.pubkey)
	root, actionID, requestID := gate(t, relay, agent, ada)

	other := strings.Repeat("ab", 32)
	msg := publish(t, relay.connect(t, ada), ada,
		approvalResponse(root, requestID, actionID, other, "approved"))
	assertRejected(t, msg, "echo the input_digest")
}

func TestAnApprovalAnsweringSomethingThatIsNotARequestIsRefused(t *testing.T) {
	agent, ada := newActor(t, "agent"), newActor(t, "ada")
	relay := start(t, agent.pubkey)
	root, actionID, _ := gate(t, relay, agent, ada)

	// `e`-tagged at the proposal rather than at the request. The proposal names
	// no approvers, so treating it as one would mean an approval nobody asked
	// for, wearing a request's clothes.
	msg := publish(t, relay.connect(t, ada), ada,
		approvalResponse(root, actionID, actionID, inputDigestHex, "approved"))
	assertRejected(t, msg, "not an approval_request")
}

func TestAForeignTransitionIsRefused(t *testing.T) {
	// Mallory declares somebody else's deploy a success. The event is
	// well-formed and correctly signed; it is simply not hers to write.
	agent, ada, mallory := newActor(t, "agent"), newActor(t, "ada"), newActor(t, "mallory")
	relay := start(t, agent.pubkey)
	root, actionID, _ := gate(t, relay, agent, ada)

	malloryConn := relay.connect(t, mallory)
	admit(t, relay.connect(t, agent), agent, mallory)

	msg := publish(t, malloryConn, mallory, transition(root, actionID, "succeeded"))
	assertRejected(t, msg, "proposed an action may advance it")
}

func TestAForeignApprovalRequestIsRefused(t *testing.T) {
	// A gate somebody else wrote is a question the agent never asked, with
	// approvers the agent never chose. Mallory asks herself to approve the
	// agent's deploy.
	agent, ada, mallory := newActor(t, "agent"), newActor(t, "ada"), newActor(t, "mallory")
	relay := start(t, agent.pubkey)
	root, actionID, _ := gate(t, relay, agent, ada)

	malloryConn := relay.connect(t, mallory)
	admit(t, relay.connect(t, agent), agent, mallory)

	msg := publish(t, malloryConn, mallory,
		approvalRequest(root, actionID, inputDigestHex, mallory.pubkey))
	assertRejected(t, msg, "proposed an action may advance it")
}

func TestTheProposerMayAdvanceTheirOwnAction(t *testing.T) {
	agent, ada := newActor(t, "agent"), newActor(t, "ada")
	relay := start(t, agent.pubkey)
	root, actionID, _ := gate(t, relay, agent, ada)

	agentConn := relay.connect(t, agent)
	for _, status := range []string{"awaiting_approval", "running", "succeeded"} {
		mustPublish(t, agentConn, agent, transition(root, actionID, status))
	}
}

func TestAnActionTagMustNameTheProposal(t *testing.T) {
	// Pointing it at a transition instead would split one action into two chains
	// that each read as complete.
	agent, ada := newActor(t, "agent"), newActor(t, "ada")
	relay := start(t, agent.pubkey)
	root, actionID, _ := gate(t, relay, agent, ada)

	agentConn := relay.connect(t, agent)
	running := mustPublish(t, agentConn, agent, transition(root, actionID, "running"))

	msg := publish(t, agentConn, agent, transition(root, running.ID, "succeeded"))
	assertRejected(t, msg, "must name the chain's `proposed` event")
}

func TestAChainThisRelayDoesNotHoldIsLetThrough(t *testing.T) {
	// The documented fail-open. Events legitimately travel between relays, and a
	// relay that demanded the whole chain be local would reject correct events
	// and teach operators that Quorum needs one true relay. The offline audit
	// makes no such allowance: to it, an approval whose request is absent simply
	// does not count.
	agent, ada := newActor(t, "agent"), newActor(t, "ada")
	relay := start(t, agent.pubkey)

	agentConn := relay.connect(t, agent)
	createGroup(t, agentConn, agent)
	adaConn := relay.connect(t, ada)
	admit(t, agentConn, agent, ada)

	root := mustPublish(t, agentConn, agent, thread("deploy")).ID
	elsewhere := strings.Repeat("cd", 32)

	mustPublish(t, agentConn, agent, transition(root, elsewhere, "running"))
	mustPublish(t, adaConn, ada,
		approvalResponse(root, elsewhere, elsewhere, inputDigestHex, "approved"))
}

func TestAnApprovalMustSayWhatItAnswers(t *testing.T) {
	agent, ada := newActor(t, "agent"), newActor(t, "ada")
	relay := start(t, agent.pubkey)
	root, actionID, requestID := gate(t, relay, agent, ada)

	orphan := approvalResponse(root, requestID, actionID, inputDigestHex, "approved")
	orphan.Tags = dropTag(orphan.Tags, "e")

	msg := publish(t, relay.connect(t, ada), ada, orphan)
	// The envelope rule (parentKind 8102 needs a parent) catches this before the
	// approval policy does, which is the order we want: structural first.
	assertRejected(t, msg, "invalid")
}

func dropTag(tags nostr.Tags, name string) nostr.Tags {
	out := make(nostr.Tags, 0, len(tags))
	for _, tag := range tags {
		if len(tag) > 0 && tag[0] == name {
			continue
		}
		out = append(out, tag)
	}
	return out
}

func assertRejected(t *testing.T, msg, want string) {
	t.Helper()
	if msg == "" {
		t.Fatal("the relay accepted it; this is the event the policy exists to refuse")
	}
	if !strings.Contains(msg, want) {
		t.Fatalf("rejected for the wrong reason:\n  got  %s\n  want it to mention %q", msg, want)
	}
}
