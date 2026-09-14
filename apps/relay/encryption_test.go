package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nbd-wtf/go-nostr"

	"github.com/quorum-chat/quorum/apps/relay/internal/policy"
	"github.com/quorum-chat/quorum/apps/relay/internal/threads"
)

// The claim these tests exist to check is an uncomfortable one: a relay that
// cannot read a single byte of a channel is nonetheless the thing standing
// between that channel and a plaintext leak.
//
// It works because the two facts the check needs are deliberately *not*
// encrypted — the kind 38107 policy, and the `enc` tag. Everything below is
// written as an attack for the same reason the capability tests are. A suite
// that only publishes correctly sealed events and watches them stored passes
// against a relay with no encryption policy at all.

// sealed builds an event that looks encrypted to the relay. The content is not
// real ciphertext and does not need to be: the relay cannot tell the
// difference, which is exactly the property under test.
func sealed(event *nostr.Event, epoch string) *nostr.Event {
	event.Content = "AqDS3ZBcLooksLikeCiphertextToARelay=="
	event.Tags = append(event.Tags, nostr.Tag{"enc", "nip44"})
	if epoch != "" {
		event.Tags = append(event.Tags, nostr.Tag{"epoch", epoch})
	}
	return event
}

func TestAnEncryptedChannelRefusesPlaintext(t *testing.T) {
	alice := newActor(t, "alice")
	relay := start(t, alice.pubkey)
	conn := relay.connect(t, alice)

	createGroup(t, conn, alice)
	root := mustPublish(t, conn, alice, thread("deploy api v1.4.2"))
	encryptChannel(t, conn, alice, 1)

	// The leak this prevents. One client with encryption misconfigured, or an
	// older build that predates the policy, and the message is stored in the
	// clear in a channel where every reader believes it is holding ciphertext.
	// Nothing else in the system reports it: `openEvent` passes an untagged
	// event straight through, so it renders normally for everybody.
	msg := publish(t, conn, alice, action(root.ID, map[string]any{
		"name": "deploy.production", "status": "proposed", "summary": "Deploy api 1.4.2",
	}))
	if msg == "" {
		t.Fatal("the relay stored a plaintext action in an encrypted channel")
	}
	if !strings.Contains(msg, "refuses to store it in the clear") {
		t.Errorf("rejected for the wrong reason: %s", msg)
	}

	// The control. The same event, sealed, goes through — or the policy is
	// simply refusing everything and proves nothing.
	mustPublish(t, conn, alice, sealed(action(root.ID, nil), "1"))
}

func TestASealedEventMustSayWhichKeyItUsed(t *testing.T) {
	// A reader without the key sees a MAC failure, and a MAC failure is what
	// tampering looks like too. The epoch tag is the only thing that makes "ask
	// an admin for epoch 3" distinguishable from "this event was altered" —
	// two conclusions that send an operator to opposite ends of the building.
	alice := newActor(t, "alice")
	relay := start(t, alice.pubkey)
	conn := relay.connect(t, alice)

	createGroup(t, conn, alice)
	root := mustPublish(t, conn, alice, thread("deploy api v1.4.2"))
	encryptChannel(t, conn, alice, 1)

	if msg := publish(t, conn, alice, sealed(action(root.ID, nil), "")); msg == "" {
		t.Error("the relay stored a sealed event with no epoch tag")
	}
	if msg := publish(t, conn, alice, sealed(action(root.ID, nil), "0")); msg == "" {
		t.Error("the relay stored a sealed event with epoch 0")
	}

	// Not the *current* epoch, deliberately. An event written a second before a
	// rotation is honest and is still readable by everyone who held the old
	// key, and so is one arriving from another relay.
	mustPublish(t, conn, alice, sealed(action(root.ID, nil), "1"))
}

func TestKeyManagementAndAuthorizationStayReadable(t *testing.T) {
	// The four exemptions are not a convenience. A capability grant nobody can
	// audit is not a capability, and a channel policy nobody can read is a
	// channel nobody can join — so encrypting one of these does not make a
	// workspace more private, it makes it unadministrable.
	alice, bob := newActor(t, "alice"), newActor(t, "bob")
	relay := start(t, alice.pubkey)
	conn := relay.connect(t, alice)

	createGroup(t, conn, alice)
	admit(t, conn, alice, bob)
	encryptChannel(t, conn, alice, 1)

	sealedGrant := sealed(grant(bob.pubkey, policy.ResourceThreadBudget, nil), "1")
	if msg := publish(t, conn, alice, sealedGrant); msg == "" {
		t.Error("the relay stored an encrypted capability grant")
	} else if !strings.Contains(msg, "stays readable on an encrypted channel") {
		t.Errorf("rejected for the wrong reason: %s", msg)
	}

	// And the control: the same grant, in the clear, on the same encrypted
	// channel. Administration keeps working after encryption is turned on.
	mustPublish(t, conn, alice, grant(bob.pubkey, policy.ResourceThreadBudget, nil))
}

func TestAPlaintextChannelRefusesASealedEvent(t *testing.T) {
	// Not symmetry for its own sake. ValidateQuorumEvent skips body validation
	// whenever `enc` is set, so without this rule a single tag is a complete
	// bypass of the schema on a channel that never turned encryption on — and
	// the content would not even have to be ciphertext.
	alice := newActor(t, "alice")
	relay := start(t, alice.pubkey)
	conn := relay.connect(t, alice)

	createGroup(t, conn, alice)
	root := mustPublish(t, conn, alice, thread("deploy api v1.4.2"))

	msg := publish(t, conn, alice, sealed(action(root.ID, nil), "1"))
	if msg == "" {
		t.Fatal("the relay accepted a sealed event in a channel with no encryption policy")
	}
	if !strings.Contains(msg, "no encryption policy") {
		t.Errorf("rejected for the wrong reason: %s", msg)
	}
}

func TestOnlyAnAdminMaySetTheEncryptionPolicy(t *testing.T) {
	// The dangerous edit is `plaintext`, not `nip44`. A member who can publish
	// one declassifies the channel for every message written after it: no
	// ciphertext fails, no MAC complains, the next message simply arrives
	// readable. They never have to decrypt a word to do it.
	alice, bob := newActor(t, "alice"), newActor(t, "bob")
	relay := start(t, alice.pubkey)
	aliceConn, bobConn := relay.connect(t, alice), relay.connect(t, bob)

	createGroup(t, aliceConn, alice)
	admit(t, aliceConn, alice, bob)

	msg := publish(t, bobConn, bob, channelPolicy("nip44", 1))
	if msg == "" {
		t.Fatal("an ordinary member set the channel's encryption policy")
	}
	if !strings.Contains(msg, policy.ResourceChannelEncrypt) {
		t.Errorf("rejected for the wrong reason: %s", msg)
	}

	// A grant from the owner is the other way in, and it has to work or the
	// capability is decorative.
	mustPublish(t, aliceConn, alice, grant(bob.pubkey, policy.ResourceChannelEncrypt, nil))
	mustPublish(t, bobConn, bob, channelPolicy("nip44", 1))
}

func TestAChannelPolicyMustBeKeyedByItsChannel(t *testing.T) {
	// Addressable events are found by `d`. A 38107 keyed by anything else is a
	// policy that exists, passes every other check, and governs nothing —
	// every reader queries `d = <group>` and finds no policy at all.
	alice := newActor(t, "alice")
	relay := start(t, alice.pubkey)
	conn := relay.connect(t, alice)

	createGroup(t, conn, alice)

	misfiled := channelPolicy("nip44", 1)
	for i, tag := range misfiled.Tags {
		if tag[0] == "d" {
			misfiled.Tags[i] = nostr.Tag{"d", "some-other-channel"}
		}
	}
	if msg := publish(t, conn, alice, misfiled); msg == "" {
		t.Error("the relay stored a channel policy keyed by another channel")
	}
}

func TestTheThreadProjectorStandsDownOnAnEncryptedChannel(t *testing.T) {
	// On a nip44 channel there is no 38101 at all, and that is the answer a
	// client needs: it projects locally instead. A projection folded from the
	// subset of ops the relay happened to be able to parse would be worse than
	// none, because nothing about it would say it was partial.
	//
	// No wait before the assertion. khatru runs OnEventSaved inside AddEvent,
	// before the OK, so the projector has already had its chance by the time
	// mustPublish returns — see internal/threads for the unit test that pins
	// the same rule against an op whose body is perfectly readable JSON.
	alice := newActor(t, "alice")
	relay := start(t, alice.pubkey)
	conn := relay.connect(t, alice)

	createGroup(t, conn, alice)
	root := mustPublish(t, conn, alice, thread("deploy api v1.4.2"))

	// One op in the clear first, so the thread has a projection to change and
	// the assertion below is about the projector standing down rather than
	// about it never having run.
	mustPublish(t, conn, alice, threadOp(root.ID, `{"op":"set_status","status":"working"}`))
	if got := statusOf(t, conn, relay, root.ID); got != "working" {
		t.Fatalf("the relay did not fold a plaintext op: status is %q", got)
	}

	encryptChannel(t, conn, alice, 1)

	// The body is readable JSON on purpose. Real ciphertext is base64, so a
	// sealed op with realistic content would be ignored by the Unmarshal in
	// Fold whether or not the projector checked `enc` — and this test would
	// pass against a relay that folds encrypted ops.
	leaky := threadOp(root.ID, `{"op":"set_status","status":"done"}`)
	leaky.Tags = append(leaky.Tags, nostr.Tag{"enc", "nip44"}, nostr.Tag{"epoch", "1"})
	mustPublish(t, conn, alice, leaky)

	if got := statusOf(t, conn, relay, root.ID); got != "working" {
		t.Errorf("the projector folded a sealed op: thread status is %q, want %q", got, "working")
	}
}

func statusOf(t *testing.T, conn *nostr.Relay, relay testRelay, thread string) string {
	t.Helper()
	events := query(t, conn, nostr.Filter{
		Kinds:   []int{threads.KindThreadState},
		Authors: []string{relay.pubkey},
		Tags:    nostr.TagMap{"d": []string{thread}, "h": []string{group}},
	})
	var newest *nostr.Event
	for _, event := range events {
		if newest == nil || event.CreatedAt > newest.CreatedAt {
			newest = event
		}
	}
	if newest == nil {
		return ""
	}
	var state struct {
		Status string `json:"status"`
	}
	if json.Unmarshal([]byte(newest.Content), &state) != nil {
		return ""
	}
	return state.Status
}
