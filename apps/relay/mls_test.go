package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nbd-wtf/go-nostr"
)

// The `enc=mls` arm, which is three refusals and a number.
//
// What this relay does for an MLS channel is exactly what RFC 9420 calls a
// delivery service: store, route, order. It holds no key, parses no MLSMessage
// and will never be able to say whether a commit is valid — members decide
// that. So every test here is about a failure that is *silent* at the MLS
// layer: a KeyPackage that is never retired, a Welcome nobody can find, two
// commits for one epoch. Each of them produces a member in good standing who
// reads nothing, with no error anywhere naming them.
//
// Written as attacks and mistakes rather than happy paths, for the same reason
// the capability tests are: a suite that publishes only well-formed MLS traffic
// passes against a relay with no MLS rules at all.

const keyPackagePayload = "AAEAIE9uZSBmcmFtZWQgbWxzX2tleV9wYWNrYWdlIE1MU01lc3NhZ2U="

// mlsEncrypt sets a channel's policy to `mls`.
//
// No epoch, and that is the rule rather than an omission: on an `mls` channel
// the epoch belongs to the ratchet, which advances on every commit any member
// makes and which this relay cannot read. A number in the policy would be stale
// the moment somebody was added.
func mlsEncrypt(t *testing.T, conn *nostr.Relay, who actor) {
	t.Helper()
	mustPublish(t, conn, who, channelPolicy("mls", 0))
}

// mlsChannel creates the group and encrypts it in one step, for the tests that
// have nothing to say in the clear first.
func mlsChannel(t *testing.T, conn *nostr.Relay, owner actor) {
	t.Helper()
	createGroup(t, conn, owner)
	mlsEncrypt(t, conn, owner)
}

// mlsSealed is `sealed` for the other mode: content the relay cannot read, an
// `enc` tag it can, and an epoch that may legitimately be zero.
func mlsSealed(event *nostr.Event, epoch string) *nostr.Event {
	event.Content = "AAEAAUxvb2tzIGxpa2UgYW4gTUxTTWVzc2FnZSB0byBhIHJlbGF5"
	event.Tags = append(event.Tags, nostr.Tag{"enc", "mls"})
	if epoch != "" {
		event.Tags = append(event.Tags, nostr.Tag{"epoch", epoch})
	}
	return event
}

func keyPackage(slot string) *nostr.Event {
	return &nostr.Event{
		Kind:    30443,
		Content: keyPackagePayload,
		Tags: nostr.Tags{
			{"h", group},
			{"d", slot},
			{"alt", "an MLS KeyPackage"},
			{"mls_protocol_version", "1.0"},
			{"i", strings.Repeat("a", 64)},
			{"mls_ciphersuite", "0x0001"},
			{"mls_extensions", "0x0001", "0x0002", "0x0003"},
			{"mls_proposals", "0x0000"},
		},
	}
}

func welcome(recipients ...string) *nostr.Event {
	tags := nostr.Tags{{"h", group}, {"alt", "an invitation to an encrypted channel"}}
	for _, pubkey := range recipients {
		tags = append(tags, nostr.Tag{"p", pubkey, "", "to"})
	}
	body, _ := json.Marshal(map[string]any{
		"epoch":       1,
		"invite":      strings.Repeat("A", 140),
		"recipient":   firstOr(recipients, strings.Repeat("b", 64)),
		"key_package": strings.Repeat("c", 64),
	})
	return &nostr.Event{Kind: 8111, Content: string(body), Tags: tags}
}

func commit(epoch int, adds ...string) *nostr.Event {
	body, _ := json.Marshal(map[string]any{
		"epoch":  epoch,
		"commit": "AAEAAUEgZnJhbWVkIG1sc19wcml2YXRlX21lc3NhZ2U=",
		"adds":   adds,
	})
	return &nostr.Event{
		Kind:    8112,
		Content: string(body),
		Tags:    nostr.Tags{{"h", group}, {"alt", "the channel moved to a new epoch"}},
	}
}

func firstOr(values []string, fallback string) string {
	if len(values) == 0 {
		return fallback
	}
	return values[0]
}

func TestAnMlsChannelStartsAtEpochZero(t *testing.T) {
	// The bug this pins refused every opening message of every MLS channel this
	// relay would ever host, with "epoch must be a positive integer" — about a
	// number RFC 9420 requires. A `nip44` generation is minted from 1 so that
	// zero stays distinguishable from a missing field; MLS gets no such choice,
	// because a group is at epoch 0 from the moment it is created until its
	// first commit.
	alice := newActor(t, "alice")
	relay := start(t, alice.pubkey)
	conn := relay.connect(t, alice)

	createGroup(t, conn, alice)
	root := mustPublish(t, conn, alice, thread("rotate the signing key"))
	mlsEncrypt(t, conn, alice)

	mustPublish(t, conn, alice, mlsSealed(action(root.ID, nil), "0"))

	// The controls, so this is not simply a relay that stopped checking. An
	// epoch tag is still required, and still has to be a number.
	if msg := publish(t, conn, alice, mlsSealed(action(root.ID, nil), "")); msg == "" {
		t.Error("the relay stored an mls event with no epoch tag")
	}
	if msg := publish(t, conn, alice, mlsSealed(action(root.ID, nil), "-1")); msg == "" {
		t.Error("the relay stored an mls event at epoch -1")
	}
	if msg := publish(t, conn, alice, mlsSealed(action(root.ID, nil), "soon")); msg == "" {
		t.Error("the relay stored an mls event whose epoch is not a number")
	}
}

func TestANip44ChannelStillCountsFromOne(t *testing.T) {
	// The other half of the same rule, and the reason the minimum is per mode
	// rather than simply lowered to zero. On a `nip44` channel there is no
	// epoch 0: a client that tagged one either forgot to set the field or is
	// running against a channel it has not read the policy of, and both are
	// worth a refusal.
	alice := newActor(t, "alice")
	relay := start(t, alice.pubkey)
	conn := relay.connect(t, alice)

	createGroup(t, conn, alice)
	root := mustPublish(t, conn, alice, thread("rotate the signing key"))
	encryptChannel(t, conn, alice, 1)

	if msg := publish(t, conn, alice, sealed(action(root.ID, nil), "0")); msg == "" {
		t.Error("the relay stored a nip44 event at epoch 0")
	}
	mustPublish(t, conn, alice, sealed(action(root.ID, nil), "1"))
}

func TestAnMlsPolicyMayNotStateAnEpoch(t *testing.T) {
	// The cross-field rule the committed schemas cannot carry. `epoch` is legal
	// on a `nip44` policy and mandatory there, so the dependency is on `enc`,
	// and `z.toJSONSchema()` emits neither — which left the rule enforced in
	// TypeScript only, and this relay storing an event every client in the repo
	// refuses to parse. An admin could brick a channel with a policy that was
	// accepted and unreadable, and the symptom is a channel that appears to
	// have no encryption policy at all.
	//
	// Found by act 1 of examples/mls-channel/src/live.ts, not by a Go test,
	// because both languages were asked the same question only once.
	alice := newActor(t, "alice")
	relay := start(t, alice.pubkey)
	conn := relay.connect(t, alice)

	createGroup(t, conn, alice)

	if msg := publish(t, conn, alice, channelPolicy("mls", 3)); msg == "" {
		t.Error("the relay stored an mls policy stating an epoch")
	} else if !strings.Contains(msg, "must not state an epoch") {
		t.Errorf("refused for the wrong reason: %s", msg)
	}

	// Two controls, one in each direction, or this passes against a relay that
	// refuses every policy or every mls one.
	mustPublish(t, conn, alice, channelPolicy("mls", 0))
	encryptChannel(t, conn, alice, 4)
}

func TestAKeyPackageMustLandInTheSlotThatRetiresIt(t *testing.T) {
	// A KeyPackage is single-use, and the only thing enforcing that is
	// addressable replacement: the next 30443 this member publishes overwrites
	// the last one, because they share a `d`. Put one in some other slot and it
	// is never overwritten by anything — while still answering the `#h` query an
	// inviter makes, so it looks entirely usable.
	//
	// What follows is the expensive part. The inviter commits an Add against a
	// KeyPackage whose private half the joiner discarded when they published
	// their replacement, and the joiner ends up in the ratchet tree, counted as
	// a member by everyone, able to read nothing.
	alice := newActor(t, "alice")
	relay := start(t, alice.pubkey)
	conn := relay.connect(t, alice)

	mlsChannel(t, conn, alice)

	msg := publish(t, conn, alice, keyPackage("f4c2a1b8d3e5"))
	if msg == "" {
		t.Fatal("the relay stored a KeyPackage in a slot nothing will ever retire")
	}
	if !strings.Contains(msg, "never retired by the one that replaces it") {
		t.Errorf("rejected for the wrong reason: %s", msg)
	}

	// The control: the same package, keyed by the channel, goes through. And
	// then a second one in the same slot, which is what single-use looks like
	// from the relay's side — a replacement, not a duplicate.
	mustPublish(t, conn, alice, keyPackage(group))
	mustPublish(t, conn, alice, keyPackage(group))
}

func TestAWelcomeIsForExactlyOneMember(t *testing.T) {
	// Both ends of the rule, because they fail in opposite directions and look
	// identical from the invitee's chair: nobody addressed means nobody can find
	// it, two addressed means one of them cannot open it and is required by the
	// spec to conclude it was not theirs. Either way a member waits forever for
	// a Welcome that was published.
	alice, bob, cat := newActor(t, "alice"), newActor(t, "bob"), newActor(t, "cat")
	relay := start(t, alice.pubkey)
	conn := relay.connect(t, alice)

	mlsChannel(t, conn, alice)
	admit(t, conn, alice, bob)

	unaddressed := welcome()
	if msg := publish(t, conn, alice, unaddressed); msg == "" {
		t.Error("the relay stored a Welcome nobody is addressed by")
	} else if !strings.Contains(msg, "must address someone") {
		t.Errorf("rejected for the wrong reason: %s", msg)
	}

	both := welcome(bob.pubkey, cat.pubkey)
	if msg := publish(t, conn, alice, both); msg == "" {
		t.Fatal("the relay stored a Welcome addressed to two members")
	} else if !strings.Contains(msg, "one member") {
		t.Errorf("rejected for the wrong reason: %s", msg)
	}

	mustPublish(t, conn, alice, welcome(bob.pubkey))
}

func TestOnlyOneCommitPerEpochSurvives(t *testing.T) {
	// Two members holding the same epoch may both commit, and MLS allows exactly
	// one of them to become the group's next epoch. Nothing in the protocol
	// picks the winner — a delivery service does, and this is that.
	//
	// First stored wins, which is arbitrary on purpose: what matters is that
	// every member sees the same one, not which one it is. The loser is stranded
	// at the old epoch by the ordinary "a commit was missed" rule, which is the
	// correct outcome, because a committer whose commit was refused has not
	// moved and knows it.
	alice, bob, cat := newActor(t, "alice"), newActor(t, "bob"), newActor(t, "cat")
	relay := start(t, alice.pubkey)
	aliceConn, bobConn := relay.connect(t, alice), relay.connect(t, bob)

	mlsChannel(t, aliceConn, alice)
	admit(t, aliceConn, alice, bob)

	first := mustPublish(t, aliceConn, alice, commit(0, cat.pubkey))

	msg := publish(t, bobConn, bob, commit(0, bob.pubkey))
	if msg == "" {
		t.Fatal("the relay stored two commits for epoch 0; the group has split")
	}
	if !strings.Contains(msg, "already has a commit for epoch 0") {
		t.Errorf("rejected for the wrong reason: %s", msg)
	}

	// Re-publishing the winner is a mirror or a backfill, not a race. Refusing
	// it would make this relay reject its own history the first time anybody
	// re-broadcast it, which on a protocol whose ids are content hashes is
	// ordinary traffic rather than an attack.
	mustPublish(t, aliceConn, alice, first)

	// And the epoch the winning commit produced is free, or the channel could
	// only ever change its membership once.
	mustPublish(t, aliceConn, alice, commit(1, cat.pubkey))
}

func TestACommitMustStateItsEpochInTheClear(t *testing.T) {
	// The one field this relay reads out of an MLS body, and the reason it can
	// order commits without implementing any part of MLS. A commit whose epoch
	// is unreadable is one this relay cannot serialise, so storing it would be
	// quietly giving up the only job it has on an encrypted channel.
	alice := newActor(t, "alice")
	relay := start(t, alice.pubkey)
	conn := relay.connect(t, alice)

	mlsChannel(t, conn, alice)

	vague := commit(0)
	vague.Content = `{"commit":"AAEAAQ==","adds":[]}`
	if msg := publish(t, conn, alice, vague); msg == "" {
		t.Error("the relay stored a commit that states no epoch")
	}

	// A commit is not sealed, so its body is schema-validated like any other —
	// which is the layer that catches this first. Both are deliberate: the
	// schema says what a commit is, and SerialiseCommits says what this relay
	// needs from one, and neither should be the only thing standing between a
	// channel and a split.
	negative := commit(-1)
	if msg := publish(t, conn, alice, negative); msg == "" {
		t.Error("the relay stored a commit at a negative epoch")
	}
}
