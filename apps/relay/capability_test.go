package main

import (
	"encoding/json"
	"testing"

	"github.com/nbd-wtf/go-nostr"

	"github.com/quorum-chat/quorum/apps/relay/internal/policy"
	"github.com/quorum-chat/quorum/apps/relay/internal/protocol"
	"github.com/quorum-chat/quorum/apps/relay/internal/threads"
)

// Membership as a capability.
//
// relay29 admits anyone who publishes a kind 9021 into an open group, which is
// the right default for a public chat relay and was, until this file existed,
// the largest hole in a system whose pitch is scoped and revocable permissions:
// the coarsest capability of all — being in the workspace — was the one thing
// nobody had to be granted.
//
// These are written as attacks for the same reason the approval tests are. A
// suite that only issues correct grants and watches them work would pass
// against a relay that admits everybody.

// grant builds a kind 38102 the way the SDK does, with a hook for the field
// each test is about.
func grant(grantee, resource string, edit func(spec map[string]any)) *nostr.Event {
	spec := map[string]any{
		"resource": resource,
		"actions":  []string{"invoke"},
		"scope":    map[string]any{"group": group},
	}
	body := map[string]any{"grantee": grantee, "grant": spec, "revoked": false}
	if edit != nil {
		edit(body)
	}
	content, _ := json.Marshal(body)

	return &nostr.Event{
		Kind:    policy.KindCapabilityGrant,
		Content: string(content),
		Tags: nostr.Tags{
			{"h", group},
			// One coordinate per (grantee, resource), so re-issuing replaces and
			// a revocation can withdraw. The SDK derives this from a digest of
			// the whole spec; here the shorter version is enough because no test
			// issues two grants of one resource to one key.
			{"d", resource + ":" + grantee[:16]},
			{"p", grantee, "", "to"},
			{"alt", "capability granted: " + resource},
		},
	}
}

func joinRequest() *nostr.Event {
	return &nostr.Event{Kind: nostr.KindSimpleGroupJoinRequest, Tags: nostr.Tags{{"h", group}}}
}

// workspace stands up a group owned by ada.
func workspace(t *testing.T) (testRelay, actor, *nostr.Relay) {
	t.Helper()
	ada := newActor(t, "ada")
	relay := start(t, ada.pubkey)
	conn := relay.connect(t, ada)
	createGroup(t, conn, ada)
	return relay, ada, conn
}

func TestAStrangerCannotJoinByAsking(t *testing.T) {
	// The whole gap, in four lines. Before this policy the relay signed mallory
	// a put-user and she was in.
	relay, _, _ := workspace(t)
	mallory := newActor(t, "mallory")

	msg := publish(t, relay.connect(t, mallory), mallory, joinRequest())
	assertRejected(t, msg, "group:join")

	if admitted := query(t, relay.connect(t, mallory), nostr.Filter{
		Kinds: []int{nostr.KindSimpleGroupPutUser},
		Tags:  nostr.TagMap{"h": []string{group}, "p": []string{mallory.pubkey}},
	}); len(admitted) != 0 {
		t.Fatal("the relay signed a put-user for someone it refused")
	}
}

func TestAJoinGrantFromTheOwnerAdmits(t *testing.T) {
	// The other half: the point is not that nobody gets in, it is that getting
	// in is something somebody signed. Ada issues the invitation before the bot
	// has ever connected, which is the case a put-user cannot serve as well —
	// she can hand the grant over with the key.
	relay, ada, adaConn := workspace(t)
	bot := newActor(t, "bot")

	mustPublish(t, adaConn, ada, grant(bot.pubkey, policy.ResourceJoin, nil))

	botConn := relay.connect(t, bot)
	mustPublish(t, botConn, bot, joinRequest())
	waitForMembership(t, botConn, bot)

	// And membership means what it always meant.
	mustPublish(t, botConn, bot, chat("reporting for duty"))
}

func TestARevokedJoinGrantDoesNotAdmit(t *testing.T) {
	relay, ada, adaConn := workspace(t)
	bot := newActor(t, "bot")

	issued := mustPublish(t, adaConn, ada, grant(bot.pubkey, policy.ResourceJoin, nil))

	// Dated after the grant it withdraws, deliberately. An addressable event is
	// replaced by created_at, which has one-second resolution, so a revocation
	// published in the same second as its grant is resolved by id order — and
	// half the time the store keeps the grant and never hears the revocation.
	// This is the trap Grants.revoke in the SDK exists to avoid, and a test that
	// tripped over it would fail one run in two.
	revocation := grant(bot.pubkey, policy.ResourceJoin, func(body map[string]any) {
		body["revoked"] = true
		body["revoked_reason"] = "the key leaked"
	})
	revocation.CreatedAt = issued.CreatedAt + 1
	mustPublish(t, adaConn, ada, revocation)

	msg := publish(t, relay.connect(t, bot), bot, joinRequest())
	assertRejected(t, msg, "the key leaked")
}

func TestAnExpiredJoinGrantDoesNotAdmit(t *testing.T) {
	relay, ada, adaConn := workspace(t)
	bot := newActor(t, "bot")

	mustPublish(t, adaConn, ada, grant(bot.pubkey, policy.ResourceJoin, func(body map[string]any) {
		spec := body["grant"].(map[string]any)
		spec["expires_at"] = int64(nostr.Now()) - 60
	}))

	msg := publish(t, relay.connect(t, bot), bot, joinRequest())
	assertRejected(t, msg, "expired")
}

func TestAnExpiredGrantCannotBeRevivedByBackdatingTheRequest(t *testing.T) {
	// created_at is chosen by whoever publishes. If expiry were read against the
	// event's own clock rather than the relay's, every lapsed invitation would
	// still work for anyone willing to claim it is last week.
	relay, ada, adaConn := workspace(t)
	bot := newActor(t, "bot")

	mustPublish(t, adaConn, ada, grant(bot.pubkey, policy.ResourceJoin, func(body map[string]any) {
		spec := body["grant"].(map[string]any)
		spec["expires_at"] = int64(nostr.Now()) - 60
	}))

	backdated := joinRequest()
	backdated.CreatedAt = nostr.Now() - 300
	msg := publish(t, relay.connect(t, bot), bot, backdated)
	assertRejected(t, msg, "expired")
}

func TestAJoinGrantFromAPlainMemberDoesNotAdmit(t *testing.T) {
	// Mallory is inside the workspace and can publish a perfectly valid 38102.
	// If the relay honoured it, one compromised agent would be able to walk in
	// as many more as it liked — and membership would be back to self-service
	// with an extra step.
	relay, ada, adaConn := workspace(t)
	mallory, eve := newActor(t, "mallory"), newActor(t, "eve")
	admit(t, adaConn, ada, mallory)

	malloryConn := relay.connect(t, mallory)
	mustPublish(t, malloryConn, mallory, grant(eve.pubkey, policy.ResourceJoin, nil))

	msg := publish(t, relay.connect(t, eve), eve, joinRequest())
	assertRejected(t, msg, "not an owner or admin")
}

func TestAJoinGrantScopedToAnotherWorkspaceDoesNotAdmit(t *testing.T) {
	relay, ada, adaConn := workspace(t)
	bot := newActor(t, "bot")

	mustPublish(t, adaConn, ada, grant(bot.pubkey, policy.ResourceJoin, func(body map[string]any) {
		spec := body["grant"].(map[string]any)
		spec["scope"] = map[string]any{"group": "some-other-workspace"}
	}))

	msg := publish(t, relay.connect(t, bot), bot, joinRequest())
	assertRejected(t, msg, "scoped to group")
}

func TestAJoinGrantOfSomethingElseDoesNotAdmit(t *testing.T) {
	// Resource strings match exactly and never widen. `action:deploy` is a
	// capability to deploy, not a capability to be anywhere.
	relay, ada, adaConn := workspace(t)
	bot := newActor(t, "bot")

	mustPublish(t, adaConn, ada, grant(bot.pubkey, "action:deploy", nil))

	msg := publish(t, relay.connect(t, bot), bot, joinRequest())
	assertRejected(t, msg, "nobody has issued group:join")
}

func TestAJoinGrantWithMaxUsesIsNotHonoured(t *testing.T) {
	// A relay has no caller to ask how many times something has been used, so
	// honouring the grant would mean enforcing every field on it except the one
	// restricting it. Refusing says so out loud and names the field that works.
	relay, ada, adaConn := workspace(t)
	bot := newActor(t, "bot")

	mustPublish(t, adaConn, ada, grant(bot.pubkey, policy.ResourceJoin, func(body map[string]any) {
		spec := body["grant"].(map[string]any)
		spec["max_uses"] = 1
	}))

	msg := publish(t, relay.connect(t, bot), bot, joinRequest())
	assertRejected(t, msg, "max_uses")
}

func TestADemotedAdminsInvitationsStopWorking(t *testing.T) {
	// Authority is read at the moment of the check, not at the moment of issue.
	// The alternative is a grant that outlives the standing behind it — which is
	// precisely what happens when permissions are copied into a row.
	relay, ada, adaConn := workspace(t)
	deputy, eve := newActor(t, "deputy"), newActor(t, "eve")

	promotion := mustPublish(t, adaConn, ada, &nostr.Event{
		Kind: nostr.KindSimpleGroupPutUser,
		Tags: nostr.Tags{{"h", group}, {"p", deputy.pubkey, "admin"}},
	})
	waitForMembership(t, adaConn, deputy)

	deputyConn := relay.connect(t, deputy)
	mustPublish(t, deputyConn, deputy, grant(eve.pubkey, policy.ResourceJoin, nil))

	// An admin's invitation works, because an admin could have added eve by hand.
	eveConn := relay.connect(t, eve)
	mustPublish(t, eveConn, eve, joinRequest())
	waitForMembership(t, eveConn, eve)

	// The deputy signs one more invitation while they still can, then loses the
	// role. Dated a second after the promotion for the same reason the revocation
	// above is: two moderation events in one second are ordered by id, and a
	// replay that put the demotion first would pass this test by accident.
	frank := newActor(t, "frank")
	mustPublish(t, deputyConn, deputy, grant(frank.pubkey, policy.ResourceJoin, nil))

	demotion := &nostr.Event{
		Kind: nostr.KindSimpleGroupPutUser,
		Tags: nostr.Tags{{"h", group}, {"p", deputy.pubkey}},
	}
	demotion.CreatedAt = promotion.CreatedAt + 1
	mustPublish(t, adaConn, ada, demotion)
	waitFor(t, "the deputy to lose the admin role", func() bool {
		for _, list := range query(t, adaConn, nostr.Filter{
			Kinds: []int{39001},
			Tags:  nostr.TagMap{"d": []string{group}},
		}) {
			for _, tag := range list.Tags {
				if len(tag) > 1 && tag[0] == "p" && tag[1] == deputy.pubkey {
					return false
				}
			}
		}
		return true
	})

	msg := publish(t, relay.connect(t, frank), frank, joinRequest())
	assertRejected(t, msg, "not an owner or admin")
}

func TestTheRelayWillNotStartIfItAndTheProtocolDisagree(t *testing.T) {
	// The constants in the policy package are a second copy of
	// packages/protocol/src/resources.ts, and a resource name is matched exactly.
	// So the failure this guards against is not a rejected event: it is an
	// operator issuing `group:jion`, seeing a green tick, and finding the grantee
	// still locked out.
	published := protocol.RelayEnforced{
		Action:   policy.ActionInvoke,
		ScopeKey: policy.ScopeGroup,
		Resources: map[string]string{
			policy.ResourceJoin:         "admits the grantee",
			policy.ResourceThreadBudget: "sets a ceiling",
		},
	}
	if err := policy.ConfirmResourceNames(published); err != nil {
		t.Fatalf("the committed protocol should agree with the policy: %v", err)
	}

	cases := map[string]protocol.RelayEnforced{
		"a renamed resource": func() protocol.RelayEnforced {
			broken := published
			broken.Resources = map[string]string{"group:jion": "a typo"}
			return broken
		}(),
		"a different action": func() protocol.RelayEnforced {
			broken := published
			broken.Action = "use"
			return broken
		}(),
		"a different scope key": func() protocol.RelayEnforced {
			broken := published
			broken.ScopeKey = "workspace"
			return broken
		}(),
	}
	for name, broken := range cases {
		t.Run(name, func(t *testing.T) {
			if err := policy.ConfirmResourceNames(broken); err == nil {
				t.Fatal("the relay would have started")
			}
		})
	}

	// And the real file, which is what actually keeps the two in step.
	index, err := protocol.Load("../../packages/protocol/schemas")
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.ConfirmResourceNames(index.RelayEnforced); err != nil {
		t.Fatalf("schemas/index.json disagrees with internal/policy: %v", err)
	}
}

// --- the thread budget -------------------------------------------------------

func threadOp(root, body string) *nostr.Event {
	return &nostr.Event{
		Kind:    threads.KindThreadOp,
		Content: body,
		Tags: nostr.Tags{
			{"h", group},
			{"E", root},
			{"K", "11"},
			{"alt", "a thread op"},
		},
	}
}

const setBudget = `{"op":"set_budget","budget":{"usd":500}}`

func TestAMemberCannotSetAThreadBudget(t *testing.T) {
	// Budget exhaustion is half the runaway-agent backstop: it pauses the thread
	// and pings a human. An agent that can raise its own ceiling has a speed
	// bump, not a backstop, and the mechanism still reads as a safety feature to
	// everyone who has not checked who may move the number.
	relay, ada, adaConn := workspace(t)
	bot := newActor(t, "bot")
	admit(t, adaConn, ada, bot)

	root := mustPublish(t, adaConn, ada, thread("ship it"))

	msg := publish(t, relay.connect(t, bot), bot, threadOp(root.ID, setBudget))
	assertRejected(t, msg, "thread:budget")
}

func TestAGrantedMemberCanSetAThreadBudget(t *testing.T) {
	relay, ada, adaConn := workspace(t)
	bot := newActor(t, "bot")
	admit(t, adaConn, ada, bot)

	root := mustPublish(t, adaConn, ada, thread("ship it"))
	mustPublish(t, adaConn, ada, grant(bot.pubkey, policy.ResourceThreadBudget, nil))

	mustPublish(t, relay.connect(t, bot), bot, threadOp(root.ID, setBudget))
}

func TestAnOwnerNeedsNoGrantToSetABudget(t *testing.T) {
	// The role is where a grant's authority comes from. Making an owner issue
	// themselves one would add a step and no check.
	_, ada, adaConn := workspace(t)
	root := mustPublish(t, adaConn, ada, thread("ship it"))
	mustPublish(t, adaConn, ada, threadOp(root.ID, setBudget))
}

func TestTheOtherThreadOpsStayOpenToMembers(t *testing.T) {
	// Deliberately not gated. Status, assignee and title are how a workspace
	// coordinates, and a task board only administrators can touch is one every
	// team routes around with a grant wide enough to cover all four — leaving a
	// control that is in the threat model and not in the way.
	relay, ada, adaConn := workspace(t)
	bot := newActor(t, "bot")
	admit(t, adaConn, ada, bot)

	root := mustPublish(t, adaConn, ada, thread("ship it"))
	botConn := relay.connect(t, bot)

	mustPublish(t, botConn, bot, threadOp(root.ID, `{"op":"set_status","status":"working"}`))
	mustPublish(t, botConn, bot, threadOp(root.ID, `{"op":"set_title","title":"ship api 1.4.2"}`))
	mustPublish(t, botConn, bot, threadOp(root.ID, `{"op":"assign","assignee":null}`))
}
