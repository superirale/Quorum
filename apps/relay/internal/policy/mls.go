package policy

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nbd-wtf/go-nostr"

	"github.com/quorum-chat/quorum/apps/relay/internal/protocol"
)

const (
	KindMlsWelcome    = 8111
	KindMlsCommit     = 8112
	KindMlsKeyPackage = 30443
)

// The `enc=mls` arm of this relay, which contains no MLS code and is not going
// to.
//
// That is the property worth protecting rather than a limitation to apologise
// for. RFC 9420 assumes a "delivery service" that stores, routes and orders
// messages it cannot read, and every rule in this file is one of those three
// jobs done from the envelope and from one JSON field that Quorum deliberately
// leaves in the clear. A relay that parsed MLSMessages would be a second
// implementation of a wire format, in a second language, that must agree with
// `ts-mls` forever — and the first disagreement would present as a workspace
// whose members cannot talk to each other.
//
// So the checks here are the ones a delivery service can make honestly:
//
//   - a KeyPackage lands in the slot that will retire it;
//   - a Welcome names exactly one member, so the addressing filter finds it;
//   - at most one commit per group per epoch, so members do not split.
//
// Everything else — whether the ciphertext opens, whether the committer was in
// the tree, whether the credential matches the pubkey — is checked by members,
// because only members can check it. See "Membership on an `mls` channel is two
// lists" in the spec: the relay decides admission and the ratchet decides
// readership, and neither may be inferred from the other.

// RequireKeyPackageSlot refuses a kind 30443 whose `d` is not its channel.
//
// Marmot randomises the identifier of a KeyPackage event, on the grounds that a
// derived one would leak which group a member is trying to join. A Quorum 30443
// publishes the channel in its `h` tag anyway — it has to, or this relay could
// neither route nor admit it — so randomness protects nothing here, and the
// derived slot buys something real: `30443:<pubkey>:<channel>` names exactly one
// member's current KeyPackage, and addressable replacement does the single-use
// bookkeeping for free.
//
// Which is the whole reason this check exists. A package in some other slot is
// not merely untidy: it still answers the `#h` query an inviter makes, so it
// looks fetchable and usable, but the member's *next* KeyPackage lands somewhere
// else and never replaces it. The spent one stays live forever, an inviter picks
// it up and commits an Add against a private half the joiner has long discarded,
// and the outcome is a member sitting in the ratchet tree who can never read a
// word of the channel they were told they had joined.
//
// Refused here as well as in the SDK because the relay is the only party every
// client passes through, and the failure it prevents is silent at every other
// layer.
func RequireKeyPackageSlot() func(context.Context, *nostr.Event) (bool, string) {
	return func(ctx context.Context, event *nostr.Event) (reject bool, msg string) {
		if event.Kind != KindMlsKeyPackage {
			return false, ""
		}
		group := protocol.Group(event)
		if group == "" {
			return true, "invalid: a KeyPackage must name its channel in an `h` tag"
		}
		if slot := identifier(event); slot != group {
			return true, fmt.Sprintf(
				"invalid: a KeyPackage's `d` must be the channel id, but this one says %q in #%s; "+
					"a package in another slot is never retired by the one that replaces it",
				slot, group)
		}
		return false, ""
	}
}

// RequireOneWelcomeRecipient refuses a kind 8111 addressed to more than one
// member.
//
// The protocol index already requires *at least* one, because a Welcome nobody
// is addressed by is invisible to the `#p` filter every reader uses. This is the
// other end of the same rule, and it is a tag check rather than a body check on
// purpose: it has to keep working on a channel whose bodies this relay cannot
// read.
//
// One commit produces one Welcome and the committer publishes it once per
// recipient, so a second `to` tag is always a mistake — and a quiet one. A
// Welcome carries key material sealed to a single member's KeyPackage, so the
// other addressee fetches it, fails to find their own package among its secrets,
// and is required by the spec to treat that as "not mine" rather than as an
// error. They are told nothing. The member who was owed a Welcome waits for one
// that was, from their point of view, never sent.
func RequireOneWelcomeRecipient(index *protocol.Index) func(context.Context, *nostr.Event) (bool, string) {
	return func(ctx context.Context, event *nostr.Event) (reject bool, msg string) {
		if event.Kind != KindMlsWelcome {
			return false, ""
		}
		if to := index.Addressees(event); len(to) > 1 {
			return true, fmt.Sprintf(
				"invalid: a Welcome carries key material for one member and this one is addressed to %d; "+
					"publish one per recipient, or the others cannot tell \"not mine\" from \"tampered with\"",
				len(to))
		}
		return false, ""
	}
}

// SerialiseCommits keeps at most one kind 8112 per group per epoch.
//
// Two members holding the same epoch may both commit — adding different people,
// at the same moment, neither having seen the other — and MLS allows exactly one
// of those to become the group's next epoch. Nothing in the protocol picks the
// winner; a delivery service does, which under Quorum means this relay for the
// channels it hosts and, for everyone else, the spec's deterministic tie-break
// on the lowest event id.
//
// First stored wins, which is arbitrary and is meant to be: the property that
// matters is that every member sees the same one, not which one it is. The loser
// is stranded at their old epoch by the ordinary "a commit was missed" rule and
// has to be re-added — the correct outcome rather than a degradation of it,
// because a committer whose commit was refused has not moved, and knows it.
//
// # It reads the epoch from the body, and that is the design
//
// A commit's epoch is also inside the MLSMessage, where reading it would require
// an MLS wire parser in Go. Quorum puts it in the clear in the JSON body for
// precisely this check, which is what lets the entire `mls` arm of this relay be
// the three refusals in this file. The number is not trusted for anything but
// serialisation: a committer that lies about its epoch loses to, or blocks, a
// slot it cannot use, since the members who apply commits read the epoch out of
// the ciphertext where a liar cannot reach it.
//
// # Bounded, and honest about it
//
// The scan is over the newest commits in the channel, not all of them. A channel
// with more commits than the bound could admit a second 8112 for an epoch buried
// below it. That is acceptable exactly because the relay rule is a SHOULD and
// never the thing correctness rests on: every Quorum event is valid on any
// generic relay, which serialises nothing at all, so a receiver must settle ties
// deterministically regardless of who is carrying the channel.
func SerialiseCommits(store Lookup) func(context.Context, *nostr.Event) (bool, string) {
	const scan = 500

	return func(ctx context.Context, event *nostr.Event) (reject bool, msg string) {
		if event.Kind != KindMlsCommit {
			return false, ""
		}
		group := protocol.Group(event)
		if group == "" {
			return true, "invalid: a commit must name its channel in an `h` tag"
		}
		epoch, ok := commitEpoch(event)
		if !ok {
			// The body is schema-validated upstream, because 8112 stays in the
			// clear on an encrypted channel — so reaching this means the event
			// bypassed that, and a commit whose epoch cannot be read is one this
			// relay cannot order. Storing it would mean silently giving up the
			// one job it has here.
			return true, "invalid: a commit must state the epoch it applies to, in the clear, " +
				"as an integer `epoch` field; this relay orders commits and cannot read MLS"
		}

		lookup, cancel := context.WithTimeout(ctx, lookupTimeout)
		defer cancel()

		results, err := store.QueryEvents(lookup, nostr.Filter{
			Kinds: []int{KindMlsCommit},
			Tags:  nostr.TagMap{protocol.TagGroup: []string{group}},
			Limit: scan,
		})
		if err != nil {
			// Fail open, for the same reason readPolicy does: an unreachable
			// store is already an outage, and turning it into "no member may
			// change the membership of any channel" adds an outage of its own
			// while catching nothing a tie-break would not.
			return false, ""
		}

		for stored := range results {
			// An identical event arriving twice is a mirror or a backfill, not a
			// race. Refusing it would make this relay reject its own history the
			// first time somebody re-broadcast it, which on a protocol whose ids
			// are content hashes is a normal Tuesday.
			if stored.ID == event.ID {
				continue
			}
			if at, ok := commitEpoch(stored); ok && at == epoch {
				return true, fmt.Sprintf(
					"restricted: #%s already has a commit for epoch %d (%s); "+
						"two members committed from the same epoch and only one can win, "+
						"so this committer is still at %d and must be re-added",
					group, epoch, stored.ID[:8], epoch)
			}
		}
		return false, ""
	}
}

// commitEpoch reads the one field of an 8112 this relay understands.
func commitEpoch(event *nostr.Event) (int, bool) {
	var body struct {
		Epoch *int `json:"epoch"`
	}
	if json.Unmarshal([]byte(event.Content), &body) != nil || body.Epoch == nil || *body.Epoch < 0 {
		return 0, false
	}
	return *body.Epoch, true
}
