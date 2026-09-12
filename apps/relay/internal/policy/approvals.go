package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"github.com/quorum-chat/quorum/apps/relay/internal/protocol"
)

// Quorum kinds these policies care about.
const (
	KindAction           = 8101
	KindApprovalRequest  = 8102
	KindApprovalResponse = 8103
)

// lookupTimeout bounds a single store read. A policy that can block forever is
// a way to stall the relay by publishing.
const lookupTimeout = 2 * time.Second

// Lookup is the slice of the event store these policies need.
type Lookup interface {
	QueryEvents(ctx context.Context, filter nostr.Filter) (chan *nostr.Event, error)
}

// RejectUnaskedApprovals refuses an approval_response the request it answers
// does not support.
//
// # This is defence in depth, and only that
//
// The authoritative check happens at the resource: the deploy tool verifies the
// signature chain itself, offline, before it does anything. That has to be true
// — the relay may be someone else's, may be generic, may be compromised — and
// anything here is a second opinion, never the thing standing between an agent
// and production.
//
// What it buys is that garbage never enters the log in the first place. An
// unasked approval sitting in a channel is a document someone will eventually
// read as consent: it renders in a client, it turns up in a context pack, it
// looks exactly like the real thing to anyone not running a verifier. Refusing
// it at the door means the only approvals in the record are ones somebody asked
// for.
//
// # Why it fails open when the request is missing
//
// If the relay does not hold the referenced request, this accepts. That is
// deliberate. Events legitimately travel between relays — a client mirroring an
// approval to a second relay, a relay restored from a partial backup — and a
// relay that demanded the whole chain be local would reject correct events and
// teach operators that Quorum needs one true relay. The audit in the SDK has no
// such excuse and makes no such allowance: to it, an approval whose request is
// absent simply does not count.
func RejectUnaskedApprovals(index *protocol.Index, store Lookup) func(context.Context, *nostr.Event) (bool, string) {
	return func(ctx context.Context, event *nostr.Event) (reject bool, msg string) {
		if event.Kind != KindApprovalResponse {
			return false, ""
		}

		requestID := protocol.Parent(event)
		if requestID == "" {
			return true, "invalid: an approval_response must `e`-tag the approval_request it answers"
		}
		request := fetch(ctx, store, requestID)
		if request == nil {
			return false, ""
		}

		if request.Kind != KindApprovalRequest {
			return true, fmt.Sprintf(
				"invalid: this approval_response answers a kind %d event, not an approval_request",
				request.Kind,
			)
		}
		if protocol.Group(request) != protocol.Group(event) {
			return true, "invalid: an approval_response must be in the same channel as its request"
		}

		// The rule that makes a signature mean something. Without it, any member
		// of the workspace can approve anything, and the event proves only that
		// somebody said yes.
		asked := false
		for _, pubkey := range index.Addressees(request) {
			if pubkey == event.PubKey {
				asked = true
				break
			}
		}
		if !asked {
			return true, "restricted: this approval_request did not ask you"
		}

		// Bodies are readable only on plaintext channels. On an encrypted one the
		// digest check is the SDK's alone, which is the same trade every
		// relay-side check in this package makes.
		if protocol.EncMode(event) != protocol.EncPlaintext ||
			protocol.EncMode(request) != protocol.EncPlaintext {
			return false, ""
		}
		wanted := inputDigest(request)
		if wanted != "" && inputDigest(event) != wanted {
			// An approval that does not name what it approved is an approval of
			// the action's *name* — which would make one yes to deploy.production
			// a standing yes to every future deploy.
			return true, "invalid: an approval_response must echo the input_digest it was asked to approve"
		}
		return false, ""
	}
}

// RejectForeignActionTransitions keeps one author in charge of one action.
//
// An action's id is the id of its `proposed` event, and every later event in
// the chain carries that id in an `action` tag. Nothing about that stops a
// stranger tagging their own `succeeded` onto somebody else's deploy — the
// event is perfectly well-formed and perfectly well-signed, just not by anyone
// with standing to say it happened.
//
// Approval requests are held to the same rule: an action gated by a request
// somebody else wrote is gated by a question the agent never asked, with
// approvers the agent never chose.
//
// Fails open on a proposal this relay does not hold, for the reason given on
// RejectUnaskedApprovals.
func RejectForeignActionTransitions(store Lookup) func(context.Context, *nostr.Event) (bool, string) {
	return func(ctx context.Context, event *nostr.Event) (reject bool, msg string) {
		// Deliberately not 8103: an approval_response carries the action tag and
		// is written by the approver, who is precisely not the proposer.
		if event.Kind != KindAction && event.Kind != KindApprovalRequest {
			return false, ""
		}
		actionID := protocol.ActionID(event)
		if actionID == "" {
			return false, ""
		}

		proposed := fetch(ctx, store, actionID)
		if proposed == nil {
			return false, ""
		}
		if proposed.Kind != KindAction {
			return true, fmt.Sprintf(
				"invalid: an `action` tag must name a kind %d proposal, but names a kind %d event",
				KindAction, proposed.Kind,
			)
		}
		if proposed.PubKey != event.PubKey {
			return true, "restricted: only the pubkey that proposed an action may advance it"
		}
		if protocol.EncMode(proposed) == protocol.EncPlaintext && actionStatus(proposed) != "proposed" {
			// Pointing the tag at a transition rather than at the proposal would
			// split one action into two chains that each look complete.
			return true, "invalid: an `action` tag must name the chain's `proposed` event"
		}
		return false, ""
	}
}

// fetch reads one event by id, or nil if this relay does not have it.
func fetch(ctx context.Context, store Lookup, id string) *nostr.Event {
	if !nostr.IsValid32ByteHex(id) {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()

	results, err := store.QueryEvents(ctx, nostr.Filter{IDs: []string{id}, Limit: 1})
	if err != nil {
		return nil
	}
	// Drained to completion even once the answer is known: abandoning the
	// channel leaks the goroutine feeding it.
	var found *nostr.Event
	for event := range results {
		if found == nil {
			found = event
		}
	}
	return found
}

func inputDigest(event *nostr.Event) string {
	var body struct {
		InputDigest string `json:"input_digest"`
	}
	if json.Unmarshal([]byte(event.Content), &body) != nil {
		return ""
	}
	return body.InputDigest
}

func actionStatus(event *nostr.Event) string {
	var body struct {
		Status string `json:"status"`
	}
	if json.Unmarshal([]byte(event.Content), &body) != nil {
		return ""
	}
	return body.Status
}
