// Package policy holds the Quorum-specific relay rules that sit on top of
// NIP-29 groups.
//
// The division of labour is deliberate. relay29 owns everything NIP-29 defines:
// membership, moderation, the relay-signed 39000-series metadata, private-group
// read control. This package owns only what the Quorum NIP adds. Folding the
// two together would make it impossible to say which behaviours a generic
// NIP-29 client can rely on — and that answer is the whole basis for claiming
// interoperability.
package policy

import (
	"context"
	"fmt"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"github.com/quorum-chat/quorum/apps/relay/internal/protocol"
)

// ValidateQuorumEvent enforces the Quorum envelope, and the body where it can.
//
// Both checks come from schemas/index.json rather than from Go source. See
// internal/protocol for why that matters.
func ValidateQuorumEvent(index *protocol.Index) func(context.Context, *nostr.Event) (bool, string) {
	return func(ctx context.Context, event *nostr.Event) (reject bool, msg string) {
		if err := index.ValidateEnvelope(event); err != nil {
			return true, "invalid: " + err.Error()
		}

		// Body validation is possible only when the relay can read the body.
		// On nip44 and mls channels content is ciphertext, and a relay that
		// insisted on parsing it would reject every event the moment a
		// workspace enabled encryption.
		if protocol.EncMode(event) != protocol.EncPlaintext {
			return false, ""
		}
		if err := index.ValidateBody(event); err != nil {
			return true, "invalid: " + err.Error()
		}
		return false, ""
	}
}

// RestrictToSupportedKinds rejects kinds this relay does not serve.
//
// The list comes from the protocol index, so it covers the borrowed kinds
// (chat, threads, comments, deletions) as well as the Quorum ones. NIP-29's own
// moderation and metadata kinds are added on top, because relay29 needs to
// accept them and they are not Quorum's to publish.
func RestrictToSupportedKinds(index *protocol.Index, alsoAllow []int) func(context.Context, *nostr.Event) (bool, string) {
	allowed := make(map[int]bool, len(alsoAllow))
	for _, kind := range alsoAllow {
		allowed[kind] = true
	}

	return func(ctx context.Context, event *nostr.Event) (reject bool, msg string) {
		if index.Supported(event.Kind) || allowed[event.Kind] {
			return false, ""
		}
		return true, fmt.Sprintf(
			"invalid: this relay does not serve kind %d; see its NIP-11 document for what it does serve",
			event.Kind,
		)
	}
}

// RestrictGroupCreation limits who may create a workspace.
//
// relay29 lets anyone create a group, which is the right default for a public
// NIP-29 relay and the wrong one here: Quorum is deployed one relay per
// workspace, and its groups accumulate approval records and capability grants.
// A stranger who can create a group on your relay owns a namespace inside your
// audit trail.
//
// An empty owner list keeps relay29's open behaviour, for local development.
// main.go says so out loud at startup rather than leaving it to be discovered.
func RestrictGroupCreation(owners []string) func(context.Context, *nostr.Event) (bool, string) {
	if len(owners) == 0 {
		return func(context.Context, *nostr.Event) (bool, string) { return false, "" }
	}
	allowed := make(map[string]bool, len(owners))
	for _, owner := range owners {
		allowed[owner] = true
	}

	return func(ctx context.Context, event *nostr.Event) (reject bool, msg string) {
		if event.Kind != nostr.KindSimpleGroupCreateGroup {
			return false, ""
		}
		if allowed[event.PubKey] {
			return false, ""
		}
		return true, "restricted: only this relay's owners may create workspaces"
	}
}

// RejectImplausibleTimestamps bounds created_at around the relay's clock.
//
// created_at is client-supplied and unverifiable, so this cannot make ordering
// trustworthy — that is what per-author counters and checkpoints are for. What
// it does prevent is one clearly-wrong clock burying every other event in a
// thread at the top or bottom of every client's view, which is a bad enough
// experience to be worth a crude bound.
func RejectImplausibleTimestamps(skew time.Duration) func(context.Context, *nostr.Event) (bool, string) {
	return func(ctx context.Context, event *nostr.Event) (reject bool, msg string) {
		drift := time.Since(event.CreatedAt.Time())
		if drift > skew {
			return true, fmt.Sprintf("invalid: created_at is %s in the past, limit is %s", drift.Truncate(time.Second), skew)
		}
		if -drift > skew {
			return true, fmt.Sprintf("invalid: created_at is %s in the future, limit is %s", (-drift).Truncate(time.Second), skew)
		}
		return false, ""
	}
}

// RejectRelaySignedForgeries stops anyone else publishing under the relay's key.
//
// Kind 38101 thread_state and kind 8108 checkpoint are meaningful precisely
// because the relay signed them: a checkpoint is the relay committing to what it
// holds, and a forged one would let a third party manufacture proof about
// somebody else's relay. Signature verification alone would not catch this —
// the events would be perfectly valid, just not from who they claim.
func RejectRelaySignedForgeries(relayPubkey string, kinds []int) func(context.Context, *nostr.Event) (bool, string) {
	reserved := make(map[int]bool, len(kinds))
	for _, kind := range kinds {
		reserved[kind] = true
	}

	return func(ctx context.Context, event *nostr.Event) (reject bool, msg string) {
		if !reserved[event.Kind] {
			return false, ""
		}
		if event.PubKey == relayPubkey {
			return false, ""
		}
		return true, fmt.Sprintf(
			"invalid: kind %d is signed by the relay; publish a kind 8109 thread_op instead",
			event.Kind,
		)
	}
}
