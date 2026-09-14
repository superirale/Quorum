package policy

import (
	"context"
	"encoding/json"

	"github.com/nbd-wtf/go-nostr"

	"github.com/quorum-chat/quorum/apps/relay/internal/protocol"
	"github.com/quorum-chat/quorum/apps/relay/internal/threads"
)

// RejectWorkOnPausedThread stops new work in a thread that is paused.
//
// # Why this exists
//
// A budget that only pauses a thread is a label. The thread's 38101 says
// `paused`, the agent that is looping does not read it, and the spend continues
// — which means the safety valve the plan describes ("budget exhaustion →
// auto-pause → ping a human") would announce the problem rather than stop it.
// This is the half that bites.
//
// # What it refuses, and what it deliberately does not
//
// Only a kind 8101 entering or continuing work: `proposed` and `running`. Every
// other transition is allowed through, because each of them is a way for work
// already underway to *stop*:
//
//   - `succeeded` / `failed` / `cancelled` / `denied` close a chain. Refusing a
//     terminal event would leave an action that ran forever in the record, and
//     would strand an agent that cannot report what it already did.
//   - `awaiting_approval` spends nothing and is how an action parks.
//
// Thread ops (8109) are never refused here — a `set_status` back to `working`
// and a `set_budget` raising the ceiling are precisely how a human gets out of
// this state, and an `add_spend` is how the true total gets told. Nor is chat:
// kinds 9 and 1111 are how the humans and agents in a paused thread work out
// what to do about it, and a relay that silenced a thread it had paused would
// turn a budget alert into an outage.
//
// # Why it is safe to be a relay-side check
//
// Same as every other policy in this package: it is defence in depth, and the
// SDK checks the budget before it proposes. On an encrypted channel there is no
// status to read and this policy stands down entirely, so it can never be the
// only thing enforcing a budget.
//
// # Why a missing projection allows
//
// If no 38101 exists for the thread, nobody has ever changed its state, so it
// is open by definition. That is not the fail-open compromise
// RejectUnaskedApprovals makes — there is no hidden evidence here, because the
// projection is written by this relay and only this relay. A thread whose state
// lives on another relay was never paused on this one.
func RejectWorkOnPausedThread(store Lookup, relayPubkey string) func(context.Context, *nostr.Event) (bool, string) {
	return func(ctx context.Context, event *nostr.Event) (reject bool, msg string) {
		if event.Kind != KindAction {
			return false, ""
		}
		if protocol.EncMode(event) != protocol.EncPlaintext {
			return false, ""
		}
		if status := actionStatus(event); status != "proposed" && status != "running" {
			return false, ""
		}
		thread := protocol.RootEvent(event)
		if thread == "" {
			return false, ""
		}

		state := threadState(ctx, store, relayPubkey, thread)
		if state == nil || state.Status != "paused" {
			return false, ""
		}
		if threads.BudgetExhausted(state.Spent, state.Budget) {
			// Worth distinguishing from a human pressing pause: it tells the
			// agent's operator that resuming alone will not hold, and it tells a
			// human reading the OK message why the thread stopped without
			// anybody having stopped it.
			return true, "restricted: this thread has spent its budget and is paused; raise the budget to continue"
		}
		return true, "restricted: this thread is paused; resume it before starting more work"
	}
}

// threadState reads the relay's own projection for a thread.
func threadState(ctx context.Context, store Lookup, relayPubkey, thread string) *threads.State {
	if !nostr.IsValid32ByteHex(thread) {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()

	results, err := store.QueryEvents(ctx, nostr.Filter{
		Kinds:   []int{threads.KindThreadState},
		Authors: []string{relayPubkey},
		Tags:    nostr.TagMap{"d": []string{thread}},
		Limit:   1,
	})
	if err != nil {
		return nil
	}

	// Newest wins, and the channel is drained either way: a limit of 1 is a hint
	// the store may exceed, and abandoning the channel leaks the goroutine
	// feeding it.
	var latest *nostr.Event
	for event := range results {
		if latest == nil || event.CreatedAt > latest.CreatedAt {
			latest = event
		}
	}
	if latest == nil {
		return nil
	}

	var state threads.State
	if json.Unmarshal([]byte(latest.Content), &state) != nil {
		return nil
	}
	return &state
}
