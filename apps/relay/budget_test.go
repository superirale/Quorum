package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/nbd-wtf/go-nostr"

	"github.com/quorum-chat/quorum/apps/relay/internal/threads"
)

// Cost, budgets, and the pause that has to actually stop something.
//
// The plan names budget exhaustion as the backstop for a runaway agent:
// exhaustion pauses the thread and pings a human. A pause that only changes a
// word in a projection is a label — the agent looping in that thread never
// reads its own task's status, and the spend continues. So these tests are
// about the second half: that a paused thread refuses new work, and that
// everything a human or an agent needs in order to get *out* of the state still
// goes through.

// spend builds the `add_spend` op an SDK publishes after a turn of work.
func spend(root string, cost map[string]any) *nostr.Event {
	body, _ := json.Marshal(map[string]any{"op": "add_spend", "cost": cost})
	return threadOp(root, string(body))
}

// paused waits for the relay's projection to say the thread is paused, which is
// the state the policy reads. Folding happens in an OnEventSaved hook, so the
// OK for the op that caused it arrives first.
func awaitStatus(t *testing.T, conn *nostr.Relay, root, want string) threads.State {
	t.Helper()

	var state threads.State
	waitFor(t, fmt.Sprintf("the thread to be %s", want), func() bool {
		for _, event := range query(t, conn, nostr.Filter{
			Kinds: []int{threads.KindThreadState},
			Tags:  nostr.TagMap{"h": []string{group}, "d": []string{root}},
		}) {
			var body threads.State
			if json.Unmarshal([]byte(event.Content), &body) != nil {
				continue
			}
			if body.Status == want {
				state = body
				return true
			}
		}
		return false
	})
	return state
}

// The whole M8 claim in one test: an agent reports what it spent, crosses the
// ceiling somebody set for it, and the next thing it tries to do is refused.
func TestAnAgentThatSpendsItsBudgetIsStopped(t *testing.T) {
	relay, ada, adaConn := workspace(t)
	agent := newActor(t, "agent")
	admit(t, adaConn, ada, agent)

	root := mustPublish(t, adaConn, ada, thread("summarise the backlog"))
	mustPublish(t, adaConn, ada, threadOp(root.ID, `{"op":"set_budget","budget":{"tokens":1000}}`))

	agentConn := relay.connect(t, agent)
	mustPublish(t, agentConn, agent, spend(root.ID, map[string]any{"tokens_in": 400, "tokens_out": 200}))

	// Under the ceiling, work continues. Without this half the test would pass
	// against a relay that refuses every action in every thread.
	mustPublish(t, agentConn, agent, action(root.ID, map[string]any{
		"name": "summarise", "status": "proposed", "summary": "read the next page",
	}))

	mustPublish(t, agentConn, agent, spend(root.ID, map[string]any{"tokens_in": 300, "tokens_out": 300}))
	state := awaitStatus(t, agentConn, root.ID, "paused")
	if got := *state.Spent.TokensIn + *state.Spent.TokensOut; got != 1200 {
		t.Errorf("the relay totalled %d tokens, want 1200", got)
	}

	msg := publish(t, agentConn, agent, action(root.ID, map[string]any{
		"name": "summarise", "status": "proposed", "summary": "read the next page",
	}))
	assertRejected(t, msg, "budget")
}

// A pause is a pause however it got there. A human hitting the button on a
// thread that is costing too much must stop the same work the ceiling would.
func TestAPausedThreadRefusesNewWork(t *testing.T) {
	relay, ada, adaConn := workspace(t)
	agent := newActor(t, "agent")
	admit(t, adaConn, ada, agent)

	root := mustPublish(t, adaConn, ada, thread("summarise the backlog"))
	mustPublish(t, adaConn, ada, threadOp(root.ID, `{"op":"set_status","status":"paused"}`))

	agentConn := relay.connect(t, agent)
	awaitStatus(t, agentConn, root.ID, "paused")

	msg := publish(t, agentConn, agent, action(root.ID, map[string]any{
		"name": "summarise", "status": "proposed", "summary": "keep going",
	}))
	assertRejected(t, msg, "paused")

	// A chain whose proposal this relay never stored, because the paragraph
	// above is it being refused. The transition policies fail open on an action
	// they do not hold, so what this event meets is the budget policy.
	running := transition(root.ID, strings.Repeat("a1", 32), "running")
	assertRejected(t, publish(t, agentConn, agent, running), "paused")
}

// Everything that is a way out of the state, or a way to close down work that
// was already in flight. A policy that refused these would be an outage with a
// budget attached: the agent could not report what it had already done, the
// humans could not talk about it, and the thread could not be resumed.
func TestAPausedThreadStillAcceptsTheWayOut(t *testing.T) {
	relay, ada, adaConn := workspace(t)
	agent := newActor(t, "agent")
	admit(t, adaConn, ada, agent)

	root := mustPublish(t, adaConn, ada, thread("summarise the backlog"))
	proposal := mustPublish(t, adaConn, ada, action(root.ID, map[string]any{
		"name": "summarise", "status": "proposed", "summary": "the work already underway",
	}))
	mustPublish(t, adaConn, ada, threadOp(root.ID, `{"op":"set_status","status":"paused"}`))

	agentConn := relay.connect(t, agent)
	awaitStatus(t, agentConn, root.ID, "paused")

	// The agent finishes what it had started and says what it cost.
	mustPublish(t, adaConn, ada, transition(root.ID, proposal.ID, "cancelled"))
	mustPublish(t, agentConn, agent, spend(root.ID, map[string]any{"tokens_in": 12}))

	// The humans work out what to do about it.
	mustPublish(t, agentConn, agent, chat("I have stopped; this needs a bigger budget"))

	// And Ada gets the thread moving again.
	mustPublish(t, adaConn, ada, threadOp(root.ID, `{"op":"set_budget","budget":{"tokens":100000}}`))
	mustPublish(t, adaConn, ada, threadOp(root.ID, `{"op":"set_status","status":"working"}`))
	awaitStatus(t, adaConn, root.ID, "working")

	mustPublish(t, agentConn, agent, action(root.ID, map[string]any{
		"name": "summarise", "status": "proposed", "summary": "back to it",
	}))
}

// The negative control for the whole file: an ordinary thread is untouched.
func TestWorkInARunningThreadIsNotRefused(t *testing.T) {
	relay, ada, adaConn := workspace(t)
	agent := newActor(t, "agent")
	admit(t, adaConn, ada, agent)

	root := mustPublish(t, adaConn, ada, thread("summarise the backlog"))
	agentConn := relay.connect(t, agent)

	// No budget at all, and a spend far larger than any of the ceilings the
	// other tests use. An empty budget must not read as a ceiling of zero.
	mustPublish(t, agentConn, agent, spend(root.ID, map[string]any{"tokens_in": 5_000_000}))
	mustPublish(t, agentConn, agent, action(root.ID, map[string]any{
		"name": "summarise", "status": "proposed", "summary": "carry on",
	}))
}
