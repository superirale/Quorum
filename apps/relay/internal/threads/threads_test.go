package threads

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/nbd-wtf/go-nostr"

	"github.com/quorum-chat/quorum/apps/relay/internal/protocol"
)

const schemaDir = "../../../../packages/protocol/schemas"

// memoryStore is the smallest thing that behaves like the eventstore for the
// two calls the projector makes. Addressable replacement is keyed the way the
// real store keys it: kind + author + `d`.
type memoryStore struct {
	mu     sync.Mutex
	events map[string]*nostr.Event
}

func newStore() *memoryStore { return &memoryStore{events: map[string]*nostr.Event{}} }

func coordinate(event *nostr.Event) string {
	return fmt.Sprintf("%d:%s:%s", event.Kind, event.PubKey, event.Tags.GetD())
}

// ReplaceEvent keeps the real store's rule rather than the obvious one: an
// addressable event is replaced only by a *newer* one, and same-second ties are
// broken by NIP-01's lowest id. A fake that overwrites unconditionally would
// hide the exact defect this rule causes — see
// TestEachProjectionIsNewerThanTheLast.
func (s *memoryStore) ReplaceEvent(ctx context.Context, event *nostr.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if previous, ok := s.events[coordinate(event)]; ok && !isOlder(previous, event) {
		return nil
	}
	s.events[coordinate(event)] = event
	return nil
}

// isOlder is eventstore/internal.IsOlder, copied because it is unexported.
func isOlder(previous, next *nostr.Event) bool {
	return previous.CreatedAt < next.CreatedAt ||
		(previous.CreatedAt == next.CreatedAt && previous.ID > next.ID)
}

func (s *memoryStore) QueryEvents(ctx context.Context, filter nostr.Filter) (chan *nostr.Event, error) {
	s.mu.Lock()
	matches := []*nostr.Event{}
	for _, event := range s.events {
		if filter.Matches(event) {
			matches = append(matches, event)
		}
	}
	s.mu.Unlock()

	// Deliberately unbuffered and produced on a goroutine, like the real store:
	// a consumer that abandons the channel leaks this goroutine, which is the
	// bug current() has to avoid.
	out := make(chan *nostr.Event)
	go func() {
		defer close(out)
		for _, event := range matches {
			out <- event
		}
	}()
	return out, nil
}

type recorder struct {
	mu     sync.Mutex
	events []*nostr.Event
}

func (r *recorder) BroadcastEvent(event *nostr.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events)
}

type harness struct {
	projector *Projector
	store     *memoryStore
	published *recorder
	author    string
	thread    string
}

func setup(t *testing.T) *harness {
	t.Helper()

	index, err := protocol.Load(schemaDir)
	if err != nil {
		t.Fatalf("loading the protocol index: %v", err)
	}
	store := newStore()
	published := &recorder{}

	projector, err := New(index, store, published, nostr.GeneratePrivateKey())
	if err != nil {
		t.Fatalf("building the projector: %v", err)
	}

	return &harness{
		projector: projector,
		store:     store,
		published: published,
		author:    nostr.GeneratePrivateKey(),
		thread:    "0000000000000000000000000000000000000000000000000000000000000abc",
	}
}

// op signs a kind 8109 the way a client would and folds it.
func (h *harness) op(t *testing.T, body Op) *nostr.Event {
	t.Helper()

	content, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshalling the op: %v", err)
	}
	event := &nostr.Event{
		Kind:      KindThreadOp,
		CreatedAt: nostr.Now(),
		Content:   string(content),
		Tags: nostr.Tags{
			{protocol.TagRootEvent, h.thread},
			{protocol.TagRootKind, "11"},
			{protocol.TagGroup, "payments"},
			{protocol.TagAlt, "thread op"},
		},
	}
	if err := event.Sign(h.author); err != nil {
		t.Fatalf("signing the op: %v", err)
	}
	h.projector.Fold(context.Background(), event)
	return event
}

func (h *harness) state(t *testing.T) State {
	t.Helper()

	stored := h.store.events[fmt.Sprintf("%d:%s:%s", KindThreadState, h.projector.PublicKey(), h.thread)]
	if stored == nil {
		t.Fatal("no thread state was written")
	}
	var state State
	if err := json.Unmarshal([]byte(stored.Content), &state); err != nil {
		t.Fatalf("the projected state is not valid JSON: %v", err)
	}
	return state
}

func TestOpsFoldIntoState(t *testing.T) {
	h := setup(t)

	assignee := "b" + "0000000000000000000000000000000000000000000000000000000000001"
	h.op(t, Op{Op: "set_status", Status: "working"})
	h.op(t, Op{Op: "assign", Assignee: &assignee})
	h.op(t, Op{Op: "set_title", Title: "deploy api v1.4.2"})

	state := h.state(t)
	if state.Status != "working" {
		t.Errorf("status is %q, want working", state.Status)
	}
	if state.Assignee == nil || *state.Assignee != assignee {
		t.Errorf("assignee is %v, want %s", state.Assignee, assignee)
	}
	if state.Title != "deploy api v1.4.2" {
		t.Errorf("title is %q", state.Title)
	}
	if len(state.FoldedFrom) != 3 {
		t.Errorf("folded_from lists %d ops, want 3", len(state.FoldedFrom))
	}
}

// The projection is only trustworthy if it can be recomputed, and it can only
// be recomputed if it names its inputs. This is the property that keeps the
// relay from becoming an authority on what a task says.
func TestFoldedFromNamesEveryOpInOrder(t *testing.T) {
	h := setup(t)

	first := h.op(t, Op{Op: "set_status", Status: "working"})
	second := h.op(t, Op{Op: "set_status", Status: "blocked"})

	state := h.state(t)
	want := []string{first.ID, second.ID}
	if len(state.FoldedFrom) != len(want) {
		t.Fatalf("folded_from is %v, want %v", state.FoldedFrom, want)
	}
	for i, id := range want {
		if state.FoldedFrom[i] != id {
			t.Errorf("folded_from[%d] is %s, want %s", i, state.FoldedFrom[i], id)
		}
	}
}

// A no-op op must not produce a new state event. Otherwise every duplicate
// delivery rewrites the addressable event and every subscriber gets woken for
// a change that did not happen.
func TestRedundantOpsDoNotRepublish(t *testing.T) {
	h := setup(t)

	h.op(t, Op{Op: "set_status", Status: "working"})
	if got := h.published.count(); got != 1 {
		t.Fatalf("published %d events after the first op, want 1", got)
	}

	h.op(t, Op{Op: "set_status", Status: "working"})
	if got := h.published.count(); got != 1 {
		t.Errorf("published %d events after a redundant op, want 1", got)
	}
}

// This relay's body schema is a oneOf over the known ops, so an unknown op
// never reaches the projector here. It does on a generic relay, which validates
// nothing and where clients fold locally with this same logic — and adding an
// op is only a MINOR bump, so that case is expected rather than hypothetical.
func TestUnknownOpsAreIgnored(t *testing.T) {
	h := setup(t)

	h.op(t, Op{Op: "set_status", Status: "working"})
	h.op(t, Op{Op: "set_vibe", Status: "cosmic"})

	state := h.state(t)
	if state.Status != "working" {
		t.Errorf("an unknown op changed the status to %q", state.Status)
	}
	if len(state.FoldedFrom) != 1 {
		t.Errorf("an unknown op was recorded in folded_from: %v", state.FoldedFrom)
	}
}

func TestNonThreadOpEventsAreIgnored(t *testing.T) {
	h := setup(t)

	chat := &nostr.Event{Kind: 9, Content: "hello", Tags: nostr.Tags{{protocol.TagGroup, "payments"}}}
	if err := chat.Sign(h.author); err != nil {
		t.Fatal(err)
	}
	h.projector.Fold(context.Background(), chat)

	if got := h.published.count(); got != 0 {
		t.Errorf("folding a kind 9 published %d events", got)
	}
}

func TestOpsWithoutAThreadAreIgnored(t *testing.T) {
	h := setup(t)

	orphan := &nostr.Event{
		Kind:      KindThreadOp,
		CreatedAt: nostr.Now(),
		Content:   `{"op":"set_status","status":"working"}`,
		Tags:      nostr.Tags{{protocol.TagGroup, "payments"}},
	}
	if err := orphan.Sign(h.author); err != nil {
		t.Fatal(err)
	}
	h.projector.Fold(context.Background(), orphan)

	if got := h.published.count(); got != 0 {
		t.Errorf("an op with no `E` tag produced %d events", got)
	}
}

// folded_from is an audit list inside a replaceable event, so it cannot grow
// forever. Losing the oldest ids is the right trade: they are still fetchable
// from the relay by thread, and the alternative is a state event that grows
// without bound on a long-running task.
func TestFoldedFromIsBounded(t *testing.T) {
	h := setup(t)

	for i := 0; i < maxFoldedFrom+10; i++ {
		status := "working"
		if i%2 == 1 {
			status = "blocked"
		}
		h.op(t, Op{Op: "set_status", Status: status})
	}

	state := h.state(t)
	if len(state.FoldedFrom) != maxFoldedFrom {
		t.Errorf("folded_from holds %d ids, want %d", len(state.FoldedFrom), maxFoldedFrom)
	}
}

// Two ops arriving together must not each read the same prior state and
// overwrite one another. Run with -race; without the per-thread lock the
// folded_from list comes out short.
func TestConcurrentOpsAreSerialised(t *testing.T) {
	h := setup(t)

	const ops = 20
	var wg sync.WaitGroup
	for i := 0; i < ops; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			h.op(t, Op{Op: "set_title", Title: fmt.Sprintf("title %d", i)})
		}(i)
	}
	wg.Wait()

	state := h.state(t)
	if len(state.FoldedFrom) != ops {
		t.Errorf("folded_from holds %d ids after %d concurrent ops", len(state.FoldedFrom), ops)
	}
}

func ints(v int64) *int64       { return &v }
func floats(v float64) *float64 { return &v }

// `spent` is a sum of reports, never an assignment. An agent says what a turn
// cost; the total is nobody's single statement, which is what makes it
// recomputable from the ops in folded_from.
func TestSpendAccumulates(t *testing.T) {
	h := setup(t)

	h.op(t, Op{Op: "add_spend", Cost: &Cost{TokensIn: ints(100), TokensOut: ints(20), USD: floats(0.5)}})
	h.op(t, Op{Op: "add_spend", Cost: &Cost{TokensIn: ints(5), USD: floats(0.25)}})

	state := h.state(t)
	if tokensSpent(state.Spent) != 125 {
		t.Errorf("tokens spent is %d, want 125", tokensSpent(state.Spent))
	}
	if state.Spent.USD == nil || *state.Spent.USD != 0.75 {
		t.Errorf("usd spent is %v, want 0.75", state.Spent.USD)
	}
}

// `{}` and `{"usd": 0}` are different claims — "nobody said" and "it was free".
// A thread reported in tokens that grows a usd total reads as having been
// priced, and somebody downstream will believe it.
func TestAnUnreportedDimensionStaysAbsent(t *testing.T) {
	h := setup(t)

	h.op(t, Op{Op: "add_spend", Cost: &Cost{TokensIn: ints(10)}})

	body := h.published.events[0].Content
	if strings.Contains(body, `"usd"`) || strings.Contains(body, `"msat"`) {
		t.Errorf("a token-only spend invented a currency total: %s", body)
	}
}

func TestAnAddSpendWithNoCostChangesNothing(t *testing.T) {
	h := setup(t)

	h.op(t, Op{Op: "add_spend"})
	if got := h.published.count(); got != 0 {
		t.Errorf("an empty add_spend published %d events", got)
	}
}

// The safety valve. Both halves of the spend count against a ceiling stated in
// tokens: 600 in and 500 out is over 1000, and looks fine from either column.
func TestCrossingTheBudgetPausesTheThread(t *testing.T) {
	h := setup(t)

	h.op(t, Op{Op: "set_budget", Budget: &Budget{Tokens: ints(1000)}})
	h.op(t, Op{Op: "set_status", Status: "working"})
	h.op(t, Op{Op: "add_spend", Cost: &Cost{TokensIn: ints(600), TokensOut: ints(100)}})

	if state := h.state(t); state.Status != "working" {
		t.Fatalf("status is %q after spending 700 of 1000, want working", state.Status)
	}

	h.op(t, Op{Op: "add_spend", Cost: &Cost{TokensOut: ints(400)}})
	if state := h.state(t); state.Status != "paused" {
		t.Errorf("status is %q after spending 1100 of 1000, want paused", state.Status)
	}
}

// Lowering the ceiling under the spend is the other way the relationship
// changes, and `set_budget {usd: 0}` is therefore a freeze — using a capability
// that already exists rather than a new verb for stopping a thread.
func TestSettingABudgetBelowTheSpendPausesImmediately(t *testing.T) {
	h := setup(t)

	h.op(t, Op{Op: "set_status", Status: "working"})
	h.op(t, Op{Op: "add_spend", Cost: &Cost{USD: floats(4)}})
	h.op(t, Op{Op: "set_budget", Budget: &Budget{USD: floats(0)}})

	if state := h.state(t); state.Status != "paused" {
		t.Errorf("status is %q after a zero budget, want paused", state.Status)
	}
}

// A budget with nothing in it is not a ceiling of zero. The version of this
// that ships broken pauses every thread in the workspace the day budgets land.
func TestAThreadWithNoCeilingIsNeverPaused(t *testing.T) {
	h := setup(t)

	h.op(t, Op{Op: "set_status", Status: "working"})
	h.op(t, Op{Op: "set_budget", Budget: &Budget{}})
	h.op(t, Op{Op: "add_spend", Cost: &Cost{TokensIn: ints(1_000_000)}})

	if state := h.state(t); state.Status != "working" {
		t.Errorf("status is %q with no ceiling set, want working", state.Status)
	}
}

// The rule that keeps the pause resumable. If the fold re-paused on a
// set_status, a human's "working" would be rewritten to "paused" by the very
// event that stored it, and the only visible effect would be a button that does
// nothing.
func TestAHumanCanResumeAnExhaustedThread(t *testing.T) {
	h := setup(t)

	h.op(t, Op{Op: "set_budget", Budget: &Budget{Tokens: ints(10)}})
	h.op(t, Op{Op: "add_spend", Cost: &Cost{TokensIn: ints(50)}})
	if state := h.state(t); state.Status != "paused" {
		t.Fatalf("status is %q, want paused", state.Status)
	}

	h.op(t, Op{Op: "set_status", Status: "working"})
	if state := h.state(t); state.Status != "working" {
		t.Errorf("status is %q after a human resumed it, want working", state.Status)
	}

	// And it holds only until the next report, which is the honest answer:
	// resuming does not unspend anything, so raising the budget is the durable
	// fix and the next spend says so.
	h.op(t, Op{Op: "add_spend", Cost: &Cost{TokensIn: ints(1)}})
	if state := h.state(t); state.Status != "paused" {
		t.Errorf("status is %q after more spending on an exhausted thread, want paused", state.Status)
	}
}

// A late spend report must not un-finish delivered work.
func TestAFinishedThreadIsNotPaused(t *testing.T) {
	h := setup(t)

	h.op(t, Op{Op: "set_budget", Budget: &Budget{Tokens: ints(10)}})
	h.op(t, Op{Op: "set_status", Status: "done"})
	h.op(t, Op{Op: "add_spend", Cost: &Cost{TokensIn: ints(500)}})

	if state := h.state(t); state.Status != "done" {
		t.Errorf("status is %q after a late spend report, want done", state.Status)
	}
}

// Two folds inside one second is the normal case, and the store replaces an
// addressable event only with a newer one — ties going to the lowest id. So a
// projector that signs everything at `now` loses about half its updates to a
// hash, and the thread is left asserting something that was true one op ago.
//
// This bit for real: the budget tests published `set_budget` and `set_status`
// together and the relay kept whichever won the tiebreak.
func TestEachProjectionIsNewerThanTheLast(t *testing.T) {
	h := setup(t)

	h.op(t, Op{Op: "set_status", Status: "working"})
	h.op(t, Op{Op: "set_title", Title: "ship it"})
	h.op(t, Op{Op: "set_status", Status: "blocked"})

	if got := h.published.count(); got != 3 {
		t.Fatalf("published %d states, want 3", got)
	}
	for i := 1; i < len(h.published.events); i++ {
		if h.published.events[i].CreatedAt <= h.published.events[i-1].CreatedAt {
			t.Errorf("state %d is dated %d, not after %d",
				i, h.published.events[i].CreatedAt, h.published.events[i-1].CreatedAt)
		}
	}

	// And the store kept the last one, which is the consequence that matters.
	if state := h.state(t); state.Status != "blocked" || state.Title != "ship it" {
		t.Errorf("the stored state is %+v; an update was dropped", state)
	}
}

// The state event is relay-signed; that signature is the only reason a client
// should believe the projection over its own local fold.
func TestStateEventsAreSignedByTheRelay(t *testing.T) {
	h := setup(t)
	h.op(t, Op{Op: "set_status", Status: "done"})

	published := h.published.events[0]
	if published.PubKey != h.projector.PublicKey() {
		t.Errorf("state was signed by %s, want the relay key %s", published.PubKey, h.projector.PublicKey())
	}
	if published.GetID() != published.ID {
		t.Error("the state event's id does not cover its content")
	}
	if ok, err := published.CheckSignature(); err != nil || !ok {
		t.Errorf("the state event's signature does not verify: %v", err)
	}
	if published.Tags.GetD() != h.thread {
		t.Errorf("`d` is %q, want the thread id", published.Tags.GetD())
	}
	if protocol.Group(published) != "payments" {
		t.Errorf("`h` is %q, want payments", protocol.Group(published))
	}
}

// The alt tag rides outside any future encryption, so it must not carry the
// title or the assignee.
func TestAltLeaksNothingFromTheBody(t *testing.T) {
	h := setup(t)

	secret := "acquire-competitor-ltd"
	h.op(t, Op{Op: "set_title", Title: secret})

	alt := ""
	for _, tag := range h.published.events[0].Tags {
		if tag[0] == protocol.TagAlt {
			alt = tag[1]
		}
	}
	if alt != "thread state: open" {
		t.Errorf("alt is %q; it must stay generic, and it must not repeat %q", alt, secret)
	}
}
