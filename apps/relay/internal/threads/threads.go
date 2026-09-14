// Package threads folds kind 8109 thread_op events into the relay-signed kind
// 38101 thread_state that clients read.
//
// Why the relay does this at all: thread state is the "blocked on you" queue,
// and a queue every client computes for itself is a queue clients disagree
// about. Folding once, server-side, gives every reader the same answer.
//
// Why it stays auditable: the folded 38101 lists every op id it incorporated in
// `folded_from`. A client that distrusts the projection can fetch those ops and
// recompute it. This is the difference between the relay asserting a state and
// the relay showing its work — and it is what keeps the relay from quietly
// becoming a trusted authority over what a task says.
//
// On a generic relay none of this happens and clients fold locally, reaching the
// same state from the same ops. The projection is an optimisation, never a
// dependency.
package threads

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/nbd-wtf/go-nostr"

	"github.com/quorum-chat/quorum/apps/relay/internal/protocol"
)

const (
	KindThreadOp    = 8109
	KindThreadState = 38101
	// maxFoldedFrom bounds the audit list. A thread worked on for months would
	// otherwise grow an unbounded tag list inside a replaceable event that is
	// rewritten on every change.
	maxFoldedFrom = 200
)

type Budget struct {
	USD    *float64 `json:"usd,omitempty"`
	Msat   *int64   `json:"msat,omitempty"`
	Tokens *int64   `json:"tokens,omitempty"`
}

// Spent is a cost: what a thread has run up in total, or — as Cost, the same
// shape under the name the `add_spend` op uses — what one turn of work cost.
// They are one type because the total is nothing but the sum of the reports.
type Spent struct {
	TokensIn  *int64   `json:"tokens_in,omitempty"`
	TokensOut *int64   `json:"tokens_out,omitempty"`
	USD       *float64 `json:"usd,omitempty"`
	Msat      *int64   `json:"msat,omitempty"`
}

type Cost = Spent

// State is the body of a kind 38101 event.
type State struct {
	Status     string   `json:"status"`
	Title      string   `json:"title,omitempty"`
	Assignee   *string  `json:"assignee,omitempty"`
	Budget     *Budget  `json:"budget,omitempty"`
	Spent      *Spent   `json:"spent,omitempty"`
	FoldedFrom []string `json:"folded_from"`
	UpdatedAt  int64    `json:"updated_at,omitempty"`
}

// Op is the body of a kind 8109 event. The schema is a discriminated union, so
// only the fields matching `op` are populated.
type Op struct {
	Op       string  `json:"op"`
	Status   string  `json:"status,omitempty"`
	Assignee *string `json:"assignee,omitempty"`
	Title    string  `json:"title,omitempty"`
	Budget   *Budget `json:"budget,omitempty"`
	Cost     *Cost   `json:"cost,omitempty"`
}

// Store is the subset of the event database the projector needs.
type Store interface {
	QueryEvents(ctx context.Context, filter nostr.Filter) (chan *nostr.Event, error)
	ReplaceEvent(ctx context.Context, event *nostr.Event) error
}

// Publisher broadcasts a newly signed event to subscribers.
type Publisher interface {
	BroadcastEvent(event *nostr.Event)
}

type Projector struct {
	index     *protocol.Index
	store     Store
	publish   Publisher
	secretKey string
	pubkey    string

	// One fold at a time per thread. Two ops arriving together would otherwise
	// each read the same prior state and the second would overwrite the first,
	// losing an op that the relay had already acknowledged.
	locks sync.Map // thread id -> *sync.Mutex
}

func New(index *protocol.Index, store Store, publish Publisher, secretKey string) (*Projector, error) {
	pubkey, err := nostr.GetPublicKey(secretKey)
	if err != nil {
		return nil, fmt.Errorf("deriving the relay public key: %w", err)
	}
	return &Projector{
		index:     index,
		store:     store,
		publish:   publish,
		secretKey: secretKey,
		pubkey:    pubkey,
	}, nil
}

func (p *Projector) PublicKey() string { return p.pubkey }

// Fold is a khatru OnEventSaved hook: it reacts to a stored thread_op by
// rewriting the thread's state event.
func (p *Projector) Fold(ctx context.Context, event *nostr.Event) {
	if event.Kind != KindThreadOp {
		return
	}

	thread := protocol.RootEvent(event)
	group := protocol.Group(event)
	if thread == "" || group == "" {
		return
	}

	var op Op
	if err := json.Unmarshal([]byte(event.Content), &op); err != nil {
		return // already rejected by validation; nothing to fold
	}

	mutex, _ := p.locks.LoadOrStore(thread, &sync.Mutex{})
	lock := mutex.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()

	state, previous := p.current(ctx, thread)
	if !apply(&state, op) {
		return
	}
	pauseIfExhausted(&state, op)

	at := after(previous)
	state.UpdatedAt = int64(at)
	state.FoldedFrom = append(state.FoldedFrom, event.ID)
	if len(state.FoldedFrom) > maxFoldedFrom {
		state.FoldedFrom = state.FoldedFrom[len(state.FoldedFrom)-maxFoldedFrom:]
	}

	signed, err := p.sign(state, thread, group, at)
	if err != nil {
		return
	}
	if err := p.store.ReplaceEvent(ctx, signed); err != nil {
		return
	}
	p.publish.BroadcastEvent(signed)
}

// after returns the timestamp to sign the next projection with: now, unless a
// projection already exists at or after now.
//
// Two folds inside one second is the normal case — a client publishes
// `set_budget` and `set_status` together, or an agent reports a spend that
// pauses the thread — and the store's addressable replace falls through to
// NIP-01's lowest-id tiebreak when the timestamps are equal. Half the time the
// *older* state wins on a hash, the newer one is silently not stored, and the
// thread is left saying something that was true one op ago.
//
// The relay is the author of these events, so the honest fix is to keep them
// strictly ordered: a projection folded later really is later. The cost is that
// a burst of ops can date the state event a few seconds ahead of the wall
// clock, which no reader minds — NIP-01 orders by `created_at` and that is
// precisely the order being asserted. Client events get no such licence; they
// still face RejectImplausibleTimestamps.
func after(previous nostr.Timestamp) nostr.Timestamp {
	now := nostr.Now()
	if previous >= now {
		return previous + 1
	}
	return now
}

// current reads the thread's existing state, defaulting to a fresh open thread,
// and reports when that state was signed.
func (p *Projector) current(ctx context.Context, thread string) (State, nostr.Timestamp) {
	fresh := State{Status: "open", FoldedFrom: []string{}}

	results, err := p.store.QueryEvents(ctx, nostr.Filter{
		Kinds:   []int{KindThreadState},
		Authors: []string{p.pubkey},
		Tags:    nostr.TagMap{"d": []string{thread}},
		Limit:   1,
	})
	if err != nil {
		return fresh, 0
	}

	// Drain fully rather than breaking early: the store produces on a goroutine
	// that blocks on send, and abandoning the channel would leak it.
	var latest *nostr.Event
	for event := range results {
		if latest == nil || event.CreatedAt > latest.CreatedAt {
			latest = event
		}
	}
	if latest == nil {
		return fresh, 0
	}

	var state State
	if err := json.Unmarshal([]byte(latest.Content), &state); err != nil {
		return fresh, latest.CreatedAt
	}
	if state.FoldedFrom == nil {
		state.FoldedFrom = []string{}
	}
	if state.Status == "" {
		state.Status = "open"
	}
	return state, latest.CreatedAt
}

// apply mutates state by one op, reporting whether anything changed.
func apply(state *State, op Op) bool {
	switch op.Op {
	case "set_status":
		if op.Status == "" || state.Status == op.Status {
			return false
		}
		state.Status = op.Status
	case "assign":
		if same(state.Assignee, op.Assignee) {
			return false
		}
		state.Assignee = op.Assignee
	case "set_title":
		if op.Title == "" || state.Title == op.Title {
			return false
		}
		state.Title = op.Title
	case "set_budget":
		state.Budget = op.Budget
	case "add_spend":
		// Added, never assigned: an op says what a turn cost, not what the
		// total now is. Two agents reporting concurrently must both be counted,
		// and the lock above is what makes that read-add-write safe.
		if op.Cost == nil {
			return false
		}
		state.Spent = addCost(state.Spent, op.Cost)
	default:
		// An op this relay does not know about. Unknown ops are ignored rather
		// than rejected: the protocol's versioning policy says adding one is a
		// MINOR bump, so a newer client must not be broken by an older relay.
		return false
	}
	return true
}

// pauseIfExhausted is the safety valve: a thread that has spent its budget
// stops, and a human is looking at a paused task rather than a bill.
//
// It fires only for the two ops that can change the relationship between the
// spend and the ceiling. A `set_status` must never trigger it, or an exhausted
// thread could never be resumed — the human's "working" would be rewritten back
// to "paused" by the same fold that stored it, and the only visible effect
// would be that the button does nothing. Resuming an exhausted thread is
// therefore allowed and holds until the next spend report; raising the budget
// is what makes it durable, which is the right place for that decision.
//
// A finished thread is left alone. Pausing a `done` task because a late spend
// report crossed a line would un-finish work that is already delivered.
func pauseIfExhausted(state *State, op Op) {
	if op.Op != "add_spend" && op.Op != "set_budget" {
		return
	}
	if state.Status == "paused" || state.Status == "done" {
		return
	}
	if BudgetExhausted(state.Spent, state.Budget) {
		state.Status = "paused"
	}
}

// BudgetExhausted mirrors `checkBudget` in packages/protocol/src/cost.ts, and
// the two must agree: a client folding ops itself on a channel this relay
// cannot read has to reach the same verdict, or the same thread is paused in
// one place and running in another.
//
// Three rules, each of them a decision: a budget with nothing set is not a
// ceiling of zero; any stated dimension is enough, because whoever set two
// ceilings meant both; and `>=` is exhausted, which makes `set_budget {usd: 0}`
// an immediate freeze using a capability that already exists.
func BudgetExhausted(spent *Spent, budget *Budget) bool {
	if budget == nil {
		return false
	}
	if budget.Tokens != nil && tokensSpent(spent) >= *budget.Tokens {
		return true
	}
	if budget.USD != nil && floatValue(costUSD(spent)) >= *budget.USD {
		return true
	}
	if budget.Msat != nil && intValue(costMsat(spent)) >= *budget.Msat {
		return true
	}
	return false
}

// tokensSpent adds both halves of the spend, because a budget states tokens as
// one number. A thread capped at 40,000 that has spent 39,000 in and 38,000 out
// is nearly twice over and looks comfortable from either column alone.
func tokensSpent(spent *Spent) int64 {
	if spent == nil {
		return 0
	}
	return intValue(spent.TokensIn) + intValue(spent.TokensOut)
}

// addCost sums two costs dimension by dimension, keeping absent absent.
//
// `{}` and `{"usd": 0}` are different claims — "nobody said" and "it was free"
// — and a thread priced in tokens should not grow a `usd` total that reads as
// having been costed.
func addCost(a, b *Cost) *Cost {
	if a == nil && b == nil {
		return nil
	}
	if a == nil {
		a = &Cost{}
	}
	if b == nil {
		b = &Cost{}
	}
	return &Cost{
		TokensIn:  addInts(a.TokensIn, b.TokensIn),
		TokensOut: addInts(a.TokensOut, b.TokensOut),
		USD:       addFloats(a.USD, b.USD),
		Msat:      addInts(a.Msat, b.Msat),
	}
}

func addInts(a, b *int64) *int64 {
	if a == nil && b == nil {
		return nil
	}
	sum := intValue(a) + intValue(b)
	return &sum
}

func addFloats(a, b *float64) *float64 {
	if a == nil && b == nil {
		return nil
	}
	sum := floatValue(a) + floatValue(b)
	return &sum
}

func costUSD(spent *Spent) *float64 {
	if spent == nil {
		return nil
	}
	return spent.USD
}

func costMsat(spent *Spent) *int64 {
	if spent == nil {
		return nil
	}
	return spent.Msat
}

func intValue(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}

func floatValue(v *float64) float64 {
	if v == nil {
		return 0
	}
	return *v
}

func same(a, b *string) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	default:
		return *a == *b
	}
}

func (p *Projector) sign(state State, thread, group string, at nostr.Timestamp) (*nostr.Event, error) {
	content, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}

	event := &nostr.Event{
		Kind:      KindThreadState,
		CreatedAt: at,
		Content:   string(content),
		Tags: nostr.Tags{
			{"d", thread},
			{"h", group},
			{"alt", altFor(state)},
		},
	}
	if err := event.Sign(p.secretKey); err != nil {
		return nil, err
	}
	return event, nil
}

// altFor writes the NIP-31 fallback the protocol requires on every Quorum kind.
//
// Kept generic on purpose. This tag is not encrypted even when the channel is,
// so a title or an assignee's key here would leak past the encryption sitting
// beside it. "a thread is blocked" is all a reader without the body is owed.
func altFor(state State) string {
	return fmt.Sprintf("thread state: %s", state.Status)
}
