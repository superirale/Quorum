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
	"time"

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

type Spent struct {
	TokensIn  *int64   `json:"tokens_in,omitempty"`
	TokensOut *int64   `json:"tokens_out,omitempty"`
	USD       *float64 `json:"usd,omitempty"`
	Msat      *int64   `json:"msat,omitempty"`
}

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

	thread := rootEventID(event)
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

	state := p.current(ctx, thread)
	if !apply(&state, op) {
		return
	}

	state.UpdatedAt = time.Now().Unix()
	state.FoldedFrom = append(state.FoldedFrom, event.ID)
	if len(state.FoldedFrom) > maxFoldedFrom {
		state.FoldedFrom = state.FoldedFrom[len(state.FoldedFrom)-maxFoldedFrom:]
	}

	signed, err := p.sign(state, thread, group)
	if err != nil {
		return
	}
	if err := p.store.ReplaceEvent(ctx, signed); err != nil {
		return
	}
	p.publish.BroadcastEvent(signed)
}

// current reads the thread's existing state, defaulting to a fresh open thread.
func (p *Projector) current(ctx context.Context, thread string) State {
	fresh := State{Status: "open", FoldedFrom: []string{}}

	results, err := p.store.QueryEvents(ctx, nostr.Filter{
		Kinds:   []int{KindThreadState},
		Authors: []string{p.pubkey},
		Tags:    nostr.TagMap{"d": []string{thread}},
		Limit:   1,
	})
	if err != nil {
		return fresh
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
		return fresh
	}

	var state State
	if err := json.Unmarshal([]byte(latest.Content), &state); err != nil {
		return fresh
	}
	if state.FoldedFrom == nil {
		state.FoldedFrom = []string{}
	}
	if state.Status == "" {
		state.Status = "open"
	}
	return state
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
	default:
		// An op this relay does not know about. Unknown ops are ignored rather
		// than rejected: the protocol's versioning policy says adding one is a
		// MINOR bump, so a newer client must not be broken by an older relay.
		return false
	}
	return true
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

func (p *Projector) sign(state State, thread, group string) (*nostr.Event, error) {
	content, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}

	event := &nostr.Event{
		Kind:      KindThreadState,
		CreatedAt: nostr.Now(),
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

func rootEventID(event *nostr.Event) string {
	for _, tag := range event.Tags {
		if len(tag) > 1 && tag[0] == protocol.TagRootEvent {
			return tag[1]
		}
	}
	return ""
}
