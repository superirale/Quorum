package checkpoint

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"github.com/quorum-chat/quorum/apps/relay/internal/protocol"
)

// Kind is the checkpoint event kind. Relay-signed; see relaySignedKinds.
const Kind = 8108

const (
	// pageSize keeps each query under the event store's own MaxLimit. Asking
	// for more than the store allows does not fail — eventstore's badger
	// backend silently serves a *quarter* of the maximum instead, which is how
	// the context packer lost half a thread in M6. A checkpoint built from a
	// silently truncated read would accuse the relay of withholding the events
	// it failed to ask for.
	pageSize = 2000

	// latestPage is how many of a group's own checkpoints are read back to find
	// the end of the chain. See latest: the store orders by created_at and the
	// chain is ordered by `to`, so one is not enough.
	latestPage = 32

	// maxWindowEvents bounds one checkpoint. Reached only by a group whose
	// first checkpoint has to cover months of backlog; steady-state windows are
	// one interval long. When it is hit the window is *narrowed* rather than
	// truncated — see collect.
	maxWindowEvents = 20000
)

// Body is a kind 8108 body.
//
// Field order is RFC 8785 key order (sorted by UTF-16 code unit), which is what
// lets encoding/json produce the canonical bytes here. That shortcut is safe
// only because every value is a hex digest, an integer, or the fixed algorithm
// name: there is no character in any of them that Go's HTML escaping would
// touch and no float to format. A test pins it.
type Body struct {
	Algorithm  string `json:"algorithm"`
	Count      int    `json:"count"`
	From       int64  `json:"from"`
	MerkleRoot string `json:"merkle_root"`
	Prev       string `json:"prev,omitempty"`
	To         int64  `json:"to"`
}

// Committed reports whether an event of this kind belongs in a checkpoint.
//
// Only regular events do, and the reason is that a checkpoint must stay
// verifiable forever. A replaceable or addressable event is *superseded* — the
// store drops the old copy — so committing to its id would guarantee that a
// later reader recomputing the root comes up short and concludes the relay
// withheld something. The relay would be manufacturing evidence against itself
// on a schedule. Ephemeral events are never stored at all.
//
// This is a protocol rule, not an implementation detail: a client recomputing a
// root has to apply exactly the same filter, so it is specified in the NIP and
// mirrored in the SDK.
func Committed(kind int) bool {
	switch {
	case kind == 0 || kind == 3:
		return false // replaceable by NIP-01's special cases
	case kind >= 10000 && kind < 20000:
		return false // replaceable
	case protocol.IsEphemeral(kind):
		return false
	case protocol.IsAddressable(kind):
		return false
	default:
		return true
	}
}

// Store is the subset of the event database the checkpointer needs.
type Store interface {
	QueryEvents(ctx context.Context, filter nostr.Filter) (chan *nostr.Event, error)
	SaveEvent(ctx context.Context, event *nostr.Event) error
}

// Publisher broadcasts a newly signed event to subscribers.
type Publisher interface {
	BroadcastEvent(event *nostr.Event)
}

// Checkpointer cuts windows and signs what the relay held in them.
type Checkpointer struct {
	store     Store
	publish   Publisher
	secretKey string
	pubkey    string

	every time.Duration
	lag   time.Duration

	// Groups the relay has seen an event for. Seeded lazily by Observe rather
	// than enumerated up front: relay29 keeps group metadata in kinds 39000+
	// that are generated on demand and never stored, so there is no query that
	// lists them.
	groups sync.Map // group id -> struct{}

	// now is swappable so tests can cut windows without sleeping.
	now func() time.Time

	// One cut at a time per group, so a manual Cut during a tick cannot write
	// two checkpoints claiming the same prev.
	locks sync.Map // group id -> *sync.Mutex
}

// New builds a checkpointer.
//
// lag is the distance behind now at which a window closes, and it must be at
// least the relay's clock skew. That is the whole reason the design works:
// RejectImplausibleTimestamps is symmetric, so the relay already refuses any
// event dated more than skew in the *past*. Close the window at now-lag with
// lag >= skew and no honest event can ever arrive for a window already
// committed to — the set is final at the moment it is cut, and a client can
// reconstruct exactly it. Layer 3 therefore adds no new refusals; the
// federation cost was paid in M2 by the skew bound itself.
//
// Getting this wrong is not a degradation, it is a false accusation: an event
// that lands inside a closed window makes an honest relay look like a caught
// one. main.go refuses to boot when lag < skew for that reason.
func New(store Store, publish Publisher, secretKey string, every, lag time.Duration) (*Checkpointer, error) {
	pubkey, err := nostr.GetPublicKey(secretKey)
	if err != nil {
		return nil, fmt.Errorf("deriving the relay public key: %w", err)
	}
	if every <= 0 {
		return nil, fmt.Errorf("checkpoint interval must be positive, got %s", every)
	}
	if lag <= 0 {
		return nil, fmt.Errorf("checkpoint lag must be positive, got %s", lag)
	}
	return &Checkpointer{
		store:     store,
		publish:   publish,
		secretKey: secretKey,
		pubkey:    pubkey,
		every:     every,
		lag:       lag,
		now:       time.Now,
	}, nil
}

func (c *Checkpointer) PublicKey() string { return c.pubkey }

// Observe is a khatru OnEventSaved hook. It only notes which groups exist.
func (c *Checkpointer) Observe(_ context.Context, event *nostr.Event) {
	if group := protocol.Group(event); group != "" {
		c.groups.LoadOrStore(group, struct{}{})
	}
}

// Run cuts a checkpoint for every known group on every interval, until ctx ends.
func (c *Checkpointer) Run(ctx context.Context) {
	ticker := time.NewTicker(c.every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.Tick(ctx)
		}
	}
}

// Tick cuts one checkpoint per known group. Exported so tests drive it directly.
func (c *Checkpointer) Tick(ctx context.Context) {
	var groups []string
	c.groups.Range(func(key, _ any) bool {
		groups = append(groups, key.(string))
		return true
	})
	sort.Strings(groups) // deterministic, so a test can read the log

	for _, group := range groups {
		if _, err := c.Cut(ctx, group); err != nil {
			log.Printf("checkpoint: %s: %v", group, err)
		}
	}
}

// Cut signs one checkpoint for a group, covering everything since the last one.
//
// A window with no events in it still gets a checkpoint, which is the only
// thing that distinguishes a quiet workspace from a relay serving nothing: a
// signed empty root says "I held nothing", and silence says only that the relay
// stopped talking.
func (c *Checkpointer) Cut(ctx context.Context, group string) (*nostr.Event, error) {
	mutex, _ := c.locks.LoadOrStore(group, &sync.Mutex{})
	lock := mutex.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()

	to := c.now().Add(-c.lag).Unix()

	prev, prevBody := c.latest(ctx, group)
	from := int64(0)
	prevID := ""
	if prev != nil {
		from = prevBody.To + 1
		prevID = prev.ID
	}
	if to < from {
		// The clock went backwards, or the interval is shorter than the lag
		// allows. Signing a window that ends before it starts would be worse
		// than signing nothing.
		return nil, nil
	}

	held, from, err := c.collect(ctx, group, from, to)
	if err != nil {
		return nil, err
	}

	ids := make([]string, len(held))
	for i, h := range held {
		ids[i] = h.id
	}
	leaves := Leaves(ids)

	body := Body{
		Algorithm:  Algorithm,
		Count:      len(leaves),
		From:       from,
		MerkleRoot: Root(leaves),
		Prev:       prevID,
		To:         to,
	}

	event, err := c.sign(body, group)
	if err != nil {
		return nil, err
	}
	if err := c.store.SaveEvent(ctx, event); err != nil {
		return nil, fmt.Errorf("storing the checkpoint: %w", err)
	}
	c.publish.BroadcastEvent(event)
	return event, nil
}

type held struct {
	id string
	at int64
}

// collect reads every committed event the relay holds for a group in [from, to].
//
// It pages backwards because the store cannot serve an unbounded window, and it
// returns the `from` it actually managed to cover. Narrowing rather than
// truncating is the point: a checkpoint whose `from` is later than requested is
// a smaller true claim, while one that keeps the requested bounds and drops the
// events it could not read is a false one.
func (c *Checkpointer) collect(ctx context.Context, group string, from, to int64) ([]held, int64, error) {
	seen := make(map[string]struct{})
	var found []held
	until := to

	for {
		since := nostr.Timestamp(from)
		upto := nostr.Timestamp(until)
		results, err := c.store.QueryEvents(ctx, nostr.Filter{
			Tags:  nostr.TagMap{protocol.TagGroup: []string{group}},
			Since: &since,
			Until: &upto,
			Limit: pageSize,
		})
		if err != nil {
			return nil, from, fmt.Errorf("querying events: %w", err)
		}

		read := 0
		oldest := int64(-1)
		// Drained fully rather than broken out of: the store produces on a
		// goroutine that blocks on send, and abandoning the channel leaks it.
		for event := range results {
			read++
			if oldest == -1 || int64(event.CreatedAt) < oldest {
				oldest = int64(event.CreatedAt)
			}
			if !Committed(event.Kind) {
				continue
			}
			if _, dup := seen[event.ID]; dup {
				continue
			}
			seen[event.ID] = struct{}{}
			found = append(found, held{id: event.ID, at: int64(event.CreatedAt)})
		}

		if read < pageSize || oldest <= from {
			return found, from, nil
		}
		if len(found) >= maxWindowEvents || oldest == until {
			// Either the backlog is larger than one checkpoint may cover, or a
			// single second holds a whole page and paging cannot make progress.
			// Both are resolved the same way: keep only what is provably
			// complete, which is everything strictly after the oldest second we
			// touched, and say so in `from`.
			narrowed := oldest + 1
			kept := found[:0]
			for _, h := range found {
				if h.at >= narrowed {
					kept = append(kept, h)
				}
			}
			return kept, narrowed, nil
		}
		until = oldest // re-reads that second; the id set dedupes it
	}
}

// latest returns the newest checkpoint the relay signed for a group.
//
// Read back from the store rather than held in memory, so a restart continues
// the chain instead of starting a second one. A relay that forgot its own last
// checkpoint would re-cover a window it had already committed to, and the two
// commitments would be indistinguishable from a relay re-cutting history.
func (c *Checkpointer) latest(ctx context.Context, group string) (*nostr.Event, Body) {
	results, err := c.store.QueryEvents(ctx, nostr.Filter{
		Kinds:   []int{Kind},
		Authors: []string{c.pubkey},
		Tags:    nostr.TagMap{protocol.TagGroup: []string{group}},
		// More than one, because the store orders by created_at and the chain is
		// ordered by `to`. Cut keeps those in step — it refuses a window ending
		// before it starts — but only for checkpoints it wrote. One that arrives
		// by any other path, a restored snapshot most plausibly, can sit at the
		// top by created_at while covering an older window, and continuing from
		// it re-covers seconds already committed to. An overlap is precisely
		// what a reader reads as a relay re-cutting history, so the relay would
		// be manufacturing the accusation out of a backup restore. `to` is
		// strictly increasing by construction, so the maximum below is the real
		// end of the chain.
		Limit: latestPage,
	})
	if err != nil {
		return nil, Body{}
	}

	var newest *nostr.Event
	var body Body
	for event := range results {
		var candidate Body
		if err := json.Unmarshal([]byte(event.Content), &candidate); err != nil {
			continue
		}
		// By `to`, not by created_at: the chain is ordered by the windows it
		// covers, and those are the relay's own monotonic bounds rather than a
		// wall clock two processes might disagree about.
		if newest == nil || candidate.To > body.To {
			newest, body = event, candidate
		}
	}
	return newest, body
}

func (c *Checkpointer) sign(body Body, group string) (*nostr.Event, error) {
	content, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	event := &nostr.Event{
		Kind:      Kind,
		CreatedAt: nostr.Now(),
		Content:   string(content),
		Tags: nostr.Tags{
			{"h", group},
			{"alt", altFor(body)},
		},
	}
	if err := event.Sign(c.secretKey); err != nil {
		return nil, err
	}
	return event, nil
}

// altFor writes the NIP-31 fallback every Quorum kind requires.
//
// Deliberately says nothing a reader without the body is not owed. The count
// and the window are already public in the body of an event anyone may fetch;
// what does not go here is anything derived from the events themselves.
func altFor(body Body) string {
	return fmt.Sprintf(
		"checkpoint: %d events held up to %s",
		body.Count,
		time.Unix(body.To, 0).UTC().Format(time.RFC3339),
	)
}
