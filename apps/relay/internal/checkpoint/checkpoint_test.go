package checkpoint

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

const group = "workspace-1"

// memoryStore behaves like the eventstore for the three calls the checkpointer
// makes. Limit and reverse-chronological order are implemented rather than
// ignored: paging is the part of collect that can silently lose events, and a
// store that serves every match regardless of Limit would never exercise it.
type memoryStore struct {
	mu     sync.Mutex
	events []*nostr.Event
	// queries records every filter served, so a test can see how the window
	// was actually read.
	queries []nostr.Filter
}

func newStore() *memoryStore { return &memoryStore{} }

func (s *memoryStore) SaveEvent(_ context.Context, event *nostr.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return nil
}

func (s *memoryStore) QueryEvents(_ context.Context, filter nostr.Filter) (chan *nostr.Event, error) {
	s.mu.Lock()
	s.queries = append(s.queries, filter)
	var matches []*nostr.Event
	for _, event := range s.events {
		if filter.Matches(event) {
			matches = append(matches, event)
		}
	}
	s.mu.Unlock()

	sort.Slice(matches, func(i, j int) bool {
		if matches[i].CreatedAt != matches[j].CreatedAt {
			return matches[i].CreatedAt > matches[j].CreatedAt
		}
		return matches[i].ID < matches[j].ID
	})
	if filter.Limit > 0 && len(matches) > filter.Limit {
		matches = matches[:filter.Limit]
	}

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

// --- harness -----------------------------------------------------------------

const relayKey = "0000000000000000000000000000000000000000000000000000000000000001"
const authorKey = "0000000000000000000000000000000000000000000000000000000000000002"

type harness struct {
	*Checkpointer
	store *memoryStore
	feed  *recorder
	clock time.Time
}

func newHarness(t *testing.T, lag time.Duration) *harness {
	t.Helper()
	store, feed := newStore(), &recorder{}
	c, err := New(store, feed, relayKey, time.Minute, lag)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h := &harness{Checkpointer: c, store: store, feed: feed, clock: time.Unix(100000, 0)}
	c.now = func() time.Time { return h.clock }
	c.Observe(context.Background(), h.event(9, "seed", 1))
	return h
}

// event builds and stores nothing; it only signs. Use publish to store.
func (h *harness) event(kind int, content string, at int64) *nostr.Event {
	event := &nostr.Event{
		Kind:      kind,
		CreatedAt: nostr.Timestamp(at),
		Content:   content,
		Tags:      nostr.Tags{{"h", group}, {"alt", "test"}},
	}
	if err := event.Sign(authorKey); err != nil {
		panic(err)
	}
	return event
}

func (h *harness) publish(t *testing.T, kind int, content string, at int64) *nostr.Event {
	t.Helper()
	event := h.event(kind, content, at)
	if err := h.store.SaveEvent(context.Background(), event); err != nil {
		t.Fatalf("SaveEvent: %v", err)
	}
	return event
}

func (h *harness) cut(t *testing.T) (*nostr.Event, Body) {
	t.Helper()
	event, err := h.Cut(context.Background(), group)
	if err != nil {
		t.Fatalf("Cut: %v", err)
	}
	if event == nil {
		t.Fatal("Cut produced no checkpoint")
	}
	var body Body
	if err := json.Unmarshal([]byte(event.Content), &body); err != nil {
		t.Fatalf("unmarshalling the checkpoint body: %v", err)
	}
	return event, body
}

// --- what a checkpoint covers ------------------------------------------------

func TestCommitsToTheEventsInTheWindow(t *testing.T) {
	h := newHarness(t, 900*time.Second)
	h.clock = time.Unix(100000, 0)

	inside := []*nostr.Event{
		h.publish(t, 9, "one", 98000),
		h.publish(t, 9, "two", 98500),
		h.publish(t, 1111, "three", 99000),
	}
	// Inside the lag, so the window has not closed over it yet. This is the
	// event the whole lag rule exists to leave out.
	tooNew := h.publish(t, 9, "not yet", 99500)

	_, body := h.cut(t)

	if body.To != 99100 {
		t.Errorf("window ends at %d, want now-lag = 99100", body.To)
	}
	if body.From != 0 {
		t.Errorf("the first checkpoint should start at 0, got %d", body.From)
	}
	if body.Count != len(inside) {
		t.Errorf("count %d, want %d", body.Count, len(inside))
	}

	ids := []string{inside[0].ID, inside[1].ID, inside[2].ID}
	if body.MerkleRoot != Root(ids) {
		t.Error("the root is not the root of the events in the window")
	}
	if _, ok := Proof(ids, tooNew.ID); ok {
		t.Fatal("the test is wrong: the too-new event is in the committed set")
	}
}

func TestExcludesEventsThatCanBeSuperseded(t *testing.T) {
	// The relay must not commit to an id the store will later drop, or it
	// manufactures evidence against itself every time a task's status changes.
	h := newHarness(t, 900*time.Second)
	regular := h.publish(t, 9, "a message", 98000)
	h.publish(t, 38101, "thread state", 98001) // addressable, replaced
	h.publish(t, 10002, "a relay list", 98002) // replaceable
	h.publish(t, 28103, "a heartbeat", 98003)  // ephemeral, never stored anyway
	h.publish(t, 0, "a profile", 98004)        // replaceable by NIP-01

	_, body := h.cut(t)

	if body.Count != 1 {
		t.Fatalf("committed to %d events, want only the regular one", body.Count)
	}
	if body.MerkleRoot != Root([]string{regular.ID}) {
		t.Error("the root is not the root of the one committed event")
	}

	for _, kind := range []int{0, 3, 10002, 28103, 38101, 39000} {
		if Committed(kind) {
			t.Errorf("kind %d should not be committed to", kind)
		}
	}
	for _, kind := range []int{1, 9, 11, 1111, 8101, 8108, 8109} {
		if !Committed(kind) {
			t.Errorf("kind %d should be committed to", kind)
		}
	}
}

func TestAQuietWindowStillGetsACheckpoint(t *testing.T) {
	// Silence and an empty root are different claims. Only one of them is
	// signed, and it is the one that says the relay held nothing.
	h := newHarness(t, 900*time.Second)
	_, body := h.cut(t)

	if body.Count != 0 || body.MerkleRoot != EmptyRoot {
		t.Fatalf("empty window gave count=%d root=%s", body.Count, body.MerkleRoot)
	}
}

// --- the chain ---------------------------------------------------------------

func TestWindowsChainAndDoNotOverlap(t *testing.T) {
	h := newHarness(t, 900*time.Second)
	h.publish(t, 9, "first", 98000)
	first, firstBody := h.cut(t)

	h.clock = h.clock.Add(600 * time.Second)
	second := h.publish(t, 9, "second", 99500)
	_, secondBody := h.cut(t)

	if secondBody.Prev != first.ID {
		t.Errorf("prev is %q, want the previous checkpoint's event id %q", secondBody.Prev, first.ID)
	}
	if secondBody.From != firstBody.To+1 {
		t.Errorf("second window starts at %d, want %d", secondBody.From, firstBody.To+1)
	}
	if secondBody.Count != 1 || secondBody.MerkleRoot != Root([]string{second.ID}) {
		t.Error("the second window should hold exactly the event published into it")
	}
	if firstBody.Prev != "" {
		t.Error("the first checkpoint for a group must have no prev")
	}
}

func TestARestartContinuesTheChain(t *testing.T) {
	// The previous checkpoint is read back from the store, never remembered. A
	// relay that forgot would re-cover a window it had already committed to,
	// and two commitments over overlapping windows are indistinguishable from a
	// relay re-cutting history to suit itself.
	h := newHarness(t, 900*time.Second)
	h.publish(t, 9, "before the restart", 98000)
	first, firstBody := h.cut(t)

	restarted, err := New(h.store, h.feed, relayKey, time.Minute, 900*time.Second)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	later := h.clock.Add(600 * time.Second)
	restarted.now = func() time.Time { return later }

	event, err := restarted.Cut(context.Background(), group)
	if err != nil || event == nil {
		t.Fatalf("Cut after restart: %v", err)
	}
	var body Body
	if err := json.Unmarshal([]byte(event.Content), &body); err != nil {
		t.Fatal(err)
	}
	if body.Prev != first.ID || body.From != firstBody.To+1 {
		t.Errorf("the restarted relay started a second chain: prev=%q from=%d", body.Prev, body.From)
	}
}

func TestTheChainIsFoundByWindowNotByClock(t *testing.T) {
	// The store orders by created_at; the chain is ordered by `to`. Cut keeps
	// the two in step, because it refuses a window that would end before it
	// starts. Nothing keeps them in step for a checkpoint that reaches the
	// store by some other path — a restored snapshot is the plausible one — and
	// an old window sitting at the top by created_at would have the relay
	// re-covering seconds it had already committed to. That overlap is exactly
	// what a reader reads as re-cut history, so the relay would be
	// manufacturing the accusation out of a backup restore.
	h := newHarness(t, 900*time.Second)
	h.publish(t, 9, "before", 98000)
	first, firstBody := h.cut(t)

	stale := &nostr.Event{
		Kind:      Kind,
		CreatedAt: first.CreatedAt + 1,
		Content:   `{"algorithm":"` + Algorithm + `","count":0,"from":0,"merkle_root":"` + EmptyRoot + `","to":50000}`,
		Tags:      nostr.Tags{{"h", group}, {"alt", "a window from before the restore"}},
	}
	if err := stale.Sign(relayKey); err != nil {
		t.Fatal(err)
	}
	if err := h.store.SaveEvent(context.Background(), stale); err != nil {
		t.Fatalf("SaveEvent: %v", err)
	}

	h.clock = h.clock.Add(1000 * time.Second)
	_, body := h.cut(t)
	if body.Prev != first.ID {
		t.Errorf("chained on the stale checkpoint: prev=%q, want %q", body.Prev, first.ID)
	}
	if body.From != firstBody.To+1 {
		t.Errorf("window from=%d, want %d — it overlaps a window already signed", body.From, firstBody.To+1)
	}
}

// --- the claim the milestone is about ----------------------------------------

func TestWithholdingIsProvable(t *testing.T) {
	// The relay signs a commitment, then serves a client a set with one event
	// missing. Both halves of the proof are checked here: the recomputed root
	// does not match, which says *something* is missing, and the inclusion
	// proof says exactly which event and that the relay's own signature covers
	// it.
	h := newHarness(t, 900*time.Second)
	var all []string
	for i, text := range []string{"one", "two", "three", "four", "five"} {
		all = append(all, h.publish(t, 9, text, 98000+int64(i)).ID)
	}
	signed, body := h.cut(t)

	withheld := all[2]
	var served []string
	for _, id := range all {
		if id != withheld {
			served = append(served, id)
		}
	}

	if Root(served) == body.MerkleRoot {
		t.Fatal("a short set reproduced the committed root")
	}
	path, ok := Proof(all, withheld)
	if !ok {
		t.Fatal("no inclusion proof for a committed event")
	}
	if !VerifyProof(withheld, path, body.MerkleRoot) {
		t.Fatal("the inclusion proof does not verify against the signed root")
	}
	if ok, err := signed.CheckSignature(); !ok || err != nil {
		t.Fatalf("the checkpoint is not signed by the relay: %v", err)
	}
	if signed.PubKey != h.PublicKey() {
		t.Fatal("the checkpoint is not the relay's")
	}

	// The negative control: a set that is merely *reordered* is not an
	// accusation. Without it this test would pass against an implementation
	// that hashed arrival order and called every client a victim.
	shuffled := []string{all[4], all[1], all[3], all[0], all[2]}
	if Root(shuffled) != body.MerkleRoot {
		t.Fatal("reordering the same events broke the root")
	}
}

// --- reading the window ------------------------------------------------------

func TestPagesThroughAWindowLargerThanOneQuery(t *testing.T) {
	// The store serves at most `pageSize` per query and the checkpointer must
	// not mistake that for the end of the window. This is the M6 MaxLimit trap
	// in its M7 form, where the consequence is an accusation rather than a
	// short prompt.
	h := newHarness(t, 10*time.Second)
	total := pageSize + 250
	for i := 0; i < total; i++ {
		h.publish(t, 9, "bulk", 50000+int64(i))
	}
	h.clock = time.Unix(50000+int64(total)+20, 0)

	_, body := h.cut(t)
	if body.Count != total {
		t.Fatalf("committed to %d of %d events", body.Count, total)
	}
	if len(h.store.queries) < 3 {
		t.Errorf("expected the window to be read in pages, saw %d queries", len(h.store.queries))
	}
}

func TestASecondTooDenseToPageNarrowsTheWindow(t *testing.T) {
	// A whole page inside one second means paging cannot make progress, since
	// the next query would ask for the same second again. Narrowing keeps the
	// claim true: the checkpoint covers only what was provably read in full,
	// and `from` says where that starts.
	h := newHarness(t, 10*time.Second)
	for i := 0; i < pageSize+50; i++ {
		h.publish(t, 9, "flood", 50000)
	}
	h.publish(t, 9, "after the flood", 50001)
	h.clock = time.Unix(50030, 0)

	_, body := h.cut(t)
	if body.From != 50001 {
		t.Fatalf("from is %d, want the window narrowed past the unreadable second", body.From)
	}
	if body.Count != 1 {
		t.Fatalf("count is %d, want only the event after the flood", body.Count)
	}
}

// --- the bytes ---------------------------------------------------------------

func TestTheBodyIsCanonicalJSON(t *testing.T) {
	// RFC 8785 key order, which here is just the struct field order, because
	// every value is hex or an integer. If a field is ever added that carries
	// free text, this shortcut stops being safe and the body needs a writer of
	// its own like contextpack has.
	h := newHarness(t, 900*time.Second)
	h.publish(t, 9, "one", 98000)
	h.cut(t)
	h.clock = h.clock.Add(600 * time.Second)
	event, _ := h.cut(t)

	keys := []string{`"algorithm"`, `"count"`, `"from"`, `"merkle_root"`, `"prev"`, `"to"`}
	at := -1
	for _, key := range keys {
		next := strings.Index(event.Content, key)
		if next < 0 {
			t.Fatalf("%s missing from %s", key, event.Content)
		}
		if next <= at {
			t.Fatalf("%s is out of RFC 8785 order in %s", key, event.Content)
		}
		at = next
	}
	if strings.ContainsAny(event.Content, `&<`) {
		t.Error("the content has been HTML-escaped; encoding/json is no longer safe here")
	}
}

func TestAltSaysWhatHappened(t *testing.T) {
	h := newHarness(t, 900*time.Second)
	h.publish(t, 9, "one", 98000)
	event, _ := h.cut(t)

	alt := ""
	for _, tag := range event.Tags {
		if len(tag) > 1 && tag[0] == "alt" {
			alt = tag[1]
		}
	}
	if !strings.Contains(alt, "1 events") || len(alt) > 280 {
		t.Errorf("alt is %q", alt)
	}
}

// --- configuration -----------------------------------------------------------

func TestRefusesNonsenseIntervals(t *testing.T) {
	store, feed := newStore(), &recorder{}
	if _, err := New(store, feed, relayKey, 0, time.Minute); err == nil {
		t.Error("a zero interval was accepted")
	}
	if _, err := New(store, feed, relayKey, time.Minute, 0); err == nil {
		t.Error("a zero lag was accepted")
	}
}

func TestTickCoversEveryGroupItHasSeen(t *testing.T) {
	h := newHarness(t, 900*time.Second)
	other := &nostr.Event{
		Kind:      9,
		CreatedAt: nostr.Timestamp(98000),
		Content:   "elsewhere",
		Tags:      nostr.Tags{{"h", "workspace-2"}, {"alt", "test"}},
	}
	if err := other.Sign(authorKey); err != nil {
		t.Fatal(err)
	}
	if err := h.store.SaveEvent(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	h.Observe(context.Background(), other)

	h.Tick(context.Background())

	groups := map[string]bool{}
	for _, event := range h.feed.events {
		if event.Kind != Kind {
			continue
		}
		for _, tag := range event.Tags {
			if len(tag) > 1 && tag[0] == "h" {
				groups[tag[1]] = true
			}
		}
	}
	if !groups[group] || !groups["workspace-2"] {
		t.Errorf("one tick checkpointed %v, want both groups", groups)
	}
}
