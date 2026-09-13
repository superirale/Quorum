package contextpack

import (
	"context"
	"fmt"

	"github.com/nbd-wtf/go-nostr"

	"github.com/quorum-chat/quorum/apps/relay/internal/protocol"
)

const (
	// KindJobFeedbackStatus is NIP-90's tag name for why a job did not produce
	// a result.
	KindJobFeedbackStatus = "status"

	// MaxThreadEvents bounds one gather.
	//
	// A cap is unavoidable — a year-old thread must not be read into memory to
	// answer one request — and it is honest rather than lossy: a packer that
	// holds fewer events is not a packer that is wrong, which is the same
	// allowance the SDK-side packer already needs for a client that backfilled
	// a window. What it must never do is vary, so this is a constant and not a
	// configuration knob, and 5000 is far above the 500-message thread the
	// budget maths was designed around.
	//
	// Exported because the event store has to know it. eventstore's badger
	// backend honours a filter's limit only while it is under the store's own
	// MaxLimit and otherwise falls back to a *quarter* of that — so a gather
	// asking for more than the store allows silently receives far less than one
	// asking for nothing at all. main.go pins the two together.
	MaxThreadEvents = 5000

	// maxManifests bounds the provenance lookup. One per agent in a workspace.
	maxManifests = 500

	// MaxResultBytes is how much content one event can carry here.
	//
	// Not a Quorum rule and not a NIP-01 one: eventstore's binary encoding
	// writes the content length as a uint16, so 64KiB is the hard ceiling of
	// the store this relay is built on. It is stated here because it is the
	// number that decides whether a pack can be *delivered*, and it is far
	// below what a generous `budget_tokens` implies — a segment costs about
	// 210 bytes of ids and provenance on top of its text, and the token proxy
	// counts none of that. Roughly: 20k tokens of a chatty thread will not fit,
	// and the same pack computed in the SDK, which publishes nothing, is fine.
	MaxResultBytes = 65535
)

// Store is the subset of the event database the packer needs.
type Store interface {
	QueryEvents(ctx context.Context, filter nostr.Filter) (chan *nostr.Event, error)
	SaveEvent(ctx context.Context, event *nostr.Event) error
}

// Publisher broadcasts a newly signed event to subscribers.
type Publisher interface {
	BroadcastEvent(event *nostr.Event)
}

// Packer answers kind 5600 context requests addressed to this relay.
//
// It is a DVM and not a privileged relay endpoint, which is the whole point:
// the packer is addressed by pubkey, so on an encrypted channel a client can
// address a different one — its own — and nothing else about the protocol
// changes. That also means this implementation has no authority. It answers
// when asked, it is not the only thing that may answer, and a requester that
// dislikes its answer can compute the same result itself from the same events.
type Packer struct {
	index     *protocol.Index
	store     Store
	publish   Publisher
	secretKey string
	pubkey    string
}

func NewPacker(index *protocol.Index, store Store, publish Publisher, secretKey string) (*Packer, error) {
	pubkey, err := nostr.GetPublicKey(secretKey)
	if err != nil {
		return nil, fmt.Errorf("deriving the relay public key: %w", err)
	}
	return &Packer{index: index, store: store, publish: publish, secretKey: secretKey, pubkey: pubkey}, nil
}

func (p *Packer) PublicKey() string { return p.pubkey }

// Answer is a khatru OnEventSaved hook: it reacts to a stored context request.
//
// Every path that does not produce a 6600 produces a kind 7000 refusal, except
// the two where the request was not this packer's to answer. "The packer will
// not answer" and "the thread is empty" are different facts, and an agent that
// cannot tell them apart reasons happily from no history at all.
func (p *Packer) Answer(ctx context.Context, event *nostr.Event) {
	if event.Kind != KindContextPackRequest {
		return
	}
	// Addressed by the `to` marker, not by any `p` tag. A workspace may hold
	// several packers, and one that answered every request it could see would
	// leave a requester unable to say whose answer it got — while they are
	// allowed to differ, since one may hold events another has never seen.
	if !addressedTo(p.index, event, p.pubkey) {
		return
	}
	group := protocol.Group(event)
	if group == "" {
		return
	}

	// An encrypted channel is refused rather than attempted. The relay cannot
	// read the request, let alone the thread, and the refusal is the thing that
	// tells a client to ask a packer that can — silence would look like a relay
	// that is merely slow.
	if protocol.EncMode(event) != protocol.EncPlaintext {
		p.refuse(ctx, event, group, "this channel is encrypted; ask a packer that holds the keys")
		return
	}

	request, err := ParseRequest(event.Content)
	if err != nil || request.Thread == "" {
		p.refuse(ctx, event, group, "the request body does not parse")
		return
	}

	result := Pack(request, event.PubKey, p.gather(ctx, request.Thread, group))
	content := result.CanonicalJSON()

	// A pack that does not fit in one event is refused rather than trimmed to
	// fit. Trimming here would be the one thing this package exists to prevent:
	// the algorithm is what makes two packers interchangeable, and a relay that
	// quietly dropped the segments its storage could not hold would answer the
	// same request differently from the SDK-side packer — with the same
	// `algorithm` field on it, and nothing in the body saying so.
	//
	// So the limit is reported instead, with the number in it, because the
	// caller has an actionable fix: ask for fewer tokens, or pack locally, where
	// nothing has to be stored at all.
	if len(content) > MaxResultBytes {
		p.refuse(ctx, event, group, fmt.Sprintf(
			"the pack is %d bytes and an event here holds %d; ask for a smaller budget_tokens, or pack it yourself",
			len(content), MaxResultBytes,
		))
		return
	}

	if err := p.deliver(ctx, event, group, content, result); err != nil {
		p.refuse(ctx, event, group, "the packer could not publish its result")
	}
}

// gather reads everything a pack may draw on: the thread root, the thread's
// events, the relay's projection of its state, and the workspace's agent
// manifests.
//
// The manifests are here for one reason and it is easy to drop: provenance.
// Without them every agent in the result is labelled `human` and `untrusted`
// collapses to `member`, which is the label that decides whether a caller
// fences a segment before a model reads it. The SDK-side packer fetches the
// same four filters, and a golden fixture would not catch a divergence here —
// this is the input to the pure function, not the function.
func (p *Packer) gather(ctx context.Context, thread, group string) []*nostr.Event {
	filters := []nostr.Filter{
		{IDs: []string{thread}, Limit: 1},
		{Tags: nostr.TagMap{protocol.TagRootEvent: {thread}, protocol.TagGroup: {group}}, Limit: MaxThreadEvents},
		{
			Kinds: []int{KindThreadState},
			Tags:  nostr.TagMap{protocol.TagIdentifier: {thread}, protocol.TagGroup: {group}},
			Limit: MaxThreadEvents,
		},
		{Kinds: []int{KindAgentManifest}, Tags: nostr.TagMap{protocol.TagGroup: {group}}, Limit: maxManifests},
	}

	seen := make(map[string]bool)
	var events []*nostr.Event
	for _, filter := range filters {
		results, err := p.store.QueryEvents(ctx, filter)
		if err != nil {
			continue
		}
		// Drained fully rather than broken out of: the store produces on a
		// goroutine that blocks on send, and abandoning the channel leaks it.
		for event := range results {
			// The group is re-checked on the way in because the first filter
			// cannot carry it — an id lookup has no `h` — and because a `#h`
			// query is only as good as the tag. Without this, a member of one
			// channel could publish a 1111 with an `E` tag pointing at another
			// channel's thread and have it packed into context there.
			if seen[event.ID] || protocol.Group(event) != group {
				continue
			}
			seen[event.ID] = true
			events = append(events, event)
		}
	}
	return events
}

// deliver signs, stores and broadcasts the 6600.
//
// Stored as well as broadcast, so a requester that asked and then crashed finds
// its answer waiting. It goes through the store directly rather than back
// around the policy chain, exactly as the thread projector's 38101 does.
func (p *Packer) deliver(ctx context.Context, request *nostr.Event, group, content string, result Result) error {
	event := &nostr.Event{
		Kind:      KindContextPackResult,
		CreatedAt: nostr.Now(),
		Content:   content,
		Tags: nostr.Tags{
			{protocol.TagEvent, request.ID},
			{protocol.TagPubkey, request.PubKey, "", p.index.Envelope.AddressMarker},
			{protocol.TagGroup, group},
			{protocol.TagAlt, altFor(result)},
		},
	}
	if err := event.Sign(p.secretKey); err != nil {
		return err
	}
	if err := p.store.SaveEvent(ctx, event); err != nil {
		return err
	}
	p.publish.BroadcastEvent(event)
	return nil
}

// refuse publishes NIP-90's kind 7000 job feedback.
//
// Not a Quorum kind, so it carries no `alt` and the envelope rules do not touch
// it; the shape is NIP-90's — a `status` tag whose third element is the human
// reason, `e` at the request, `p` at whoever asked.
//
// A failure to publish a refusal is dropped rather than retried. The caller has
// a timeout for precisely this case, and a packer that cannot write is not a
// packer that can explain itself.
func (p *Packer) refuse(ctx context.Context, request *nostr.Event, group, reason string) {
	event := &nostr.Event{
		Kind:      KindJobFeedback,
		CreatedAt: nostr.Now(),
		Content:   "",
		Tags: nostr.Tags{
			{KindJobFeedbackStatus, "error", reason},
			{protocol.TagEvent, request.ID},
			{protocol.TagPubkey, request.PubKey, "", p.index.Envelope.AddressMarker},
			{protocol.TagGroup, group},
		},
	}
	if err := event.Sign(p.secretKey); err != nil {
		return
	}
	if err := p.store.SaveEvent(ctx, event); err != nil {
		return
	}
	p.publish.BroadcastEvent(event)
}

// altFor writes the NIP-31 fallback, and must match the TypeScript `defaultAlt`
// for kind 6600 — the same event built by either packer reads the same to a
// client that cannot parse the body.
//
// It counts rather than quotes. This tag is not encrypted even when the channel
// is, so a line of the conversation here would leak straight past whatever
// encryption the body is wearing.
func altFor(result Result) string {
	return fmt.Sprintf("Context packed: %d segments, %d tokens", len(result.Segments), result.UsedTokens)
}

func addressedTo(index *protocol.Index, event *nostr.Event, pubkey string) bool {
	for _, addressee := range index.Addressees(event) {
		if addressee == pubkey {
			return true
		}
	}
	return false
}
