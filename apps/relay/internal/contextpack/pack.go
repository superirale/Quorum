// Package contextpack is the relay's half of the Quorum context API: the
// deterministic extractive compactor, `extractive-v1`.
//
// It exists twice on purpose. On a `plaintext` channel the relay can read the
// thread and one round trip replaces a client-side backfill; on `nip44` or
// `mls` the relay cannot read a word and the packer has to live in the SDK. So
// there are two implementations in two languages, and if they disagree then
// "which packer answered" becomes a fact an agent's behaviour depends on —
// turning on encryption would quietly change what every agent in the workspace
// knows.
//
// The defence against that is the shape of this package rather than a comment
// in it: Pack is a pure function of (request, requester, events) with no clock,
// no database and no configuration, and Result.CanonicalJSON is compared byte
// for byte against the TypeScript packer's output over
// fixtures/context-pack.json. packages/sdk/src/context.ts is the other half.
// The numbered steps below match the numbered steps in the `Context` section of
// spec/nip-quorum.md, so a divergence between the two is always traceable to a
// sentence somebody can change.
//
// Nothing here paraphrases anything. There is no summarizer, and that is a
// security position: one designated agent writing the summaries every other
// agent reads means a single prompt injection against it rewrites the working
// memory of the whole workspace.
package contextpack

import (
	"encoding/json"
	"sort"
	"unicode/utf8"

	"github.com/nbd-wtf/go-nostr"
)

const (
	// Algorithm is named in every result so a reader knows which rules produced
	// it, and so the algorithm can change later without ambiguity.
	Algorithm = "extractive-v1"

	// RecentVerbatim is how many events at the end of a thread are never
	// dropped and never cut.
	RecentVerbatim = 10

	// MaxSegmentChars is where an optional segment is cut, in Unicode code
	// points — not bytes, which would split a character and leave the two
	// packers to disagree about the replacement, and not words, whose
	// boundaries are locale-dependent.
	MaxSegmentChars = 400

	// SegmentOverheadTokens is added to every segment for the header a caller
	// renders: who said it, when, and how far to trust it.
	SegmentOverheadTokens = 8

	// BytesPerToken is the token proxy, and is deliberately not a tokenizer. A
	// real BPE count is model-specific and versioned, so agreement between the
	// two packers would depend on both shipping the same build of a vendor's
	// vocabulary file — which a protocol cannot require. budget_tokens is
	// advisory for exactly this reason.
	BytesPerToken = 4

	// DefaultBudgetTokens mirrors the default in the 5600 body schema.
	DefaultBudgetTokens = 2000
)

// Kinds this package reasons about. Duplicated from the protocol index rather
// than read from it because these are algorithm constants: a relay that packed
// a different set of kinds because its schema directory was a version behind
// would be the exact divergence this package exists to prevent.
const (
	KindDeletion           = 5
	KindReaction           = 7
	KindChatMessage        = 9
	KindThread             = 11
	KindComment            = 1111
	KindContextPackRequest = 5600
	KindContextPackResult  = 6600
	KindJobFeedback        = 7000
	KindAction             = 8101
	KindApprovalRequest    = 8102
	KindApprovalResponse   = 8103
	KindSummary            = 8104
	KindCheckpoint         = 8108
	KindThreadState        = 38101
	KindAgentManifest      = 38103
	KindAgentMemory        = 38104
	KindAgentCursor        = 38105
)

// Request is the body of a kind 5600 event.
//
// Pointers where the schema has a default, so "absent" and "zero" stay
// distinguishable: a `since` of 0 is the epoch, not the absence of a filter.
type Request struct {
	Thread       string `json:"thread"`
	BudgetTokens *int   `json:"budget_tokens"`
	VerbatimOnly bool   `json:"verbatim_only"`
	IncludeKinds []int  `json:"include_kinds"`
	ExcludeKinds []int  `json:"exclude_kinds"`
	Since        *int64 `json:"since"`
}

// ParseRequest reads a 5600 body.
func ParseRequest(content string) (Request, error) {
	var request Request
	if err := json.Unmarshal([]byte(content), &request); err != nil {
		return Request{}, err
	}
	return request, nil
}

// Budget is the requested budget, or the schema's default.
//
// A non-positive budget is treated as absent rather than refused: the body
// schema already rejects it at the door, so reaching here means the relay is
// packing something it should not have stored, and answering with the default
// beats answering with nothing.
func (r Request) Budget() int {
	if r.BudgetTokens == nil || *r.BudgetTokens <= 0 {
		return DefaultBudgetTokens
	}
	return *r.BudgetTokens
}

// Provenance says who wrote a segment and how far to trust them.
type Provenance struct {
	Pubkey string `json:"pubkey"`
	Kind   string `json:"kind"`
	Trust  string `json:"trust"`
}

// Segment is one event, as the model will see it.
type Segment struct {
	EventID    string     `json:"event_id"`
	Kind       int        `json:"kind"`
	CreatedAt  int64      `json:"created_at"`
	Text       string     `json:"text"`
	Provenance Provenance `json:"provenance"`
	Truncated  bool       `json:"truncated"`
	Mandatory  bool       `json:"mandatory"`
}

// Result is the body of a kind 6600 event.
type Result struct {
	Thread        string    `json:"thread"`
	Segments      []Segment `json:"segments"`
	UsedTokens    int       `json:"used_tokens"`
	BudgetTokens  int       `json:"budget_tokens"`
	DroppedEvents int       `json:"dropped_events"`
	Algorithm     string    `json:"algorithm"`
}

// Pack compacts a thread into a budget. Deterministic: same inputs, same bytes.
//
// requester is whose perspective this is packed from; it decides `self` and
// `operator` and nothing else. events is everything the packer holds — a packer
// that has seen fewer events is not wrong, and DroppedEvents is a count over
// this set rather than over the workspace.
func Pack(request Request, requester string, events []*nostr.Event) Result {
	thread := request.Thread
	budget := request.Budget()

	// 1–3: select the thread, apply the caller's filters, drop what is never
	// context. The caller's filters win over the mandatory-keep rules below:
	// mandatory-keep protects history from the budget, never from an
	// instruction.
	candidates := make([]*nostr.Event, 0, len(events))
	for _, event := range events {
		if belongsTo(event, thread) && passesFilters(event, request) && !neverContext(event.Kind) {
			candidates = append(candidates, event)
		}
	}

	// 4: one proposal and one outcome per action; the middle of a chain is
	// inferable from its ends.
	ordered := collapseActions(candidates)

	// 5–6: NIP-01 order with the thread root pinned first, then mark what the
	// budget may not touch. Deliberately not the parent-link order an action
	// chain verifies in — nothing is authorised on a pack, and a reader wants a
	// transcript, not a proof.
	//
	// The root is the exception because everything else in the thread `E`-tags
	// it, so its causal position is the one fact the ordering cannot get wrong
	// by accident — and `created_at` gets it wrong routinely, since a thread
	// opened and answered inside the same second falls through to the hash
	// tiebreak and hands a model two replies before the task they answer.
	sort.Slice(ordered, func(i, j int) bool {
		if (ordered[i].ID == thread) != (ordered[j].ID == thread) {
			return ordered[i].ID == thread
		}
		return before(ordered[i], ordered[j])
	})

	recent := make(map[string]bool, RecentVerbatim)
	for i := max(0, len(ordered)-RecentVerbatim); i < len(ordered); i++ {
		recent[ordered[i].ID] = true
	}
	mandatory := func(event *nostr.Event) bool {
		switch {
		case event.ID == thread,
			event.Kind == KindThreadState,
			event.Kind == KindApprovalRequest,
			event.Kind == KindApprovalResponse,
			event.Kind == KindAction,
			recent[event.ID]:
			return true
		default:
			return false
		}
	}

	actors := newActors(events, requester)

	// 7: mandatory first at any price, then optional segments newest first
	// while they fit. Admission *stops* at the first one that does not: a model
	// handed the last hour with one arbitrary paragraph from Tuesday wedged
	// into it reasons worse than one handed a shorter hour.
	chosen := make(map[string]Segment, len(ordered))
	used := 0
	for _, event := range ordered {
		if !mandatory(event) {
			continue
		}
		segment := toSegment(event, actors, false)
		chosen[event.ID] = segment
		used += Tokens(segment.Text)
	}
	for i := len(ordered) - 1; i >= 0; i-- {
		event := ordered[i]
		if mandatory(event) {
			continue
		}
		segment := toSegment(event, actors, true)
		if used+Tokens(segment.Text) > budget {
			break
		}
		chosen[event.ID] = segment
		used += Tokens(segment.Text)
	}

	segments := make([]Segment, 0, len(chosen))
	for _, event := range ordered {
		if segment, ok := chosen[event.ID]; ok {
			segments = append(segments, segment)
		}
	}

	return Result{
		Thread:        thread,
		Segments:      segments,
		UsedTokens:    used,
		BudgetTokens:  budget,
		DroppedEvents: len(candidates) - len(segments),
		Algorithm:     Algorithm,
	}
}

// belongsTo matches a thread's events plus the state that is *about* it.
//
// The 38101 carries no `E` tag — it is a projection, not an utterance — so it
// is found by `d`. Including it is the difference between a pack that says what
// was talked about and one that says what the task currently is, which is the
// first question an agent asks.
func belongsTo(event *nostr.Event, thread string) bool {
	if event.ID == thread {
		return true
	}
	if event.Kind == KindThreadState {
		return tagValue(event, "d") == thread
	}
	return tagValue(event, "E") == thread
}

func passesFilters(event *nostr.Event, request Request) bool {
	if len(request.IncludeKinds) > 0 && !containsInt(request.IncludeKinds, event.Kind) {
		return false
	}
	if containsInt(request.ExcludeKinds, event.Kind) {
		return false
	}
	if request.Since != nil && int64(event.CreatedAt) < *request.Since {
		return false
	}
	// A summary is somebody's account of events rather than the events. A
	// caller paying full price for history may refuse all of them without
	// having to reason about who wrote which.
	if request.VerbatimOnly && event.Kind == KindSummary {
		return false
	}
	return true
}

// neverContext names the kinds that are never context, whatever the caller asks
// for: control plane, moderation, reactions, deletions and the context API's
// own traffic.
func neverContext(kind int) bool {
	switch {
	case kind >= 20000 && kind < 30000: // ephemeral
		return true
	case kind >= 9000 && kind <= 9022: // NIP-29 moderation
		return true
	case kind >= 39000 && kind <= 39003: // NIP-29 relay-signed metadata
		return true
	case kind == KindDeletion, kind == KindReaction:
		return true
	case kind == KindContextPackRequest, kind == KindContextPackResult:
		return true
	case kind == KindAgentMemory, kind == KindAgentCursor:
		return true
	default:
		return false
	}
}

var statusRank = map[string]int{
	"proposed":          0,
	"awaiting_approval": 1,
	"running":           2,
	"succeeded":         3,
	"failed":            3,
	"denied":            3,
	"cancelled":         3,
}

// collapseActions keeps each action's proposal and its furthest transition and
// drops the middle. The input and the outcome are what a later reader needs;
// "it started running" is implied by both being there.
//
// Ties in rank break by `(created_at, id)` keeping the last, so two events
// claiming the same terminal status resolve the same way in both
// implementations.
func collapseActions(events []*nostr.Event) []*nostr.Event {
	furthest := make(map[string]*nostr.Event)
	survivors := make(map[string]bool)

	for _, event := range events {
		if event.Kind != KindAction {
			continue
		}
		action := tagValue(event, "action")
		if action == "" {
			continue
		}
		if rankOf(event) == 0 {
			survivors[event.ID] = true
		}

		held, ok := furthest[action]
		if !ok || rankOf(event) > rankOf(held) || (rankOf(event) == rankOf(held) && before(held, event)) {
			furthest[action] = event
		}
	}
	for _, event := range furthest {
		survivors[event.ID] = true
	}

	kept := make([]*nostr.Event, 0, len(events))
	for _, event := range events {
		// An 8101 with no `action` tag belongs to no chain and cannot be
		// collapsed against anything, so it is kept. Refusing it here would
		// silently delete an event the validator accepted.
		if event.Kind != KindAction || survivors[event.ID] || tagValue(event, "action") == "" {
			kept = append(kept, event)
		}
	}
	return kept
}

// actionBody is the subset of an 8101 that ranking needs, plus the fields the
// TypeScript packer's schema requires. A body missing one of those fails to
// parse there and ranks 0, so it has to rank 0 here too.
type actionBody struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Summary string `json:"summary"`
}

func rankOf(event *nostr.Event) int {
	var body actionBody
	if json.Unmarshal([]byte(event.Content), &body) != nil {
		return 0
	}
	if body.Name == "" || body.Summary == "" {
		return 0
	}
	return statusRank[body.Status]
}

// summaryBody is the 8104 body, with the required fields as pointers so that a
// body missing one is distinguishable from a body whose value is the zero.
type summaryBody struct {
	Text      string  `json:"text"`
	FromEvent string  `json:"from_event"`
	ToEvent   string  `json:"to_event"`
	Covers    *int    `json:"covers"`
	Method    string  `json:"method"`
	Model     *string `json:"model"`
}

// textOf is what a segment says.
//
// For the plain-text kinds it is the content; for a summary it is the summary;
// for everything else it is the `alt` tag. That last rule is what `alt` is
// required for. The primary consumer of an event nobody has implemented yet is
// a context packer feeding a model, and a packer that understood every kind it
// emitted would break on the first kind added after it shipped — so this one
// understands none of them and reads the line the author was made to write.
func textOf(event *nostr.Event) string {
	switch event.Kind {
	case KindChatMessage, KindThread, KindComment:
		return event.Content
	case KindSummary:
		var body summaryBody
		if json.Unmarshal([]byte(event.Content), &body) == nil &&
			body.Text != "" && body.FromEvent != "" && body.ToEvent != "" &&
			body.Covers != nil && *body.Covers >= 0 &&
			(body.Method == "extractive" || body.Method == "model") {
			return body.Text
		}
		return tagValue(event, "alt")
	default:
		return tagValue(event, "alt")
	}
}

func toSegment(event *nostr.Event, actors *actors, mayTruncate bool) Segment {
	full := textOf(event)
	text := full
	if mayTruncate {
		text = truncate(full)
	}
	return Segment{
		EventID:    event.ID,
		Kind:       event.Kind,
		CreatedAt:  int64(event.CreatedAt),
		Text:       text,
		Provenance: actors.of(event.PubKey),
		Truncated:  text != full,
		Mandatory:  !mayTruncate,
	}
}

// truncate cuts at MaxSegmentChars code points and marks the cut.
func truncate(text string) string {
	if utf8.RuneCountInString(text) <= MaxSegmentChars {
		return text
	}
	count := 0
	for offset := range text {
		if count == MaxSegmentChars {
			return text[:offset] + "…"
		}
		count++
	}
	return text
}

// Tokens is the token proxy, including the per-segment framing.
func Tokens(text string) int {
	return (len(text)+BytesPerToken-1)/BytesPerToken + SegmentOverheadTokens
}

// actors is who everybody is, derived from the event set and nothing else.
//
// Both packers must label a segment identically, so every input here has to be
// something both of them hold. That rules out anything requiring a lookup: no
// profile fetch, no relay-side membership table, no configuration. What is left
// is what the events themselves say — a manifest makes you an agent, a
// relay-signed kind makes you a relay — which is also honest about how much any
// of it is worth. A manifest is self-published and therefore a claim.
type actors struct {
	agents    map[string]bool
	relays    map[string]bool
	requester string
	operator  string
}

func newActors(events []*nostr.Event, requester string) *actors {
	a := &actors{
		agents:    make(map[string]bool),
		relays:    make(map[string]bool),
		requester: requester,
	}
	var mine *nostr.Event
	for _, event := range events {
		switch event.Kind {
		case KindAgentManifest:
			a.agents[event.PubKey] = true
			if event.PubKey == requester && (mine == nil || before(mine, event)) {
				mine = event
			}
		case KindThreadState, KindCheckpoint:
			a.relays[event.PubKey] = true
		}
	}
	if mine != nil {
		var body struct {
			Operator string `json:"operator"`
		}
		if json.Unmarshal([]byte(mine.Content), &body) == nil {
			a.operator = body.Operator
		}
	}
	return a
}

func (a *actors) of(pubkey string) Provenance {
	return Provenance{Pubkey: pubkey, Kind: a.kindOf(pubkey), Trust: a.trustOf(pubkey)}
}

func (a *actors) kindOf(pubkey string) string {
	switch {
	case a.relays[pubkey]:
		return "relay"
	case a.agents[pubkey]:
		return "agent"
	default:
		return "human"
	}
}

// trustOf labels how far to trust a segment.
//
// `untrusted` means "delimit this before a model reads it", not "this is
// hostile". Another agent's output is the normal case in this protocol and is
// exactly the content a prompt injection travels in, so it is labelled
// untrusted regardless of who runs it — including a sibling replica of the
// requester's own operator's fleet.
func (a *actors) trustOf(pubkey string) string {
	switch {
	case pubkey == a.requester:
		return "self"
	case a.operator != "" && pubkey == a.operator:
		return "operator"
	case a.agents[pubkey]:
		return "untrusted"
	default:
		return "member"
	}
}

// before is NIP-01's `(created_at, id)` order.
func before(a, b *nostr.Event) bool {
	if a.CreatedAt != b.CreatedAt {
		return a.CreatedAt < b.CreatedAt
	}
	return a.ID < b.ID
}

func tagValue(event *nostr.Event, name string) string {
	for _, tag := range event.Tags {
		if len(tag) > 1 && tag[0] == name {
			return tag[1]
		}
	}
	return ""
}

func containsInt(values []int, want int) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
