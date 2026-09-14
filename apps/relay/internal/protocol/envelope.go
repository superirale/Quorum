package protocol

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/nbd-wtf/go-nostr"
)

// Tag names. Single-letter tags are relay-indexed under NIP-01; the
// multi-character ones are read locally and deliberately consume no index.
const (
	TagGroup      = "h"
	TagAlt        = "alt"
	TagPubkey     = "p"
	TagRootEvent  = "E"
	TagRootKind   = "K"
	TagEvent      = "e"
	TagParentKind = "k"
	TagIdentifier = "d"
	TagEnc        = "enc"
	TagCounter    = "counter"
	TagAction     = "action"
)

const EncPlaintext = "plaintext"

// ValidateEnvelope applies the Quorum tag rules to an event.
//
// Only tags are checked here, never content, and that split is load-bearing
// rather than tidiness: on nip44 and mls channels the body is ciphertext, so a
// relay that folded body checks into this function would have to either reject
// every encrypted event or skip validation entirely the moment a workspace
// turned encryption on.
func (i *Index) ValidateEnvelope(event *nostr.Event) error {
	definition, isQuorum := i.Kind(event.Kind)
	if !isQuorum {
		// A borrowed kind. Its own NIP governs it; inventing extra rules here
		// would break the generic clients this design promises to support.
		return nil
	}

	for _, name := range i.Envelope.RequiredTags {
		if firstTagValue(event, name) == "" {
			return fmt.Errorf("a %s event must carry a %q tag", definition.Name, name)
		}
	}

	if err := i.validateAlt(event); err != nil {
		return err
	}

	if mode := firstTagValue(event, TagEnc); mode != "" && !i.ValidEncMode(mode) {
		return fmt.Errorf("unknown enc mode %q", mode)
	}

	if counter := firstTagValue(event, TagCounter); counter != "" {
		if n, err := strconv.ParseUint(counter, 10, 64); err != nil || n == 0 {
			return fmt.Errorf("counter must be a positive integer, got %q", counter)
		}
	}

	if IsAddressable(event.Kind) && firstTagValue(event, TagIdentifier) == "" {
		return fmt.Errorf("an addressable %s event must carry a `d` tag", definition.Name)
	}

	return i.validateRequirements(event, definition)
}

func (i *Index) validateAlt(event *nostr.Event) error {
	alt := firstTagValue(event, TagAlt)
	if length := len([]rune(alt)); length > i.Envelope.AltMaxLength {
		return fmt.Errorf("alt is %d characters, limit is %d", length, i.Envelope.AltMaxLength)
	}
	if strings.ContainsAny(alt, "\r\n") {
		return fmt.Errorf("alt must be a single line")
	}
	return nil
}

func (i *Index) validateRequirements(event *nostr.Event, definition Kind) error {
	requires := definition.Requires

	if requires.Threaded {
		if firstTagValue(event, TagRootEvent) == "" {
			return fmt.Errorf("a %s event must carry an `E` tag naming its thread", definition.Name)
		}
		if firstTagValue(event, TagRootKind) == "" {
			return fmt.Errorf("a %s event must carry a `K` tag naming its thread's kind", definition.Name)
		}
	}

	if requires.Addressed && len(i.Addressees(event)) == 0 {
		return fmt.Errorf(
			"a %s event must address someone with a `p` tag marked %q; unaddressed, there is nobody to answer it",
			definition.Name, i.Envelope.AddressMarker,
		)
	}

	if requires.ParentKind != 0 {
		// Checking for any `e` tag would pass trivially: a top-level NIP-22
		// comment parents to the thread root, so every threaded event already
		// has one. The `k` tag is the only thing that says the parent is the
		// right kind of event — without it an approval response parented to the
		// thread is an approval of nothing, and an agent matching on action id
		// alone would honour it.
		if firstTagValue(event, TagEvent) == "" {
			return fmt.Errorf("a %s event must point at a kind %d parent", definition.Name, requires.ParentKind)
		}
		parentKind := firstTagValue(event, TagParentKind)
		if parentKind == "" {
			return fmt.Errorf("a %s event must carry a `k` tag naming its parent's kind", definition.Name)
		}
		if parentKind != strconv.Itoa(requires.ParentKind) {
			return fmt.Errorf(
				"a %s event must answer a kind %d event, but its `k` tag says %s",
				definition.Name, requires.ParentKind, parentKind,
			)
		}
	}

	return nil
}

// ValidateBody checks content against the kind's JSON Schema.
//
// Separate from ValidateEnvelope because it is only possible on plaintext
// channels. Callers must skip it when `enc` is anything else.
func (i *Index) ValidateBody(event *nostr.Event) error {
	body, ok := i.Body(event.Kind)
	if !ok {
		return nil
	}
	if err := body.Validate(event.Content); err != nil {
		definition, _ := i.Kind(event.Kind)
		return fmt.Errorf("invalid %s body: %w", definition.Name, err)
	}
	return nil
}

// Addressees returns the pubkeys an event is addressed to: `p` tags carrying
// the address marker in position 4.
//
// The marker exists because `p` is overloaded — NIP-22 requires it for the
// parent's author, and Quorum wants it for addressing so agents can use the
// indexed #p filter. The filter stays a coarse superset and exact matching
// happens here.
func (i *Index) Addressees(event *nostr.Event) []string {
	var out []string
	for _, tag := range event.Tags {
		if len(tag) > 3 && tag[0] == TagPubkey && tag[3] == i.Envelope.AddressMarker && tag[1] != "" {
			out = append(out, tag[1])
		}
	}
	return out
}

// Group returns the NIP-29 group id an event belongs to.
func Group(event *nostr.Event) string { return firstTagValue(event, TagGroup) }

// Parent returns the NIP-22 `e` tag: the id of what this event directly answers.
func Parent(event *nostr.Event) string { return firstTagValue(event, TagEvent) }

// RootEvent returns the NIP-22 `E` tag: the id of the kind 11 root, which is
// also the thread id every 38101 is keyed by.
func RootEvent(event *nostr.Event) string { return firstTagValue(event, TagRootEvent) }

// ActionID returns the action chain an event belongs to, which is the id of the
// chain's `proposed` event. Empty for a proposal, which names the chain by
// being it, and for everything outside an action.
func ActionID(event *nostr.Event) string { return firstTagValue(event, TagAction) }

// EncMode returns the channel encryption mode, defaulting to plaintext.
func EncMode(event *nostr.Event) string {
	if mode := firstTagValue(event, TagEnc); mode != "" {
		return mode
	}
	return EncPlaintext
}

func firstTagValue(event *nostr.Event, name string) string {
	for _, tag := range event.Tags {
		if len(tag) > 1 && tag[0] == name {
			return tag[1]
		}
	}
	return ""
}

// Kind ranges, per NIP-01.
func IsEphemeral(kind int) bool   { return kind >= 20000 && kind < 30000 }
func IsAddressable(kind int) bool { return kind >= 30000 && kind < 40000 }
