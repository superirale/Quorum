// Package protocol loads the Quorum protocol definition from the JSON Schema
// artifacts published by @quorum/protocol.
//
// This relay deliberately does not reimplement the protocol rules in Go. It
// reads schemas/index.json — the same file the TypeScript SDK and the Python
// validator read — and enforces what it finds there. A relay carrying its own
// hand-written copy of the kind table would drift from the spec on the first
// change nobody remembered to mirror, and the drift would surface as events
// being rejected in production for reasons no document explains.
//
// The corollary is that a missing or unreadable schema directory is fatal at
// startup rather than a warning. A relay that silently stops enforcing the
// Quorum envelope still accepts events and still looks healthy; it just quietly
// stops being the thing it claims to be.
package protocol

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// Requirements are the per-kind envelope rules, published as data by the
// generator so every implementation enforces the same table.
type Requirements struct {
	// Threaded events carry NIP-22 root scope: E (thread root) and K (root kind).
	Threaded bool `json:"threaded"`
	// Addressed events carry at least one `p` tag with the address marker.
	Addressed bool `json:"addressed"`
	// ParentKind, when non-zero, is the kind the `e`/`k` parent must have.
	ParentKind int `json:"parentKind"`
}

type Kind struct {
	Name     string       `json:"name"`
	Body     string       `json:"body"`
	Requires Requirements `json:"requires"`
}

type Envelope struct {
	RequiredTags  []string `json:"required_tags"`
	AltMaxLength  int      `json:"alt_max_length"`
	EncModes      []string `json:"enc_modes"`
	AddressMarker string   `json:"address_marker"`
}

// RelayEnforced names the handful of capabilities a relay has to check itself,
// because they have no resource anywhere else to check them.
//
// Published as data for the same reason the envelope table is. A resource name
// is matched exactly and never widened — that is what makes the capability
// system safe — which also means a relay and a console that disagree by one
// character produce a grant that authorises nothing and reports no error. This
// relay refuses to start on that disagreement; see policy.ConfirmResourceNames.
type RelayEnforced struct {
	Action    string            `json:"action"`
	ScopeKey  string            `json:"scope_key"`
	Resources map[string]string `json:"resources"`
}

// Index is schemas/index.json, plus the body schemas resolved alongside it.
type Index struct {
	Version        string          `json:"version"`
	Kinds          map[string]Kind `json:"kinds"`
	SupportedKinds []string        `json:"supported_kinds"`
	RelayEnforced  RelayEnforced   `json:"relay_enforced"`
	Envelope       Envelope        `json:"envelope"`

	// Derived at load time so the hot path does no string parsing.
	byKind    map[int]Kind
	supported map[int]bool
	encModes  map[string]bool
	bodies    map[int]*BodySchema
}

// Load reads schemas/index.json and every body schema it names.
func Load(dir string) (*Index, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		return nil, fmt.Errorf("reading the protocol index: %w", err)
	}

	var index Index
	if err := json.Unmarshal(raw, &index); err != nil {
		return nil, fmt.Errorf("parsing the protocol index: %w", err)
	}
	if len(index.Kinds) == 0 {
		return nil, fmt.Errorf("the protocol index declares no kinds; is %s the right directory?", dir)
	}

	index.byKind = make(map[int]Kind, len(index.Kinds))
	index.bodies = make(map[int]*BodySchema, len(index.Kinds))
	for key, kind := range index.Kinds {
		number, err := strconv.Atoi(key)
		if err != nil {
			return nil, fmt.Errorf("the protocol index has a non-numeric kind %q", key)
		}
		index.byKind[number] = kind

		if kind.Body == "" {
			continue
		}
		body, err := loadBodySchema(filepath.Join(dir, kind.Body))
		if err != nil {
			return nil, fmt.Errorf("kind %d: %w", number, err)
		}
		index.bodies[number] = body
	}

	index.supported = make(map[int]bool, len(index.SupportedKinds))
	for _, key := range index.SupportedKinds {
		number, err := strconv.Atoi(key)
		if err != nil {
			return nil, fmt.Errorf("the protocol index has a non-numeric supported kind %q", key)
		}
		index.supported[number] = true
	}

	index.encModes = make(map[string]bool, len(index.Envelope.EncModes))
	for _, mode := range index.Envelope.EncModes {
		index.encModes[mode] = true
	}

	if index.Envelope.AddressMarker == "" {
		return nil, fmt.Errorf("the protocol index declares no address marker")
	}
	if index.Envelope.AltMaxLength <= 0 {
		return nil, fmt.Errorf("the protocol index declares no alt length limit")
	}

	return &index, nil
}

// Kind returns the definition for a kind, and whether it is a Quorum kind at
// all. Borrowed kinds (9, 11, 1111, …) are supported but not defined here;
// their own NIPs govern them and this relay must not invent extra rules for
// them, or a generic client would find its perfectly valid events rejected.
func (i *Index) Kind(kind int) (Kind, bool) {
	definition, ok := i.byKind[kind]
	return definition, ok
}

// Supported reports whether the relay should accept this kind at all.
func (i *Index) Supported(kind int) bool { return i.supported[kind] }

// SupportedKindNumbers is the NIP-29 39000 `supported_kinds` list.
func (i *Index) SupportedKindNumbers() []int {
	numbers := make([]int, 0, len(i.supported))
	for kind := range i.supported {
		numbers = append(numbers, kind)
	}
	return numbers
}

func (i *Index) ValidEncMode(mode string) bool { return i.encModes[mode] }

// Body returns the JSON Schema for a kind's content, if it has one.
func (i *Index) Body(kind int) (*BodySchema, bool) {
	body, ok := i.bodies[kind]
	return body, ok
}
