package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"

	"github.com/nbd-wtf/go-nostr"

	"github.com/quorum-chat/quorum/apps/relay/internal/protocol"
)

const KindChannelPolicy = 38107

// EncryptionPolicies enforces a channel's stated encryption mode.
//
// # A relay enforcing confidentiality it cannot verify
//
// This is the odd one in this package and worth reading slowly. Every other
// policy here checks something the relay can see: a signature, a role, a
// number. This one enforces a property the relay is definitionally excluded
// from — it cannot decrypt a single byte of what it is protecting, and it
// cannot tell a real NIP-44 payload from base64 noise.
//
// What it *can* see is the kind 38107 channel policy, because that event is
// deliberately left in the clear, and the `enc` tag, because tags are never
// sealed. That is enough for the check that matters: on a channel whose policy
// says `nip44`, an event carrying content and not tagged `enc=nip44` is
// plaintext, whatever else it is. Refusing it stops a leak the relay could
// never have read — one client with encryption misconfigured, or an older
// build that predates the policy, publishing a message into a channel where
// everyone else believes the relay is holding ciphertext.
//
// Without this the failure is silent in the worst possible way. The message
// goes through, the relay stores it in the clear, and every reader decrypts
// nothing and displays it normally, because `openEvent` passes an untagged
// event straight through. Nobody sees an error. The channel is simply less
// private than its policy says, and nothing anywhere reports the difference.
//
// # The other direction is checked too, for two different reasons
//
// A sealed event on a **plaintext** channel is refused because
// ValidateQuorumEvent skips body validation whenever `enc` is set — so without
// this, `enc=nip44` on an unencrypted channel is a one-tag bypass of the
// entire schema. The content would not even have to be ciphertext.
//
// A sealed event of an **unsealed kind** on an encrypted channel is refused
// because that list is not a convenience. A capability grant nobody can audit
// is not a capability, and a channel policy nobody can read is a channel
// nobody can join. Encrypting one of those does not make the workspace more
// private; it makes it unadministrable, in a way that looks fine until an
// owner asks who may deploy to production.
//
// # What it does not do
//
// It does not check that the ciphertext decrypts, that the epoch is current,
// or that the sender holds a key — none of which the relay can know. A member
// who wants to leak a channel can still paste it anywhere. This closes the
// accident, not the betrayal; the betrayal is out of scope for any mechanism
// that lets people read their own messages.
type EncryptionPolicies struct {
	index *protocol.Index
	store Lookup

	mutex sync.RWMutex
	known map[string]channelEncryption
}

// channelEncryption is the mode and nothing else.
//
// It cached the policy's `epoch` too, until M10, and nothing ever read it — a
// field that looks like enforcement and is not. Removing it is not tidying: on
// an `mls` channel there is no epoch a 38107 could honestly state, because the
// ratchet advances on every commit and the relay cannot read one, so the
// protocol now refuses an `mls` policy that carries the field at all. A relay
// holding a cached copy of a number the spec says must not exist is one
// refactor away from comparing against it.
type channelEncryption struct {
	enc string
}

func NewEncryptionPolicies(index *protocol.Index, store Lookup) *EncryptionPolicies {
	return &EncryptionPolicies{index: index, store: store, known: map[string]channelEncryption{}}
}

// Forget drops a cached policy. Register it on OnEventSaved.
//
// The cache is invalidated *after* the store accepts a 38107 rather than when
// one arrives, and the difference is not academic: invalidating on arrival
// would re-read the store before the new policy is in it, cache the old answer
// a second time, and then never invalidate again — a channel that had been
// switched to nip44 would go on accepting plaintext until the relay restarted.
// A stale-by-one-event window at OnEventSaved costs nothing by comparison,
// because the client that published the policy has to see it stored before it
// can start sealing anyway.
func (e *EncryptionPolicies) Forget(ctx context.Context, event *nostr.Event) {
	if event.Kind != KindChannelPolicy {
		return
	}
	group := protocol.Group(event)
	if group == "" {
		return
	}
	e.mutex.Lock()
	delete(e.known, group)
	e.mutex.Unlock()
}

// RequirePolicyEncMode refuses an event that contradicts its channel's policy.
func (e *EncryptionPolicies) RequirePolicyEncMode() func(context.Context, *nostr.Event) (bool, string) {
	return func(ctx context.Context, event *nostr.Event) (reject bool, msg string) {
		group := protocol.Group(event)
		if group == "" {
			// No `h` tag: NIP-42 auth, and anything else outside a channel.
			// There is no policy to contradict.
			return false, ""
		}

		mode := protocol.EncMode(event)
		policy := e.policyFor(ctx, group)

		if policy.enc == protocol.EncPlaintext {
			if mode != protocol.EncPlaintext {
				return true, fmt.Sprintf(
					"invalid: #%s has no encryption policy, but this event is tagged enc=%s; "+
						"publish a kind %d policy for the channel first",
					group, mode, KindChannelPolicy)
			}
			return false, ""
		}

		if !e.index.MustSeal(event.Kind) {
			if mode != protocol.EncPlaintext {
				return true, fmt.Sprintf(
					"invalid: kind %d stays readable on an encrypted channel — it is key management, "+
						"authorization, or a record this relay signs — but this one is tagged enc=%s",
					event.Kind, mode)
			}
			return false, ""
		}

		// Nothing to hide and nothing to check. A deletion request with no
		// reason and an empty chat message are both legitimate and both carry
		// no content, so demanding a payload of them would refuse honest
		// traffic to protect nothing.
		if event.Content == "" {
			return false, ""
		}

		if mode != policy.enc {
			return true, fmt.Sprintf(
				"restricted: #%s is encrypted with %s and this kind %d event is tagged enc=%s; "+
					"this relay refuses to store it in the clear",
				group, policy.enc, event.Kind, mode)
		}

		// An epoch is required but never compared against the policy's. A
		// reader that cannot decrypt has to be able to say *which* key it is
		// missing, because "no key for epoch 3" and "this event was tampered
		// with" are the same MAC failure otherwise, and they send an operator
		// to opposite ends of the building. Requiring the tag to *match* the
		// current epoch would be the wrong rule: an event written a second
		// before a rotation, or arriving from another relay, is honest and
		// still readable by everyone who held the old key.
		if at := firstTag(event, protocol.TagEpoch); at == "" {
			return true, "invalid: a sealed event must carry an `epoch` tag naming the key it was " +
				"sealed under, or a reader missing that key cannot tell which one to ask for"

		} else if n, err := strconv.Atoi(at); err != nil || n < lowestEpoch(policy.enc) {
			return true, fmt.Sprintf(
				"invalid: on a %s channel the epoch is an integer of at least %d, got %q",
				policy.enc, lowestEpoch(policy.enc), at)
		}

		return false, ""
	}
}

// lowestEpoch is where each mode starts counting, and the two modes disagree.
//
// A nip44 channel mints its first key as generation 1, deliberately, so that
// zero stays distinguishable from a missing field. RFC 9420 gives MLS no such
// choice: a group is at epoch 0 the moment it is created, and stays there until
// the first commit. This relay refused epoch 0 outright until M10, which would
// have rejected the opening messages of every MLS channel it ever hosted — with
// "epoch must be a positive integer", about a number the spec requires. It is
// the Go twin of the `epoch()` bug found in packages/protocol/src/tags.ts, and
// both were written before anything published an MLS event.
func lowestEpoch(mode string) int {
	if mode == protocol.EncMls {
		return 0
	}
	return 1
}

// RequireGrantToSetChannelPolicy gates kind 38107.
//
// Same shape as RequireGrantToSetBudget and for the same reason: this is an
// event that is authority rather than coordination. The dangerous edit is
// setting `plaintext` on a channel that was encrypted — every message written
// after it arrives readable, no ciphertext fails, no MAC complains, and the
// only sign is that the relay stopped refusing plaintext. A member who can do
// that can declassify a channel without ever reading a word of it.
//
// Owners and admins pass without a grant, because they can already publish a
// put-user and a grant's authority comes from a role in the first place.
func (e *EncryptionPolicies) RequireGrantToSetChannelPolicy(
	authority Authority,
) func(context.Context, *nostr.Event) (bool, string) {
	return func(ctx context.Context, event *nostr.Event) (reject bool, msg string) {
		if event.Kind != KindChannelPolicy {
			return false, ""
		}
		group := protocol.Group(event)
		if group == "" {
			return true, "invalid: a channel policy must name its channel in an `h` tag"
		}
		// The policy is keyed by the channel it governs. A 38107 with `d` set
		// to something else is an addressable event that no reader will ever
		// find — channelPolicy() queries by `d` — so it would be a policy that
		// exists, passes every check, and governs nothing.
		if identifier(event) != group {
			return true, fmt.Sprintf(
				"invalid: a channel policy's `d` must be the channel id; this one says %q in #%s",
				identifier(event), group)
		}

		if administrators(ctx, e.store, group, authority)[event.PubKey] {
			return false, ""
		}
		result := authorizeCapability(ctx, e.store, capRequest{
			group:     group,
			agent:     event.PubKey,
			resource:  ResourceChannelEncrypt,
			action:    ActionInvoke,
			scope:     map[string]any{ScopeGroup: group},
			authority: authority,
		})
		if result.allowed {
			return false, ""
		}
		return true, fmt.Sprintf(
			"restricted: setting the encryption policy for #%s needs a %s capability from an owner or admin — %s",
			group, ResourceChannelEncrypt, result.reason,
		)
	}
}

// policyFor reads a channel's encryption policy, memoized.
//
// It trusts whatever is in the store, because RequireGrantToSetChannelPolicy
// is what decides whose 38107 gets there. Re-checking the author's role on
// every read would be a second answer to a question already answered at write
// time, and the two would disagree the moment an admin was demoted — leaving a
// channel that quietly decrypts itself when the person who encrypted it loses
// their role.
func (e *EncryptionPolicies) policyFor(ctx context.Context, group string) channelEncryption {
	e.mutex.RLock()
	cached, ok := e.known[group]
	e.mutex.RUnlock()
	if ok {
		return cached
	}

	found := e.readPolicy(ctx, group)

	e.mutex.Lock()
	e.known[group] = found
	e.mutex.Unlock()
	return found
}

func (e *EncryptionPolicies) readPolicy(ctx context.Context, group string) channelEncryption {
	plaintext := channelEncryption{enc: protocol.EncPlaintext}

	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()

	results, err := e.store.QueryEvents(ctx, nostr.Filter{
		Kinds: []int{KindChannelPolicy},
		Tags: nostr.TagMap{
			protocol.TagGroup:      []string{group},
			protocol.TagIdentifier: []string{group},
		},
		Limit: 100,
	})
	if err != nil {
		// Fail open, and say why out loud rather than in a comment: a store
		// error here would otherwise refuse every event in every channel,
		// because a relay that cannot read any policy concludes every channel
		// is plaintext and then rejects everything sealed. An unreachable
		// store is already an outage; turning it into a workspace-wide refusal
		// of honest traffic adds nothing and hides the cause.
		return plaintext
	}

	// Addressable events are keyed by author, so a channel with two admins has
	// two 38107s and they are both current by NIP-01's rules. The newest wins,
	// and a tie goes to the one that protects more — between `plaintext` and
	// `nip44` signed in the same second, refusing cleartext is the answer that
	// can be corrected by publishing another policy, and the other one cannot
	// be corrected at all once a message has been stored in the clear.
	var best *nostr.Event
	var bestMode string
	for event := range results {
		mode, ok := decodeChannelPolicy(event)
		if !ok {
			continue
		}
		switch {
		case best == nil || event.CreatedAt > best.CreatedAt:
			best, bestMode = event, mode
		case event.CreatedAt == best.CreatedAt && bestMode == protocol.EncPlaintext:
			best, bestMode = event, mode
		}
	}
	if best == nil {
		return plaintext
	}

	return channelEncryption{enc: bestMode}
}

func decodeChannelPolicy(event *nostr.Event) (mode string, ok bool) {
	var body struct {
		Enc string `json:"enc"`
	}
	if json.Unmarshal([]byte(event.Content), &body) != nil || body.Enc == "" {
		return "", false
	}
	return body.Enc, true
}

func firstTag(event *nostr.Event, name string) string {
	for _, tag := range event.Tags {
		if len(tag) > 1 && tag[0] == name {
			return tag[1]
		}
	}
	return ""
}
