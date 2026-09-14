package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/nbd-wtf/go-nostr"

	"github.com/quorum-chat/quorum/apps/relay/internal/protocol"
)

const (
	KindCapabilityGrant = 38102
	KindThreadOp        = 8109

	// moderationLogLimit bounds the replay in administrators(). NIP-29 groups
	// accumulate one moderation event per membership change, so a workspace
	// would have to churn thousands of members before this truncates — and if
	// it ever does, the replay drops the *oldest* events, which is the direction
	// that forgets an owner rather than inventing one.
	moderationLogLimit = 5000
)

// Resources this relay enforces itself.
//
// Both are scoped by `{group: <id>}` rather than named per group. `group:join`
// with a scope is narrowable — a delegation can hand on the right to invite
// into one workspace and not another — whereas `group:join.payments` is a
// string that can only be whitelisted, and a typo in it silently grants
// nothing. That is the M4 finding, applied to the two capabilities the relay is
// the enforcement point for.
const (
	ResourceJoin           = "group:join"
	ResourceThreadBudget   = "thread:budget"
	ResourceChannelEncrypt = "channel:encrypt"
	ActionInvoke           = "invoke"
	ScopeGroup             = "group"
)

// ConfirmResourceNames fails if the published protocol and this package
// disagree about what the relay-enforced capabilities are called.
//
// The constants above are duplicated in packages/protocol/src/resources.ts,
// which is where the console and the SDK read them from, and a resource name is
// matched exactly and never widened. So a one-character divergence is not a
// build error or a rejected event — it is an operator issuing `group:jion`,
// seeing a green tick, and finding the grantee still cannot get in. Checking it
// at startup turns the worst failure mode this design has into a relay that
// will not start.
func ConfirmResourceNames(published protocol.RelayEnforced) error {
	if published.Action != ActionInvoke {
		return fmt.Errorf(
			"the protocol says relay-enforced capabilities are granted with %q; this relay checks for %q",
			published.Action, ActionInvoke)
	}
	if published.ScopeKey != ScopeGroup {
		return fmt.Errorf(
			"the protocol scopes relay-enforced capabilities on %q; this relay narrows on %q",
			published.ScopeKey, ScopeGroup)
	}
	for _, resource := range []string{ResourceJoin, ResourceThreadBudget, ResourceChannelEncrypt} {
		if _, ok := published.Resources[resource]; !ok {
			return fmt.Errorf(
				"this relay enforces %q, which the protocol does not publish; it publishes %s",
				resource, strings.Join(sorted(published.Resources), ", "))
		}
	}
	return nil
}

func sorted(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// Authority names the roles whose holders may confer capabilities in a group.
//
// The test for membership on this list is not "who do we like" but "who could
// have done it by hand anyway". An owner or admin can already add any pubkey to
// a workspace with a kind 9000 put-user, so honouring a join grant they signed
// gives away no authority they did not have — it only lets them hand it over in
// advance, to a key that has not connected yet, in a form the grantee can be
// shown and a third party can check.
type Authority struct {
	// Roles that confer it, by NIP-29 role name.
	Roles []string
	// CreatorRole is what relay29 gives whoever created the group. It is
	// assigned in memory when the create-group event is applied and appears in
	// no event, so a replay that did not know it would conclude a fresh
	// workspace has no owner at all.
	CreatorRole string
}

func (a Authority) confers(held []string) bool {
	for _, role := range held {
		for _, confers := range a.Roles {
			if role == confers {
				return true
			}
		}
	}
	return false
}

// RequireGrantToJoin closes relay29's open door.
//
// # The gap this fills
//
// relay29 installs ReactToJoinRequest on OnEventSaved, and that function admits
// *anyone* who publishes a kind 9021 into a group that is not marked closed: it
// signs a put-user as the relay and the requester is a member. For a public
// chat relay that is the right default. For a workspace relay whose channels
// accumulate approval records and capability grants it means the coarsest
// permission in the system — being in the room at all — was the one thing not
// gated by a permission.
//
// Rejecting the 9021 here closes it without touching relay29: khatru only runs
// OnEventSaved for events it stored, so a refused join request never reaches
// the auto-admit at all.
//
// # Two ways in, and only two
//
// An owner or admin publishes a put-user naming you (what `quorum workspace
// add` does), or an owner or admin has already signed you a `group:join` grant
// and you present yourself. Nothing else admits anybody. In particular a
// stranger's own say-so does not, which was the entire previous mechanism.
func RequireGrantToJoin(store Lookup, authority Authority) func(context.Context, *nostr.Event) (bool, string) {
	return func(ctx context.Context, event *nostr.Event) (reject bool, msg string) {
		if event.Kind != nostr.KindSimpleGroupJoinRequest {
			return false, ""
		}
		group := protocol.Group(event)
		if group == "" {
			// relay29's RequireHTagForExistingGroup runs first and already
			// refuses this. Checked anyway because the alternative is a policy
			// whose correctness depends on the order of somebody else's chain.
			return true, "invalid: a join request must name a group in an `h` tag"
		}

		result := authorizeCapability(ctx, store, capRequest{
			group:     group,
			agent:     event.PubKey,
			resource:  ResourceJoin,
			action:    ActionInvoke,
			scope:     map[string]any{ScopeGroup: group},
			authority: authority,
		})
		if result.allowed {
			return false, ""
		}
		return true, fmt.Sprintf(
			"restricted: joining #%s needs a %s capability from an owner or admin — %s",
			group, ResourceJoin, result.reason,
		)
	}
}

// RequireGrantToSetBudget gates the one thread op that is a control.
//
// # Why only this op
//
// A thread's budget is half of the runaway-agent backstop: exhaustion pauses
// the thread and pings a human. An agent that can raise its own budget has no
// backstop, only a speed bump — and the whole mechanism reads as a safety
// feature to everyone who has not checked who may move the number.
//
// The other three ops are deliberately left open to any member. Status,
// assignee and title are how a workspace coordinates; requiring a capability to
// mark a thread done would make the task board a thing only administrators can
// touch, and the first workaround anybody reaches for is a grant wide enough to
// cover all four. A control everybody routes around is worse than no control,
// because it still appears in the threat model.
//
// # Who may, without a grant
//
// Owners and admins. The role is where a grant's authority comes from in the
// first place — see Authority — so requiring a role-holder to issue themselves
// a grant would add a step and no check.
//
// # What encryption costs here
//
// The op is in the body, so on a nip44 or mls channel the relay cannot tell
// set_budget from set_status and this passes everything through. That is the
// same trade every body-reading policy in this package makes and it is stated
// rather than hidden: on encrypted channels the budget backstop is the SDK's
// alone, exactly as the context packer and the approval digest check are.
func RequireGrantToSetBudget(store Lookup, authority Authority) func(context.Context, *nostr.Event) (bool, string) {
	return func(ctx context.Context, event *nostr.Event) (reject bool, msg string) {
		if event.Kind != KindThreadOp || protocol.EncMode(event) != protocol.EncPlaintext {
			return false, ""
		}
		var body struct {
			Op string `json:"op"`
		}
		if json.Unmarshal([]byte(event.Content), &body) != nil || body.Op != "set_budget" {
			return false, ""
		}
		group := protocol.Group(event)
		if group == "" {
			return false, ""
		}

		if administrators(ctx, store, group, authority)[event.PubKey] {
			return false, ""
		}
		result := authorizeCapability(ctx, store, capRequest{
			group:     group,
			agent:     event.PubKey,
			resource:  ResourceThreadBudget,
			action:    ActionInvoke,
			scope:     map[string]any{ScopeGroup: group},
			authority: authority,
		})
		if result.allowed {
			return false, ""
		}
		return true, fmt.Sprintf(
			"restricted: setting a thread budget in #%s needs a %s capability — %s",
			group, ResourceThreadBudget, result.reason,
		)
	}
}

// --- the check itself --------------------------------------------------------

type capRequest struct {
	group     string
	agent     string
	resource  string
	action    string
	scope     map[string]any
	authority Authority
}

type capResult struct {
	allowed bool
	grant   *nostr.Event
	// reason is why not: one clause per grant that looked relevant and did not
	// apply, or a single line when none did. It is shown to the publisher, so it
	// has to be enough to act on — "you have no grant" and "your grant expired
	// an hour ago" lead to different next steps.
	reason string
}

// authorizeCapability is the Go half of packages/sdk/src/grants.ts.
//
// # Two implementations of one rule
//
// That file is authoritative: it runs at the resource, offline, over signed
// events, and it is what actually stands between an agent and production. This
// is defence in depth for the two capabilities where the relay is unavoidably
// the enforcement point, because membership and the relay's own thread
// projection have no "resource" elsewhere to check them.
//
// Where the two could drift, this one is the stricter. Three things the SDK
// resolves are refused outright here rather than approximated:
//
//   - **Delegation.** A grant citing `via` is not honoured. Resolving a
//     delegation chain means intersecting specs, and a relay that got the
//     intersection subtly wide would be granting authority nobody issued. The
//     resource does this properly; the relay declines to guess.
//   - **max_uses.** Nothing in a signed log knows how many times something ran,
//     so the SDK takes a use count from its caller and fails closed without one.
//     A relay has no caller to ask, so a grant carrying max_uses authorises
//     nothing here. Join invitations should bound themselves with expires_at.
//   - **Issuer.** The SDK's trust roots are configuration. Here they are the
//     group's current owners and admins, which is data — but data this relay
//     already treats as authoritative, since it is the same list relay29
//     consults before letting anyone add a member by hand.
//
// Every one of those differences fails in the direction of refusing. A grant
// this relay will not honour is still a perfectly good grant at the resource.
func authorizeCapability(ctx context.Context, store Lookup, req capRequest) capResult {
	issuers := administrators(ctx, store, req.group, req.authority)
	if len(issuers) == 0 {
		return capResult{reason: fmt.Sprintf(
			"#%s has no owner or admin on this relay who could have issued one", req.group)}
	}

	held := fetchGrants(ctx, store, req.group, req.agent)

	// The relay's clock, never the event's. created_at is chosen by whoever
	// publishes, so reading expiry against it would let a requester revive a
	// grant that lapsed last week by claiming to be last week.
	now := int64(nostr.Now())

	var reasons []string
	for _, event := range effectiveAddressable(held) {
		if event.Kind != KindCapabilityGrant {
			continue
		}
		body, ok := grantBodyOf(event)
		if !ok {
			continue
		}
		// The `p` filter is a coarse prefilter — a grant can name other pubkeys
		// — so the body has the final say about who holds this.
		if body.Grantee != req.agent || body.Grant.Resource != req.resource {
			continue
		}

		name := "grant " + shortHex(event.ID)
		if valid, err := event.CheckSignature(); err != nil || !valid {
			// Everything in the store arrived through khatru, which verifies on
			// the way in. This catches the store itself having been edited,
			// which is the one attack a relay-side policy is uniquely placed to
			// notice and the operator is uniquely placed to perform.
			reasons = append(reasons, name+": its signature does not verify")
			continue
		}
		if body.Revoked {
			if body.RevokedReason != "" {
				reasons = append(reasons, name+": revoked — "+body.RevokedReason)
			} else {
				reasons = append(reasons, name+": revoked")
			}
			continue
		}
		if !issuers[event.PubKey] {
			reasons = append(reasons, fmt.Sprintf(
				"%s: issued by %s, who is not an owner or admin of #%s",
				name, shortHex(event.PubKey), req.group))
			continue
		}
		if body.Via != "" {
			reasons = append(reasons, name+
				": issued under a delegation, which this relay does not resolve")
			continue
		}
		if body.Grant.MaxUses != nil {
			reasons = append(reasons, name+
				": carries max_uses, which a relay cannot count; bound it with expires_at instead")
			continue
		}
		if !contains(body.Grant.Actions, req.action) {
			reasons = append(reasons, fmt.Sprintf("%s: permits %s, not %s",
				name, strings.Join(body.Grant.Actions, ", "), req.action))
			continue
		}
		if body.Grant.ExpiresAt != nil && *body.Grant.ExpiresAt < now {
			reasons = append(reasons, fmt.Sprintf("%s: expired %d seconds ago",
				name, now-*body.Grant.ExpiresAt))
			continue
		}
		if problem := scopeCovers(body.Grant.Scope, req.scope); problem != "" {
			reasons = append(reasons, name+": "+problem)
			continue
		}

		return capResult{allowed: true, grant: event}
	}

	if len(reasons) == 0 {
		return capResult{reason: fmt.Sprintf("nobody has issued %s to %s",
			req.resource, shortHex(req.agent))}
	}
	return capResult{reason: strings.Join(reasons, "; ")}
}

// grantSpec mirrors the published schema for a 38102 body, and nothing more.
// Fields the relay refuses to act on (via, max_uses) are still read, because
// ignoring a field is how a restriction becomes a comment.
type grantBody struct {
	Grantee string `json:"grantee"`
	Grant   struct {
		Resource  string         `json:"resource"`
		Actions   []string       `json:"actions"`
		Scope     map[string]any `json:"scope"`
		ExpiresAt *int64         `json:"expires_at"`
		MaxUses   *int64         `json:"max_uses"`
	} `json:"grant"`
	Via           string `json:"via"`
	Revoked       bool   `json:"revoked"`
	RevokedReason string `json:"revoked_reason"`
}

func grantBodyOf(event *nostr.Event) (grantBody, bool) {
	var body grantBody
	if json.Unmarshal([]byte(event.Content), &body) != nil {
		return body, false
	}
	return body, body.Grantee != "" && body.Grant.Resource != ""
}

func fetchGrants(ctx context.Context, store Lookup, group, grantee string) []*nostr.Event {
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()

	results, err := store.QueryEvents(ctx, nostr.Filter{
		Kinds: []int{KindCapabilityGrant},
		Tags: nostr.TagMap{
			protocol.TagGroup:  []string{group},
			protocol.TagPubkey: []string{grantee},
		},
		Limit: 500,
	})
	if err != nil {
		return nil
	}
	var held []*nostr.Event
	for event := range results {
		held = append(held, event)
	}
	return held
}

// effectiveAddressable keeps one version of each addressable event, breaking a
// created_at tie towards *less* authority.
//
// NIP-01 breaks the tie by lowest id, which between a grant and the revocation
// that withdraws it is a coin flip — and issuing something and taking it back
// in the same second is an ordinary thing to do when the grant was a mistake. A
// coin flip is a fine answer to "which copy does a relay keep" and not to "may
// this key into the workspace". Same rule, same reasoning, as
// effectiveAddressable in packages/sdk/src/grants.ts.
func effectiveAddressable(events []*nostr.Event) []*nostr.Event {
	newest := map[string]*nostr.Event{}
	var out []*nostr.Event

	for _, event := range events {
		if !protocol.IsAddressable(event.Kind) {
			out = append(out, event)
			continue
		}
		key := fmt.Sprintf("%d:%s:%s", event.Kind, event.PubKey, identifier(event))
		held, seen := newest[key]
		switch {
		case !seen || event.CreatedAt > held.CreatedAt:
			newest[key] = event
		case event.CreatedAt == held.CreatedAt:
			newest[key] = lessAuthority(event, held)
		}
	}

	for _, event := range newest {
		out = append(out, event)
	}
	// Map iteration is random, and the reason returned to a publisher must not
	// be. Sorting by id also makes two relays holding the same events report the
	// same refusal.
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func lessAuthority(a, b *nostr.Event) *nostr.Event {
	revokedA, revokedB := isRevoked(a), isRevoked(b)
	if revokedA != revokedB {
		if revokedA {
			return a
		}
		return b
	}
	if a.ID < b.ID {
		return a
	}
	return b
}

func isRevoked(event *nostr.Event) bool {
	var body struct {
		Revoked bool `json:"revoked"`
	}
	return json.Unmarshal([]byte(event.Content), &body) == nil && body.Revoked
}

// scopeCovers reports why a grant's scope does not cover a request, or "".
//
// A key the grant does not mention is unconstrained; a key it does mention must
// match exactly. There is no wildcard and no prefix match, on purpose: a
// capability system acquires ambient authority the first time a grant is
// inconvenient and somebody widens it by one character.
func scopeCovers(grant, asked map[string]any) string {
	for key, want := range grant {
		got, named := asked[key]
		if !named {
			return fmt.Sprintf("is scoped to %s=%s, which this does not name", key, jsonish(want))
		}
		if !reflect.DeepEqual(want, got) {
			return fmt.Sprintf("is scoped to %s=%s, but this is %s", key, jsonish(want), jsonish(got))
		}
	}
	return ""
}

// --- who holds a role --------------------------------------------------------

// administrators replays a group's NIP-29 moderation log to find the pubkeys
// holding a role that confers authority.
//
// # Why not ask relay29
//
// It has the answer in memory, in State.Groups, and reading it would be one
// line. Two reasons not to. The members map is guarded by an unexported mutex,
// so every read from outside the package is a data race — relay29 takes a few
// itself, but importing that bug is not the same as having it. And the point of
// this project is that authority is derivable from signed events; deriving it
// from signed events costs one indexed query on a rare event and keeps the
// relay's answer checkable by anyone holding the same log.
//
// The reading is deliberately the same as relay29's own: put-user *sets* a
// member's roles rather than adding to them, remove-user deletes them, and the
// group's creator holds the creator role even though no event says so.
func administrators(ctx context.Context, store Lookup, group string, authority Authority) map[string]bool {
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()

	results, err := store.QueryEvents(ctx, nostr.Filter{
		Kinds: []int{
			nostr.KindSimpleGroupCreateGroup,
			nostr.KindSimpleGroupPutUser,
			nostr.KindSimpleGroupRemoveUser,
		},
		Tags:  nostr.TagMap{protocol.TagGroup: []string{group}},
		Limit: moderationLogLimit,
	})
	if err != nil {
		return nil
	}

	var log []*nostr.Event
	for event := range results {
		log = append(log, event)
	}
	// Oldest first. The store answers newest-first, and applied in that order a
	// promotion and the demotion that undid it swap places.
	sort.SliceStable(log, func(i, j int) bool {
		if log[i].CreatedAt != log[j].CreatedAt {
			return log[i].CreatedAt < log[j].CreatedAt
		}
		return log[i].ID < log[j].ID
	})

	roles := map[string][]string{}
	for _, event := range log {
		switch event.Kind {
		case nostr.KindSimpleGroupCreateGroup:
			roles[event.PubKey] = []string{authority.CreatorRole}
		case nostr.KindSimpleGroupPutUser:
			for _, tag := range event.Tags {
				if len(tag) > 1 && tag[0] == protocol.TagPubkey {
					roles[tag[1]] = append([]string(nil), tag[2:]...)
				}
			}
		case nostr.KindSimpleGroupRemoveUser:
			for _, tag := range event.Tags {
				if len(tag) > 1 && tag[0] == protocol.TagPubkey {
					delete(roles, tag[1])
				}
			}
		}
	}

	out := map[string]bool{}
	for pubkey, held := range roles {
		if authority.confers(held) {
			out[pubkey] = true
		}
	}
	return out
}

// --- small helpers -----------------------------------------------------------

func identifier(event *nostr.Event) string {
	for _, tag := range event.Tags {
		if len(tag) > 1 && tag[0] == protocol.TagIdentifier {
			return tag[1]
		}
	}
	return ""
}

func contains(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

func shortHex(hex string) string {
	if len(hex) > 12 {
		return hex[:8] + "…"
	}
	return hex
}

func jsonish(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "?"
	}
	return string(encoded)
}
