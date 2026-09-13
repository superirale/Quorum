package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"github.com/quorum-chat/quorum/apps/relay/internal/config"
	"github.com/quorum-chat/quorum/apps/relay/internal/protocol"
	"github.com/quorum-chat/quorum/apps/relay/internal/threads"
)

// These are end-to-end tests over a real websocket against the same wiring
// main() serves, because most of what M2 claims is a property of the whole
// pipeline rather than of any one policy: that relay29's checks and Quorum's
// compose in the right order, that a generic NIP-29 client is unaffected by
// the Quorum kinds sitting beside it, and that the thread projection reaches a
// subscriber.

const group = "payments"

type actor struct {
	name   string
	secret string
	pubkey string
}

func newActor(t *testing.T, name string) actor {
	t.Helper()
	secret := nostr.GeneratePrivateKey()
	pubkey, err := nostr.GetPublicKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	return actor{name: name, secret: secret, pubkey: pubkey}
}

type testRelay struct {
	url  string
	http string
	// pubkey is the relay's own key: the author of the thread projection, of
	// checkpoints, and the address a context request is sent to.
	pubkey string
}

func start(t *testing.T, owners ...string) testRelay {
	t.Helper()

	cfg := config.Config{
		Domain:    "localhost",
		DataDir:   t.TempDir(),
		SchemaDir: "../../packages/protocol/schemas",
		SecretKey: nostr.GeneratePrivateKey(),
		Owners:    owners,
		ClockSkew: 15 * time.Minute,
		// Rate limits off: every client here shares 127.0.0.1, so the limiter
		// would be measuring the test harness rather than any relay behaviour.
		EventsPerMinute:  0,
		FiltersPerMinute: 0,
		Name:             "test relay",
	}

	relay, _, closeDB, err := build(cfg)
	if err != nil {
		t.Fatalf("building the relay: %v", err)
	}

	pubkey, err := cfg.PublicKey()
	if err != nil {
		t.Fatalf("deriving the relay public key: %v", err)
	}

	server := httptest.NewServer(relay)
	t.Cleanup(func() {
		server.Close()
		closeDB()
	})

	return testRelay{
		url:    "ws" + strings.TrimPrefix(server.URL, "http"),
		http:   server.URL,
		pubkey: pubkey,
	}
}

func (r testRelay) connect(t *testing.T, who actor) *nostr.Relay {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := nostr.RelayConnect(ctx, r.url)
	if err != nil {
		t.Fatalf("%s could not connect: %v", who.name, err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// publish signs and sends, returning the relay's rejection message (empty on
// acceptance) rather than an error, because on this relay a rejection is the
// expected outcome about as often as an acceptance.
func publish(t *testing.T, conn *nostr.Relay, who actor, event *nostr.Event) string {
	t.Helper()

	if event.CreatedAt == 0 {
		event.CreatedAt = nostr.Now()
	}
	if err := event.Sign(who.secret); err != nil {
		t.Fatalf("%s could not sign: %v", who.name, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := conn.Publish(ctx, *event); err != nil {
		return err.Error()
	}
	return ""
}

func mustPublish(t *testing.T, conn *nostr.Relay, who actor, event *nostr.Event) *nostr.Event {
	t.Helper()
	if msg := publish(t, conn, who, event); msg != "" {
		t.Fatalf("%s: kind %d was rejected: %s", who.name, event.Kind, msg)
	}
	return event
}

func query(t *testing.T, conn *nostr.Relay, filter nostr.Filter) []*nostr.Event {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	events, err := conn.QuerySync(ctx, filter)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	return events
}

// createGroup runs the NIP-29 dance a client performs on first use.
func createGroup(t *testing.T, conn *nostr.Relay, owner actor) {
	t.Helper()
	mustPublish(t, conn, owner, &nostr.Event{
		Kind: nostr.KindSimpleGroupCreateGroup,
		Tags: nostr.Tags{{"h", group}},
	})
}

// admit adds a member the way `quorum workspace add` does: an owner publishes a
// put-user naming them.
//
// This used to be a kind 9021 the joiner signed themselves, which worked
// because the relay admitted anyone who asked. It no longer does — see
// capability_test.go — and the tests that only need a populated workspace say
// so through the owner, which is the path an operator actually uses.
func admit(t *testing.T, conn *nostr.Relay, owner, who actor) {
	t.Helper()
	mustPublish(t, conn, owner, &nostr.Event{
		Kind: nostr.KindSimpleGroupPutUser,
		Tags: nostr.Tags{{"h", group}, {"p", who.pubkey}},
	})
	waitForMembership(t, conn, who)
}

// waitForMembership blocks until the relay's own member list names someone.
//
// Membership is applied on a post-save hook, so the put-user being stored is
// not yet the member being able to write — and the next line of a test usually
// is them writing. Kind 39002 is generated from the in-memory group state
// rather than read back from the store, which makes it the one answer that
// cannot be ahead of the thing being waited for.
func waitForMembership(t *testing.T, conn *nostr.Relay, who actor) {
	t.Helper()
	waitFor(t, fmt.Sprintf("%s to be admitted", who.name), func() bool {
		for _, list := range query(t, conn, nostr.Filter{
			Kinds: []int{39002},
			Tags:  nostr.TagMap{"d": []string{group}},
		}) {
			for _, tag := range list.Tags {
				if len(tag) > 1 && tag[0] == "p" && tag[1] == who.pubkey {
					return true
				}
			}
		}
		return false
	})
}

func waitFor(t *testing.T, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if done() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func chat(text string) *nostr.Event {
	// Deliberately bare: an `h` tag and nothing else. This is what a generic
	// NIP-C7 client emits, and the relay must not want more from it.
	return &nostr.Event{Kind: 9, Content: text, Tags: nostr.Tags{{"h", group}}}
}

func thread(title string) *nostr.Event {
	return &nostr.Event{
		Kind:    11,
		Content: title,
		Tags:    nostr.Tags{{"h", group}, {"title", title}},
	}
}

func action(root string, body map[string]any) *nostr.Event {
	content, _ := json.Marshal(body)
	return &nostr.Event{
		Kind:    8101,
		Content: string(content),
		Tags: nostr.Tags{
			{"h", group},
			{"E", root},
			{"K", "11"},
			{"alt", "an action was proposed"},
		},
	}
}

// The M2 demo, as a test: two humans hold a conversation, and a client that
// knows only NIP-29 and NIP-C7 reads the same channel back.
func TestTwoHumansChatAndAGenericClientReadsIt(t *testing.T) {
	alice, bob := newActor(t, "alice"), newActor(t, "bob")
	relay := start(t, alice.pubkey)

	aliceConn := relay.connect(t, alice)
	bobConn := relay.connect(t, bob)

	createGroup(t, aliceConn, alice)
	admit(t, aliceConn, alice, bob)

	mustPublish(t, aliceConn, alice, chat("shipping the payments fix today"))
	mustPublish(t, bobConn, bob, chat("what's the rollback plan"))
	mustPublish(t, aliceConn, alice, chat("previous release, one command"))

	// A generic client: it has never heard of Quorum, and NIP-C7 tells it to
	// ask for kind 9 only.
	generic := relay.connect(t, newActor(t, "generic reader"))
	var conversation []*nostr.Event
	waitFor(t, "the conversation to arrive", func() bool {
		conversation = query(t, generic, nostr.Filter{
			Kinds: []int{9},
			Tags:  nostr.TagMap{"h": []string{group}},
		})
		return len(conversation) == 3
	})

	for _, event := range conversation {
		if ok, err := event.CheckSignature(); err != nil || !ok {
			t.Errorf("a served event does not verify: %v", err)
		}
		if event.Content == "" {
			t.Error("a served chat message has no content")
		}
	}
}

// Quorum kinds sitting in the same channel must not change what a generic
// client sees. This is the whole basis for the "valid on any relay" claim, in
// the direction that is easiest to break by accident.
func TestQuorumEventsAreInvisibleToAGenericChatClient(t *testing.T) {
	alice := newActor(t, "alice")
	relay := start(t, alice.pubkey)
	conn := relay.connect(t, alice)

	createGroup(t, conn, alice)
	mustPublish(t, conn, alice, chat("morning"))
	root := mustPublish(t, conn, alice, thread("deploy api v1.4.2"))
	mustPublish(t, conn, alice, action(root.ID, map[string]any{
		"name":    "deploy.production",
		"status":  "proposed",
		"summary": "Deploy api v1.4.2 to production",
	}))

	chats := query(t, conn, nostr.Filter{
		Kinds: []int{9},
		Tags:  nostr.TagMap{"h": []string{group}},
	})
	if len(chats) != 1 {
		t.Fatalf("a kind 9 subscription returned %d events, want 1", len(chats))
	}
	if chats[0].Content != "morning" {
		t.Errorf("got %q", chats[0].Content)
	}
}

func TestTheRelayEnforcesTheQuorumEnvelope(t *testing.T) {
	alice := newActor(t, "alice")
	relay := start(t, alice.pubkey)
	conn := relay.connect(t, alice)

	createGroup(t, conn, alice)
	root := mustPublish(t, conn, alice, thread("deploy api v1.4.2"))

	valid := map[string]any{
		"name":    "deploy.production",
		"status":  "proposed",
		"summary": "Deploy api v1.4.2 to production",
	}

	cases := []struct {
		name  string
		event *nostr.Event
		want  string
	}{
		{"an action with no alt", func() *nostr.Event {
			event := action(root.ID, valid)
			event.Tags = nostr.Tags{{"h", group}, {"E", root.ID}, {"K", "11"}}
			return event
		}(), `"alt" tag`},
		{"an action outside any thread", func() *nostr.Event {
			event := action(root.ID, valid)
			event.Tags = nostr.Tags{{"h", group}, {"alt", "an action"}}
			return event
		}(), "`E` tag"},
		{"an action whose body is not JSON", func() *nostr.Event {
			event := action(root.ID, valid)
			event.Content = "deploying now"
			return event
		}(), "invalid"},
		{"an action with a status outside the enum", action(root.ID, map[string]any{
			"name": "deploy.production", "status": "vibing", "summary": "x",
		}), "invalid"},
		{"a kind this relay does not serve", &nostr.Event{
			Kind: 1, Content: "a note", Tags: nostr.Tags{{"h", group}},
		}, "does not serve kind 1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := publish(t, conn, alice, tc.event)
			if msg == "" {
				t.Fatal("the relay accepted it")
			}
			if !strings.Contains(msg, tc.want) {
				t.Errorf("rejected for the wrong reason:\n got: %s\nwant substring: %s", msg, tc.want)
			}
		})
	}
}

// An encrypted body is opaque to the relay, so the envelope is all it can
// check — and it must still check that much, or turning on encryption would
// silently turn off validation.
func TestEncryptedBodiesSkipBodyValidationButNotTheEnvelope(t *testing.T) {
	alice := newActor(t, "alice")
	relay := start(t, alice.pubkey)
	conn := relay.connect(t, alice)

	createGroup(t, conn, alice)
	root := mustPublish(t, conn, alice, thread("deploy api v1.4.2"))

	encrypted := action(root.ID, nil)
	encrypted.Content = "AqDS3ZBcNotRealCiphertextButNotJSONEither=="
	encrypted.Tags = append(encrypted.Tags, nostr.Tag{"enc", "nip44"})
	mustPublish(t, conn, alice, encrypted)

	unaddressedAndEncrypted := action(root.ID, nil)
	unaddressedAndEncrypted.Content = "AqDS3ZBcStillCiphertext=="
	unaddressedAndEncrypted.Tags = nostr.Tags{{"h", group}, {"alt", "an action"}, {"enc", "nip44"}}
	if msg := publish(t, conn, alice, unaddressedAndEncrypted); msg == "" {
		t.Error("an encrypted event skipped the envelope check too")
	}
}

// The relay-signed kinds are meaningful only because the relay signed them.
func TestRelaySignedKindsCannotBeForged(t *testing.T) {
	alice := newActor(t, "alice")
	relay := start(t, alice.pubkey)
	conn := relay.connect(t, alice)

	createGroup(t, conn, alice)

	forged := &nostr.Event{
		Kind:    threads.KindThreadState,
		Content: `{"status":"done","folded_from":[]}`,
		Tags: nostr.Tags{
			{"h", group},
			{"d", "0000000000000000000000000000000000000000000000000000000000000abc"},
			{"alt", "thread state: done"},
		},
	}
	msg := publish(t, conn, alice, forged)
	if msg == "" {
		t.Fatal("the relay accepted a thread_state it did not sign")
	}
	if !strings.Contains(msg, "signed by the relay") {
		t.Errorf("rejected for the wrong reason: %s", msg)
	}
}

// The projection, end to end: a client publishes an op and reads back state
// signed by the relay, naming the op it folded.
func TestThreadOpsProduceRelaySignedState(t *testing.T) {
	alice := newActor(t, "alice")
	relay := start(t, alice.pubkey)
	conn := relay.connect(t, alice)

	createGroup(t, conn, alice)
	root := mustPublish(t, conn, alice, thread("deploy api v1.4.2"))

	op := mustPublish(t, conn, alice, &nostr.Event{
		Kind:    threads.KindThreadOp,
		Content: `{"op":"set_status","status":"blocked","reason":"waiting on approval"}`,
		Tags: nostr.Tags{
			{"h", group},
			{"E", root.ID},
			{"K", "11"},
			{"alt", "thread blocked"},
		},
	})

	var state *nostr.Event
	waitFor(t, "the thread state to be projected", func() bool {
		for _, event := range query(t, conn, nostr.Filter{
			Kinds: []int{threads.KindThreadState},
			Tags:  nostr.TagMap{"h": []string{group}, "d": []string{root.ID}},
		}) {
			state = event
			return true
		}
		return false
	})

	if ok, err := state.CheckSignature(); err != nil || !ok {
		t.Fatalf("the projected state does not verify: %v", err)
	}

	var body threads.State
	if err := json.Unmarshal([]byte(state.Content), &body); err != nil {
		t.Fatalf("the projected state is not valid JSON: %v", err)
	}
	if body.Status != "blocked" {
		t.Errorf("status is %q, want blocked", body.Status)
	}
	if len(body.FoldedFrom) != 1 || body.FoldedFrom[0] != op.ID {
		t.Errorf("folded_from is %v, want [%s]", body.FoldedFrom, op.ID)
	}
	if protocol.EncMode(state) != protocol.EncPlaintext {
		t.Errorf("the projection should be plaintext, got %q", protocol.EncMode(state))
	}
}

// A workspace relay whose groups anyone can create is a workspace relay with
// somebody else's namespace in its audit trail.
func TestOnlyOwnersMayCreateWorkspaces(t *testing.T) {
	alice, mallory := newActor(t, "alice"), newActor(t, "mallory")
	relay := start(t, alice.pubkey)

	msg := publish(t, relay.connect(t, mallory), mallory, &nostr.Event{
		Kind: nostr.KindSimpleGroupCreateGroup,
		Tags: nostr.Tags{{"h", "mallorys-workspace"}},
	})
	if msg == "" {
		t.Fatal("a stranger created a workspace")
	}
	if !strings.Contains(msg, "owners") {
		t.Errorf("rejected for the wrong reason: %s", msg)
	}

	createGroup(t, relay.connect(t, alice), alice)
}

// Non-members must not write. relay29 owns this rule; the test is here because
// the Quorum policies are appended to the same chain and could shadow it.
func TestNonMembersCannotWrite(t *testing.T) {
	alice, mallory := newActor(t, "alice"), newActor(t, "mallory")
	relay := start(t, alice.pubkey)

	createGroup(t, relay.connect(t, alice), alice)

	msg := publish(t, relay.connect(t, mallory), mallory, chat("hello from outside"))
	if msg == "" {
		t.Fatal("a non-member wrote to the group")
	}
	if !strings.Contains(msg, "unknown member") {
		t.Errorf("rejected for the wrong reason: %s", msg)
	}
}

func TestNIP11AdvertisesWhatTheRelayDoes(t *testing.T) {
	relay := start(t)

	request, err := http.NewRequest(http.MethodGet, relay.http, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Accept", "application/nostr+json")

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("fetching the NIP-11 document: %v", err)
	}
	defer response.Body.Close()

	var info struct {
		Name          string `json:"name"`
		PubKey        string `json:"pubkey"`
		Version       string `json:"version"`
		SupportedNIPs []int  `json:"supported_nips"`
	}
	if err := json.NewDecoder(response.Body).Decode(&info); err != nil {
		t.Fatalf("parsing the NIP-11 document: %v", err)
	}

	if info.Name != "test relay" {
		t.Errorf("name is %q", info.Name)
	}
	if len(info.PubKey) != 64 {
		t.Errorf("pubkey is %q, want 32 bytes of hex", info.PubKey)
	}
	if info.Version == "" {
		t.Error("no version advertised")
	}

	for _, want := range []int{22, 29, 42} {
		found := false
		for _, nip := range info.SupportedNIPs {
			if nip == want {
				found = true
			}
		}
		if !found {
			t.Errorf("NIP-%d is not advertised: %v", want, info.SupportedNIPs)
		}
	}

	// Advertising the same NIP twice is the kind of thing that happens when a
	// framework already added it and the application adds it again.
	seen := map[int]bool{}
	for _, nip := range info.SupportedNIPs {
		if seen[nip] {
			t.Errorf("NIP-%d is advertised twice: %v", nip, info.SupportedNIPs)
		}
		seen[nip] = true
	}
}

// closedReason subscribes and reports the relay's CLOSED message, or "" if the
// subscription reached EOSE.
//
// QuerySync cannot be used for this: it drains the event channel and returns a
// nil error whether the subscription ended in EOSE or in CLOSED, so a rejected
// filter is indistinguishable from one that matched nothing.
func closedReason(t *testing.T, conn *nostr.Relay, filter nostr.Filter) string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sub, err := conn.Subscribe(ctx, nostr.Filters{filter})
	if err != nil {
		t.Fatalf("subscribing: %v", err)
	}
	defer sub.Unsub()

	select {
	case reason := <-sub.ClosedReason:
		return reason
	case <-sub.EndOfStoredEvents:
		return ""
	case <-ctx.Done():
		t.Fatal("the relay neither answered nor closed the subscription")
		return ""
	}
}

// Documented for the SDK, not aspirational: relay29 rejects a filter scoped
// only by `#p`, which is exactly the filter an agent reaching for "everything
// addressed to me" would write first. Agents must scope by workspace too.
func TestFiltersMustNameAGroup(t *testing.T) {
	alice := newActor(t, "alice")
	relay := start(t, alice.pubkey)
	conn := relay.connect(t, alice)
	createGroup(t, conn, alice)

	reason := closedReason(t, conn, nostr.Filter{
		Kinds: []int{8102},
		Tags:  nostr.TagMap{"p": []string{alice.pubkey}},
	})
	if reason == "" {
		t.Fatal("a `#p`-only filter was accepted; the SDK note about this is stale")
	}
	if !strings.Contains(reason, "must have 'h', 'e' or 'a' tag") {
		t.Errorf("closed for the wrong reason: %s", reason)
	}

	if reason := closedReason(t, conn, nostr.Filter{
		Kinds: []int{8102},
		Tags:  nostr.TagMap{"p": []string{alice.pubkey}, "h": []string{group}},
	}); reason != "" {
		t.Errorf("adding `#h` should make it valid, but: %s", reason)
	}
}
