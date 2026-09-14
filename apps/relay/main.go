// Command relay is the Quorum reference relay.
//
// It is a NIP-29 relay (via relay29) that additionally enforces the Quorum
// envelope, validates Quorum bodies against the published JSON Schema, and
// projects thread_op events into relay-signed thread state.
//
// Everything Quorum-specific is additive. A generic NIP-29 client can join a
// workspace, read the conversation and post to it without knowing this relay is
// anything unusual — that property is tested, not assumed, and it is the reason
// Quorum events are required to be valid on relays that have never heard of it.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	badgerdb "github.com/dgraph-io/badger/v4"
	"github.com/fiatjaf/eventstore/badger"
	"github.com/fiatjaf/khatru"
	"github.com/fiatjaf/khatru/policies"
	"github.com/fiatjaf/relay29"
	"github.com/fiatjaf/relay29/khatru29"
	"github.com/nbd-wtf/go-nostr/nip29"

	"github.com/quorum-chat/quorum/apps/relay/internal/checkpoint"
	"github.com/quorum-chat/quorum/apps/relay/internal/config"
	"github.com/quorum-chat/quorum/apps/relay/internal/contextpack"
	"github.com/quorum-chat/quorum/apps/relay/internal/policy"
	"github.com/quorum-chat/quorum/apps/relay/internal/protocol"
	"github.com/quorum-chat/quorum/apps/relay/internal/threads"
)

var (
	roleOwner     = &nip29.Role{Name: "owner", Description: "created the workspace; can do anything"}
	roleAdmin     = &nip29.Role{Name: "admin", Description: "manages members and channels"}
	roleModerator = &nip29.Role{Name: "moderator", Description: "removes events and members"}
)

// NIP-29's own kinds. Not Quorum's to publish in supported_kinds, but the relay
// must accept them or groups cannot be administered at all.
var nip29Kinds = []int{
	9000, 9001, 9002, 9003, 9004, 9005, 9006, 9007, 9008, 9009,
	9021, 9022,
	39000, 39001, 39002, 39003,
}

// Kinds only the relay may sign. See policy.RejectRelaySignedForgeries.
var relaySignedKinds = []int{
	threads.KindThreadState,
	checkpoint.Kind,
}

// Who may confer a capability inside a workspace.
//
// Owners and admins, because both can already admit a member by hand with a
// kind 9000 — so honouring a grant they signed hands over nothing they could
// not do directly. Moderators are excluded for the same reason they cannot put
// users: removing people is not the same authority as letting them in.
var authority = policy.Authority{
	Roles:       []string{roleOwner.Name, roleAdmin.Name},
	CreatorRole: roleOwner.Name,
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "quorum-relay: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	relay, index, closeDB, err := build(cfg)
	if err != nil {
		return err
	}
	defer closeDB()

	pubkey, err := cfg.PublicKey()
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           relay,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("quorum relay v%s on %s", index.Version, cfg.Addr)
	log.Printf("  domain     %s", cfg.Domain)
	log.Printf("  pubkey     %s", pubkey)
	log.Printf("  data       %s", cfg.DataDir)
	log.Printf("  schemas    %s", cfg.SchemaDir)
	log.Printf("  kinds      %d supported", len(index.SupportedKindNumbers()))
	if cfg.CheckpointEvery > 0 {
		log.Printf("  checkpoint every %s, closing windows %s behind now", cfg.CheckpointEvery, cfg.CheckpointLag)
	} else {
		log.Printf("  warning    checkpoints are off; readers get ordering layers 1 and 2 only")
	}
	if !cfg.RequireAuth {
		log.Printf("  warning    reads are open; set QUORUM_REQUIRE_AUTH=true to demand NIP-42")
	}
	if len(cfg.Owners) == 0 {
		log.Printf("  warning    anyone may create a workspace; set QUORUM_OWNER_PUBKEYS to restrict it")
	}

	errs := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- err
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errs:
		return err
	case <-stop:
	}

	log.Println("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return server.Shutdown(ctx)
}

// build assembles the relay without listening on anything.
//
// Kept separate from run so the end-to-end tests drive the same wiring the
// binary serves. A test that stands up its own approximation of the policy
// chain tests the approximation.
func build(cfg config.Config) (*khatru.Relay, *protocol.Index, func(), error) {
	// Loading the protocol definition is fatal on failure, not a warning. A
	// relay that cannot read the schemas would still start, still accept
	// events and still look healthy — it would just have silently stopped
	// enforcing the thing it exists to enforce.
	index, err := protocol.Load(cfg.SchemaDir)
	if err != nil {
		return nil, nil, nil, fmt.Errorf(
			"%w\n\nQUORUM_SCHEMA_DIR must point at the schemas/ directory published by\n"+
				"@quorum/protocol. Run `pnpm --filter @quorum/protocol schemas` to build it.",
			err,
		)
	}
	// Fatal for the same reason, one step further in: a relay whose idea of
	// `group:join` differs from the console's by a character enforces a
	// capability nobody can be granted.
	if err := policy.ConfirmResourceNames(index.RelayEnforced); err != nil {
		return nil, nil, nil, fmt.Errorf("the relay and the protocol disagree: %w", err)
	}

	db := &badger.BadgerBackend{
		Path: filepath.Join(cfg.DataDir, "events"),
		// Pinned to the packer's own bound, and it has to be said out loud
		// because the default silently truncates history. eventstore defaults
		// MaxLimit to 1000 and serves a filter that asks for *more* than that
		// by falling back to MaxLimit/4 — so the context packer's `Limit: 5000`
		// would have fetched 250 events, and a 500-message thread would have
		// been packed from its last half with nothing anywhere saying so. A
		// client's unlimited backfill gets a quarter of this for the same
		// reason, which is the other half of why it is raised rather than the
		// packer's bound lowered.
		MaxLimit: contextpack.MaxThreadEvents,
		// Badger logs a table-size report at every level on open. Warnings and
		// errors still come through; what is dropped is only the startup dump,
		// which otherwise buries the relay's own first lines.
		BadgerOptionsModifier: func(opts badgerdb.Options) badgerdb.Options {
			return opts.WithLoggingLevel(badgerdb.WARNING)
		},
	}
	if err := db.Init(); err != nil {
		return nil, nil, nil, fmt.Errorf("opening the event store: %w", err)
	}

	relay, state := khatru29.Init(relay29.Options{
		Domain:                  cfg.Domain,
		DB:                      db,
		SecretKey:               cfg.SecretKey,
		DefaultRoles:            []*nip29.Role{roleOwner, roleAdmin, roleModerator},
		GroupCreatorDefaultRole: roleOwner,
	})

	pubkey, err := cfg.PublicKey()
	if err != nil {
		db.Close()
		return nil, nil, nil, fmt.Errorf("deriving the relay public key: %w", err)
	}

	describe(relay, cfg, index)

	state.AllowAction = allowAction

	projector, err := threads.New(index, db, relay, cfg.SecretKey)
	if err != nil {
		db.Close()
		return nil, nil, nil, err
	}

	// The context packer. Note what is *not* here: kind 6600 is absent from
	// relaySignedKinds, so anyone may publish one. That is deliberate — from M9
	// the SDK-side packer answers encrypted channels under its own key, and a
	// relay that reserved the result kind for itself would make the packer
	// unswappable, which is the one property the DVM shape exists to keep.
	packer, err := contextpack.NewPacker(index, db, relay, cfg.SecretKey)
	if err != nil {
		db.Close()
		return nil, nil, nil, err
	}

	// These run after the ones khatru29.Init already installed, which is the
	// order we want: relay29 has rejected non-members and unknown groups before
	// anything here compiles a JSON Schema.
	//
	// Within this block, cheap structural checks come first so a flood of
	// malformed events costs little to refuse. There is no `h`-tag check here
	// because relay29's RequireHTagForExistingGroup is strictly stronger — it
	// demands the group exist, not merely be named.
	relay.RejectEvent = append(relay.RejectEvent,
		policies.PreventLargeTags(1024),
		policies.PreventTooManyIndexableTags(64, nil, nil),
		policy.RestrictToSupportedKinds(index, nip29Kinds),
		policy.RestrictGroupCreation(cfg.Owners),
		policy.RejectImplausibleTimestamps(cfg.ClockSkew),
		policy.RejectRelaySignedForgeries(pubkey, relaySignedKinds),
		policy.ValidateQuorumEvent(index),
		// Last, because these are the only policies that read the database. An
		// event that is malformed, out of range or from a stranger has already
		// been refused without touching a disk.
		policy.RejectForeignActionTransitions(db),
		policy.RejectUnaskedApprovals(index, db),
		policy.RequireGrantToJoin(db, authority),
		policy.RequireGrantToSetBudget(db, authority),
		policy.RejectWorkOnPausedThread(db, projector.PublicKey()),
	)

	if cfg.EventsPerMinute > 0 {
		relay.RejectEvent = append(relay.RejectEvent,
			policies.EventIPRateLimiter(cfg.EventsPerMinute, time.Minute, cfg.MaxEventsBurst),
		)
	}
	if cfg.FiltersPerMinute > 0 {
		relay.RejectFilter = append(relay.RejectFilter,
			policies.FilterIPRateLimiter(cfg.FiltersPerMinute, time.Minute, cfg.MaxFiltersBurst),
		)
	}
	if cfg.RequireAuth {
		relay.RejectFilter = append(relay.RejectFilter, policies.MustAuth)
	}

	relay.OnEventSaved = append(relay.OnEventSaved, projector.Fold, packer.Answer)

	// Ordering integrity, layer 3. Started here rather than in run() so the
	// end-to-end tests exercise the same wiring the binary serves; the returned
	// cleanup stops it.
	stopCheckpoints := func() {}
	if cfg.CheckpointEvery > 0 {
		checkpointer, err := checkpoint.New(db, relay, cfg.SecretKey, cfg.CheckpointEvery, cfg.CheckpointLag)
		if err != nil {
			db.Close()
			return nil, nil, nil, err
		}
		// Observe only records which groups exist. It has to run on every saved
		// event because relay29 keeps group metadata in kinds 39000+ that are
		// generated on demand and never stored, so nothing in the database
		// lists the workspaces.
		relay.OnEventSaved = append(relay.OnEventSaved, checkpointer.Observe)

		ctx, cancel := context.WithCancel(context.Background())
		go checkpointer.Run(ctx)
		stopCheckpoints = cancel
	}

	return relay, index, func() { stopCheckpoints(); db.Close() }, nil
}

// allowAction decides who may perform NIP-29 moderation.
//
// relay29 calls this once per role the actor holds and accepts the action if
// any call returns true, so each case answers only for its own role.
//
// The rule that matters is that an admin cannot mint an owner. Without it the
// three roles collapse into one: an admin promotes themselves and there is no
// longer anybody who can remove them. In a workspace whose whole claim is a
// trustworthy record of who approved what, "the roles were real until someone
// bothered to escalate" is not a distinction worth publishing.
func allowAction(ctx context.Context, group nip29.Group, role *nip29.Role, action relay29.Action) bool {
	if role == nil {
		return false
	}
	switch role.Name {
	case roleOwner.Name:
		return true

	case roleAdmin.Name:
		put, isPut := action.(relay29.PutUser)
		if !isPut {
			return true
		}
		for _, target := range put.Targets {
			for _, name := range target.RoleNames {
				if name == roleOwner.Name {
					return false
				}
			}
		}
		return true

	case roleModerator.Name:
		switch action.(type) {
		case relay29.DeleteEvent, relay29.RemoveUser:
			return true
		default:
			return false
		}

	default:
		return false
	}
}

// describe fills in the NIP-11 document.
//
// khatru and khatru29 have both already contributed to SupportedNIPs — 1, 11,
// 40, 42, 70, 86 and 29 — so this adds only what Quorum brings, through the
// helper that deduplicates. Version reports the protocol version rather than a
// build number: a client's compatibility question is about the event schema it
// will be served, not about which commit is running.
func describe(relay *khatru.Relay, cfg config.Config, index *protocol.Index) {
	relay.Info.Name = cfg.Name
	relay.Info.Description = cfg.Description
	relay.Info.Software = "https://github.com/quorum-chat/quorum"
	relay.Info.Version = index.Version
	relay.Info.AddSupportedNIP(22)
}
