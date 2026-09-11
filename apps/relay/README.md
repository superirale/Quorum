# `apps/relay` — the Quorum reference relay

A NIP-29 relay that also enforces the Quorum envelope, validates Quorum bodies
against the published JSON Schema, and folds thread ops into relay-signed thread
state.

Built on [khatru](https://github.com/fiatjaf/khatru) and
[relay29](https://github.com/fiatjaf/relay29). Everything Quorum adds is
additive: a client that knows only NIP-29 and NIP-C7 can join a workspace, read
the conversation and post to it without knowing this relay is anything unusual.
That is a test, not an aspiration —
`TestQuorumEventsAreInvisibleToAGenericChatClient`.

## Run it

```sh
make run                       # builds and starts on :3334
make test                      # everything
make race                      # race detector, internal packages only (see below)
make docker                    # image; build context is the repo root
```

The relay **will not start without the protocol schemas.** They are the source
of the kind table, the envelope requirements and every body schema; a relay that
could not read them would still accept events and still look healthy, having
silently stopped being the thing it claims to be. Build them first:

```sh
pnpm --filter @quorum/protocol schemas
```

## Configuration

Everything is environment-driven. Nothing here is secret except the key.

| Variable | Default | Meaning |
| --- | --- | --- |
| `QUORUM_ADDR` | `:3334` | listen address |
| `QUORUM_DOMAIN` | `localhost:3334` | public host, used in NIP-29 group ids |
| `QUORUM_DATA_DIR` | `./data` | event database and `relay.key` |
| `QUORUM_SCHEMA_DIR` | `../../packages/protocol/schemas` | published JSON Schema |
| `QUORUM_SECRET_KEY` | — | relay identity; generated into `$DATA_DIR/relay.key` if unset |
| `QUORUM_OWNER_PUBKEYS` | — | comma-separated hex keys allowed to create workspaces |
| `QUORUM_REQUIRE_AUTH` | `false` | demand NIP-42 before serving reads |
| `QUORUM_EVENTS_PER_MINUTE` | `120` | per-IP write limit; `0` disables |
| `QUORUM_EVENTS_BURST` | `40` | |
| `QUORUM_FILTERS_PER_MINUTE` | `120` | per-IP subscription limit; `0` disables |
| `QUORUM_FILTERS_BURST` | `40` | |
| `QUORUM_CLOCK_SKEW_SECONDS` | `900` | how far `created_at` may sit from the relay's clock |

The relay's key is its identity. It signs the NIP-29 group metadata clients
trust and, from M7, the checkpoints that make withholding an event provable.
Losing it means every group's metadata is suddenly signed by a stranger, so it
is written `0600` and never logged. Under Docker, mount `/var/lib/quorum`.

## What runs on each event

relay29 installs its rules first and Quorum's are appended, which is the order
we want: non-members and unknown groups are gone before anything compiles a
JSON Schema.

**From relay29:** `h` tag present and the group exists · moderation events are
recent · only members may write · moderation actions are permitted for the
actor's role · deleted events stay deleted · `previous` tag checking.

**From Quorum** (`internal/policy`), cheapest first:

1. `PreventLargeTags`, `PreventTooManyIndexableTags` — khatru's own.
2. `RestrictToSupportedKinds` — the kind table from `schemas/index.json`, plus
   NIP-29's moderation kinds.
3. `RestrictGroupCreation` — only `QUORUM_OWNER_PUBKEYS`, if set.
4. `RejectImplausibleTimestamps`.
5. `RejectRelaySignedForgeries` — nobody else publishes kind 38101 or 8108.
6. `ValidateQuorumEvent` — the envelope always; the body only when `enc` is
   `plaintext`, because on `nip44` and `mls` channels the content is ciphertext
   and a relay that insisted on parsing it would reject every event the moment a
   workspace turned encryption on.

There is deliberately **no `h`-tag check of our own**: relay29's
`RequireHTagForExistingGroup` is strictly stronger.

## Thread state

Kind 8109 `thread_op` is what clients publish; kind 38101 `thread_state` is what
they read, and only the relay may sign it. The projector (`internal/threads`)
folds ops into state on `OnEventSaved`.

The folded state lists every op id it incorporated in `folded_from`, so a client
that distrusts the projection can fetch those ops and recompute it. That is the
difference between the relay asserting a state and the relay showing its work,
and it is what stops the relay quietly becoming an authority over what a task
says. On a generic relay none of this happens and clients fold locally with the
same logic, reaching the same state from the same ops.

`folded_from` is capped at 200 ids. It lives inside a replaceable event that is
rewritten on every change, and a thread worked on for months would otherwise
grow an unbounded tag list; the dropped ids are still fetchable by thread.

## Notes for the SDK (M3)

**A filter scoped only by `#p` is rejected.** relay29's
`RequireKindAndSingleGroupIDOrSpecificEventReference` allows a query that names
an `h`, an `e`, an `a` or explicit ids — and "everything addressed to me,"
`{"kinds":[8102],"#p":[me]}`, is none of those. Agents must scope by workspace
as well:

```json
{"kinds": [8102], "#p": ["<agent>"], "#h": ["payments"]}
```

This is correct behaviour rather than a limitation — without it one subscription
would rake `p`-tagged events out of every group on the relay — but it is not
what anyone writes first. `TestFiltersMustNameAGroup` pins it, so if relay29
changes the rule the test says so.

**`#p` is a coarse prefilter, not an answer.** Quorum marks addressees with a
fourth element, `["p", "<pubkey>", "<relay>", "to"]`, and relays index only the
tag value. A `#p` match therefore includes mentions and NIP-22 parent authors;
exact matching happens locally.

**A rejected publish is an error, but a rejected subscription is not.**
go-nostr's `QuerySync` returns `nil` whether the subscription ended in EOSE or
in CLOSED, so a filter the relay refused looks exactly like a filter that
matched nothing. Read `Subscription.ClosedReason`.

## Known gaps

- **Anyone may join an open group.** relay29 admits any join request unless the
  group is marked closed, which is wrong for a workspace holding approval
  records and capability grants. Until M4 wires grants into membership, mark
  groups closed and add members explicitly.
- **Reads are open by default.** `QUORUM_REQUIRE_AUTH=true` demands NIP-42.
  Private groups already require auth regardless.
- **The relay does not yet check who may change a thread's state.** Any member
  can publish a `thread_op`. Capability grants land in M4.
- **Checkpoints (kind 8108) are reserved but not produced.** That is M7. The
  forgery policy already covers the kind so nobody can squat it in the meantime.

## Dependency pins

`khatru` is pinned to **v0.17.7**, which is not the latest. The window is one
patch wide:

- relay29 v0.5.1 — the latest release — needs `BroadcastEvent` to return
  nothing. khatru changed it to return an `int` in v0.17.8.
- khatru v0.17.5 and earlier call `nip70.IsProtected` with a value, which
  go-nostr v0.51.8 no longer accepts.

So v0.17.6–v0.17.7 is the only version of khatru that compiles against both.
Upgrading means relay29 moving first, or us vendoring its ~600 lines.

**khatru has a data race in its listener bookkeeping.** `notifyListeners` reads
`rl.listeners` without holding `clientsMutex`, which `removeListenerId` writes
under it, so a client unsubscribing concurrently with a broadcast trips the
detector. Still present in v0.19.1, so it is not a consequence of the pin. `make
race` therefore covers `internal/...` only: running the end-to-end tests under
`-race` would fail on upstream code every time and train everyone to ignore the
output. The projector, where a missing lock would be our bug, is covered — and
`TestConcurrentOpsAreSerialised` fails without its lock, which was checked
rather than assumed.
