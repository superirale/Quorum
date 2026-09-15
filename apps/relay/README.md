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
| `QUORUM_CHECKPOINT_EVERY` | `300` | seconds between checkpoints per group; `0` disables |
| `QUORUM_CHECKPOINT_LAG` | `900` | seconds behind now at which a window closes |

**The burst is the real limit, not the per-minute rate.** khatru's rate limiter
is not a bucket that refills continuously: a counter climbs to the burst and a
goroutine subtracts the per-minute allowance once a minute. So nothing may exceed
`*_BURST` requests between two ticks whatever the rate says, and raising
`QUORUM_EVENTS_PER_MINUTE` alone has no effect at all on a burst. Both limits are
also keyed by **IP**, so on localhost a human and their agents share one bucket —
and so do two consecutive runs of the same script.

That matters more here than it looks. A runaway agent trips the rate limit long
before it trips its thread budget: both are backstops from the same paragraph of
the plan, and the cheaper one fires first. That is the right order in production
and the wrong one for `examples/runaway-agent`, which documents the settings it
needs to get past it. `@quorum/conformance` needs the same thing for a worse
reason: it publishes a few hundred events in six seconds, and a refusal it did
not expect is recorded as this relay failing a MUST. CI runs it with both
limiters at `0`.

The relay's key is its identity. It signs the NIP-29 group metadata clients
trust and the checkpoints that make withholding an event provable.
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
   workspace turned encryption on. That skip is exactly why policy 13 checks the
   other direction too: without it, `enc=nip44` on a plaintext channel is a
   one-tag bypass of the whole schema.
7. `RequireKeyPackageSlot` — a kind 30443's `d` must be the channel in its `h`.
8. `RequireOneWelcomeRecipient` — a kind 8111 may address at most one member.
9. `RejectForeignActionTransitions` — only the pubkey that published an action's
   `proposed` may advance it.
10. `RejectUnaskedApprovals` — an 8103 must answer an 8102, in the same group,
    from a pubkey that 8102 addressed, echoing its `input_digest`.
11. `RequireGrantToJoin` — a kind 9021 join request needs a `group:join` grant
    from an owner or admin of that group. See [Membership](#membership).
12. `RequireGrantToSetBudget` — a `set_budget` thread op needs `thread:budget`.
    Every other op stays open to members.
13. `RejectWorkOnPausedThread` — a kind 8101 whose status is `proposed` or
    `running` is refused in a thread the projection says is `paused`. See
    [Thread state](#thread-state) for what it must *not* refuse.
14. `RequireGrantToSetChannelPolicy` — a kind 38107 needs `channel:encrypt`, or
    a role. See [Encryption](#encryption).
15. `RequirePolicyEncMode` — the channel's stated mode, enforced in both
    directions.
16. `SerialiseCommits` — at most one kind 8112 per group per epoch.

Policies 7 and 8 are the whole of the `mls` arm that needs no state; 16 is the
rest of it. See [MLS channels](#mls-channels).

The last eight are last because they are the only policies that read the
database. An event that is malformed, out of range or from a stranger has
already been refused without touching a disk.

The two approval policies **fail open when the relay does not hold the
referenced event**, and that is deliberate rather than an oversight. Events
legitimately travel between relays; a relay that rejected every approval whose
request it has not got would break federation to catch nothing, since whoever
forged it can simply publish the request too. The SDK's auditor makes no such
allowance — it is handed the whole chain and is the party being asked to act on
the answer.

`SerialiseCommits` fails open for the same reason, and one more: an unreachable
store is already an outage, and turning it into "no member may change the
membership of any channel" adds a second one while catching nothing the
receiver-side tie-break does not already handle.

The three capability policies — join, budget, channel policy — **fail closed**,
and the asymmetry is not an inconsistency. They ask a different question. "I have not seen the request
this answers" is ordinary in a federated system; "I have not seen a grant
admitting you" is the ordinary state of everyone who was never invited, and a
relay that let an absent grant mean yes would be back to admitting anyone who
asks. A grant is also the one thing the requester could always have brought with
them — it is addressable, so presenting it is publishing it.

That division is the point. **The relay is defence in depth and is never the
authority.** It refuses what it can prove wrong from events it holds; a resource
deciding whether to actually deploy something re-derives everything itself, from
signatures, with no relay involved. `examples/deploy-agent` is that resource.

There is deliberately **no `h`-tag check of our own**: relay29's
`RequireHTagForExistingGroup` is strictly stronger.

## Membership

There are two ways into a workspace and no others:

- **An admin admits you** — a NIP-29 kind 9000 put-user, which relay29 already
  restricts to admins. `quorum workspace add <who>`.
- **An admin signed you an invitation** — a `group:join` capability grant scoped
  to that group, which you present by publishing a kind 9021 join request. The
  relay reads the grant and admits you itself. `quorum workspace invite <who>`,
  then `quorum workspace join`.

Asking is not one of them. relay29 admits any join request to an open group,
which is the correct NIP-29 default and the wrong one for a workspace holding
approval records and capability grants, so `RequireGrantToJoin` refuses the 9021
outright. That matters more than it looks: khatru runs `OnEventSaved` only for
events it stored, and relay29's auto-admit hook is registered there — refusing
the event therefore disarms the hook without forking relay29.

What the relay checks, in `internal/policy/capability.go`:

- a 38102 addressed to the requester, resource `group:join`, action `invoke`,
  `scope.group` equal to this group;
- not revoked and not expired, by `effectiveAddressable` rather than simply the
  latest — ties break toward *less* authority, so a same-second revocation wins;
- the issuer is an owner or admin of this group **now**, recomputed by replaying
  9007/9000/9001 oldest-first. A demoted admin's outstanding invitations stop
  working, which is the property that makes demotion mean anything.

`max_uses` is ignored on all three relay-enforced resources rather than
half-honoured:
counting uses needs a caller to ask "how many so far", and there is none. Bound
an invitation with `expires_at` instead.

**Revoking a `group:join` does not evict an existing member.** The grant answers
a question asked once, at the door. Removing someone is a kind 9001
(`quorum workspace remove`), and an operator who means both must do both.

Two traps worth knowing. A revocation published in the same second as the grant
**is silently dropped** — khatru v0.17.7 with no `ReplaceEvent` hook keeps the
stored event unless the incoming one is strictly newer, so `revoke` immediately
after `invite` can leave the invitation standing. And the resource names are a
second copy of `packages/protocol/src/resources.ts`; a one-character divergence
would be an operator granting `group:jion`, seeing a green tick, and watching
the grantee stay out. `policy.ConfirmResourceNames` reads the names back from
`schemas/index.json` at startup and the relay refuses to boot if they disagree.

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

### The projection's timestamp is monotonic, not the clock

A projection is signed at `max(now, previous + 1)`, which means a burst of ops
can date the 38101 a second or two ahead of the wall clock.

Two folds inside one second is the normal case rather than an edge: a client
publishes `set_budget` and `set_status` together, or an agent reports a spend
that pauses the thread. With equal timestamps the addressable replace falls
through to NIP-01's lowest-id tiebreak, so about half the time the *older* state
wins on a hash, the newer one is silently not stored, and the thread is left
saying something that was true one op ago.

The relay authors these events, so keeping them strictly ordered is the honest
fix: a projection folded later really is later, and `created_at` is exactly the
field NIP-01 orders by. Client events get no such licence — they still face
`RejectImplausibleTimestamps`.

### Budgets, and what a paused thread still accepts

`spent` is the sum of the thread's `add_spend` ops and nothing else. An action
body's own `cost` is audit detail; folding both would double every number in the
workspace. The arithmetic lives in `packages/protocol/src/cost.ts` as well, and
the two copies have to agree — `examples/runaway-agent`'s `live` script is what
checks that they do, by running an agent out of money over a socket and replaying
the relay's own `folded_from` in TypeScript.

The fold sets `paused` when the folded state has reached any stated ceiling. It
does so only while folding `add_spend` or `set_budget`, never `set_status` (or a
human could not reopen the thread — their `working` would be rewritten by the
same fold that stored it), never on a `done` thread, and it only ever *sets*
`paused`: raising a ceiling does not resume anything. Resuming and raising are
two decisions and take two ops.

`RejectWorkOnPausedThread` then refuses `proposed` and `running` there, and
nothing else. Terminal transitions of an action already running get through, or a
paused thread loses the record of work that really happened; so do chat,
comments and every thread op, or a budget alert becomes an outage in the one
thread people need to talk in.

A thread with no 38101 is allowed through, and that is **not** the fail-open
compromise the approval policies make. There is no hidden evidence here: the
projection is written by this relay and only this relay, so a thread it holds no
state for has never been paused on it. The policy also stands down entirely on
`nip44` and `mls` channels, where there is no status to read — which is the
reason it can never be the only thing enforcing a budget, and why the SDK checks
the ceiling before it proposes.

## Context packing

A NIP-90 DVM (`internal/contextpack`): kind 5600 in, kind 6600 out, addressed by
pubkey. The relay's own key is the packer's key, and clients find it in the
**NIP-11 document** — `khatru29.Init` puts it there, so no configuration is
needed to discover it. A 5600 that names somebody else goes unanswered, which is
the whole reason it is addressed rather than being an endpoint: a workspace may
hold several packers, they are allowed to give different answers, and a
requester must be able to say whose answer it got.

The algorithm is `extractive-v1`, specified in the `Context` section of the NIP
and implemented twice — here in Go and in `packages/sdk/src/context.ts`. The two
must be **byte-identical over the same events**, because on `nip44` channels the
relay cannot read the content and the SDK becomes the only packer. That makes
this an optimisation rather than a dependency, and only if the bytes agree.

Three things hold that:

- `internal/contextpack/pack_test.go` runs the golden fixture the SDK generates.
- The SDK's own suite runs the same file.
- `pnpm --filter @quorum/claude-agent live` compares a real 6600 against a local
  `packContext` over a real thread. The fixture is the *input* to the pure
  function, so it cannot notice the two implementations gathering different
  events; that last one can, and is the only test that does.

**`gather` is four filters, not one.** The root by id — it carries no `E` tag,
it *is* the root — the thread by `E`, the relay's 38101 by `d`, and the
workspace's kind 38103 agent manifests. The manifests are not about the thread
at all and are the easiest of the four to drop: provenance is derived from the
event set and nothing else, so without them every agent is labelled `human`,
`untrusted` collapses into `member`, and a caller stops fencing another agent's
output before a model reads it. The group is re-checked on every event on the
way in, because an id lookup cannot carry an `h` and because a `#h` query is only
as good as the tag — otherwise a member of one channel could publish a 1111
`E`-tagged at another channel's thread and have it packed into context there.

**A pack that will not fit is refused, not trimmed.** An event here holds 65,535
bytes; a large budget over a long thread wants more. The relay replies with a
kind 7000 naming both numbers and suggesting a smaller `budget_tokens`. Quietly
dropping segments would produce a different answer from the SDK's under the same
`algorithm`, with nothing in the body saying so — which is exactly the failure
the dual implementation exists to make impossible.

**`MaxLimit` is raised to 5000 deliberately.** eventstore defaults it to 1000 and
serves a filter asking for *more* than the maximum by falling back to
`MaxLimit/4` — so the packer's `Limit: 5000` would have fetched 250 events and a
500-message thread would have been packed from its last half with nothing
anywhere saying so. A client's unlimited backfill still gets a quarter of it,
which is the other half of why it is raised rather than the packer's bound
lowered.

**Building a long thread needs `QUORUM_EVENTS_PER_MINUTE=0`.** The default 120 a
minute is right for a workspace and wrong for a test fixture publishing five
hundred messages from one address.

## Checkpoints

Every `QUORUM_CHECKPOINT_EVERY` seconds the relay signs a kind 8108 per group: a
Merkle root over the ids of every event it holds in a closed window, with the
window bounds, the count, the algorithm name, and `prev`, the id of the previous
checkpoint for that group. It is a commitment it cannot retract. Serve a set
later that does not recompute to that root and any reader holding the missing
event can prove the relay is withholding it — see `examples/auditor`.

A window with **no events in it still gets a checkpoint**. A signed empty root
says "I held nothing"; silence says only that the relay stopped talking, and
those have to be distinguishable.

**A window closes `QUORUM_CHECKPOINT_LAG` behind now, and the lag must be at
least `QUORUM_CLOCK_SKEW_SECONDS`.** `RejectImplausibleTimestamps` is symmetric,
so the relay already refuses anything dated more than the skew in the past;
close the window a skew or more back and no honest event can ever arrive for a
window already committed to. Layer 3 therefore adds no new refusals — the
federation cost was paid in M2 by the skew bound itself.

The relay **refuses to boot** if the lag is shorter than the skew, rather than
clamping it. Getting it wrong is not a degradation; it is a false accusation,
because an event landing inside a closed window makes an honest relay look like
a caught one, and a relay silently correcting the operator's number would be
signing windows the operator does not think it is signing.

**Only regular events are committed to** (`Committed` in
`internal/checkpoint`). Replaceable, addressable and ephemeral kinds are
excluded, because a superseded event's id is gone from the store — commit to a
38101 and the first status change on any task makes the next reader recompute a
root short by one. The relay would be manufacturing evidence against itself on a
schedule. This is a protocol rule rather than an implementation choice: a client
recomputing the root must apply exactly the same filter, so it is in the NIP and
mirrored in `packages/sdk/src/checkpoints.ts`. Kind 8108 is itself regular, so
each window also commits to the checkpoints signed inside it.

Two things the implementation gets asked about:

- **`collect` pages backwards and narrows rather than truncates.** The store
  cannot serve an unbounded window, and a checkpoint whose `from` is later than
  requested is a smaller *true* claim, where one that keeps the bounds and drops
  the events it could not read is a false one. Same `MaxLimit` trap as the
  context packer.
- **Finding the end of the chain reads a page of checkpoints, not one.** The
  store orders by `created_at` and the chain is ordered by `to`. Everything
  `Cut` writes keeps the two in step, but a checkpoint arriving by another path
  — a restored snapshot, most plausibly — can sit at the top by `created_at`
  while covering an older window, and continuing from it would re-cover seconds
  already committed to. An overlap is exactly what a reader reads as a relay
  re-cutting history, so the relay would be manufacturing the accusation out of
  a backup restore. `TestTheChainIsFoundByWindowNotByClock` pins it.

The Merkle construction is `sha256-merkle-sorted-v1`, specified in the NIP and
implemented twice — here and in `packages/protocol/src/merkle.ts`, which
generates the conformance fixture `fixtures/merkle-v1.json` that
`internal/checkpoint` consumes. An odd node is **promoted, never duplicated**:
Bitcoin's padding rule is CVE-2012-2459, under which `[a,b,c]` and `[a,b,c,c]`
produce the same root.

## Encryption

A channel's mode lives in a kind 38107 `channel_policy`, addressable with
`d` = the group id. The relay reads it — that event is deliberately unsealed —
and enforces it in `internal/policy/encryption.go`.

**This is the odd policy in the set, and worth reading slowly: the relay
enforces a property it is definitionally excluded from verifying.** It cannot
decrypt a byte of what it is protecting and cannot tell a NIP-44 payload from
base64 noise. What it *can* see is the policy and the `enc` tag, because tags are
never sealed, and that is enough for the check that matters: on a channel whose
policy says `nip44`, a content-bearing event not tagged `enc=nip44` is plaintext,
whatever else it is.

Without that check the failure is silent in the worst way. The message goes
through, the relay stores it in the clear, and every reader displays it normally
because `openEvent` passes an untagged event straight through. Nobody sees an
error; the channel is simply less private than its policy says.

`RequirePolicyEncMode` therefore refuses, with the relay's own words in the OK:

| On a channel whose policy says | It refuses |
| --- | --- |
| `nip44` or `mls` | a content-bearing sealable kind tagged anything but that mode |
| `nip44` or `mls` | an **unsealed** kind (a grant, a policy, a key wrap, a commit) tagged `enc` |
| `nip44` | a sealed event with no `epoch` tag, or one below 1 |
| `mls` | a sealed event with no `epoch` tag, or one below **0** |
| `plaintext` (or none) | anything tagged `enc` at all |

**The epoch floor is per mode and that is not a detail.** A `nip44` generation is
minted from 1 so that zero stays distinguishable from a missing field; an MLS
group is at epoch **0** from creation until its first commit. One floor of 1 over
both refuses the opening messages of every MLS channel this relay will ever host,
citing a number RFC 9420 requires — which is what it did until M10 step 6.

Two of those need their own justification. The `plaintext` arm exists because
`ValidateQuorumEvent` skips body validation whenever `enc` is set, so without it
one tag bypasses the entire schema on a channel nobody is even encrypting — and
the content would not have to be ciphertext. The unsealed-kind arm exists because
that list is not a convenience: a capability grant nobody can audit is not a
capability, and a channel policy nobody can read is a channel nobody can join.
The list itself comes from `unsealed_kinds` and `unsealed_kind_ranges` in
`schemas/index.json`, not from a second copy in Go.

**The `epoch` tag is required and never compared to the current epoch.** A reader
that cannot decrypt has to be able to say *which* key it is missing, because "no
key for epoch 3" and "this event was tampered with" are otherwise the same MAC
failure and they send an operator to opposite ends of the building. Requiring a
*match* would be the wrong rule: an event written a second before a rotation, or
arriving from another relay, is honest and readable by everyone holding the old
key.

`RequireGrantToSetChannelPolicy` gates the 38107 on the `channel:encrypt`
resource, scoped `{group}`; owners and admins pass without a grant. The dangerous
edit is setting `plaintext` on a channel that was encrypted — every message after
it arrives readable, no ciphertext fails, no MAC complains, and the only sign is
that the relay stopped refusing plaintext. A member who can do that declassifies
a channel without ever reading a word of it. It also refuses a 38107 whose `d` is
not its `h`: readers query the policy by `d`, so such an event would pass every
check, exist, and govern nothing.

The cached policy is invalidated on `OnEventSaved`, after the store accepts the
38107 rather than when the write is attempted, and the cache trusts whatever is
in the store. Re-checking the author's role on every read would answer a question
already answered at write time, and the two would disagree the moment an admin
was demoted — leaving a channel that quietly decrypts itself when the person who
encrypted it loses their role.

**What the relay stops doing on such a channel**, all for the same reason —
each of them reads a body:

- the 8109→38101 projection. No thread state is ever signed; clients fold
  locally with the same logic and `threads()` reports `local`.
- the context-packing DVM, which answers with a kind 7000 saying *"this channel
  is encrypted; ask a packer that holds the keys"*. Silence would look like a
  relay that is merely slow.
- `RejectUnaskedApprovals` and `RejectForeignActionTransitions`, which need an
  `input_digest` and a status.
- budget enforcement, which needs a number. `add_spend` still works, because
  spend is *stated* by the party that spent it rather than read out of a message.

**What it keeps doing:** routing, rate limiting, NIP-29 membership, and
checkpoints. A checkpoint commits to event ids, and an id is a hash of bytes the
relay never has to understand, so layer 3 of the ordering design is untouched by
encryption. That is not luck — the Merkle tree was specified over ids rather than
over content for exactly this.

This is defence in depth and not a guarantee. The relay can only refuse what it
is asked to store, and every Quorum event is valid on a generic relay that will
happily take the plaintext. It closes the accident — a misconfigured client, an
older build, a paste into the wrong window — and not the betrayal.

`examples/sealed-channel live` runs all of this as pairs, a plaintext group and
an encrypted one against one relay in one run.

## MLS channels

`internal/policy/mls.go`, and **it contains no MLS code — that is the property,
not the limitation.** RFC 9420 assumes a *delivery service* that stores, routes
and orders messages it cannot read, and the three policies here are those three
jobs done from the envelope plus one JSON field this protocol deliberately leaves
in the clear. A relay that parsed `MLSMessage`s would be a second implementation
of a wire format, in a second language, obliged to agree with `ts-mls` forever;
the first disagreement would present as a workspace whose members cannot talk to
each other.

- **`RequireKeyPackageSlot`** — a kind 30443's `d` must equal its `h`. Single-use
  is enforced by nothing but addressable replacement: the next KeyPackage a member
  publishes retires the last one because they share a slot. A package in a foreign
  slot is never retired, yet still answers the `#h` query an inviter makes, so it
  looks perfectly usable. The inviter commits an Add against a private half the
  joiner discarded, and the joiner lands in the ratchet tree counted as a member
  by everyone and able to read nothing.
- **`RequireOneWelcomeRecipient`** — a kind 8111 may address at most one member.
  (At least one is already required by the envelope table, which is the other end
  of the same rule.) A Welcome carries key material sealed to one member's
  KeyPackage, so a second addressee fetches it, finds no secrets of theirs in it,
  and is required by the spec to read that as "not mine" rather than as an error.
  They are told nothing, and the member who was owed a Welcome waits for one that
  was, from where they sit, never sent.
- **`SerialiseCommits`** — at most one kind 8112 per group per epoch. Two members
  holding the same epoch may both commit and MLS lets exactly one of them become
  the next epoch; nothing in the protocol picks the winner, so a delivery service
  does. First stored wins, which is arbitrary on purpose — what matters is that
  every member picks the same one. The loser is stranded at the old epoch by the
  ordinary "a commit was missed" rule and must be re-added, which is the correct
  outcome: a committer whose commit was refused has not moved, and knows it.

The epoch comes from the 8112's JSON body, in the clear, which is exactly why
this file can be three refusals long. It is not trusted for anything but
serialisation — a committer that lies about its epoch blocks or loses a slot it
cannot use, because the members who *apply* commits read the epoch out of the
ciphertext, where a liar cannot reach it.

The scan is bounded at the newest 500 commits in the channel, and a channel with
more could admit a second 8112 for an epoch buried below that. Acceptable because
the rule is a SHOULD and correctness never rests on it: every Quorum event is
valid on a generic relay, which serialises nothing at all, so a receiver settles
ties deterministically on the lowest event id regardless of who is carrying the
channel.

What this relay will not attempt is any statement about whether a commit is
valid, whether the committer was in the tree, or whether a ciphertext opens.
Those are decidable only by members. See *Membership on an `mls` channel is two
lists* in the spec: the relay decides admission, the ratchet decides readership,
and neither may be inferred from the other.

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

- **Reads are open by default.** `QUORUM_REQUIRE_AUTH=true` demands NIP-42.
  Private groups already require auth regardless.
- **Only `set_budget` is authorised among the thread ops.** Any member may still
  claim, block or close a thread. That is intended for now — those are
  coordination, and a workspace where taking a task needs a capability is a
  workspace nobody works in — but it means `thread_op` is not uniformly gated,
  and the day one of the other ops becomes consequential it will need its own
  resource.
- **Commit serialisation is bounded and therefore best-effort.** See
  [MLS channels](#mls-channels): a channel with more than 500 commits could admit
  a second 8112 for an epoch below the scan. The receiver-side tie-break is what
  correctness actually rests on, here and on every generic relay.
- **Checkpoints prove withholding, not deletion.** A relay that honours a NIP-09
  delete request for an event it has already committed to will fail its own
  checkpoint from then on, and there is no way to distinguish that from
  withholding by looking at the events. Retention policy and checkpoints are in
  tension and the relay currently just lets them be.
- **A NIP-09 deletion request is acted on and then dropped**, and this is the one
  SHOULD the conformance suite reports this relay failing. khatru special-cases
  kind 5 in its message loop — `handlers.go:215-221` calls `handleDeleteRequest`
  instead of `AddEvent` — so the request never reaches the storage path and is
  never stored. Two consequences, both of them ours to live with on the pin:
  no `RejectEvent` policy runs on a kind 5, so none of the Quorum rules below
  apply to one; and a client that already holds the deleted event cannot learn
  from us that it was deleted, which is exactly what NIP-09 asks a relay to keep
  publishing the request for. Not fixable from policy code — `AddEvent` is never
  called, so there is no hook to register — and not fixable by storing the
  request ourselves from `OnEventSaved`, which also never fires for it. It needs
  khatru to stop branching on the kind, so it is in the same queue as everything
  else in [Dependency pins](#dependency-pins).

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
