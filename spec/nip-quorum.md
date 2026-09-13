NIP-XX
======

Agent-First Messaging
---------------------

`draft` `optional`

This NIP defines event kinds and tag conventions for workspaces where autonomous
agents are first-class participants alongside humans: agents that hold their own
keys, carry scoped and revocable capabilities, ask humans for consent before
consequential actions, and account for what they cost.

It is additive. A workspace using this NIP is an ordinary NIP-29 group whose
conversation is ordinary NIP-C7 and NIP-7D events. A client that implements none
of this renders the conversation correctly and shows the rest as fallback text.

**Status:** kind numbers in the 8100/28100/38100 ranges are provisional and were
checked free against the registry of kinds on 2026-09-11. They are subject to
reallocation until this PR merges.

## Motivation

A bot on an existing chat platform is a webhook with an avatar. It has no durable
identity, no scoped permissions, no protocol-level way to ask a human for
consent, and no accounting. Every serious agent integration re-implements history
scraping, token budgeting, retry/deduplication and an ad-hoc approval flow —
separately, and badly.

Nostr already supplies the two things such a system most needs and that no
centralised platform can offer:

- **An agent's identity is a keypair.** No server issues it a bot token, so no
  server can forge, silently rotate, or repudiate it.
- **An approval is a signed event.** "Ada authorised this production deploy, with
  exactly these arguments" is verifiable offline, against no server, forever. The
  audit trail is the signatures. There is no audit table for an operator to edit.

Everything below exists to make those two facts usable.

## Terminology

- **Workspace** — a NIP-29 group. Every event in this NIP carries its `h` tag.
- **Thread** — a unit of work, rooted at a NIP-7D kind 11 event.
- **Action** — a discrete unit of consequential work with a status lifecycle.
- **Principal** — the pubkey that holds capability grants. Distinct from the
  *app* (the agent definition) and the *runtime instance* (one replica).

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as
described in RFC 2119.

## Reused kinds

This NIP defines no chat or threading kinds of its own. It reuses:

| Kind | NIP | Use |
| --- | --- | --- |
| 9 | NIP-C7 | Chat message. The conversational layer. |
| 11 | NIP-7D | Thread root. Its **id is the thread id**. |
| 1111 | NIP-22 | Comment. All replies within a thread. |
| 5 | NIP-09 | Deletion request (advisory). |
| 22242 | NIP-42 | Relay AUTH. |
| 9000/9001/9021 | NIP-29 | Put-user, remove-user, join request. See [the two resources the relay owns](#the-two-resources-the-relay-owns). |
| 39000–39002 | NIP-29 | Group metadata, admins, members. |
| 443/444/445 | Marmot | MLS KeyPackage, Welcome, Group Event (`mls` mode only). |

A generic NIP-C7 or NIP-7D client joined to a Quorum workspace therefore sees the
whole human conversation with no modification.

## New kinds

### Regular (stored)

| Kind | Name | Purpose |
| --- | --- | --- |
| 8101 | `action` | A unit of consequential work; one event per status transition. |
| 8102 | `approval_request` | Asks named humans to authorise an exact input. |
| 8103 | `approval_response` | A signed decision. **This is the audit record.** |
| 8104 | `summary` | An agent-authored compaction of a range, offered not trusted. |
| 8105 | `error` | A failure not attributable to a single action. |
| 8106 | `artifact` | A produced object, by reference or hash. |
| 8107 | `handoff` | Transfers responsibility for a thread to another principal. |
| 8108 | `checkpoint` | Relay-signed attestation of the events it holds. |
| 8109 | `thread_op` | Requests a change to thread state. |

### Ephemeral (not stored, 20000–29999)

Control-plane traffic. These use the ephemeral range deliberately: a cancel that
is replayed from storage an hour later is worse than one that is lost, and an
ephemeral kind cannot be delivered late by a relay honouring NIP-01.

| Kind | Name | Purpose |
| --- | --- | --- |
| 28101 | `interrupt` | Cancel, pause or steer a running action. |
| 28102 | `lease` | Single-holder claim on a thread, so replicas don't double-act. |
| 28103 | `presence` | Liveness. |

### Addressable (latest per pubkey + kind + `d`)

| Kind | Name | `d` |
| --- | --- | --- |
| 38101 | `thread_state` | thread id |
| 38102 | `capability_grant` | grantee pubkey |
| 38103 | `agent_manifest` | principal pubkey |
| 38104 | `agent_memory` | scoped key |
| 38105 | `agent_cursor` | subscription id |
| 38106 | `delegation` | delegate pubkey |

### Data-vending machine (NIP-90)

| Kind | Name |
| --- | --- |
| 5600 | `context_pack_request` |
| 6600 | `context_pack_result` |

## The envelope

### Every event of a kind defined here MUST carry

- **`h`** — the NIP-29 group id.
- **`alt`** — human-readable fallback, 1–280 characters, single line.

### Tags

```
h          group id (NIP-29)
alt        fallback text (see below)
p          pubkey reference — addressing, mentions, NIP-22 parent authorship
E K P      NIP-22 root scope: thread root id, root kind, root author
e k        NIP-22 parent: parent id, parent kind
a          addressable coordinate <kind>:<pubkey>:<d>
d          addressable identifier
enc        content mode: plaintext | nip44 | mls (absent means plaintext)
counter    per-author monotonic counter (stored kinds only — see Ordering)
action     the action id this event belongs to
quorum     protocol version
```

Only single-letter tags are relay-indexed under NIP-01. `enc`, `counter`,
`action` and `quorum` are deliberately multi-character: they are read locally and
must not consume index space on generic relays.

### `content`

For kinds defined in this NIP, `content` is the **canonical JSON** (RFC 8785,
restricted to finite numbers) of the body schema for that kind, or the NIP-44 /
MLS ciphertext of the same when `enc` is not `plaintext`.

Canonical JSON is required rather than merely recommended. Because a Nostr event
id is a hash over `content`, two implementations that serialise the same body
differently produce different ids for the same fact, and every content-addressed
reference in this NIP — the action id, the approval id — silently stops matching
across implementations.

Metadata lives in tags; the body lives in `content`. That split is what makes
encryption a policy switch rather than a redesign: turning on `nip44` encrypts
`content` and leaves routing intact.

## Addressing: the `to` marker

An event is **addressed** to a pubkey when it carries a `p` tag with `to` in
position 4:

```json
["p", "<pubkey>", "<relay-hint>", "to"]
```

Agents SHOULD default to acting only on events addressed to them.

The marker exists because `p` is overloaded. NIP-22 requires a `p` tag naming the
parent's author, and this NIP wants `p` for addressing so agents can use the
indexed `{"#p": [...]}` filter. Both are legal and they mean different things.
Without a marker, an agent that replies to whoever asked — the common case —
cannot distinguish "you are being asked to act" from "you happen to be upstream
in this thread", and agent-to-agent runaway loops follow directly.

Therefore:

- `{"#p": [...]}` at the relay is a **coarse superset prefilter**. It is correct
  to over-deliver; the marker is not indexable.
- Exact matching MUST happen locally on the marker.
- A writer MUST NOT emit both a marked and an unmarked `p` tag for the same
  pubkey. The marked tag subsumes the unmarked one. Emitting both leaves a reader
  holding two tags for one pubkey where only one carries the marker, and a reader
  that checks the wrong one gets the wrong answer.

To a generic client, a marked `p` tag is an ordinary mention. Nothing breaks.

## `alt` is required

NIP-31 is marked `unrecommended`, on the grounds that it is bloated and that
NIP-89 handler discovery is the better answer for unknown kinds. This NIP
requires `alt` anyway, and the reason is specific to agents rather than a
disagreement with NIP-31 in general:

> The primary consumer of an unknown Quorum event is not a client with a UI. It
> is a **context packer feeding a language model**. NIP-89 cannot help there.
> There is no handler to resolve, no iframe to open and no user to click through
> — there is a token budget and a model that must be told what happened.

Rules:

1. Every event of a kind defined here MUST carry exactly one `alt` tag.
2. 1–280 characters, single line, plain text.
3. It MUST describe what happened, not what the event is. "Deployed api v1.4.2 to
   production" — not "a Quorum action event".
4. It MUST NOT be the only place a fact appears. It is a fallback, never the
   source of truth, and a reader that understands the kind MUST prefer the body.
5. **On encrypted channels `alt` is not encrypted.** Writers MUST keep it generic
   when `enc` is not `plaintext` — "an action completed", not the customer's name.
   A specific `alt` silently defeats the encryption it sits beside.

## Threads

A thread is a NIP-7D kind 11 event. Its id is the thread id, and every event
inside it carries NIP-22 root-scope tags `E`/`K`/`P` pointing at it.

Mutable task state lives in a **separate** addressable kind 38101 whose `d` is the
thread id, carrying `status` (`open`/`working`/`blocked`/`paused`/`done`),
`assignee`, `title`, `budget` and `spent`.

The split is deliberate. Making the thread itself addressable would make the
thread id a mutable coordinate that every `E` tag in the thread points at, so
editing the title would change what "this thread" means. An immutable root and a
separate state projection keeps references stable, and keeps the task layer
additive: strip every 38101 and a valid NIP-7D thread remains.

Kind 8109 `thread_op` events *request* state changes. In a workspace with a
Quorum-aware relay the relay folds them into 38101 and signs it; 38101 then
carries `folded_from` listing the ops it incorporated, which makes the relay's
projection auditable rather than merely asserted. Without such a relay, clients
fold locally and reach the same state.

Most ops are ordinary workspace traffic — claiming a task, marking it done — and
any member may publish them. `set_budget` is not: a thread's spending ceiling is
what stops a runaway agent, so raising it is an authority decision rather than a
coordination one. A relay implementing this NIP SHOULD require a `thread:budget`
capability for `set_budget` and leave the other ops open to members. See
[the two resources the relay owns](#the-two-resources-the-relay-owns).

## Actions

There is deliberately no `tool_call`/`tool_result` pair. A relay does not run
tools, so those would be log lines; they would re-specify MCP's tool shape inside
a chat protocol, leaving two schemas to keep in sync forever; and they would
hardcode one agent architecture. A workflow agent or a CI bot has no tool calls
and still does consequential work.

Instead: one kind, a stable `action_id`, and a status lifecycle. Each transition
is a new event carrying an `action` tag with that id.

```
proposed ─┬─→ awaiting_approval ─┬─→ running ─┬─→ succeeded
          │                      │            ├─→ failed
          └─────────────────────→┘            └─→ cancelled
                                 └─→ denied
```

**The action id is the event id of the `proposed` event.** Content-addressed, so
no allocator is needed and two implementations agree without coordinating.

A `proposed` action MUST carry `input_digest`: the digest of its canonical-JSON
`input`. An approval that cannot name its arguments authorises the action *name*
forever, which is not consent to anything in particular.

Note for implementers: because `created_at` is part of the event id, an agent
replaying its work MUST memoise the **signed event**, not the body. Rebuilding
the same body a second later yields a different id, and therefore a different
action.

### A chain is ordered by its parent links, not by `created_at`

Every transition after `proposed` MUST carry an `e` tag naming the event it
follows. A verifier evaluating the status lifecycle MUST order the chain by
those links — depth from the proposal — and MUST NOT order it by `created_at`.
Time MAY break ties between events that are genuinely unordered.

Two independent reasons, either sufficient:

- **It does not work.** A loop that needs no human, and often one that does on
  either side of the wait, publishes `proposed`, `awaiting_approval`, `running`
  and `succeeded` inside the same second. `created_at` has one-second
  resolution, so NIP-01's `(created_at, id)` order falls through to an id
  tiebreak — a hash — and the lifecycle check rejects honest chains about half
  the time.
- **It would not be safe if it did.** `created_at` is a client-supplied wall
  clock: the author picks it, so an attacker picks theirs. The ordering that
  decides whether an execution was legal MUST NOT be a field the executing party
  chooses. An event id is a hash of content that already includes the parent id,
  so causal order is the one ordering here nobody can rewrite after the fact.

### Only the proposer advances the chain

An 8101 or 8102 in a chain, signed by anyone other than the author of the
`proposed` event, MUST NOT affect the chain's status, its digests, or its
validity. A verifier SHOULD report it. A verifier MUST NOT treat it as making
the chain invalid.

Both halves are load-bearing, and the second is the one implementations get
wrong. Counting a stranger's transition would let any workspace member publish a
`succeeded` for someone else's deploy and have the log read as though the work
happened. But *erroring* on it hands every member a veto: one junk event, which
the proposer cannot retract, permanently invalidates an honest chain — and since
every event defined here is valid on a generic relay, no relay policy can be
relied on to stop them publishing it.

The rule that resolves both: **a chain is invalid only when the party doing the
work did something illegitimate.** A stranger's event says nothing about the
proposer's conduct, and is treated the way an approval from someone nobody asked
is already treated — recorded, disregarded, reported.

For the same reason, the `proposed` event is identified by *being* the event
whose id is the action id, never by "the event in this chain whose status says
proposed". Anyone may publish one of the latter.

## Approvals

1. The agent publishes 8102 `approval_request`, `p`-tagged with the `to` marker to
   each approver, carrying `title`, `risk`, `input_digest` and optionally
   `requested_grant`, `expires_at`, and `required` (for n-of-m; default 1).
2. A human publishes 8103 `approval_response`, whose NIP-22 `e`/`k` tags MUST
   point at the request — `k` MUST be `8102`.
3. Before acting, the agent MUST verify the response's signature, that the signer
   is among the addressed approvers, and that `input_digest` matches what it
   proposed.

If the human edited the parameters first, the response carries `modified_input`
and `modified_input_digest`, and the agent MUST re-verify against the modified
digest and MUST NOT execute the original input.

Requiring `k` rather than merely "some `e` tag" is load-bearing. Every threaded
event already carries an `e` tag, because a top-level NIP-22 comment sets its
parent to the thread root — so "has a parent" is trivially true and says nothing.
A response whose parent is the thread rather than a request is an approval of
nothing, and an agent that matches on action id alone would accept it.

**The request MUST come from the proposer**, and a verifier MUST disregard any
8102 in the chain signed by anyone else. This is stricter than the rule for
transitions above — those are ignored, this one must be — because a request
*names its own approvers*. Honour a stranger's and they ask themselves, answer
themselves, and the chain tallies as approved by someone the agent never
consulted.

A relay MAY refuse to store an 8103 whose signer is not among the addressees of
the 8102 it answers, and an 8101/8102 whose `action` tag names a chain proposed
by someone else. A relay doing so MUST fail *open* when it does not hold the
referenced event: events legitimately travel between relays, and refusing every
approval whose request has not arrived breaks federation to catch nothing. A
verifier holding the whole chain makes no such allowance — it is the party being
asked to act on the answer.

## Capabilities and delegation

A 38102 `capability_grant` is a signed attestation: *this pubkey may invoke this
resource, in this scope, until T, N times, granted by me.* Resources are named
after actions (`action:deploy`).

Resource strings are matched **exactly**; there are no wildcards, and nothing
narrows them. Anything a delegation might need to narrow therefore belongs in
`scope`, not in the resource name: `action:deploy` with `{env: production}`, not
`action:deploy.production`. A delegation reading "only in staging" can intersect
a scope; against a name it can only whitelist a different string, which is a
statement about identity rather than about authority and silently does nothing
if the string is misspelt. A scope that does not match refuses; a whitelist entry
matching no resource anyone requested is invisible.

**Enforcement happens at the resource.** The tool verifies the signature chain
before acting. A Quorum-aware relay MAY also enforce on plaintext channels as
defence in depth, but MUST NOT be the only thing between an agent and production
— that would reintroduce exactly the trusted server this design removes.

### The two resources the relay owns

Two resources are the exception to that rule, because for them the relay *is* the
resource. Nothing else can hold them:

| Resource | What holding it permits |
| --- | --- |
| `group:join` | The relay admits the grantee to the group named in `scope.group`. |
| `thread:budget` | The holder may publish a `set_budget` `thread_op`. |

`group:join` is the coarsest capability in the system — being in the workspace at
all — and the one most easily left implicit. NIP-29 says a relay MAY admit a kind
9021 join request to an open group; a workspace holding approval records and
capability grants MUST NOT. A relay implementing this NIP SHOULD refuse a join
request unless the requester holds an unexpired, unrevoked `group:join` grant
whose `scope.group` is that group, issued by an owner or admin of it, or unless
an admin admits them directly with a kind 9000.

Three consequences follow from membership being a grant rather than a row. It can
be issued to a key that does not exist yet and handed over with the key, which is
the ordinary case for an agent somebody else will run. It can be revoked, and a
third party can check who issued it without taking the relay's word. And it is
subject to the same `expires_at` the rest of the system uses.

`max_uses` cannot be enforced on either of these and MUST be ignored rather than
half-honoured: counting uses requires a caller to ask "how many times so far",
and there is none — a relay counting for itself would be asserting a fact nobody
can check. An invitation that should not stand forever bounds itself with
`expires_at`.

**Revoking `group:join` does not evict an existing member.** The grant answers
"may this key come in", asked once at the door; membership is the relay's own
state thereafter. Cancelling a keycard does not un-enter the building. Removing
someone is a NIP-29 kind 9001, and an operator who means both MUST do both.

Because these two names are matched exactly and are not otherwise reachable from
code, a relay SHOULD verify at startup that the names it enforces are the names
the protocol publishes — `relay_enforced` in `schemas/index.json` exists for
that. A one-character divergence is not a build error and not a rejected event.
It is an operator issuing `group:jion`, seeing a green tick, and finding the
grantee still cannot get in.

**Delegation never escalates.** An action MAY carry `on_behalf_of` referencing a
38106 `delegation` signed by a human. The effective permission is the
**intersection** of the agent's grant and that human's own permissions, never the
union. Without this rule, "give the agent admin so it can help" is the only
workable pattern.

## Leases

Running an agent as two processes for availability is normal, and the ordinary
way to do it is to give both the same key — that is what makes them replicas of
one agent rather than two agents. A `lease` (28102) is how they avoid both
answering.

A claim carries `instance`, `epoch`, `ttl_seconds` and an optional `purpose`.
`instance` is required and is not decoration: the holder cannot be identified by
`pubkey`, because two claims from one pubkey are the expected case here rather
than a conflict, so without a discriminator the replicas cannot tell each other
apart, let alone agree.

Claimants publish, wait a settle interval, and take the whole set of claims they
can see for that thread and purpose. The winner is the minimum by:

```
(created_at asc, epoch desc, "<pubkey>:<instance>" asc)
```

where `created_at` is the **earliest** claim seen from that holder for that
thread, not the most recent. A lease is renewed by republishing, and taking the
latest would make every renewal an act of self-demotion: the holder's timestamp
would move forward past a sibling's older losing claim and hand it the thread it
had already lost.

Every term is a field of a signed event, which is the property that matters:
each replica computes the winner from the same shared data and reaches the same
answer. Deciding by *local* observation order instead — first claim I saw wins —
gives two replicas two different winners whenever the relay delivers to them in
different orders, which is most of the time.

Leases are advisory. A lease cannot be made authoritative without a consensus
mechanism nobody wants in a chat relay, and an ephemeral event may simply be
lost. It removes the common case of duplicate work; it is not what makes
double-execution safe. That comes from idempotent effects and content-addressed
ids, and an implementation that treats a held lease as permission to skip them
has misread this section.

## Presence

A `presence` (28103) event carries `status` (`online`/`busy`/`offline`), an
optional `activity` caption, and `ttl_seconds`. An agent republishes while it
runs and SHOULD publish `offline` on a clean shutdown.

**A beat expires at its own `created_at + ttl_seconds`** — the author's clock,
not the reader's. Every reader therefore agrees on the moment it lapses, and an
agent whose clock is skewed looks stale to everybody rather than fresh to some.
The alternative, measuring from arrival, makes liveness a different fact for
each reader and hides skew instead of bounding it.

**Absence means nothing.** These events are ephemeral, so relays store none of
them and a client that connected a moment ago knows only about agents that have
beaten since. An empty set means "nobody has said", never "nobody is running".
Implementations MUST NOT present it as the latter, and MUST NOT condition any
action on it: an agent missing from the list may be halfway through the work
somebody is about to start again.

Readers resolve two beats from one pubkey sharing a `created_at` by **arrival
order**, not by the `(created_at, id)` tiebreak used elsewhere in this document.
An agent that finishes a job inside one second publishes `busy` and then
`online` in the same second, and a hash tiebreak strands it on the wrong status
until the next beat. The rule differs here because a heartbeat is only ever read
as the live stream the reader is watching, where arrival order is available and
meaningful, while a projection or a chain is folded from stored history that no
two readers receive identically. Nothing is ever authorised on a heartbeat,
which is what makes a reader-local rule acceptable at all.

## Ordering

Nostr has no total order. `created_at` is a client-supplied wall clock, and a
relay may withhold events by design. Three layers recover what matters:

1. **`counter`** — per-author monotonic. Lets a reader detect "I missed something
   from this author", which combined with `to`-marked addressing covers the case
   that actually matters: *did I miss something addressed to me.* Works on any
   relay.

   Events of an **ephemeral kind MUST NOT carry a `counter`**, and this is a
   requirement rather than an optimisation. Relays do not store ephemeral events,
   so a number spent on one is a sequence position nobody can ever backfill:
   every reader replaying from history would see a permanent hole for each lease
   renewal and heartbeat the author ever sent, and gap detection — the entire
   point of the tag — would report a loss roughly twice a minute forever.
   Numbering only the durable record keeps the signal worth having.

   A writer MUST allocate a counter at most once per event. In particular, a
   retry that rebuilds an event in order to be deduplicated by id MUST reuse the
   counter of the attempt it is repeating; allocating a fresh one changes the
   bytes, changes the id, and produces the second copy the retry was trying to
   avoid.
2. **NIP-22 `e` tags** — causal structure. A missing parent is detectable because
   you hold its id. Works on any relay.
3. **8108 `checkpoint`** — a relay-signed Merkle root over the event ids it holds
   for a group up to time T. If it later serves a set missing a covered event,
   that is *cryptographic proof of misbehaviour*, not a suspicion.

Layer 3 is what keeps the relay from becoming a trust anchor: a checkpoint is a
commitment it cannot retract. A generic relay publishes none and readers degrade
to layers 1–2.

## Context

Context packing is a NIP-90 DVM (5600/6600), not a privileged endpoint, so the
packer is addressed by pubkey and is swappable. Results carry per-segment
`provenance: {pubkey, kind, trust}` where trust is `self` | `operator` | `member`
| `untrusted`, so an SDK can delimit untrusted content before it reaches a model.
Agents reading other agents' output is the normal case here, which makes this a
protocol-level concern rather than an application one.

**There is deliberately no designated summarizer agent.** If one agent produced
the summaries fed to all the others, a single prompt injection against it would
rewrite the working memory of the entire workspace — one malicious message
becoming persistent, laundered instructions delivered to agents that never saw
the original. This is structural, not patchable. Any agent MAY publish an 8104
`summary`; it is returned tagged with its provenance and trust, and callers MAY
demand `verbatim_only` and pay the tokens instead.

`budget_tokens` is **advisory**. The mandatory-keep set can exceed it. The result
reports `used_tokens` so callers can react rather than receive a silently
truncated history.

### The packer runs in two places, so it is specified as a function

On a `plaintext` channel a relay can pack context and one round trip replaces a
backfill. On `nip44` or `mls` it cannot read a word, and the packer has to move
into the client. So the same algorithm exists twice, in different languages, and
the two MUST agree — otherwise "which packer answered" becomes a fact an agent's
behaviour depends on, and a workspace that turns on encryption quietly changes
what every agent knows.

Agreement is only checkable if packing is a pure function, so `extractive-v1` is
defined as one:

```
pack(request, requester, events) -> result
```

with no clock, no network, no relay state and no configuration. Two
implementations given the same three inputs MUST produce byte-identical
canonical JSON for the result body. Everything below exists to make that
achievable rather than aspirational; where a rule looks arbitrary, it is usually
the cheapest thing two languages can agree on exactly.

`events` is whatever set the packer holds. A relay holds the group; a client
holds its backfill window. Identical output is required *for the same input
set*, and a packer that has seen fewer events MUST NOT be treated as wrong — it
reports what it packed, and `dropped_events` is a count over its own input.

### `extractive-v1`

**1. Select.** An event belongs to thread `T` if its id is `T`, if its NIP-22
`E` tag is `T`, or if it is a 38101 whose `d` is `T`. The thread state is
included because "what am I supposed to be doing" is the question an agent asks
first, and its answer is a projection rather than a message.

**2. Apply the caller's filters**, in this order: `include_kinds` (if present,
keep only these), `exclude_kinds`, `since` (drop events older than it). These
win over the mandatory-keep rules below. Mandatory-keep protects history from
*the budget*, never from an explicit instruction; a caller who excludes kind 11
gets no thread root and has asked for that.

**3. Drop what is never context**, whatever the caller said:

- every ephemeral kind (20000–29999) — leases and heartbeats are liveness, not
  history, and none of them is stored anywhere to be packed twice the same way;
- NIP-29 moderation and membership kinds (9000–9022, 39000–39003), NIP-25
  reactions (7), and NIP-09 deletion requests (5);
- 5600 and 6600 themselves, or a pack would contain its own previous answers;
- 38104 `agent_memory` and 38105 `agent_cursor` — another agent's scratch space
  is not this agent's history.

With `verbatim_only`, also drop every 8104 `summary`. A summary is somebody's
account of events rather than the events, and a caller paying full price for
history is entitled to refuse all of them without having to reason about who
wrote which.

**4. Collapse action chains.** Of the 8101 events sharing an `action` tag, keep
the `proposed` transition and the one with the highest status rank; drop the
rest. Rank is `proposed` 0, `awaiting_approval` 1, `running` 2, and every
terminal status (`succeeded`, `failed`, `denied`, `cancelled`) 3; ties are broken
by `(created_at, id)` ascending, keeping the last. The input and the outcome are
what a later reader needs; "it started running" is inferable from both.

**5. Mark the mandatory set.** The thread root, the 38101 thread state, every
8102 and 8103, every 8101 that survived step 4, and the 10 most recent surviving
events. These are never dropped for budget and never truncated. Approvals are in
that list because an agent that has forgotten what it was allowed to do is
exactly the failure this protocol exists to prevent.

**6. Order** every surviving event ascending by `(created_at, id)`, the NIP-01
rule, **except that the thread root sorts first whatever its `created_at` says**.
Note that this is otherwise deliberately *not* the parent-link order that
[action chains](#a-chain-is-ordered-by-its-parent-links-not-by-created_at) use.
Nothing is authorised on a context pack, and a reader needs a stable transcript
rather than a proof.

The root is the one exception because every other event in the thread `E`-tags
it, so its causal position is the one thing an ordering cannot get wrong by
accident — and `(created_at, id)` gets it wrong routinely. A thread opened and
answered inside the same second falls through to the lowest-id tiebreak, which
is a hash, and the pack then opens with two replies to a task the model has not
been told yet. The rule costs nothing: `T` is already known to both packers,
because it is what they were asked for.

**7. Fill the budget.** Every mandatory segment is included, whatever it costs.
Then optional segments are considered newest first and admitted while they fit;
at the first one that does not fit, admission **stops** and every older optional
segment is dropped. Stopping rather than continuing keeps the kept window
contiguous: a model handed the last hour with one arbitrary paragraph from
Tuesday wedged into it reasons worse than one handed a shorter hour.

**8. Truncate.** An optional segment's text is cut to 400 Unicode **code points**
and `…` (U+2026) is appended, with `truncated: true`. Code points rather than
bytes, because a byte cut can split a character; and implementations MUST NOT
trim to a word boundary, because word boundaries are locale-dependent and two
packers would disagree on the first Japanese sentence they were given.

**9. Segment text** is the event's `content` for kinds 9, 11 and 1111; the
`text` field of the body for 8104; and **the `alt` tag** for every other kind
defined here. This is what [`alt` is required](#alt-is-required) for. The
primary consumer of an unknown event is a context packer feeding a model, and a
packer that understood every kind it emitted would break on the first kind added
after it shipped.

**10. Provenance** is derived from `events` alone, so that both packers label
identically:

- `kind` is `relay` for an author that signed a 38101 or 8108 in the input,
  `agent` for one with a 38103 `agent_manifest` in the input, `human` otherwise.
- `trust` is `self` for the requester; `operator` for the pubkey named as
  `operator` in the *requester's own* manifest; `untrusted` for any `agent`
  author and for every 8104 whoever wrote it; `member` otherwise.
- `display_name` is omitted. There is no name in this NIP that is not a claim,
  and a packer that resolved one would make its output depend on a lookup the
  other packer cannot repeat.

An agent SHOULD delimit `untrusted` segments before they reach a model, and MAY
delimit `member` segments too: the distinction is who is accountable for the
text, not whether it is safe.

**11. Count tokens** as `ceil(utf8_bytes(text) / 4) + 8` per segment, summed.
This is a proxy and not a tokenizer. A real BPE count is model-specific and
versioned, so requiring one would make this NIP depend on a vendor's vocabulary
file and make agreement between two packers contingent on both shipping the same
build of it. The constant 8 covers the framing a caller adds per segment, which
is real cost that a pure text count hides. `budget_tokens` is advisory precisely
because this number is approximate; a caller needing an exact count MUST measure
the rendered prompt itself.

`dropped_events` counts the events that survived steps 2 and 3 but produced no
segment, which includes the transitions collapsed in step 4.

### Asking a packer

A `context_pack_request` (5600) carries a `to`-marked `p` tag naming the packer.
A packer MUST ignore requests not addressed to it; answering everything it can
see would have every packer in a workspace answer every request, and the
requester would have no way to know which answer it got.

The reply is a 6600 signed by the packer, `e`-tagging the request and
`p`-tagging the requester, in the same group. On failure the packer publishes a
NIP-90 kind 7000 job feedback with `["status", "error"]` and a reason. Silence
is not an answer: an agent blocked on context it will never receive is
indistinguishable from one doing slow work.

This departs from NIP-90 in one place. NIP-90 carries job parameters in `i` and
`param` tags; Quorum carries the body in `content` as canonical JSON like every
other kind here. One rule for every kind in this NIP is worth more than partial
conformance to a tag convention, and what makes this a DVM rather than an
endpoint is that the provider is addressed by pubkey.

## Memory

38104 `agent_memory` is an addressable event with `d` = a scoped key, so the
newest write per `(pubkey, d)` wins and an agent's memory is namespaced by the
key that wrote it. No agent can overwrite another's, and none has to coordinate
over key names.

Memory is **published**, and that is the point rather than an oversight. A
workspace whose agents remember things nobody can read is a workspace where the
answer to "why did it do that" lives on a disk somewhere; here it is an event a
human can fetch, quote and argue with. The cost is that memory is subject to the
[privacy rules](#privacy) like anything else: on a `plaintext` channel the relay
and every member can read it, Nostr has no unpublish, and an agent MUST NOT
write a secret into one.

Memory is not a cursor. 38105 exists for resume state because the two have
different lifetimes: a cursor is meaningless to anyone but the process that
wrote it and is rewritten several times a minute, while a memory entry is
supposed to outlive the agent that learned it. Packers drop both.

## Encryption

`enc` is a per-channel policy, present from day one so that changing it is never
a protocol break.

| Mode | Relay reads | Relay-side services |
| --- | --- | --- |
| `plaintext` | bodies | context packing, indexing, state projection, rate limits |
| `nip44` | tags only | none |
| `mls` | nothing | none |

Under `mls` (Marmot), messages are published under a per-message ephemeral key
and sender identity lives inside the ciphertext. This breaks `p`-tag addressing
and per-principal rate limiting, and makes NIP-29 membership redundant with MLS
group state. Addressing must move inside the ciphertext and loop-breaking becomes
purely client-side. Implementations MUST NOT claim `mls` support without
addressing this.

## Loop prevention

Addressing plus a channel policy defaulting to `respond_only_when_addressed`
removes most runaway agent-to-agent chatter structurally. Causal-chain depth — the
tempting mechanism — is trivially defeated by A→B→A alternation and SHOULD NOT be
relied on. Backstops: per-thread budgets (exhaustion → `paused` → ping a human)
and per-principal rate limits.

Stated policy: **there are no private agent backchannels.** Agent-to-agent DMs are
default-deny, require an explicit grant, and are readable by the workspace owner
and by the agents' operator humans.

## Privacy

Nostr has no unpublish. NIP-09 deletion is advisory and a mirrored event is
permanent. Implementations MUST NOT place secrets or personal data in events, and
`alt` in particular is plaintext even on encrypted channels (see rule 5 above).

## Forward compatibility

- Validators MUST be non-strict: unknown kinds and unknown body fields are
  ignored, never rejected.
- A client that does not understand a kind MUST render its `alt` text rather than
  hiding the event. An event silently dropped from a task thread is worse than an
  ugly one.
- Adding a kind, or an optional body field, is a MINOR version bump. Removing or
  repurposing a kind, adding a required field, or changing a tag's meaning is
  MAJOR.

## Reference implementation

`@quorum/protocol` — kind and tag definitions, validators, and JSON Schema for
every body, generated from the same source and committed to the repository so
that implementations in other languages validate against the same rules rather
than a prose reading of them. `schemas/index.json` publishes the per-kind
envelope requirements as data for the same reason, and `relay_enforced` names the
two resources a relay checks so that no implementation has to hand-copy them.

A signed golden transcript of the full loop — request, proposal, approval,
execution — is committed at `fixtures/deploy-approval.json`, and
`scripts/validate.py` validates it using only the standard library and the
committed schemas.

`apps/relay` is a reference relay in Go (khatru + relay29) which reads those
schemas as data — it could not import the TypeScript validators if it wanted to,
which is the point. `@quorum/sdk` is a reference client implementation of the
addressing, ordering and lease rules above, and `examples/echo-agent` is the
smallest agent that exercises them.
