# Changelog

Every change to `nip-quorum.md`, and to the artefacts that are part of the spec rather than test
data: `packages/protocol/schemas/` and `packages/protocol/fixtures/`. The policy these entries
are written under is in [VERSIONING.md](VERSIONING.md).

The format is one section per protocol version, newest first, and within a version one entry per
day the spec changed. A **Breaking** heading carries the migration note a MAJOR bump requires;
there has not been one yet, because 0.1 has never been published.

## 0.1 — unreleased

Kind numbers in the 8100/28100/38100 ranges are **provisional**. They were checked free against
the registry of kinds on 2026-09-11 and are re-checkable with
`pnpm --filter @quorum/protocol check-registry`. A reallocation forced by the registry is a MAJOR
bump under the policy, and it is the likeliest one this protocol will have.

### 2026-09-15 — a rule that exists in one language

- **`RejectMlsPolicyEpoch`.** "An `mls` channel policy MUST NOT carry `epoch`" was a cross-field
  rule enforced by the TypeScript validator and by nothing else. `z.toJSONSchema()` emits nothing
  for a Zod refinement, so the rule was invisible in the committed schemas the Go relay validates
  from, and the relay stored an event every TypeScript client in the repository refuses to parse —
  a channel policy that reads to every client as *no policy at all*. Found by publishing one at a
  live relay rather than by comparing tables.
- **`cross_field_rules` is now published in `schemas/index.json`**: the code, the kinds and a
  one-line statement of each rule that spans a field and a tag, or two fields. Not the check
  itself, which no schema language can carry — the *list*, so that a second implementation knows
  what it has to implement by hand and a conformance suite can iterate it. The suite's
  `cross-field` section is driven by this table, and a rule added with no probe fails the section
  instead of going unasked.
- Two of the rules in that table exist because the conformance suite asked for them and nothing
  answered.

### 2026-09-14 — `mls` channels

Encryption mode `mls`, specified before any of it was built, and corrected twice while it was.

- **Quorum-native routing, with Marmot's transport as a documented optional profile.** An `mls`
  event keeps the Quorum envelope — same kind, same tags, same signature — and `content` becomes a
  base64 `MLSMessage`. Marmot publishes each message under a fresh ephemeral key carrying one `h`
  tag and normatively no other, which deletes `alt`, `p` addressing, `counter` and `enc` from the
  wire in a single rule, and takes relay-side membership, rate limiting, budgets and the
  checkpoint anchor with them.
- **The MLS `group_id` is the UTF-8 bytes of the NIP-29 group id**, corrected from "the 32 bytes
  of the group id" — NIP-29 places no constraint on the string, and the ids this repository mints
  are human-chosen names. A receiver MUST check that an opened message's `group_id` is the one its
  `h` tag named, or a member of two channels can lift a message from one into the other.
- **Authorship is the Nostr signature, not the MLS credential.** The credential identity MUST
  equal the event `pubkey`, checked at join time. The per-message form of that rule was
  unimplementable as written — RFC 9420 encrypts the sender index and `ts-mls` does not surface
  it — so per-message authorship travels as the sender's pubkey in the MLS `authenticated_data`,
  covered by the AEAD and the `FramedContent` signature, and checkable before a generation is
  spent. A binding failure MUST discard the ratchet step that detected it, or republishing each
  message a moment before its author takes the channel permanently dark.
- **Kind 8111 `mls_welcome`** — a regular, fully signed Quorum event, replacing Marmot's
  1059/13/444 gift-wrap chain. A gift wrap would need an `h` tag to be routed and an ephemeral
  signing key to be a gift wrap, and relay29 refuses an `h`-tagged event from a non-member; both
  cannot be true of one event. Kind 444 also falls outside every NIP-01 storage range, so a stored
  one has undefined semantics on a generic relay, which Option A forbids.
- **Kind 8112 `mls_commit`**, with `epoch` in the clear in a JSON body. A relay has to serialise
  commits — at most one per channel per epoch — and reading the epoch out of the MLSMessage would
  put an MLS wire parser in the relay.
- **Kind 30443 KeyPackage is reused from Marmot and diverges in three places**: `d` is the channel
  id rather than 32 random bytes, no `app_components` identity proof, no `encoding` tag.
- **Ciphersuite 1 only.** MLS negotiates nothing at the message level, so a workspace setting
  moves a compatibility failure from configuration time to join time, where it presents as a
  member who silently reads nothing.
- **The epoch obligation is asymmetric**: a sender MUST write the `epoch` tag; a reader that has
  already opened the message MUST NOT discard it for want of one. Disagreement between the tag and
  the ciphertext is still a rejection.
- **A ratchet cannot repeat itself**, so `once()`'s byte-identical retry does not survive: the
  sealed envelope MUST be persisted before publishing and replayed verbatim. The counter rule
  gains a second reading — same counter and same plaintext is a retry that lost its cache, same
  counter and different plaintext is still "the key is in two places".
- **Forward secrecy makes a channel unreadable to its own members**, including to the author of a
  message, who is the one member for whom the generation is already spent. The relay is the
  transport and each member is the record; a new member gets no history at all.
- Envelope fix found while writing the relay's arm: **kind 8111 was missing `addressed: true`** in
  the published envelope table. An unaddressed Welcome is stored, valid, and invisible, because
  `#p` is how every reader locates key material.
- Envelope fix: the `epoch` floor became per-mode. `nip44` mints generations from 1 so that zero
  stays distinguishable from a missing field; an MLS group is at epoch 0 from creation until its
  first commit.

### 2026-09-14 — `nip44` channels

- **`enc` becomes a signed per-channel policy** (kind 38107) rather than a bare tag. An `enc` tag
  on a channel with no policy is refused, which closes a one-tag bypass of body validation.
- **A shared channel key in epochs**, wrapped per recipient in kind 8110, rather than
  per-recipient fan-out of every message.
- **The nonce MUST be derived, not random**: `hmac_sha256(channel key, id of the event in the
  clear)`. A random nonce makes a retry a second message. A MAC rather than a plain hash, so an
  observer holding no key cannot confirm a guess at a low-entropy message by recomputing its
  nonce. This is synthetic-IV and carries SIV's cost: identical plaintexts seal identically.
- **`UNSEALED_KINDS` is written as exceptions**, published in `schemas/index.json`, so a kind
  invented later is sealed by default. Four reasons are on the list and no others: key management,
  authorization, relay-authored records, NIP-29 moderation.
- **The approval digest travels in the sealed body, not in a tag**, and a sealed event's `alt`
  MUST stay generic — a self-describing fallback publishes in the clear the sentence the body was
  hidden to protect.
- **Verify the signature against the sealed bytes, then open for the body.** The reverse breaks
  the audit silently: every honest approval rejected, which looks exactly like a human who has not
  answered yet.
- **A NIP-90 refusal reason lives in the `status` tag, not in `content`**, because `content` is
  what a sealed event encrypts and the client that needs the reason is the one holding no key.

### 2026-09-14 — budgets, spend and interrupts

- **`add_spend` is the only path into `spent`.** An action body also carries a `cost`; folding
  both doubles every number in the workspace. The ops version is also the only one that survives
  encryption.
- **Both token columns count against a `tokens` ceiling**, or a thread at 29,000 in and 28,000 out
  looks fine under a 30,000 cap.
- **Pausing an exhausted thread has three arms**, each fixing a different failure: the fold pauses
  only while folding `add_spend` or `set_budget` (never `set_status`, or a human's `working` is
  rewritten by the same fold that stored it); never on a `done` thread (or a late spend report
  un-finishes delivered work); and it only ever *sets* `paused`, so raising a ceiling resumes
  nothing. Resuming and raising are two decisions and take two ops.
- **A paused thread still accepts the way out.** Only `proposed` and `running` are refused;
  terminal transitions, chat, comments and every thread op go through.
- **Kind 28101 interrupts have no receipt and no mechanism can give them one.** Ephemeral, so an
  OK means only that the relay routed it. Interfaces MUST say so.
- **`cancelled` is not `failed`.** A job that broke and a job a human stopped send different
  people to different screens.
- **A relay's own projection is signed at `max(now, previous + 1)`**, not at the clock. Two folds
  inside one second is the normal case, and NIP-01's lowest-id tiebreak silently drops the newer
  state about half the time.

### 2026-09-14 — checkpoints

- **Kind 8108**, relay-signed, committing to a Merkle root over the event ids held for a group in
  a closed window. `sha256-merkle-sorted-v1`, with a cross-language fixture at
  `fixtures/merkle-v1.json`.
- **Only regular events may be committed to.** An addressable event is superseded and its id
  leaves the store, so a checkpoint covering a 38101 fails the first time anyone changes a task's
  status — and it fails as "the relay is withholding an event", the most serious thing this system
  can say.
- **An odd node is promoted, never duplicated.** Bitcoin's padding rule is CVE-2012-2459: `[a,b,c]`
  and `[a,b,c,c]` collide, which here would be two different held sets with one root. A promoted
  node contributes no proof step, so nothing may assume a path length from the leaf count.
- **`prev` is the previous checkpoint's event id, not its root**, so a relay cannot re-cut the same
  events into different windows and two consecutive quiet windows stay distinguishable.
- **A checkpoint MUST NOT be dated inside its own window**, since kind 8108 is itself regular and
  `h`-tagged and would otherwise be a member of the set it describes.
- **A window may only be closed once it can no longer receive an honest event**, which is what
  makes checkpoints free: with the clock-skew rule symmetric, layer 3 adds no new refusals.
- **An empty window still gets a signed checkpoint.** An empty root says "I held nothing"; silence
  says only that the relay stopped talking.
- Detecting a short window and proving withholding are separate claims: only
  `root(served ∪ held) == committed root` accuses anybody.

### 2026-09-13 — context and memory

- **`extractive-v1` is specified as a function over an event set**, because it runs in two places
  — relay-side for plaintext channels, SDK-side for encrypted ones — and the two MUST produce
  byte-identical output.
- **The thread root comes first**, which is an ordering exception rather than a sort key:
  everything else is oldest-first within the admitted set. A packer that treats the oldest message
  as the least important one drops the only statement of what the thread is for.
- **`budget_tokens` is advisory.** The mandatory-keep set may exceed it; the response reports
  `used_tokens`.
- **A pack too large to deliver is refused with its own numbers, not trimmed.** Trimming would give
  a different answer from the SDK's under the same `algorithm`, with nothing in the body saying so.
- **Provenance is derived from the event set alone**, which makes a missing agent manifest a silent
  security failure: a rival agent's injection comes back labelled `human`, and the renderer stops
  fencing it.
- **No summarizer agent.** One designated summarizer feeding every other agent means a single
  prompt-injected summary rewrites the working memory of the whole workspace. Structural, not
  patchable — hence deterministic extractive compaction plus opt-in `summary` write-back carrying
  provenance.
- **Kind 38104 `agent_memory`**, `d` = a scoped key.

### 2026-09-13 — presence

- **Kind 28103**, ephemeral. An empty presence list means "nobody has said", never "nobody is
  running", and interfaces MUST say which. A same-second tie is settled on arrival order —
  deliberately the opposite call from the thread projection, because a projection is folded from
  stored history and a heartbeat is only ever read as the live stream the reader is watching.

### 2026-09-12 — capabilities as attestations

- **Grants are signed addressable events verified at the resource**, never database rows. The
  relay also enforces on plaintext channels as defence in depth and is never the only thing
  standing between an agent and production.
- **Scope, not the resource name**: `action:deploy` with `{env: production}`, never
  `action:deploy.production`. Resource strings match exactly and never narrow; scopes intersect.
  Encode the environment in the name and a delegation has nothing to narrow.
- **Delegation never escalates**: the effective permission is the intersection of the agent's grant
  and the human's own.
- **The two resources a relay owns** — `group:join` and `thread:budget` — are published as data in
  `schemas/index.json` and checked at boot, because a second copy of the names in another language
  drifts silently and a typo reads as a green tick.
- **`max_uses` is unenforceable at a relay and is ignored rather than half-honoured.** There is no
  caller to ask how many times a grant has been used, and a relay counting for itself asserts a
  fact nobody can check. Interfaces must label it not enforced.
- **Revoking `group:join` does not evict an existing member.** Two questions asked at two moments.

### 2026-09-12 — approvals and the action chain

- **An action chain is ordered by its `e`-tag parent links, never by `created_at`.** The loop
  completes inside one second, `created_at` has one-second resolution, and NIP-01's tiebreak is a
  hash — so an honest chain shuffles. Millisecond resolution would not fix it either: the ordering
  that decides whether an execution was legal must not be a field the executing party picks.
- **Only the proposer advances the chain.** A stranger's transition is a warning, never a
  rejection: counting it lets any member forge an outcome, and erroring on it lets any member veto
  any action forever with one junk event the proposer cannot retract — and every Quorum event is
  valid on a generic relay that will store it. The exception is `approval_request`, which MUST come
  from the proposer, because a request names its own approvers.
- **An approval is bound to an `input_digest`**, and an approver who edits parameters returns
  `modified_input_digest`, which the agent MUST re-check.
- **A signed human approval is not a capability.** Consent and authority are two questions asked at
  two moments; a system that conflates them cannot revoke anything mid-flight.

### 2026-09-11 — leases and ordering

- **Kind 28102 `lease`**, with the `instance` field and the
  `(created_at asc, epoch desc, holder asc)` rule over the *earliest* claim per holder. Advisory.
- **Ephemeral kinds carry no `counter`.**
- **The `counter` MUST be reserved inside `once()`.** A retry that allocates a fresh counter
  rebuilds different bytes, so the relay stores a second copy and the reservation is defeated.

### 2026-09-11 — first draft

The kinds, the envelope, and the rules that were not cuttable later.

- Kinds 8101–8109 regular, 28101–28103 ephemeral, 38101–38106 addressable, 5600/6600 DVM; chat,
  threading and comments reused unchanged from NIP-C7, NIP-7D and NIP-22.
- **`alt` is REQUIRED on every kind defined here**, against NIP-31's `unrecommended` marking. The
  justification is specific: the primary consumer of an unknown Quorum event is a context packer
  feeding a language model, and NIP-89 handler discovery cannot help there — no handler to
  resolve, no user to click through, just a token budget and a model that must be told what
  happened.
- **The `to` marker**: `["p", "<pubkey>", "<relay>", "to"]`, because NIP-22 has already spent an
  unmarked `p` on the parent author. The relay filter stays a coarse superset prefilter and exact
  matching happens locally. A writer MUST NOT emit both a marked and an unmarked `p` for the same
  pubkey.
- **One `action` kind with a status lifecycle**, not a `tool_call`/`tool_result` pair. The relay
  runs no tools, so those would be log lines in a wire protocol re-specifying MCP's shape inside a
  chat protocol, and they would hardcode one agent architecture.
- **Per-author `counter` tags** — multi-character, so no relay index is needed — and causal `e`
  tags. There is no gapless sequence number: `created_at` is a client-supplied wall clock and a
  relay may withhold by design.
- **Validators MUST be non-strict** and unknown kinds MUST be rendered through their `alt` text.
  These are what make every later MINOR addition safe; see [VERSIONING.md](VERSIONING.md).
