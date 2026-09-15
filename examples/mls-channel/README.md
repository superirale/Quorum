# mls-channel

A channel nobody can read twice — and an honest account of what that costs.

```sh
pnpm --filter @quorum/mls-channel demo   # five acts, no relay and no network
pnpm --filter @quorum/mls-channel live   # five more, against the Go relay
```

`sealed-channel` was mostly subtraction. This one subtracts from the subtraction, and the thing it
takes away is not the relay's access — that went in M9 — but **the channel's own memory**. MLS
deletes the key material that opens a message as it is used. That is not a limitation of this
implementation; it is what forward secrecy *is*. So a member who joins today reads none of
yesterday, a member who restarts reads only what they wrote down, and a member who misses one
commit goes dark until somebody re-adds them.

The relay becomes the transport and **each member becomes the record**. Every act below is one
consequence of that sentence, with a plaintext control beside it so the cost is measured rather
than asserted.

## The mode

An `mls` event keeps the **Quorum envelope**: same kind, same `h`, same `alt`, same `p`
addressing, same `counter`, same signature. Only `content` changes, to a base64 `MLSMessage`, with
the MLS epoch in the `epoch` tag and the MLS `group_id` set to the UTF-8 bytes of the NIP-29 group
id.

Marmot's transport — a fresh ephemeral key per message carrying one `h` tag and normatively *no
other tag* — is a documented optional profile and not the default, because adopting it deletes
`alt`, addressing, counters and the `enc` tag in one rule, and takes relay-side membership,
per-principal rate limiting, budget enforcement and the checkpoint anchor with them. What keeping
the envelope costs is metadata privacy: the same social-graph leak `nip44` already has. Marmot
says the quiet part itself — under that transport "a non-member can submit envelopes that reach
trial decryption". Metadata privacy and relay-side admission control are not jointly achievable,
and the choice belongs to a workspace rather than to a library.

**Authorship is the Nostr signature, not the MLS credential.** MLS authenticates a sender only to
whoever holds the ratchet tree, and forward secrecy deletes that on a schedule; an approval nobody
can attribute in six months is not an audit record. The sender's pubkey travels in the MLS
`authenticated_data` — covered by the AEAD *and* the `FramedContent` signature — and MUST equal
the event `pubkey`. The cost is deniability, and the spec says so.

Ciphersuite 1 only, refused at join time rather than negotiated: MLS negotiates nothing at the
message level, so a mismatch would otherwise present as a member who silently reads nothing.

## What the demo shows

Five acts against `FakeRelay`, in process, with no keys crossing a network.

**1. Joining hands over nothing.** Ada founds the group, says one sentence, then adds Bob. Bob
cannot read the sentence — not "not yet", not "ask an admin", *never*; the material is gone. Both
read the next one.

This is the `nip44` answer being withdrawn. There, an admin can wrap old epochs for a new member
and decide how much history they get. Here there is no such decision to make and no library should
pretend otherwise. The plaintext control backfills the same two messages in one query.

**2. Each member is the record.** Ada restarts, warms her archive and reads the channel back —
including **her own words**, which took a defect to get right (see below). Then Bob prunes his
archive to now, restarts, warms nothing, and can no longer read a message he read a moment ago.
The relay is still serving that exact event and it still verifies. The control is a plaintext
client, which simply asks again.

A client that keeps no durable plaintext archive is a client whose history is one reconnect from
gone. Nothing runs retention on a timer: a background thread quietly deleting the audit trail is
the incident, not the feature.

**3. A retry is replayed, because a ratchet cannot repeat itself.** M9 bought idempotency with a
derived nonce — seal the same bytes twice, get the same event. MLS advances a secret tree per
message, so re-encrypting is a *different* message and spends a generation. `once()` therefore
persists the sealed envelope **before** publishing and replays it verbatim. Two `say()` calls with
the same counter produce one id; the relay logs two arrivals and stores one.

The counter rule gains a second reading: same counter and same plaintext is a retry that lost its
cache, same counter and different plaintext is still "the key is in two places".

**4. A commit is about everybody.** Ada adds Cat, which moves the group from epoch 1 to 2. Cat
reads what is said next and nothing said before. Bob, who never fetched the commit, reads nothing
at all — with `CryptoError: OperationError`, four frames inside `ts-mls`, naming no epoch, no group
and no member. The error is printed rather than paraphrased, because how unhelpful it is *is* the
finding. `catchUpMls` returns 1 and he is back.

Two claims are deliberately **not** asserted here and are named in the output instead: that the two
membership lists disagree, and that removal at the relay is not removal. `FakeRelay` keeps no
NIP-29 member list, so either assertion would pass against a relay that keeps a perfect one. They
are act 5 of `live.ts`.

**5. Authorship is the signature.** Mallory takes Ada's ciphertext verbatim and re-signs it under
her own key. Cat refuses it — and the assertion is on the *reason*, not on the refusal, because an
earlier draft refused the forgery with "epoch too old" (Cat was a whole epoch behind, from a bug
elsewhere in this file) and a bare "she refused it" passed happily while proving nothing about the
binding the act is named after.

The control is the one that matters: **the honest copy still opens afterwards.** A binding failure
MUST discard the ratchet step that detected it. Commit it and Mallory has a denial of service —
republish every message a moment before its author and the channel goes permanently dark, one
unopenable event at a time.

### Mutation check

Five mutations in `packages/sdk` and `packages/protocol`, each caught by exactly the act that
claims the thing: the envelope cache never hitting (act 3), a refused forgery spending the
generation (act 5's control), the commit never being published (act 1), the authorship binding
removed (act 5), and `applyCommit` returning true without applying (act 4).

## What `live` adds

```sh
cd apps/relay && QUORUM_EVENTS_BURST=400 QUORUM_FILTERS_BURST=400 \
  QUORUM_CHECKPOINT_EVERY=5 QUORUM_CHECKPOINT_LAG=10 \
  QUORUM_CLOCK_SKEW_SECONDS=10 make run
pnpm --filter @quorum/mls-channel live
```

The three checkpoint variables move together or the relay refuses to boot — the lag must be at
least the skew — and are shortened only so act 4 does not wait for the default window.
`QUORUM_OWNER_PUBKEYS` is left unset, which means anyone may create a workspace; every key here is
minted at startup.

Same rule as `sealed-channel`: every act is a **pair**, the same operation in a plaintext group and
in an `mls` one, against one relay in one run. A claim about what a relay stops doing is worth
nothing without the same relay still doing it.

1. **It refuses a leak it could never have read.** Plaintext into the `mls` channel, refused; and
   `enc=mls` on a plaintext channel, refused too, because `enc` being set is what skips body
   validation and one tag is otherwise a bypass of the whole schema. Plus the rule this script
   found missing: an `mls` policy that states an `epoch` is refused, and a sealed kind 9 at
   **epoch 0** is accepted — the first message of every MLS group is at zero, and a single epoch
   floor of 1 rejected all of them.
2. **The three checks a delivery service can make without reading anything.** A KeyPackage in the
   wrong `d` slot, a Welcome addressed to two members, and a second commit for an epoch the channel
   already has — each refused in the relay's own words, each with its correct-version control in
   the same run. RFC 9420 asks a delivery service to store, route and order; these are those three
   jobs done from the envelope and one JSON field left in the clear on purpose.
3. **The projection stops.** The identical `set_status` op folds into a signed 38101 in the
   plaintext group and produces nothing in the `mls` one. This is the same subtraction `nip44`
   made by a different route: there an admin *can* hand the relay an epoch key and turn the fold
   back on, and choosing not to is a policy. Here the material is deleted as it is used, so the
   relay-side fold is not switched off — it is unimplementable.
4. **Checkpoints do not stop.** The relay signs a checkpoint covering the MLS ciphertext and it
   verifies as `agrees`. The commitment is over event **ids**, and an id is a hash of bytes the
   relay never has to understand. M7 specified the merkle tree over ids rather than over content,
   and this is the second milestone to collect on it.
5. **Two membership lists, disagreeing in both directions at once.** Bob is on the relay's NIP-29
   list and never joined the ratchet; Cat is in the ratchet and is then removed from the relay's
   list. Bob can publish nothing anybody could read — and is caught at the door only because the
   `enc` policy refuses his plaintext, which is the kinder failure and only by accident. Cat can
   publish nothing at all, and **still reads every word said after her removal**, from a copy of
   the event obtained anywhere.

   That last one is the tension this milestone could not dissolve. Option A says every Quorum event
   is valid on any generic relay, so removing a member is **two acts**: the relay removal, and an
   MLS Remove commit. `MlsCrypto` has `create`, `add`, `applyCommit` and `join` — and no `remove`.
   It is stated as a gap rather than demonstrated.

   The two lists are not a design failure waiting to be unified. "Who may publish here" is a
   relay's question and has to be answerable over ciphertext; "who can read this" is the ratchet's
   and no relay can know it. `quorum mls members` prints both side by side for exactly that reason.

### Mutation check

Removing the four `policy.*` registrations for the `mls` arm from `apps/relay/main.go`
(`RequireKeyPackageSlot`, `RequireOneWelcomeRecipient`, `RejectMlsPolicyEpoch`,
`SerialiseCommits`) fails 6 `live.ts` assertions — the four refusals, plus the honest-Welcome
control and Cat's read, which cascade because without the Welcome rule she never joins — and
leaves every plaintext control green.

`RejectMlsPolicyEpoch` exists *because* of this script. The "an `mls` policy states no epoch" rule
is cross-field — `epoch` is legal on a `nip44` policy and mandatory there — and `z.toJSONSchema()`
cannot express the dependency, so it lived in `crossFieldIssues()` in TypeScript and was invisible
to the committed schemas the Go relay validates from. Act 1 published one and watched it stored:
an event every TypeScript client in the repo refuses to parse, which is worse than either extreme,
because an admin can brick a channel with a policy the relay accepts and no client will read.

## Two defects worth knowing about

**An author could not read their own message.** `createApplicationMessage` advances the sender's
own ratchet past the generation it just used, so `processPrivateMessage` on the result answers
`Desired gen in the past`. Every other member reads it; the author is the one member for whom it
is already gone, and no key exists that anyone could hand over. The fix writes the plaintext into
`SealedEnvelopes` in the same awaited write as the envelope, keyed by the id of the **sealed**
event and scoped by `h` tag. Pinned by a test against raw `ts-mls`, so the claim is about MLS
rather than about this repo.

**MLS state is single-writer.** Two `MlsCrypto` objects over one store each advance a generation
the other does not know about, and the loser's messages are unopenable by everybody. This bit
`demo.ts` itself: `restart()` replaced the reader and left the `Publisher` holding the stale
writer, and three assertions in acts 4 and 5 failed against a member who was perfectly up to date.
The ratchet now lives behind one level of indirection so a restart replaces the writer everywhere.

It is also why **the browser refuses to be an MLS member.** `publishKeyPackage` writes kind 30443
with `d: group`, so there is exactly one KeyPackage slot per (pubkey, channel): a tab and a console
held by the same human cannot both be in the ratchet, and two clients over one store *lose*
messages permanently. The real fix is M4's third identity — a runtime instance as a subkey or a
NIP-46 session — and it is not a web-surface change.

## Where the code is

The envelope bindings are `packages/protocol/src/mls.ts`, which has **no `ts-mls` dependency and
is not going to get one**: MLS is stateful, so sealing cannot be a pure function of an event the
way `sealEvent` is. What lives there is the part a second implementation must agree with to
interoperate. The KeyPackage tag contract is `src/mls-keys.ts`.

`packages/sdk/src/mls.ts` is the only file in the repo that imports an MLS library. `MlsCrypto` is
a `ChannelSealer` and deliberately *not* a subclass of `ChannelCrypto`: `nip44` holds a map of
epoch keys that opens any message any number of times, this holds one evolving state that opens
each message once, and one interface over both is how a caller replays a decryption and loses a
message. Key establishment is `src/mls-keys.ts`; the durable half is `src/archive.ts`.

The relay's entire `mls` arm is `apps/relay/internal/policy/mls.go` — four refusals and a number,
and no MLS code. The console is `apps/console/src/commands/mls.ts`; the browser's refusal is
`apps/web/src/components/Encryption.tsx`.
