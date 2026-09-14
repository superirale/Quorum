# sealed-channel

A channel the relay cannot read — and an honest account of what that costs.

```sh
pnpm --filter @quorum/sealed-channel demo   # five acts, no relay and no network
pnpm --filter @quorum/sealed-channel live   # the subtractions, against the Go relay
```

Every milestone before this one added something. This one mostly **takes away**, and a demo that
only showed the encryption working would be advertising rather than documenting. So acts 3 and 4
are the load-bearing half: a stranger can no longer audit a consent chain, the relay stops
projecting tasks, stops packing context and stops enforcing approvals, and a removed member can
still read every word said before they left.

None of that is a defect queued for a later milestone. It is what encrypting a channel means.
The number of systems that ship end-to-end encryption without saying so is the reason it is two
whole acts here rather than a footnote.

## The mode

`nip44` is a **shared channel key with epochs**, not per-recipient fan-out. One symmetric key per
epoch; each member gets it in a kind 8110 wrap, encrypted pairwise to them; a kind 38107 channel
policy names the current epoch. A message is sealed once, whoever is listening.

Fan-out — sealing each message separately to each member — was the alternative, and it costs a
copy of every message per member and makes adding a member a rewrite of the future rather than a
single event. Its one advantage, that removing someone needs no re-key, is not an advantage:
rotation is one event either way and neither can un-give bytes somebody already holds.

**The nonce is derived, not random:** `hmac_sha256(channel key, id of the event in the clear)`.
That is a requirement rather than a preference. `once()`'s idempotency rests on a retry rebuilding
byte-identical events, and a random nonce makes the retry a *second* message in the channel. It is
a MAC rather than a plain hash so that an observer holding no key cannot confirm a guess at a
low-entropy message by recomputing its nonce.

## What the demo shows

**1. The channel goes dark.** The same author says one sentence before the rotation and one
after. The first is stored as the sentence; the second is NIP-44 v2 payload the relay cannot
distinguish from noise. Both members open the second one with a key that never crossed this relay,
and it still verifies — the signature is over the ciphertext, as published.

Rotation **publishes the wraps first and the policy last**, and the order is the whole of it. The
policy is what tells every writer to start sealing; publish it first and everyone encrypts to an
epoch that has not reached anybody yet. The other order costs a few hundred milliseconds of stale
readable access, which is the much shorter outage.

Then the half worth reading twice: **the bodies are gone and the graph is not.** Kind, `h`,
`enc`, `epoch`, `counter` and every `p`, `e` and `E` tag stay in the clear, because that is what
routing and rate-limiting are made of. An observer still learns who talks to whom, how often, and
about how many things. `nip44` hides payloads, not the social graph — if the graph is what you
needed to hide, M10 is the mode you want.

**2. The loop, sealed.** propose → ask → approve → run, with every body ciphertext, and the agent
handed the epoch key by an admin exactly as a human is. An agent is a member, not an integration.

Two things fall out of it. The approval request's `alt` tag is deliberately generic: NIP-31
requires a readable fallback on every Quorum kind, so a sealed event must not describe itself in
one, or the `alt` publishes in the clear the very sentence the body was hidden to protect. And
**the digest travels in the sealed body, not in a tag** — `approvalResponse` reads `input_digest`
out of the request body, so a client handed the ciphertext would sign consent to nothing.

The control is the bug this milestone was mostly about. A keyless `tallyApprovals` over the same
two events does not return a *worse* answer, it returns the opposite one, silently: every honest
approval is rejected, and an action that can never be approved looks exactly like a human who has
not answered yet. Hence one rule, applied everywhere — **verify the signature against the sealed
bytes, then open for the body** — expressed as a single `OpenSealed` hook with one implementation,
`ChannelCrypto.opener()`.

**3. The auditor needs a key, and says so.** A stranger still finds the chain, because the tags
are in the clear, and reports `sealed` — never `bad_signature`, which is the control: a sealed
chain must not look like a forged one. It also reports `no_proposal`, and that is the honest
answer rather than a gap: a proposal carries no `action` tag because its own id *is* the action
id, so a keyless reader cannot locate the anchor of the chain it can see.

The same events through the same function with one key give the whole verdict, clean.

M4 sold consent that anyone could check against no server at all. On a `nip44` channel "anyone"
now means "anyone holding an epoch key". That is a real subtraction from the pitch, which is why
the auditor names it instead of quietly failing the chain.

**4. The subtraction.** Which kinds stay in the clear, and why each one does.

`UNSEALED_KINDS` is written as **exceptions**, so a kind invented in a later milestone is sealed
by default. Get that polarity backwards and a new event type is quietly published in plaintext
into channels that believe they are private. There are four reasons on the list and no others:

- **Key management** (8110 wraps, 38107 policy). A channel key wrapped under the channel key is a
  locked box containing its own key, and the policy has to be readable by somebody who cannot yet
  decrypt anything. The 8110 *body* is still private — it is wrapped pairwise to one recipient,
  which is a different key from the channel's.
- **Authorization** (38102 grants, 38106 delegations, 22242 NIP-42 auth). Two of these the relay
  enforces itself — `group:join` and `thread:budget` — so
  sealing them disarms membership control on exactly the channels that care most. The deeper
  reason: a capability nobody can audit is not a capability. "Who may deploy to production" must
  still have an answer for an owner.
- **Relay-authored records** (8108 checkpoints, 38101 projections, and 7000 job feedback from
  anyone to anyone). The relay signs these and cannot encrypt to a key it does not hold. On an
  encrypted channel the 38101 simply stops existing; the checkpoints keep working untouched.
- **NIP-29 moderation** (9000–9030, 39000–39999). Addressed to the relay by definition.

Both lists are published into `packages/protocol/schemas/index.json` and the Go relay enforces
them from there rather than from a second copy in Go. This table decides what a relay refuses on
an encrypted channel, so a copy that had drifted by one kind would either leak that kind in
plaintext or refuse honest traffic — and neither surfaces as an error anywhere.

This act also contains the one claim the demo **refuses** to assert. There is no 38101 in the
transcript, and saying so would prove nothing: `FakeRelay` has never projected anything in any
milestone, so the assertion would pass against a relay that folds perfectly well. That claim
belongs in `live.ts`.

**5. Rotation.** Ada removes Bob and rotates. Bob cannot read what is said next, gets a named
epoch rather than a crash, and can still read every word said before he left — forever.

**Rotation does not revoke, it mints.** Nobody can un-give bytes somebody already holds, and the
window between the removal and the rotation is real: until the new policy lands the removed member
is still reading the channel. The mirror problem is joining, which does not hand over history: an
admin decides which past epochs a new member may have, one 8110 each. Handing over all of them is
the useful answer and handing over only the current one is the conservative answer, and no library
should make that call on an admin's behalf.

## What `live` adds

```sh
cd apps/relay && QUORUM_EVENTS_BURST=400 QUORUM_FILTERS_BURST=400 \
  QUORUM_CHECKPOINT_EVERY=5 QUORUM_CHECKPOINT_LAG=10 \
  QUORUM_CLOCK_SKEW_SECONDS=10 make run
pnpm --filter @quorum/sealed-channel live
```

The three checkpoint variables move together or the relay refuses to boot — the lag must be at
least the skew, or an honest late event lands inside a window already signed. They are shortened
only so act 5 does not wait twenty minutes for the default window to close.
`QUORUM_OWNER_PUBKEYS` is deliberately left unset, which means anyone may create a workspace; the
relay warns about it, and Ada's key is minted at startup.

Every act here is a **pair**: the same operation in a plaintext group and in an encrypted one,
against one relay in one run. A claim about what a relay stops doing is worth nothing without the
same relay still doing it, and a second process — or a second run — is a different relay as far
as any reader of the output can tell.

1. **It refuses the leak, both ways round.** A plaintext kind 9 into the sealed channel is
   refused by a relay that cannot read a byte of what it is protecting. So is `enc=nip44` on a
   plaintext channel — and that arm is not symmetry for its own sake: `enc` being set is what
   skips body validation, so without it one tag is a bypass of the entire schema on a channel
   nobody is even encrypting.
2. **It refuses to over-seal.** A kind 38102 grant tagged `enc=nip44` is refused *on the
   encrypted channel*. The unsealed list is enforced in both directions or it is decorative.
3. **The projection stops.** The identical `set_status` op folds into a signed 38101 in the
   plaintext group and produces nothing in the sealed one. The client is not worse off —
   `threads()` folds locally from the same ops, which is why M8 made the two agree field for
   field. What is lost is the relay's *signature* on the result, so `threads()` reports `local`.
4. **The packer stops, out loud.** The DVM answers with a 6600 in the plaintext group and with a
   kind 7000 in the sealed one: *"this channel is encrypted; ask a packer that holds the keys"*.
   The reason travels in the `status` tag rather than in `content`, which is the right place for
   it here and not only by convention — `content` is what a sealed event encrypts, and a refusal
   whose text was sealed would be unreadable by exactly the client that needs it.

   Then the control that explains why refusing is mandatory: `packContext` is a pure function over
   events, so a packer with no key **does not fail**. It returns a well-formed 6600 full of base64
   with nothing in the body saying so, which a model then reads as the conversation.
5. **Checkpoints do not stop.** The relay signs a checkpoint covering the sealed events and it
   verifies as `agrees`. A commitment is over event **ids**, and an id is a hash of bytes the
   relay never has to understand — so layer 3 of the ordering design survives encryption entirely.
   That is not luck: M7 specified the merkle tree over ids rather than over content, and this is
   the milestone that collects on it.

### Mutation check

Commenting out the two `encryption.Require*` registrations in `apps/relay/main.go` fails exactly
6 Go tests in `apps/relay/encryption_test.go` and 3 `live.ts` assertions — and leaves both
plaintext controls green, which is the shape the check should have.

## Where the code is

NIP-44 itself is `packages/protocol/src/nip44.ts`, with the reference vectors in
`fixtures/nip44-v2.json`. Sealing an event, the unsealed-kinds rule and the derived nonce are
`packages/protocol/src/seal.ts`; the key-wrap and channel-policy bodies are
`packages/protocol/src/bodies/encryption.ts`.

`packages/sdk/src/channel.ts` is where a client keeps its epochs: `ChannelCrypto` and
`rotateChannelKey`. The relay's half is `apps/relay/internal/policy/encryption.go`, registered in
`apps/relay/main.go`. The browser reads sealed channels in `apps/web`, which also gained the NIP-46
path this milestone — a remote signer is the real answer to the dev key in `localStorage`, and a
channel key handed to a page holding a plaintext secret was never worth much.
