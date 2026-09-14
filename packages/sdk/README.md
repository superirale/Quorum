# @quorum/sdk

Write an agent. The SDK is the answer to "what do I need to run one" being *node and a key* —
no framework, no runtime to deploy into, and nothing here that runs a language model. An agent
is a process holding a keypair, and this package is the part between that key and a relay.

```ts
import { Kinds } from '@quorum/protocol'
import { FileStore, LocalSigner, createAgent } from '@quorum/sdk'

const agent = createAgent({
  relay: 'ws://localhost:3334',
  signer: LocalSigner.fromEnv('QUORUM_AGENT_KEY'),
  group: 'payments',
  store: FileStore.in('./state'),
  kinds: [Kinds.ChatMessage, Kinds.Thread, Kinds.Comment],
})

agent.on(async (event, ctx) => {
  const lease = await ctx.lease('reply')   // one replica answers
  if (!lease.held) return
  await ctx.say(`you said: ${event.content}`)
})

await agent.start()
```

`examples/echo-agent` is that program, complete, with the reasoning in comments.

## Five things to know before writing the handler

**`on()` only ever fires for events addressed to you.** Addressing is a `to`-marked `p` tag —
`["p", "<pubkey>", "", "to"]` — and nothing else. Not your name in the text, not a bare mention,
not a `mention`-marked `p`. "Should I answer this?" is not a judgement the handler has to make,
which is the whole point: the M0 spike inferred it from prose and shipped a bot that answered
every message containing the word "deploy". `onAny()` gives you the firehose if you insist, and
is deliberately less comfortable to use.

**The handler is replayed, not resumed.** After a crash the next process runs your handler again
*from the top* for any event that was in flight. There is no "continue from line 40" — that
would require a durable call stack, and pretending to have one is how agents half-deploy things.
So every side effect goes through `ctx.once(label, effect)` or `ctx.publish()`, which is
`once()` with the publish already wired.

**`once()` is genuinely exactly-once for publishes, and honestly at-least-once for everything
else.** It writes a reservation containing a timestamp *before* running the effect, and hands
that timestamp back on every attempt. A retry therefore rebuilds a byte-identical event, whose
id the relay already holds, and the relay drops it. An HTTP POST to something outside Nostr
cannot be made idempotent from here — but the reservation still records that an attempt was in
flight, which is what you need to decide whether to retry it. Label effects by *what they are*
(`deploy:staging`), never by *which step they are* (`step:3`): insert a branch above a numbered
label and every key below it shifts, so a replay matches the wrong record and returns the wrong
cached value.

**Anything consequential goes through `ctx.act()`.** It publishes a signed `proposed`, asks the
approvers by digest, waits — across restarts, because the wait outlives the process — and only
then calls your effect. The effect receives the **approved** input as its first argument, which
may not be the input you proposed: if a human edited the payload before saying yes, that is the
edit. Using the parameter rather than the value you closed over is the difference between running
what was agreed and running what was asked for.

```ts
const result = await ctx.act({
  name: 'deploy',
  summary: 'deploy api 1.4.2 to production on 3 replicas',
  input: { service: 'api', version: '1.4.2', env: 'production', replicas: 3 },
  approvers: [ada],
  risk: 'high',
  run: async (approved) => deploy(approved),   // `approved`, not `input`
})
```

The agent having verified the approval is not what makes the deploy safe — the agent is the party
with an interest in the answer. The resource re-derives it: see `examples/deploy-agent`.

**Two things can stop an action without your handler being consulted.** `act()` checks the
thread's budget *before* it proposes anything, and returns `{status: 'cancelled'}` with no
`actionId` if the ceiling is spent — nothing is published, which is deliberate: a rejected
publish raises, a raise is replayed, and a replay against a relay that will refuse it every time
is a budget stop turned into a retry loop. And any member may publish a kind 28101 while your
effect is running, which aborts the `AbortSignal` it was handed and closes the chain
`cancelled`. So **check `result.status`** rather than assuming success, and pass `run.signal`
into anything that takes one.

Report what the work cost by assigning `run.cost`, and assign it on the way *in* rather than at
the end:

```ts
run: async (approved, run) => {
  run.cost = { tokens_in: 9000, tokens_out: 3000 }
  return read(approved.page, run.signal)   // pass the signal on
}
```

Set it on the way out and an interrupted action reports nothing, which makes Stop a way to get
work for free. The SDK turns `run.cost` into an `add_spend` op named after the action — that
name is why a thread which ran out of money can be read to find out which part of it was
expensive. `examples/runaway-agent` is the whole of this, demonstrated.

## What is in here

| | |
| --- | --- |
| `signer.ts` | `LocalSigner` (hex or `nsec`, from env), `Nip07Signer` (browser extension). `Nip46Signer` talks to a remote bunker over NIP-46, so the user's key never reaches the process. The secret is a `#private` field and every stringification of it redacts. |
| `client.ts` | One relay connection: publish with a real OK/reject result, subscribe, NIP-42 AUTH on demand, reconnect with re-subscription. |
| `addressing.ts` | `isForMe`, and the four filters — channel, addressed, thread, control. `assertScopedFilter` refuses a filter that would be rejected or would leak. |
| `agent.ts` | The loop: subscribe, queue, dispatch, replay, shut down without losing in-flight work. |
| `once.ts` | The effect ledger, described above. `incompleteEffects()` tells an operator what was half-done at the last crash. |
| `store.ts` | `MemoryStore`, `FileStore`, `namespaced()`. Local on purpose: a relay-hosted dedup ledger costs a round trip per effect, and on Nostr you cannot unpublish the ops log you did not mean to publish. |
| `counter.ts` | The per-author `counter` tag: monotonic, durable across restarts, so readers can detect that they missed something from you. |
| `replay.ts` | The cursor — event ids in flight, counter watermarks, gap detection. Not a `seq` high-water mark; Nostr has no total order to have one against. |
| `lease.ts` | Single-holder claims on a thread, so N replicas of one key produce one answer. |
| `publish.ts` | Build → sign → publish. Tag assembly stays in `@quorum/protocol`. |
| `approval.ts` | `ctx.act()` — propose, ask, wait, run — plus `approvalResponse()` for the human's side and `tallyApprovals()`, which decides which responses count. The digests are computed here and never accepted from a caller. |
| `grants.ts` | Issue, revoke and fetch 38102s, and `authorize()`: may this pubkey do this, offline, from signed events alone. `effectiveAddressable()` is the replacement rule, and is not `latestAddressable()`. |
| `delegation.ts` | `intersect()` — the whole on-behalf-of idea in one function. The property worth asserting is not that it returns the right answer for a given pair, but that its output is never wider than either input. |
| `audit.ts` | `verifyActionChain()`: hand it a pile of events and it tells you who approved what and whether the log is self-consistent. No relay, no server, no trust in whoever handed them over. |
| `threads.ts` | The task list. `threadOp()` asks for a state change; `threads()` reads the answer and replays the ops the relay says it folded rather than believing the 38101 it signed. |
| `presence.ts` | `PresenceReporter` beats kind 28103 while an agent runs; `presence()` reads the beats. Ephemeral, so an empty result means "nobody has said", never "nobody is running". |
| `context.ts` | `packContext()` — the `extractive-v1` compactor, deterministic to the byte; `fetchContext()` asks a DVM for the same thing; `renderContext()` turns a pack into a prompt and fences what is not ours. `ctx.context()` picks between the two and the caller cannot tell which answered. |
| `checkpoints.ts` | The reader's half of ordering integrity. `verifyWindow()` recomputes a relay's signed root from the events it served; `withholdingProof()` turns "short" into an artifact a stranger can check with `verifyWithholdingProof()`, no relay and no network. `checkChain()` walks the windows. |
| `interrupt.ts` | Stop. `interrupt()` builds the kind 28101 a human's client publishes; `Interrupts` arms an `AbortSignal` per running action and aborts it when one arrives. `InterruptedError` is how an effect that catches broadly tells "somebody stopped me" from "it broke". Ephemeral, so there is no receipt — see below. |
| `channel.ts` | Encrypted channels. `ChannelCrypto` holds whichever epochs this key has been handed and seals or opens on the way past `Publisher`; `rotateChannelKey()` mints an epoch, wraps it for each member and publishes the policy **last**; `channelPolicy()` reads what a channel says it is. `opener()` is the one `OpenSealed` implementation every verifier takes. |
| `memory.ts` | Kind 38104, scoped by `d`. Published rather than filed away, so "why did it answer that" is a query any member can run instead of a request for shell access to the agent's host. |
| `archive.ts` | What forward secrecy forces a client to keep. `Archive` holds every event of a channel plus the plaintext this client read out of it, because on `mls` the relay's copy becomes unreadable and the relay is only the transport; `SealedEnvelopes` caches a sealed event before it is published, because a ratchet cannot produce byte-identical retries and `once()` rests on it. Both are plaintext on disk, deliberately — see below. |
| `mls.ts` | The ratchet: `ts-mls` driven from behind the `mls` envelope, and the only file in the repo that imports an MLS library. `MlsCrypto` is a `ChannelSealer` like `ChannelCrypto` and shares nothing else with it — it holds one evolving state that opens each message *once*, rather than a map of epoch keys that opens anything any number of times. `mlsKeyPackage()` puts the Nostr pubkey in the credential; `create`/`add`/`join` are the ratchet half of membership. |
| `mls-keys.ts` | The Nostr half of membership, in three kinds. `publishKeyPackage()` puts a KeyPackage in the addressable slot named for the channel; `fetchKeyPackages()` reads them back and refuses the six ways one can lie; `inviteToMls()` broadcasts the commit as a kind 8112, advances the ratchet and then publishes one kind 8111 per invitee; `acceptMlsInvite()` opens the one that is theirs; `catchUpMls()` applies the commits this member missed. Nothing here holds a secret the ratchet does not. |

## Design notes that cost something to learn

**A relay filter is a coarse prefilter, not the answer.** `{"#p": [me]}` matches every `p` tag,
including bare mentions and NIP-22 parent-author tags, because relays index only a tag's first
value and cannot see the `to` marker in position 4. So the filter is a superset by construction
and `isForMe` decides locally. A test asserts exactly that: an event the filter matches and
`isForMe` rejects.

**The counter is reserved under its own `once()` key.** `ctx.say()` nests `<label>/counter`
inside `<label>` so a retry reuses the number it already spent. Allocate a fresh counter on the
retry and the rebuilt event has different bytes, a different id, and the relay stores a second
copy of a message the agent already sent — the exact thing the reservation exists to prevent.
`examples/echo-agent/src/demo.ts` stages that failure on purpose.

**An action chain is ordered by its parent links, never by `created_at`.** The loop completes
inside one second and `created_at` has one-second resolution, so NIP-01's `(created_at, id)`
order falls through to a hash tiebreak and shuffles the transitions — `verifyActionChain` used
to reject honest chains about half the time. Millisecond resolution would not have fixed it:
`created_at` is a client-supplied wall clock, and the ordering that decides whether an execution
was legal must not be a field the executing party picks.

**A stranger's event can never make a chain invalid.** Only the proposer's transitions count and
only the proposer's `approval_request` names the approvers — but anyone else's are warnings, not
errors. Counting them would let any member forge an outcome; erroring on them would let any
member veto any action forever with one junk event, and every event here is valid on a generic
relay that will happily store it. A chain is invalid only when the party doing the work did
something illegitimate, which is the rule `tallyApprovals` already applied to responses from
people nobody asked.

**`close()` is final.** A closed `RelayClient` throws from `connect()` rather than quietly
reopening. It used to reset the flag, and the effect was that `close()` did not reliably stop
anything: a handler awaiting a human reaches `query()` or `subscribe()` some milliseconds after
shutdown, the socket comes back up under a stopped agent, and the agent acts on an approval —
the exact event its replacement is about to replay and perform again. Construct a new client to
reconnect.

**A heartbeat is read in arrival order and an action chain is not.** `presence()` settles two
beats sharing a second on which arrived first, the opposite of everything else here, because an
agent that finishes a job inside one second publishes `busy` and then `online` with the same
`created_at` and the lowest-id tiebreak would strand it on the wrong badge. A projection is
folded from stored history nobody can replay identically; a heartbeat is only ever read as the
live stream the reader is watching. Nothing is ever authorised on one, which is the only reason
that trade is available.

**The pack's ordering has one exception and it is the root.** Everything else is oldest-first
within the admitted set; the kind 11 comes first regardless, and it is mandatory-keep rather
than merely old. A packer that treated the oldest message as the least important one would drop
the only statement of what the thread is *for* — which in a five-hundred-message thread is
usually also the only place the answer is written down.

**Provenance is derived from the event set and nothing else.** A kind 38103 manifest is the only
evidence that a pubkey belongs to an agent, so an agent that never publishes one is labelled
`human`/`member`, `renderContext` stops fencing its output, and its words reach the next model
looking like a colleague's. No error, no warning. That is why `Agent.publish` exists at all —
see below — and `examples/claude-agent/src/demo.ts` stages the failure on purpose.

**`Agent.publish` exists so that nothing else needs a second `Publisher`.** An agent has things
to say outside a handler: its manifest, a shift report, a note that it is going down. Building a
`Publisher` over the same key for those allocates `counter` from a second copy of the ledger —
`Counters` caches its last value in memory as well as in the `Store`, so the two diverge on the
first write. A gap in a sequence says the agent crashed; a duplicate says the key is in two
places at once, which is a much more alarming thing to make somebody investigate.

**A short window is not an accusation, and the two are different functions for that reason.**
`verifyWindow` recomputing a smaller root than the relay signed is exactly what a client that
backfilled half the window sees, so it names nobody. `withholdingProof` is the one that accuses,
and it can only be built by someone holding an event the relay committed to and did not serve:
`root(served ∪ held) == committed root` has no innocent reading. Both are needed — a mechanism
that cries withholding at an honest relay is worse than no mechanism, because the first false
accusation is the last time anybody reads the output.

**The withheld events are verified too, and it is the step easiest to skip.** Without it anyone
can invent an event, claim the relay was hiding it, and produce a failure that reads as an
accusation gone wrong rather than as a fabrication. `verifyWithholdingProof` redoes every step
from the bytes: the checkpoint's signature, each withheld event's signature, that each falls
inside the committed window and group, that none was in the served set after all, and that the
two sets together reproduce the signed root.

**Only regular kinds are committed to** (`isCommittedKind`), and this is a protocol rule the
relay applies identically. A superseded addressable event's id is gone from the store, so
committing to a 38101 would make the relay fail its own checkpoint the first time a task changed
status. The three copies of the rule — here, in the Go relay, in the test-kit — are the kind of
duplication that drifts silently, so `examples/auditor live` checks it against the real relay
rather than against another copy of the same list.

**Verify against the sealed bytes, then open.** A signature is over the bytes as published, and
on an encrypted channel those are the ciphertext — so a verifier that decrypts first is checking
an event that was never published. This sounds pedantic and is not: the whole approval loop was
broken on a `nip44` channel and the audit was broken twice over, all from the same mistake, and
one rule fixes all three. It is expressed as a single hook, `OpenSealed`, with one implementation
— `ChannelCrypto.opener()` — rather than as a rule three call sites are trusted to remember.

**`open` is a required dependency of `tallyApprovals` and `ctx.act()`, not an option with a
default.** The failure without it is not a worse answer, it is the opposite one: a keyless tally
rejects every honest approval, so the agent waits forever on consent it is already holding, and
an action that can never be approved is indistinguishable from a human who has not replied. The
digest lives in the sealed body rather than in a tag, so there is nothing to check against
without a key.

**`opened()` keeps the `enc` tag**, so `isSealed` is still true on an opened event. That is
deliberate — the event's identity is the sealed one, and an opened copy carrying plaintext
`content` under the sealed event's id would look signed and would not be. Ask `unreadable()`
whether this key can open something, not `isSealed`.

**An agent that reads its channel policy only at startup defeats every rotation that happens
while it runs.** `ChannelCrypto` re-reads on the events it sees, which is why the 38107 and the
8110 wraps are unsealed: the key-management traffic has to be legible to a member who does not
yet hold the current key.

**Presence is sealed like everything else, so an agent holding no epoch key cannot report that
it is alive.** `PresenceReporter` takes a `Logger` for that reason. It used to say so on
`console.warn` regardless of the logger the agent was given, which made every encrypted test a
wall of warnings — and on an encrypted channel the failure is routine rather than exceptional.

**The archive is plaintext on disk, and that gives back exactly what MLS bought.** Forward
secrecy says a key compromised today does not open yesterday's traffic; `Archive` says
yesterday's traffic is in a file next to the key. There is no clever resolution — sealing the
archive under a local key stores the key beside it, and the cleverness would only hide where the
plaintext is. So it is a workspace's choice, `prune()` is the mechanism, and the default is to
keep: an approval nobody can produce in six months is what pillar two exists to prevent.

**Re-recording an event you can no longer read must not erase the plaintext you already have.**
This is how a client destroys its own archive under `mls`, and it needs no bug to happen: the
agent restarts, backfills the channel, re-sees every event it archived last month, cannot open
any of them because the epochs are gone, and writes each one back. One ordinary reconnect, and
the only readable copy of six weeks of decisions is overwritten by the blob it was made from.
`Archive.record()` is a method rather than a `store.set` for that one reason.

**An archive that held only what it could read would be a complete-looking lie.** Unreadable
events are recorded too, with no plaintext, so `unreadable()` can answer "the thread has ten
events and I can read seven". `opened()` drops the rest and reports how many — handing them back
sealed would put base64 in front of a model as the conversation, which is the M9 keyless-packer
failure in a new place.

**Under `mls`, authorship travels in the MLS `authenticated_data`, not in the credential.** The
spec's second binding says the MLS credential identity and the event `pubkey` are one author, and
`ts-mls` will not tell us the credential — `processPrivateMessage` verifies the sender's signature
and hands back `{ message, newState }` with no sender in it, because RFC 9420 encrypts the sender
index on purpose. So an `mls` application message carries the sender's pubkey as its
`authenticated_data`. It is not the weaker check: it is covered by the AEAD *and* by the sender's
FramedContent signature, so altering it does not produce a message attributed to somebody else, it
produces one that does not decrypt at all. It costs nothing on the wire, because the event's own
`pubkey` field already publishes it. The credential check does not disappear — it moves to the
moment a KeyPackage is added to the tree, which is where a credential is legible.

**A binding failure must discard the ratchet step that detected it, and that one line is the
difference between rejecting a forgery and handing Mallory the channel.** Mallory lifts Ada's
MLSMessage off the wire and republishes it under her own signature; the ratchet opens it happily,
because it *is* Ada's ciphertext, and the `authenticated_data` check then refuses it. Commit that
step and the generation is spent, so Ada's honest event can never be opened by anyone — republish
every message a moment before its author does and the channel goes permanently dark, one event at
a time. `ts-mls` is functional, so throwing away `newState` really does leave the old state able
to open the honest copy, and there is a test that does exactly that.

**Persist the ratchet state before caching the envelope, never the other way round.** A crash in
the gap between the two writes leaves a consumed generation with no cached envelope, the retry
seals again, and the channel gets the same sentence twice under one `counter` — which is
*detectable*, and the counter rule already says what it means. Envelope first would leave the
persisted state a generation behind, so the agent's next message would reuse a generation every
receiver has already spent and be silently dropped by all of them. A duplicate somebody can see
beats a message nobody gets.

**`MlsCrypto.opener()` reads the record and never the ratchet, and that narrowness is the
design.** Every verifier in the SDK — `tallyApprovals`, `verifyActionChain`, the packer, three
console commands — takes a synchronous `(event) => NostrEvent | undefined`. Making them all async
would not fix anything and would make things worse: a verifier walking a forty-event chain would
then be *decrypting* it, and decrypting one event twice throws. So the opener answers only from
what `open()` recorded on arrival and what `warm()` loaded at start. The consequence is worth
stating rather than discovering: on an `mls` channel, an event this client never saw arrive and
never archived is not readable by it, ever. That is not a limitation of the function; it is what
forward secrecy means, and it is equally true of the relay's copy.

**Exporting the driver from the SDK root costs the browser nothing until something imports it.**
`ts-mls` pulls in `@hpke/core`, and `index.ts` re-exports `mls.ts` unconditionally — but
`pnpm --filter @quorum/web build` emits a byte-identical bundle with the export removed, because
nothing in `apps/web` reaches it yet. Worth re-checking when the web surface does: this is the
kind of property that stops being true quietly.

**A KeyPackage advertises capabilities it cannot name, and `ts-mls` says so in decimal.**
`defaultCapabilities()` appends GREASE values to `ciphersuites` — RFC 9420 §13.2's exercise of
unallocated code points, so a receiver that refuses an unknown one is caught early — as decimal
*strings*, though the field is typed `CiphersuiteName[]`. Looking one up in the registry gives
`undefined`, the id-list writer correctly refuses it, and the effect was that publishing a
KeyPackage failed roughly four times in five with a message about 16-bit ids and nothing pointing
at GREASE. `suiteId()` passes them through rather than dropping them, because being advertised at
somebody else's reader is the entire point of the exercise. Found by executing code that had
typechecked for a day.

**An MLS commit has to be broadcast, and for four milestones' worth of tests it did not have to
be.** `add()` created the commit, kept the resulting state and dropped the message — which every
test agreed with, because a two-member group is added to by its only other member, who applies
the commit by producing it. The second person added to any channel silently locked the first one
out, and the error was `CryptoError: OperationError` from HPKE four frames inside `ts-mls`, naming
no epoch, no group and no member. Kind 8112 is the transport; `catchUpMls()` applies what a member
missed. The test that matters is the three-member one, and the control beside it — a member who
does not catch up — is what stops it passing against an `applyCommit` that does nothing.

**The commit is published before the ratchet advances, which is the reverse of every other write
in `mls.ts`.** An application message's validity is decided by its sender, so state-first is right
there: a crash costs a visible duplicate rather than a silently-dropped message. A *commit's*
validity is decided by everyone else — two members can commit from the same epoch and only one can
win — so advancing first would let a committer whose event is refused remove itself from its own
channel with nothing saying so. Publishing first costs nothing, because `ts-mls` is functional and
`result.newState` is simply dropped.

**The epoch is in the clear in the 8112 body, and that is what keeps MLS out of the relay.** The
relay has to serialise commits — at most one per group per epoch — and reading the epoch out of
the MLSMessage would mean an MLS wire parser in Go. A JSON body with a number in it does the same
job. This was decided while part-way through writing that parser.

**Only ciphersuite 1 can be constructed in this repo, which shapes one test rather than the
code.** `getCiphersuiteImpl` for the P256 suites fails with `CodecError: Length too large to
encode`, and the CHACHA20POLY1305 suites need `@hpke/chacha20poly1305`, an optional dependency
that is not installed. So "refuses a ciphersuite this workspace does not speak" cannot generate a
real foreign package; it forges the `cipherSuite` field on a genuine one, and says so in the test.

## Tests

```sh
pnpm --filter @quorum/sdk test        # 418 tests
```

They run against `@quorum/test-kit`'s in-process relay: no Docker, no ports, no sleeps. Two of
them use `injectRaw` to have the relay send a forged event and an unmatched one, because
"the SDK verifies what the relay hands it" is not provable through the honest path.

The fake relay is permissive by design and cannot tell you whether the real one would accept
what the SDK builds. `pnpm --filter @quorum/echo-agent live` answers that, against the Go relay
in `apps/relay`.
