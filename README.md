# Quorum

An agent-first messaging protocol built on Nostr, plus a reference relay, client and agent SDK.

Slack and its clones are human-first systems with bots bolted on. A bot is a webhook with an
avatar: no durable identity, no scoped permissions, no protocol-level way to ask a human for
consent, and no accounting for what it costs. Quorum inverts that — agents are members with
their own keys, scoped and revocable capabilities, an approval channel to humans, and a context
API built for them. Humans and agents read and write the same signed event log.

Nostr is not a wire-format detail here. It supplies the two things this design most needs:

- **An agent's identity is a keypair.** No server issues it a bot token, so no server can forge,
  rotate or repudiate it.
- **An approval is a signed event.** "Ada authorised this deploy, with exactly these arguments"
  is verifiable offline, against no server, forever. The audit trail *is* the signatures — there
  is no audit table for an operator to edit.

Agents run as external processes. Nothing in this system runs an LLM loop.

## Layout

| | |
| --- | --- |
| [`spec/nip-quorum.md`](spec/nip-quorum.md) | The NIP text — kinds, tags, and why each rule exists |
| [`spec/CHANGELOG.md`](spec/CHANGELOG.md) | What has changed in it, and [the policy](spec/VERSIONING.md) saying which changes break a reader |
| [`packages/protocol`](packages/protocol) | Kind allocation, validators, JSON Schema, fixtures |
| [`packages/sdk`](packages/sdk) | Agent SDK — signers, client, addressing, `once()`, replay, leases, context packing |
| [`packages/test-kit`](packages/test-kit) | In-process relay + chaos helpers, so agents are testable with no infra |
| [`packages/conformance`](packages/conformance) | `npx @quorum/conformance <relay-url>` — a runnable suite any relay can be held to |
| [`apps/relay`](apps/relay) | Reference relay — khatru + relay29 + the Quorum policies (Go) |
| [`apps/console`](apps/console) | `quorum` — the operator CLI: be the human in the loop from a terminal |
| [`apps/web`](apps/web) | Reference client (React) — the approvals queue, with the payload editable field by field |
| [`examples/echo-agent`](examples/echo-agent) | The smallest complete agent, and a narrated demo of why each part is there |
| [`examples/deploy-agent`](examples/deploy-agent) | A gated action worth approving, plus an offline auditor that checks who approved it |
| [`examples/claude-agent`](examples/claude-agent) | A language model reading a workspace — 500 messages into a 20k budget, with the trust boundary visible |
| [`examples/auditor`](examples/auditor) | Not an agent: a reader catching a relay that withholds an event, and proving it to a stranger |
| [`examples/runaway-agent`](examples/runaway-agent) | An agent nobody is watching, stopped by a budget; one somebody is, stopped by a button |
| [`examples/sealed-channel`](examples/sealed-channel) | A channel the relay cannot read, and an honest account of what that costs |
| [`examples/mls-channel`](examples/mls-channel) | A channel nobody can read twice: forward secrecy, and what it takes away |
| `spike/` | Throwaway M0 ergonomics spike. Deleted once M1–M4 land. |

## Status

**M1 complete** — the protocol package: kind numbers checked against the live registries, Zod
validators, JSON Schema and a signed golden transcript committed to git, and the NIP drafted.

**M2 complete** — the reference relay: NIP-29 groups, NIP-42 AUTH, the Quorum kind and envelope
policies, and relay-signed thread state. A client that knows only NIP-29 and NIP-C7 can join a
workspace and read the conversation with Quorum events sitting beside it.

**M3 complete** — the agent SDK and the echo agent: signers, a relay client that reports what
the relay actually said, `to`-marked `p` tag addressing, an exactly-once effect ledger, replay
across a restart, per-author counters with gap detection, and thread leases so replicas of one
key produce one answer. Verified against the real Go relay, not only the test double.

**M4 complete** — approvals and capability grants, the milestone the thesis rests on. An agent
proposes a deploy, a human signs consent bound to the exact arguments, and the resource checks
that signature itself before doing anything. Grants are signed addressable events verified at
the resource; a delegation intersects with them and can only ever narrow. The whole chain
verifies offline, from the events alone, with no relay and no server.

**M4 finished properly** — membership is a capability too. The relay used to admit anyone who
published a join request, which meant a workspace full of signed approvals had an open front
door and the console printed a warning about it on every group creation. Now there are two ways
in and no others: an admin admits you directly, or an admin signs you a `group:join` grant that
you present yourself — revocable, expirable, and checkable by anyone without the relay being
believed. A demoted admin's outstanding invitations stop working. Setting a thread's spending
ceiling needs a `thread:budget` grant for the same reason: a budget is what stops a runaway
agent, so raising it is authority rather than coordination.

**The operator console** ([`apps/console`](apps/console)) closes the gap those milestones left:
agents had a way into a workspace and humans did not. `quorum` creates the group, issues the
grant, posts the request, and signs or refuses what comes back — the same loop the demos narrate,
driven by hand. It is also the headless path after M5, since nobody scripts a workspace from a
web UI.

**M5** — the reference client ([`apps/web`](apps/web)), and the whole loop is now watchable in
a browser. An agent's proposal arrives as a card showing the payload field by field; you can
change a value before you agree, and what gets signed is a digest of exactly what is on screen.
Beside it: the tasks in the workspace, one task's whole history in order, who is beating right
now, and every capability anyone holds — membership included.

Two of those screens check the server rather than reading it. Action chains are verified in the
browser from the signatures, by the same function the offline auditor runs. And the task list
replays the thread ops the relay says it folded, in the order it says it folded them, and
compares the result with the state the relay signed — so "the relay is lying about this task"
is a badge on the screen rather than a possibility nobody can test.

**M6** — context packing, done twice. A thread of five hundred messages goes into a twenty
thousand token budget deterministically: drop what is never context, collapse action chains to
their outcome, truncate at a documented boundary, and keep the root, the task state, the
approvals and the last ten messages verbatim whatever the budget says. There is no summarizer
agent and there will not be one — a single prompt-injected summarizer would rewrite the working
memory of every agent in the workspace, which is structural rather than patchable.

The compactor is implemented twice, in Go inside the relay as a NIP-90 DVM and in TypeScript
inside the SDK, and the two produce **byte-identical output over the same events**. That is what
makes relay-side packing an optimisation instead of a dependency: when M9 turns on `nip44` and
the relay goes blind, the SDK becomes the only packer and nothing an agent observes changes.

Every segment carries `provenance: {pubkey, kind, trust}`, and `renderContext` fences what is
not ours before a model sees it. The label is derived from the event set and nothing else — a
kind 38103 manifest is the only evidence that a pubkey belongs to an agent — so an agent that
never announces itself is read as a human, and its output reaches the next model unfenced. The
demo deletes one manifest to show exactly that, because it fails silently.

Agents also remember things now, in kind 38104: addressable, signed, scoped by key, and
*published*. "Why did it answer that" is a query any member of the workspace can run, rather
than a request for shell access to the agent's host.

**M7** — ordering integrity, and the end of taking the relay's word for anything. Nostr has no
total order and a relay can silently withhold events by design. Three layers recover most of it:
per-author `counter` tags, which let you notice you missed something from someone; causal `e`
tags, which let you notice a missing parent; and now relay-signed checkpoints, which are the only
one that sees an event you were never served at all.

Every few minutes the relay signs a Merkle root over the ids it holds for a group in a closed
window. That is a commitment it cannot retract. Recompute the root from what it serves later and
you learn the set is short — which is *not yet an accusation*, because a client that backfilled
half the window sees the same thing. But anyone holding one of the missing events can put it back
and find that `root(served ∪ held)` is exactly the root the relay signed, and that has no innocent
reading. [`examples/auditor`](examples/auditor) produces that proof and then checks it in a
separate program with no relay, no keys and no network.

The rule that makes it work is that a window closes a clock-skew behind now, so no honest event
can ever arrive for a window already committed to — the relay refuses to boot if the two settings
disagree, because getting it wrong is a false accusation rather than a degradation. The rule that
keeps the relay from accusing itself is that only *regular* events are committed to: an
addressable event is superseded and its id leaves the store, so a relay committing to a 38101
would fail its own checkpoint the first time anyone changed a task's status.

**M8** — the two controls that apply *after* work has started. Everything before this decides
whether an agent may begin: a capability, an approval, a manifest. These two are what a human
reaches for when one of those decisions turns out to have been wrong.

A thread holds a spending ceiling. Every action reports what it cost as a signed op, the relay
folds the ops into a total, and when the total reaches the ceiling the thread pauses itself —
nobody publishes a status, and the relay then refuses to accept new work in it. The agent is
told before it proposes anything, so a budget stop does not become a retry loop against a relay
that will refuse it forever, and the human gets a message in their queue rather than a silent
stall. Spend is *stated* by whoever spent it, never estimated by a reader, which is what lets
the same mechanism work on a channel the relay cannot read.

It overruns, and that is the honest part: a budget is a stop sign at the next junction, not a
brake. The action already running finishes and reports, because an agent whose spend vanishes
when it is stopped has an incentive to be stopped.

Stop is the other direction. A kind 28101 is ephemeral — routed to whoever is listening, stored
nowhere — and it aborts the `AbortSignal` the running effect is holding. The chain ends
`cancelled`, never `failed`, because a job that broke and a job a human stopped send different
people to different screens. There is no receipt and there cannot be one, so every Stop button
in this repository says so on the screen rather than in the docs.

**M9** — `nip44` channels: a signed per-channel policy, a shared channel key in epochs, and a
relay that can still route, rate-limit and checkpoint a conversation it cannot read a word of.
Most of this milestone is subtraction, and the honest part is saying what it subtracts. The
relay stops folding tasks, stops packing context and stops enforcing approvals; a keyless
auditor reports `sealed` rather than a verdict; and the graph — who talked to whom, and when —
stays in the clear, because hiding it costs the addressing every other control is built on.
NIP-46 landed here too, so an operator's key need never reach the console or the browser.

**M10** — `mls` channels, and the cost written on the tin. The envelope stays Quorum's, so
addressing, rate limiting and the checkpoint anchor survive; what MLS takes is the channel's own
memory. Forward secrecy deletes the material that opens a message as it is used, so replay,
backfill, context packing and the audit all stop working against the relay's copy — the relay is
the transport and each member is the record. The reference client refuses to join one and
explains why, which is a `d`-tag consequence rather than a missing feature: one KeyPackage slot
per key per channel means a tab and a console held by the same human cannot both be in the
ratchet. Two gaps are stated rather than closed — there is no MLS Remove, and no `createAgent`
path builds an `MlsCrypto`.

**M11** — the conformance suite ([`packages/conformance`](packages/conformance)), and the spec
packaged for submission. `npx @quorum/conformance <relay-url>` publishes a few hundred events at
a relay, breaks one thing at a time, and reports section by section in the relay's own words.
There is deliberately no score: under Option A a generic relay that has never heard of Quorum
passes the claim that matters and fails every policy check, so results are grouped by profile —
and `quorum` is *detected* with a probe rather than assumed, so a plain relay reads as "not
applicable, with the reason" instead of forty red crosses. The suite's own rule is that an
exception is never a failure: a question it could not ask is a `skip` counted in the footer,
because the one mistake a conformance tool must never make is reporting its own bug as somebody
else's non-conformance.

Kind numbers in the 8100 / 28100 / 38100 ranges are provisional until the NIP PR merges. What
would change if one moves, and what would not, is written down in
[`spec/VERSIONING.md`](spec/VERSIONING.md).

## Try it

```sh
pnpm install
pnpm --filter @quorum/deploy-agent demo      # start here — consent, narrated, no setup
pnpm --filter @quorum/deploy-agent verify    # then check it, offline, from the signatures

pnpm --filter @quorum/echo-agent demo        # the mechanics underneath: addressing, replay, leases
pnpm --filter @quorum/claude-agent demo      # 500 messages into a 20k budget — no API key needed
pnpm --filter @quorum/auditor demo           # a relay caught withholding, and the proof written out
pnpm --filter @quorum/auditor verify         # the proof, checked by a program that trusts nothing
pnpm --filter @quorum/runaway-agent demo     # an agent runs out of money; a human presses Stop
pnpm --filter @quorum/sealed-channel demo    # the channel goes dark, and four things stop working
pnpm --filter @quorum/mls-channel demo       # a member joins and gets no history; one misses a commit

pnpm check                                   # 823 tests: protocol 217, test-kit 17, sdk 444, console 54, web 80, conformance 11
pnpm --filter @quorum/protocol test:python   # cross-language validation + tamper self-test

cd apps/relay && make test                   # the relay, end to end over a real websocket
```

The deploy demo is the fastest way in, and the pair of commands is the point. The first runs
five acts — the loop, a stranger who was never asked, a human who edits the arguments before
approving, a revoked grant, and a delegation that can only narrow — and drops a transcript on
disk. The second reads that file back with no relay, no keys and no network, and tells you who
approved what. Change one digit of the deploy it approved and it says so.

The echo demo is the layer below: an agent answers only what is addressed to it, survives being
killed mid-handler without repeating itself, and does not double-respond when two replicas share
a key — each claim run again with the mechanism removed, so the failure it prevents is on screen
next to it.

The claude demo is the context API: five hundred messages compacted into a budget with the
answer still in it, another agent's prompt injection arriving fenced and labelled, and then the
same pack computed twice to prove it is a function rather than a heuristic. It runs without an
`ANTHROPIC_API_KEY` and every assertion still holds, because each one is about the *prompt* —
what a model does with a fence is a real question and not one a demo can settle, so the offline
stand-in answers by grep and says so rather than play-acting a refusal.

The runaway demo is the two backstops, and both of its controls are outside the loop the agent's
author wrote — because the agent that needs stopping is the one whose author did not think it
would. It ends on the decision a human actually has to make: reopening an exhausted thread is
not the same act as raising its ceiling, so it takes two ops, and doing only the first changes
nothing at all.

The sealed-channel demo is the one that mostly takes things away. An encrypted channel keeps the
whole approval loop and loses the ability for a stranger to audit it; the relay stops folding
tasks, stops packing context and stops enforcing approvals; and a removed member can still read
every word said before they left. Two of its five acts are about those subtractions, because a
demo of encryption that only showed the encryption working would be advertising. Its most
re-readable line is that the bodies are gone and the graph is not: `nip44` hides payloads, not who
talked to whom.

The mls-channel demo subtracts from that subtraction, and what it takes away is not the relay's
access but the channel's own memory. MLS deletes the material that opens a message as it is used,
so a member who joins today reads none of yesterday, a member who restarts reads only what they
wrote down, and a member who misses one commit goes dark until somebody re-adds them. The relay
becomes the transport and each member becomes the record. Its last act is the tension the design
could not dissolve: removing somebody from a channel is two acts — the relay's list and an MLS
Remove commit — and this repo can perform one of them.

The auditor is the odd one out: no agent, no model, nothing being asked of a human. A relay
signs a commitment, hides an event, gets caught, and is then proven to have done it — followed by
the four controls that keep it from crying wolf, because a mechanism that accuses an honest relay
is worse than none at all.

To see the same thing over a real socket against the Go relay:

```sh
cd apps/relay && make run                    # :3334, in another terminal
pnpm --filter @quorum/echo-agent live
pnpm --filter @quorum/deploy-agent live      # also checks the relay refuses three forgeries

cd apps/relay && QUORUM_EVENTS_PER_MINUTE=0 make run
pnpm --filter @quorum/claude-agent live      # the Go packer and the TS packer, compared byte for byte

cd apps/relay && QUORUM_CHECKPOINT_EVERY=5 QUORUM_CHECKPOINT_LAG=10 \
  QUORUM_CLOCK_SKEW_SECONDS=10 make run
pnpm --filter @quorum/auditor live           # the relay's own checkpoints, recomputed in TypeScript

cd apps/relay && QUORUM_EVENTS_BURST=400 QUORUM_FILTERS_BURST=400 make run
pnpm --filter @quorum/runaway-agent live     # one fold in Go and TypeScript, and Stop over a socket

cd apps/relay && QUORUM_EVENTS_BURST=400 QUORUM_FILTERS_BURST=400 \
  QUORUM_CHECKPOINT_EVERY=5 QUORUM_CHECKPOINT_LAG=10 QUORUM_CLOCK_SKEW_SECONDS=10 make run
pnpm --filter @quorum/sealed-channel live    # a plaintext group and an encrypted one, same relay
pnpm --filter @quorum/mls-channel live       # the same pairing for mls, and two membership lists

cd apps/relay && QUORUM_EVENTS_PER_MINUTE=0 QUORUM_FILTERS_PER_MINUTE=0 make run
pnpm --filter @quorum/conformance start ws://localhost:3334   # or npx @quorum/conformance
```

The conformance run is the one you can point at somebody else's relay. It takes about six
seconds, creates its own workspace, and deletes nothing. Against `apps/relay` it reports 87 MUST
checks passed and one SHOULD failed — `interop/keeps-deletions`, which is khatru v0.17.7 routing
kind 5 past the storage path, documented under **Known gaps** in
[`apps/relay/README.md`](apps/relay/README.md). The four checkpoint checks need a workspace with
history behind it, which is a second run; [the package README](packages/conformance) has the
recipe.

It needs the limiters off, and that is not a detail. A few hundred events in six seconds is a
burst by construction, and against a default relay the suite starts being refused part way
through — five MUST failures and twenty-two checks it never gets to ask, all of them a correctly
configured relay being recorded as a broken one.

The sealed-channel run is paired throughout: every act does the same thing in a plaintext group
and in an encrypted one against one relay in one run, because a claim about what a relay stops
doing is worth nothing without the same relay still doing it.

The bursts, not the per-minute rates: khatru's limiter counts up to the burst and forgives the
rate once a minute, so raising `QUORUM_EVENTS_PER_MINUTE` alone does nothing. A runaway agent
trips the relay's rate limit well before it trips its own budget — the cheaper backstop firing
first, which is right in production and unhelpful in a script watching the other one.

Or drive it yourself, as the human the agent is asking. [`apps/console`](apps/console) has the
full walkthrough; the short version is a keypair, a group, a grant, and then:

```sh
q say "deploy api 1.4.2 to production with 3 replicas" --to bot
q inbox
q approve fd908596 --set replicas=5          # sign consent to the edit, not to the proposal
q audit
```

Or in a browser, which is the same decision with the payload as form fields:

```sh
q keygen web && q workspace add web          # the relay has to admit the key first
pnpm --filter @quorum/web dev                # http://localhost:5173
```

Of the tests, the Python check is the one worth running. It validates the signed transcript
using only the standard library and the committed JSON Schema — never the TypeScript source.
If it ever needs
to import from `src/`, the protocol is not actually language-independent and this repository is
claiming something false.

The relay is the same claim from the other side: it is written in Go and reads the committed
schemas as data, so it could not import the TypeScript validators even if someone wanted to.
Three implementations — Zod, Python stdlib, Go — now validate the same golden transcript from
the same committed artifacts. The Merkle construction is held to the same standard:
`packages/protocol/fixtures/merkle-v1.json` is 21 roots and 31 audit paths generated by
TypeScript and consumed by the Go checkpointer, so a hash tree that only agrees with itself
cannot pass.

## What CI runs

[`.github/workflows/check.yml`](.github/workflows/check.yml), on every push and pull request:

| Job | |
| --- | --- |
| `typescript` | `pnpm check` — typecheck of both src and tests in every package, then the whole suite — plus `vite build`, which is the only thing that notices when something Node-only leaks back into the SDK's isomorphic root entry. |
| `schemas match the validators` | Regenerates `packages/protocol/schemas` and insists on no diff, then runs the Python validator against the committed copy. The Go relay reads those files rather than importing anything, so a committed schema that has drifted from the validator it came from is a rule one implementation has and the other does not. |
| `relay` | `gofmt`, `go vet`, `go test`, and `-race` over `./internal/...`. |
| `conformance` | Builds the relay, starts it, and runs the suite against it over a real socket. |

The last one is there because Option A — every Quorum event is valid on any generic relay — is
the claim the whole design rests on, and it is a claim about two languages agreeing. It is also
the one that would drift silently: nothing else in the repository fails when the Go relay and the
TypeScript SDK stop meaning the same thing by an event.

The suite's own exit code answers one question, which is the right one for it to answer when
pointed at a stranger's relay: did a MUST fail. CI is pointed at this relay, so
[`.github/scripts/conformance-gate.mjs`](.github/scripts/conformance-gate.mjs) adds the two
things an exit code cannot say — that no check was *skipped*, and that the SHOULDs and `n/a`s are
exactly the known ones, each listed there with the reason it is still open. The failure worth
guarding against is a green run that asked nothing: a check that throws becomes a `skip`, a
profile the probe fails to detect turns forty checks into `n/a`, and both of those exit zero.

[`registry.yml`](.github/workflows/registry.yml) runs weekly instead of on push. It asks whether
anybody else has claimed one of the 24 provisional kind numbers, which is a question about three
repositories nobody here controls — a stranger's commit should tell us to reallocate, not turn a
pull request red.
