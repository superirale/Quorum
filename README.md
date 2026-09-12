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
| [`packages/protocol`](packages/protocol) | Kind allocation, validators, JSON Schema, fixtures |
| [`packages/sdk`](packages/sdk) | Agent SDK — signers, client, addressing, `once()`, replay, leases |
| [`packages/test-kit`](packages/test-kit) | In-process relay + chaos helpers, so agents are testable with no infra |
| [`apps/relay`](apps/relay) | Reference relay — khatru + relay29 + the Quorum policies (Go) |
| [`apps/console`](apps/console) | `quorum` — the operator CLI: be the human in the loop from a terminal |
| [`apps/web`](apps/web) | Reference client (React) — the approvals queue, with the payload editable field by field |
| [`examples/echo-agent`](examples/echo-agent) | The smallest complete agent, and a narrated demo of why each part is there |
| [`examples/deploy-agent`](examples/deploy-agent) | A gated action worth approving, plus an offline auditor that checks who approved it |
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

**M5 started** — the reference client ([`apps/web`](apps/web)), sliced to the screen that
matters: the approvals queue. An agent's proposal arrives as a card showing the payload field
by field; you can change a value before you agree, and what gets signed is a digest of exactly
what is on screen. Action chains are verified in the browser from the signatures, by the same
function the offline auditor runs. Still to come: the thread list with task status, agent
presence, and a grant inspector.

Kind numbers in the 8100 / 28100 / 38100 ranges are provisional until the NIP PR merges.

## Try it

```sh
pnpm install
pnpm --filter @quorum/deploy-agent demo      # start here — consent, narrated, no setup
pnpm --filter @quorum/deploy-agent verify    # then check it, offline, from the signatures

pnpm --filter @quorum/echo-agent demo        # the mechanics underneath: addressing, replay, leases

pnpm check                                   # 253 tests: protocol 49, test-kit 17, sdk 141, console 34, web 12
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

To see the same thing over a real socket against the Go relay:

```sh
cd apps/relay && make run                    # :3334, in another terminal
pnpm --filter @quorum/echo-agent live
pnpm --filter @quorum/deploy-agent live      # also checks the relay refuses three forgeries
```

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
the same committed artifacts.
