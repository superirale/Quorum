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
| [`examples/echo-agent`](examples/echo-agent) | The smallest complete agent, and a narrated demo of why each part is there |
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

Next: M4, approvals and capability grants — the milestone the thesis rests on.

Kind numbers in the 8100 / 28100 / 38100 ranges are provisional until the NIP PR merges.

## Try it

```sh
pnpm install
pnpm --filter @quorum/echo-agent demo        # start here — the agent, narrated, no setup

pnpm check                                   # 132 tests: protocol 48, test-kit 17, sdk 67
pnpm --filter @quorum/protocol test:python   # cross-language validation + tamper self-test

cd apps/relay && make test                   # the relay, end to end over a real websocket
```

The demo is the fastest way in. It runs the three claims M3 rests on — an agent answers only
what is addressed to it, survives being killed mid-handler without repeating itself, and does
not double-respond when two replicas share a key — and runs each one again with the mechanism
removed, so the failure it prevents is on screen next to it.

To see the same thing over a real socket against the Go relay:

```sh
cd apps/relay && make run                    # :3334, in another terminal
pnpm --filter @quorum/echo-agent live
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
