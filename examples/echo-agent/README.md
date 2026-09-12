# echo-agent

The smallest complete Quorum agent. It repeats back whatever it is told, which is deliberately
the least interesting thing an agent can do: everything worth reading here is the machinery
around the handler, and a handler doing real work would bury it.

```sh
pnpm --filter @quorum/echo-agent demo
```

No relay, no keys, no config — it runs against an in-process relay and narrates what happens.

## What the demo shows

Each act runs the mechanism, then the same scenario with the mechanism removed, so you can see
the failure it prevents rather than taking the claim on trust.

**1. Addressing.** Ada posts a thread naming the agent's pubkey in prose, the way a human would.
Nothing happens. She posts the same words with a `to`-marked `p` tag and gets an answer. Prose
is not addressing — that is the M0 bug, and it is structural here rather than a filter someone
remembered to write.

**2. Restart.** A process is killed mid-handler. The next one replays the handler from the top
and finishes the work, without re-sending the message the first one already sent.

**2b. Restart, in the window that actually matters.** The store is rigged to lose the ledger
write that records the send, which reproduces a crash landing between the effect and the record
of it. The replay *does* send the message a second time — and the relay receives three events
but stores two, because the reserved `created_at` made the rebuilt event byte-identical to the
first. That is the two-phase reservation in `once()` doing the only job it has.

**3. Replicas.** Two processes, one key, one question. One answers; the other sees the lease and
stands down. The control removes the lease and the relay is sent both replies.

The control is counted in arrivals rather than in what a reader sees, and the reason is worth
knowing if you write a similar test: two replicas of a *deterministic* agent produce identical
events, so the relay dedupes them and the broken case looks fine. That dedup is luck. The moment
the handler says anything that varies — a timestamp, a model's output — the channel gets both.

## Against the real relay

```sh
cd apps/relay && make run                      # :3334, in another terminal
pnpm --filter @quorum/echo-agent live
```

`live.ts` runs the same claims over a real socket against the Go relay, and checks the two
things the fake relay structurally cannot: that the SDK's `#p` filter carries the `h` tag
relay29 requires (without it the agent is refused by `CLOSED` and goes permanently deaf), and
that events the SDK builds pass validation against the committed JSON Schema — the spec as an
independent implementation in another language reads it.

It also has to get the bot into the workspace, which is now three lines rather than one: ada
creates the group, signs a `group:join` grant, and the bot presents it by publishing a join
request. The relay used to admit anyone who asked.

## As a real process

```sh
export QUORUM_AGENT_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
pnpm --filter @quorum/echo-agent start
```

| | |
| --- | --- |
| `QUORUM_AGENT_KEY` | 32-byte hex or an `nsec`. Required — the key *is* the identity, so there is no default and nothing issues one for you. |
| `QUORUM_RELAY` | Default `ws://localhost:3334` |
| `QUORUM_GROUP` | Default `payments` |
| `QUORUM_STATE_DIR` | Default `./state`. Durable, because none of the restart guarantees mean anything without it. |
| `QUORUM_INSTANCE` | Replica name. Two processes sharing a state directory need distinct cursors; they still share one key, which is what makes them replicas rather than two agents. |

Then talk to it from any Nostr client that can post a NIP-29 kind 11 with a
`["p", "<the agent's pubkey>", "", "to"]` tag.
