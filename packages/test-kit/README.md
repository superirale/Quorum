# @quorum/test-kit

An in-process Nostr relay and the helpers for making it misbehave. Testing an agent should need
no Docker, no port to pick, and no `sleep 200`.

```ts
import { FakeRelay, waitFor } from '@quorum/test-kit'

const relay = await FakeRelay.start()
const agent = createAgent({ relay: relay.url, signer, group: 'payments', store })
await agent.start()

relay.dropConnections()                 // the network, being the network
await waitFor(() => relay.connectionCount === 1, { describe: 'the agent to reconnect' })
```

## What it implements

NIP-01 (`EVENT`/`REQ`/`CLOSE`/`OK`/`EOSE`/`CLOSED`, filters, `limit` taking the newest), the
NIP-01 storage rules (ephemeral kinds not stored, addressable replaced by `(pubkey, kind, d)`,
regular events deduplicated by id), NIP-42 AUTH with a per-connection challenge, and relay29's
one filter constraint — a `#p` filter with no `h` tag is refused by `CLOSED`, which is the trap
that makes an agent silently deaf.

## What it deliberately does not implement

No NIP-29 membership. No Quorum validation. No rate limits.

That is not a gap to be filled in later. A test double with opinions about what is legal becomes
a second specification — unversioned, uncommitted, and free to drift from the one in `spec/`
until the tests pass against a relay nothing else agrees with. Validity is `@quorum/protocol`'s
answer to give and `apps/relay`'s to enforce. The SDK's own test harness calls `assertAllValid`
over everything published, which puts the check where it belongs: on the events, from the
package that defines them.

The consequence is worth stating plainly: **a green test suite here does not mean the real relay
would accept any of it.** `pnpm --filter @quorum/echo-agent live` is what closes that, against
the Go relay over a real socket.

## Chaos

| | |
| --- | --- |
| `dropConnections()` | Kill every socket with no close frame, the way a lost network does — not a clean disconnect the client can distinguish. |
| `withhold(...ids)` | Hide events from later queries. A relay may always serve less than it holds. |
| `withholdMatching(fn)` | Drop an event *as it arrives*: OK'd to its author, never visible to anyone. The dishonest-relay case, and the one M7's checkpoints exist to catch. |
| `reject` (option) | Refuse events by predicate, with your own machine-readable reason. |
| `injectRaw(message)` | Send any NIP-01 message to every client, bypassing every check. The only way to test that a client verifies signatures rather than trusting its socket — from M4 the forged event could be an approval. |

## Inspection

`received` is the arrival log: every event the relay was handed, duplicates included, in order.
`stored` is the reader's view: deduplicated, replaced, ephemeral kinds absent. The difference
between them is where idempotency is proved — a retry that lands as a second arrival but not as
a second message is the whole claim, and collapsing the two would hide it. `eventsOfKind` and
`storedOfKind` filter each.

## Tests

```sh
pnpm --filter @quorum/test-kit test    # 17 tests
```

Written against the raw wire with their own signer, not through `@quorum/sdk`. A relay tested
through the client that talks to it can only prove the two agree, and a bug they share is
invisible to both.
