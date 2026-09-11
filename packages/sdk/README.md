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

## Three things to know before writing the handler

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

## What is in here

| | |
| --- | --- |
| `signer.ts` | `LocalSigner` (hex or `nsec`, from env), `Nip07Signer` (browser extension). The secret is a `#private` field and every stringification of it redacts. NIP-46 is M9. |
| `client.ts` | One relay connection: publish with a real OK/reject result, subscribe, NIP-42 AUTH on demand, reconnect with re-subscription. |
| `addressing.ts` | `isForMe`, and the four filters — channel, addressed, thread, control. `assertScopedFilter` refuses a filter that would be rejected or would leak. |
| `agent.ts` | The loop: subscribe, queue, dispatch, replay, shut down without losing in-flight work. |
| `once.ts` | The effect ledger, described above. `incompleteEffects()` tells an operator what was half-done at the last crash. |
| `store.ts` | `MemoryStore`, `FileStore`, `namespaced()`. Local on purpose: a relay-hosted dedup ledger costs a round trip per effect, and on Nostr you cannot unpublish the ops log you did not mean to publish. |
| `counter.ts` | The per-author `counter` tag: monotonic, durable across restarts, so readers can detect that they missed something from you. |
| `replay.ts` | The cursor — event ids in flight, counter watermarks, gap detection. Not a `seq` high-water mark; Nostr has no total order to have one against. |
| `lease.ts` | Single-holder claims on a thread, so N replicas of one key produce one answer. |
| `publish.ts` | Build → sign → publish. Tag assembly stays in `@quorum/protocol`. |

## Two design notes that cost something to learn

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

## Tests

```sh
pnpm --filter @quorum/sdk test        # 67 tests
```

They run against `@quorum/test-kit`'s in-process relay: no Docker, no ports, no sleeps. Two of
them use `injectRaw` to have the relay send a forged event and an unmatched one, because
"the SDK verifies what the relay hands it" is not provable through the honest path.

The fake relay is permissive by design and cannot tell you whether the real one would accept
what the SDK builds. `pnpm --filter @quorum/echo-agent live` answers that, against the Go relay
in `apps/relay`.
