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

## Four things to know before writing the handler

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
| `approval.ts` | `ctx.act()` — propose, ask, wait, run — plus `approvalResponse()` for the human's side and `tallyApprovals()`, which decides which responses count. The digests are computed here and never accepted from a caller. |
| `grants.ts` | Issue, revoke and fetch 38102s, and `authorize()`: may this pubkey do this, offline, from signed events alone. `effectiveAddressable()` is the replacement rule, and is not `latestAddressable()`. |
| `delegation.ts` | `intersect()` — the whole on-behalf-of idea in one function. The property worth asserting is not that it returns the right answer for a given pair, but that its output is never wider than either input. |
| `audit.ts` | `verifyActionChain()`: hand it a pile of events and it tells you who approved what and whether the log is self-consistent. No relay, no server, no trust in whoever handed them over. |
| `threads.ts` | The task list. `threadOp()` asks for a state change; `threads()` reads the answer and replays the ops the relay says it folded rather than believing the 38101 it signed. |
| `presence.ts` | `PresenceReporter` beats kind 28103 while an agent runs; `presence()` reads the beats. Ephemeral, so an empty result means "nobody has said", never "nobody is running". |
| `context.ts` | `packContext()` — the `extractive-v1` compactor, deterministic to the byte; `fetchContext()` asks a DVM for the same thing; `renderContext()` turns a pack into a prompt and fences what is not ours. `ctx.context()` picks between the two and the caller cannot tell which answered. |
| `checkpoints.ts` | The reader's half of ordering integrity. `verifyWindow()` recomputes a relay's signed root from the events it served; `withholdingProof()` turns "short" into an artifact a stranger can check with `verifyWithholdingProof()`, no relay and no network. `checkChain()` walks the windows. |
| `memory.ts` | Kind 38104, scoped by `d`. Published rather than filed away, so "why did it answer that" is a query any member can run instead of a request for shell access to the agent's host. |

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

## Tests

```sh
pnpm --filter @quorum/sdk test        # 269 tests
```

They run against `@quorum/test-kit`'s in-process relay: no Docker, no ports, no sleeps. Two of
them use `injectRaw` to have the relay send a forged event and an unmatched one, because
"the SDK verifies what the relay hands it" is not provable through the honest path.

The fake relay is permissive by design and cannot tell you whether the real one would accept
what the SDK builds. `pnpm --filter @quorum/echo-agent live` answers that, against the Go relay
in `apps/relay`.
