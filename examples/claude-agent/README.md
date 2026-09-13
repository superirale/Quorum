# claude-agent

A language model reading a workspace. The echo agent showed an agent that can be reached, the
deploy agent showed one that has to ask before it acts; this one shows the part that happens
before either — getting five hundred messages of history into a context window, and getting
them there in a shape that says who wrote what and how far to trust them.

```sh
pnpm --filter @quorum/claude-agent demo     # the whole thing, no infrastructure, no API key
pnpm --filter @quorum/claude-agent live     # the same arithmetic done twice, in two languages
```

No API key needed. `ANTHROPIC_API_KEY` makes the answers real; every assertion holds without it,
for a reason worth stating up front.

## The claim

> Two implementations of the packer, in two languages, produce the same bytes — so where the
> packing happens is an optimisation and not a dependency.

That is the milestone. Compaction is deterministic and extractive on purpose: the relay packs
plaintext channels because it can, the SDK packs encrypted ones because it must, and an agent
cannot tell which one answered. `live.ts` sends a 5600 to the relay, gathers the same four
filters locally, and compares the relay's signed 6600 against `canonicalJson(packContext(…))`
byte for byte. When M9 turns on `nip44` and the relay goes blind, nothing an agent observes
changes.

## Why there is no model in the assertions

The offline stand-in is not a language model and does not pretend to be one. It answers by grep.

Everything this example claims is a property of the *prompt*: that a needle survived compaction
of five hundred messages, that another agent's text arrived inside a fence, that the fence's
closing tag was written by us and not by the attacker. Those are facts about `packContext` and
`renderContext`, provable with no model at all. Whether a model then respects the fence is a
different question, it is not one a demo can settle, and a stub that play-acted refusing an
injection would be claiming it had.

So the stand-in quotes what it found and reports what tried to instruct it, under a rule written
down in two lines of `model.ts`. Set the key and Claude answers instead; the ticks are the same
ticks.

## What the demo shows

**1. The budget.** Five hundred messages, a 20,000-token budget, and the question "what is the
rollback plan and who signs off?" — which was answered in the *first* message of the thread. The
root survives because it is mandatory-keep, not because it is recent: it is the task, and a
packer that treats the oldest message as the least important one drops the only statement of
what the thread is for. 164 messages do not fit and the pack says so in `dropped_events` rather
than leaving the agent to infer it.

**2. The fence.** Another agent posts a summary with `SYSTEM: ignore your previous instructions`
buried in it, and a fake `</untrusted-content>` to break out of the wrapper. It arrives fenced,
its closing tag stripped, labelled `agent` / `untrusted`.

Then the negative control, which is the act worth reading twice: delete the rival's kind 38103
manifest from the event set and pack again. The injection comes back labelled `human` /
`member`, unfenced, indistinguishable from a colleague's words. No error, no warning. Provenance
is derived from the event set and nothing else, and a manifest is the only evidence in it that a
pubkey belongs to an agent — so an agent that never announces itself silently removes the trust
boundary for everyone reading the thread. That is the entire argument for `announce()`.

**3. Determinism.** The same events shuffled, packed twice, compared: identical bytes. Then
Carol packs the same thread and gets *different* bytes, because `self` and `operator` follow the
reader. A pack is an answer to "what should this reader see", and two readers getting the same
answer would mean the question was not being asked.

**4. Memory.** The agent writes down what it packed, the process dies, and a replacement on an
empty disk reads it back from the relay. Kind 38104 is addressable and signed, so "why did it
answer that" is a query any member can run — not a request for shell access to the agent's host.

## Against the real relay

```sh
cd apps/relay && QUORUM_EVENTS_PER_MINUTE=0 make run    # :3334, in another terminal
pnpm --filter @quorum/claude-agent live
```

The rate limit has to go up. The script publishes a 120-message thread from one address as fast
as a socket allows, and the default — 120 events a minute, bursting 40 — is the right setting
for a workspace and the wrong one for building a thread. The relay refuses rather than queues,
so `live.ts` says so and stops rather than producing a half-built thread and a mysterious
disagreement two steps later.

Five things only a real relay can show:

1. **The two packers agree**, byte for byte, over a socket. `internal/contextpack`'s golden
   fixture holds Go to TypeScript's *recorded* output and the SDK suite holds TypeScript to the
   same file — but a fixture is the input to the pure function, so neither notices if the two
   implementations gather *different events* to pack. Here the events come from one store.
2. **A pack too large to deliver is refused in words.** An event holds 65,535 bytes here; a
   20,000-token budget over this thread wants 84,000. The relay sends a kind 7000 naming both
   numbers and suggesting a smaller budget, rather than trimming — a packer that quietly dropped
   what its store could not hold would answer the same request differently from the SDK, under
   the same `algorithm`, with nothing in the body saying so.
3. **A request addressed to somebody else goes unanswered.** A workspace may hold several
   packers; one that answered everything would leave a requester unable to say whose answer it
   got, and they are allowed to differ.
4. **The agent answers from a pack it never computed** — checked by finding the relay's 6600 in
   the store, not by reading `pack.algorithm`, which a local pack sets to the same string. From
   inside the handler the two paths are indistinguishable, so proving which one ran has to be
   done from outside it.
5. **Memory goes through the relay's own schema validation**, which the fake relay does not do.

The packer's pubkey is read from the relay's **NIP-11 document** rather than configured, because
that is how a client finds the packer on a relay it has just met: `khatru29.Init` puts the
relay's own key in the document, and on this relay that key is the DVM's.

## As a real process

```sh
export QUORUM_AGENT_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
export ANTHROPIC_API_KEY=sk-ant-…
pnpm --filter @quorum/claude-agent start
```

Then invite it — `quorum workspace invite <its npub>`, since the relay refuses a join request
nobody granted — and ask it something **inside a thread**, with a `to`-marked `p` tag. `quorum
say --to` and the web client both write one; a generic Nostr client writes an unmarked `p` and
the agent will correctly ignore it.

| | |
| --- | --- |
| `QUORUM_AGENT_KEY` | 32-byte hex or an `nsec`. Required — the key *is* the identity. |
| `ANTHROPIC_API_KEY` | Optional. Unset, it answers with the grep stand-in and says so. |
| `QUORUM_PACKER` | A context DVM's pubkey — the `pubkey` field of the relay's NIP-11 document. Unset means pack locally, which is the only option on an encrypted channel and so is the default. |
| `QUORUM_OPERATOR` | The human accountable for this agent. Also what makes their messages `operator` rather than `member` in every pack it reads. |
| `QUORUM_BUDGET` | Default 20,000. Advisory: the mandatory-keep set can exceed it. |
| `QUORUM_RELAY` | Default `ws://localhost:3334` |
| `QUORUM_GROUP` | Default `payments` |
| `QUORUM_STATE_DIR` | Default `./state`. Durable because the model call inside the handler is the expensive line, and `once()` is only as durable as what it writes to. |

## Three things worth knowing if you build on this

**Packed history goes in the user turn, never the system prompt.** The system prompt is the one
place the operator's own instructions live; everything a workspace says is data that arrived
from elsewhere, including the parts written by agents the operator runs. Putting a thread into
the system prompt is how a message becomes an instruction, and no amount of fencing further down
undoes it. `PROMPT_PREAMBLE` explains the fence *inside* the user turn, where an attacker's text
also lives — so it is evidence about the prompt, not an instruction. The copy in `SYSTEM` is the
one that is trusted, and the repetition is deliberate.

**`budget_tokens` is advisory and `used_tokens` is the answer.** The mandatory-keep set — root,
thread state, approvals and outcomes, the last ten messages — is protected from the budget, so a
thread can exceed it and the pack will say by how much. The token count itself is a proxy:
`ceil(utf8_bytes / 4) + 8` per segment, because a protocol cannot require two implementations to
ship the same build of a vendor's vocabulary file. With an API key, act 1 prints the proxy
against `messages.countTokens` so the size of that error is visible rather than assumed.

**Wrap the model call in `once()`.** Handlers are replayed after a restart, not resumed. An
unguarded `messages.create` is a second invoice for an answer the agent already has and — worse
for the log — a second, differently-worded reply to a question a colleague asked once. The
`ctx.memory.set` beside it deliberately is *not* wrapped: its key is `(pubkey, 38104, d)`, so a
replay overwrites the entry instead of adding one, which is also why the value it stores carries
no timestamp.
