# runaway-agent

An agent nobody is watching, stopped by a number. And one somebody is watching, stopped by a
button.

```sh
pnpm --filter @quorum/runaway-agent demo   # five acts, no relay and no network
pnpm --filter @quorum/runaway-agent live   # the same claims against the Go relay
```

The agent in `src/agent.ts` does not police itself. It reads pages until it runs out of pages,
reporting what each one cost, and there is no counter in it and no ceiling. That is the point:
both controls in this milestone live *outside* the loop the author of an agent writes, because
the agent that needs stopping is by definition the one whose author did not think it would.

## The two controls

**A budget is asynchronous and needs no one present.** The thread holds a ceiling; every
`act()` reports what it cost as a kind 8109 `add_spend` op; the fold adds them up and pauses the
thread when the total reaches the ceiling. Nobody is in the room.

**Stop is synchronous and needs someone present.** A kind 28101 interrupt is routed to whoever
is listening right now, and the SDK aborts the `AbortSignal` the running effect is holding.

They fail in opposite directions, which is why both exist. A budget cannot stop the action
already running; Stop cannot stop an agent at 3am.

## What the demo shows

**1. The meter.** Three pages read, six `add_spend` ops — one per action and one per thinking
step between them — folding to 40,500 tokens against a 30,000 ceiling.

Each action event *also* carries its own `cost`, and the total counts it exactly once.
`add_spend` is the only path into `spent`; the action body's `cost` is audit detail saying what
one turn cost. Fold both and every number in the workspace doubles. The op is also the reason
this works on a channel the relay cannot read: the number is **stated by the party that spent
it**, never estimated by a reader.

Both halves of a cost count against a ceiling. A budget says `tokens`; a spend says `tokens_in`
and `tokens_out`. Compare either column alone and a thread at 29,000 in and 28,000 out looks
comfortably inside a 30,000 cap.

**2. The overrun.** The thread is `paused` and nobody published a `set_status`. It is also
10,500 tokens over.

That overrun is correct, and the demo says so rather than rounding it away. Spend is
self-reported after the fact, so **a budget is a stop sign at the next junction, not a brake**.
The action already running has to be able to finish and report, because the alternative is
losing the record of work that really happened — and an agent whose spend vanishes when it is
stopped has an incentive to be stopped.

**3. It stops.** Three pages proposed, three succeeded, and then *no kind 8101 for page 4 of any
status*. Not a `proposed` the relay refused, not a `failed`. The action was stopped before it
was an action.

That is a deliberate ordering: `ctx.act()` checks the ceiling before it proposes. A rejected
publish throws inside a handler, a throw inside a handler is replayed, and a replay against a
relay that will refuse it every time turns a budget stop into a retry loop against the very
thing that was trying to stop it.

Then it pings a human — addressed with a `to`-marked `p` tag, so it lands in Ada's blocked-on-you
queue rather than in the channel. A pause nobody is told about is an outage.

Control: `set_budget {}` is "nobody has capped this", not a ceiling of zero. The same agent reads
all six pages and spends 81,000 tokens unopposed.

**4. Stop.** An interrupt naming a running action aborts its `AbortSignal`, and the chain ends
`cancelled` — never `failed`. A job that broke and a job a human stopped send very different
people to very different screens, and only the protocol can carry that distinction.

The terminal event still `e`-tags the `running` one, so the chain an auditor walks is whole.

**And there is no receipt.** The relay received one 28101 and stored zero, because the ephemeral
range means exactly that. An agent that is down hears nothing — which is correct, since the
action being cancelled is not running either — but it does mean **no OK from a relay ever means
"an agent heard you"**. Every screen offering a Stop button has to say so; `apps/web`'s does.

Control: an interrupt naming an action this agent is not running matches nothing and stays quiet
about it. In a channel with several agents in it, that is the normal case, not the edge one.

**5. The human decides.** Reopening the thread without touching the ceiling changes nothing —
still refused, still without publishing anything. Raising the ceiling to 200,000 then gets six
more pages.

**Resuming and raising are two decisions and take two ops.** The fold pauses on `add_spend` and
`set_budget` and never on `set_status`, or a human resuming an exhausted thread would have their
`working` rewritten to `paused` by the same fold that stored it. And the fold only ever *sets*
`paused`; raising a ceiling does not restart anything. "This task may continue" and "this task
may spend more" are different questions, and only the second is gated on a `thread:budget`
capability.

Last control: `set_budget {usd: 0}` with nothing spent is a freeze. At the ceiling counts as
exhausted, so `>=` gives you an emergency stop for a whole thread out of a capability that
already exists, rather than a new verb nobody has implemented.

## What `live` adds

```sh
cd apps/relay && QUORUM_EVENTS_BURST=400 QUORUM_FILTERS_BURST=400 make run
pnpm --filter @quorum/runaway-agent live
```

Those two settings are a finding, not boilerplate, and they are not the two variables you would
reach for. khatru's rate limiter is not a bucket that refills: a counter climbs to `maxTokens`
— our `QUORUM_*_BURST` — and a goroutine subtracts `tokensPerInterval` once per interval. The
**burst is the real ceiling** on anything happening inside one minute; `QUORUM_EVENTS_PER_MINUTE`
only decides how much is forgiven at the tick. Raising the per-minute number alone changes
nothing, which this script demonstrated by dying at act 4 with `QUORUM_FILTERS_PER_MINUTE=600`
set and the burst left at its default 40.

Underneath that is the honest version of the finding: **a runaway agent trips the relay's rate
limit long before it trips its own budget.** Both are backstops from the same paragraph of the
plan and the cheaper one fires first, which is the right order in production and useless in a
script trying to watch the other one work. Ada and the agent share 127.0.0.1 here, so they share
one bucket too.

Against the real relay the acts check what a fake one cannot:

1. **One fold, two languages.** `apps/relay/internal/threads` folds the ops in Go and signs a
   38101; `packages/sdk/src/threads.ts` replays the ops the relay says it folded and compares
   field for field. A rounding rule that differed by one would make `threads()` report
   `disagrees` about a relay telling the truth, which is the most serious thing a client can say.
   Neither test suite can catch it: the Go tests build events by hand and the fake relay projects
   nothing.
2. **The pause is the relay's.** The 38101 is signed by the key in the relay's NIP-11 document,
   it says `paused`, and there is no `set_status` op anywhere in the thread.
3. **Teeth, and their limits.** A hand-built kind 8101 `proposed` into the paused thread is
   rejected in the relay's own words. Chat is not, `set_status` is not, `set_budget` is not. A
   relay that silenced the thread it had just paused would turn a budget alert into an outage in
   the one thread people need to talk in.
4. **Two decisions.** Resume alone leaves the proposal count where it was; raising the ceiling
   gets the archive finished, and the projection still agrees at 121,500/200,000.
5. **Stop over a socket.** The chain ends `cancelled`, the relay accepted that terminal event
   into a thread it would have refused a `proposed` in — which is the whole point of allowing
   transitions *out* — and `{kinds: [28101]}` comes back empty.

## Where the code is

The arithmetic is `packages/protocol/src/cost.ts`, four functions, in the protocol package
because the relay does this too. The fold and its pause rule are
`packages/sdk/src/threads.ts` and `apps/relay/internal/threads/threads.go`. The check before an
action is proposed is in `packages/sdk/src/approval.ts`; the relay's refusal is
`apps/relay/internal/policy/budget.go`. Interrupts are `packages/sdk/src/interrupt.ts` and the
browser's buttons are in `apps/web/src/components/ThreadView.tsx`.
