# @quorum/conformance

Point it at a relay and it tells you, section by section, what that relay does with Quorum
events. It publishes a few hundred of them, reads them back, breaks one thing at a time, and
records the relay's own words for every refusal.

```sh
npx @quorum/conformance ws://localhost:3334
```

```
Quorum conformance — ws://localhost:3334
quorum reference relay · github.com/quorum-chat/quorum · protocol 0.1 · NIPs 1, 11, 40, 42, 70, 86, 29, 22, 9
suite 0.1 · profiles any, quorum

envelope  11/11
  What the relay refuses: one honest event with one thing wrong with it, each time.
  ✔ refuses a Quorum event with no `alt` tag                    MUST · envelope/alt
  ✔ refuses an `alt` longer than 280 characters                 MUST · envelope/alt-length
  …

MUST 87 passed, 0 failed · SHOULD 8 passed, 1 failed · MAY 4 offered, 1 not
conformant for any + quorum
```

A whole run takes about six seconds. It is safe to run against a live relay: it creates its own
workspace, publishes only into that, and never deletes anything.

## Turn the relay's rate limiter off first

A few hundred events in six seconds is a burst by construction, and the reference relay's
default is 40. So a run against a relay with `QUORUM_EVENTS_PER_MINUTE` at its default gets part
way through and then starts being refused — and the suite records the refusals as MUST failures,
because from out here `rate-limited: slow down, please` and "this relay rejects a valid grant"
are the same observation. A default `apps/relay` produces five MUST failures and twenty-two
checks the run never gets to ask, which is precisely the false accusation everything else in this
tool is arranged to avoid, arriving through the relay's configuration instead of through a bug.

```sh
QUORUM_EVENTS_PER_MINUTE=0 QUORUM_FILTERS_PER_MINUTE=0 ./bin/quorum-relay
```

Nothing is lost by turning it off for the run: no check in this suite is about rate limits.
Against somebody else's relay you cannot turn it off, so ask them to allow-list the owner key the
run prints on stderr — that is the other reason it prints it.

Raising `QUORUM_EVENTS_PER_MINUTE` without touching `QUORUM_EVENTS_BURST` does nothing at all;
the burst is the real limit. See **Rate limits** in `apps/relay/README.md`.

## There is no score, and that is the design

Quorum's central claim is **Option A**: every Quorum event is valid on any generic relay. So a
plain strfry that has never heard of kind 8102 *passes the claim that matters* and fails every
relay-policy check in the suite. Scored out of a hundred it looks broken. It is not — it is doing
exactly what Option A asks of it.

Results are therefore grouped by **profile**, never totalled:

| Profile | Who it applies to |
| --- | --- |
| `any` | Every relay, generic or Quorum. A failure here means Quorum events cannot live on this relay at all, which invalidates the protocol's central design decision rather than the relay's configuration. |
| `quorum` | A relay that validates Quorum events and enforces the NIP's policies. **Detected, not assumed** — the probe is a kind 8104 with its `alt` tag removed, which is invalid under the one universal envelope rule and has no NIP-29, encryption or capability machinery behind it. A generic relay stores it and is reported `n/a` throughout, not red. |
| `service` | Things the spec lets a relay offer and never requires: the thread projection, checkpoints, the context DVM. Each section probes for its own, because "does this relay project threads" and "does it sign checkpoints" are separately configurable. |

And four outcomes, of which exactly one is an accusation:

- **pass** — the relay did the right thing, with its own words attached where there are any.
- **fail** — the relay did the wrong thing. Only this counts against it.
- **n/a** — outside this relay's profile, or a service it does not offer, with the reason.
- **skip** — *the suite* could not ask the question. A dropped socket, an unmet precondition, a
  specimen this suite built wrong. Never the relay's fault, and counted in the footer so a run
  that asked half its questions is not read as a clean one.

## Options

```
quorum-conformance <relay-url> [options]

  --json            the whole report as JSON, and nothing else on stdout
  --verbose         include checks that did not apply, and their reasons
  --group <id>      use an existing workspace instead of creating one
  --key <secret>    run as this key, hex or nsec1…, instead of a fresh one
  --patience <ms>   how long to wait for a relay-authored event, default 20000
```

`QUORUM_CONFORMANCE_KEY` does what `--key` does and keeps the secret off the command line, where
`ps` can read it. The run prints the pubkey it is using on stderr before it starts, on every run
and not only when a key was passed — an operator whose relay refused the run has to know which
key to allow-list, and a suite that mints an identity and never mentions it leaves them no way to
find out.

**Exit codes.** `0` conformant, `1` a MUST failed inside a profile this relay implements, `2` the
run did not happen (bad URL, unreachable relay, unknown flag). A failed SHOULD prints in red and
exits zero: a SHOULD that fails a build is a MUST with a gentler name, and the spec would then be
lying about which is which. `1` and `2` are distinct because "this relay is not conformant" and
"nobody asked it anything" are different answers a CI job has to be able to tell apart.

## Two runs, if you want the checkpoint checks to be real

Four of the five `ordering/*` checks are about relay-signed checkpoints, and a fresh run cannot
reach them — not because it is impatient, but by arithmetic. A window may only be signed once it
can no longer receive an honest event, so the reference relay closes windows a clock-skew behind
the present (900s by default) and cuts one every 300s. A run takes six seconds. A workspace the
run created itself has no closed window, and will still have none however long the run waits;
`--patience` cannot change that, which is why the section asks once and reports `n/a` with the
arithmetic written out.

What does reach them is a second run against a workspace with some history behind it:

```sh
# once, to create the workspace and leave some events in it
export QUORUM_CONFORMANCE_KEY=$(openssl rand -hex 32)
npx @quorum/conformance ws://localhost:3334          # prints: owner <pubkey> · workspace conformance-<stamp>

# later — after at least one checkpoint window has closed
npx @quorum/conformance ws://localhost:3334 --group conformance-<stamp>
```

`--group` needs `--key` and is refused without it, before a single event is published. A key
generated a moment ago is not a member of an existing workspace, so the relay would refuse
everything the run publishes with `blocked: unknown member` — 31 MUST failures and a report that
reads as a broken relay rather than as a run that was never going to work.

The same flag is how you run against a relay with `QUORUM_OWNER_PUBKEYS` set: that relay has to
be told which key may create a workspace *before* the run, which a suite that mints its identity
at startup can never satisfy.

## What it asks

| Section | About |
| --- | --- |
| `interop` | Option A. One honest event of every kind, stored and served back **unchanged** — plus the ephemeral kinds routed and not stored, the `to` marker and `counter` tag surviving a round trip, `#p` and `#E` filters answered, id dedupe, and addressable replacement. |
| `discovery` | What NIP-11 says this relay is, and whether a client can act on it. |
| `envelope` | The universal rules, one broken thing at a time: `alt`, its length, `h`, `enc`, `counter`, `d`, the body schema, the timestamp, the id, the signature. |
| `cross-field` | The rules no JSON Schema can express — driven by the `cross_field_rules` table in `schemas/index.json` rather than by a list written here, so a rule added to the protocol with no probe fails the section instead of quietly going unasked. |
| `threads` | NIP-22 root scope, and the 8109 → 38101 projection if this relay does one. |
| `ordering` | The checkpoint forgery refusal, and the four service checks above. |
| `capabilities` | Membership, budgets and the encryption policy: the grants the relay checks itself, each with the positive control that proves the refusal was about the grant. |
| `approvals` | The two forgeries a relay can catch, and the budget stop — including that a paused thread still accepts chat. |
| `context` | The NIP-90 packer, and whether it packs a thread byte-identically to the same algorithm run locally. |
| `encryption` | The `nip44` policy and the two events it lets a relay refuse without reading either. |
| `mls` | Delivery-service rules for a channel the relay cannot read a word of: the KeyPackage slot, one recipient per Welcome, one commit per epoch, and a policy that states no epoch. |

Ninety-odd MUST checks in all. Every check id is stable across versions on purpose, because the
useful thing to say in a bug report is "your relay fails `encryption/enc-without-policy`", not
"check 19".

`interop` runs first and its result decides whether anything else runs. "The relay refused X" and
"the relay is unreachable, or has this key rate-limited" produce the same observation from out
here, and most of this suite is refusal checks — so a dead relay would score a perfect run. If
not one honest event lands, the run stops with `run/reachable` and says so.

## As a library

```ts
import { run, render, conformant, tally } from '@quorum/conformance'

const report = await run({ url: 'ws://localhost:3334', onCheck: (c) => console.error(c.id) })
process.exitCode = conformant(report) ? 0 : 1
console.log(render(report, { verbose: true }))
console.log(tally(report, 'MUST'))
```

`--json` emits the whole `Report` structure rather than a summary, because the interesting diff
between two versions of a relay is which individual check changed, and a summary cannot answer
that.

## Adding a check

Three rules, enforced by `section.ts` and worth knowing before writing one.

**Break exactly one thing on an event the relay has already accepted.** An event assembled by
hand to be wrong is usually wrong in several ways at once, so the relay's refusal proves only
that *something* was wrong with it — and the check's name then claims a rule the relay may not
have. `withoutTag`, `replaceTag` and `withTag` in `harness.ts` are the three shapes of damage;
`crossfield.ts`'s `bend()` re-signs a stored specimen with one field changed, by **its own
author**, which is not always the owner.

**Never publish something invalid.** Everything goes through `Session.craft` or `Session.vet`,
which run `validateEvent` and throw a `SuiteError` — recorded as `skip` and labelled as this
suite's fault. A suite that sent a malformed event and recorded the refusal would be reporting
its own bug as somebody else's non-conformance, and the operator on the other end has no way to
tell the difference. This is the one direction of mistake a conformance tool must never make.

**State what the relay does, in the present tense.** Not "test that…", not a rule number. The
report is read by somebody deciding whether to run their workspace on this relay.

A check that needs a key nobody trusts uses `session.stranger`; one that needs a key which then
*becomes* trusted must use `session.newcomer()`, because granting the stranger anything would
silently turn every later refusal check into a test of a member, and they would all go on passing
while testing nothing.

## Against the reference relay

`apps/relay` at the current pin reports **MUST 87 passed, 0 failed** on a fresh workspace and
**90 passed, 0 failed** on the two-run recipe, with one SHOULD failure in both:
`interop/keeps-deletions`. That one is expected and documented — khatru v0.17.7 branches on kind 5
in its message loop and never reaches the storage path, so the deletion request is acted on and
then dropped. See **Known gaps** in `apps/relay/README.md`.

## Tests

```sh
pnpm --filter @quorum/conformance test    # 11 tests
```

They run the suite against `@quorum/test-kit`'s in-process relay, which implements NIP-01 and no
Quorum rules at all — so what they pin is the half that is easiest to get wrong and impossible to
notice: that a generic relay is *detected* as generic rather than assumed, that every
Quorum-policy check is ruled out with a reason rather than a cross, that the suite asks every
question it says it asks, and that a relay refusing everything is reported as a run that did not
happen rather than as a run that went well.
