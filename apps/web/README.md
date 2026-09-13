# `@quorum/web` — the reference client

A browser client for the part of Quorum that needs a human: **the approvals queue.**

An agent proposes a consequential action; this page shows you what it proposes, field by
field, lets you change a value before you agree, and signs your decision with your key. The
signature covers a digest of the exact payload, so "you approved this deploy" cannot later be
made to mean a different deploy — not by the agent, not by the relay, and not by whoever runs
either.

Around it: the tasks in the workspace with the relay's projection of each one checked rather
than believed, one task's whole history in order, who is beating right now, and every
capability anyone holds. The loop is watchable end to end — an agent picks up a task, hits a
gate, a human approves inline, the agent finishes, and the task goes `done`.

> **This page keeps your secret key in `localStorage`, unencrypted.** Any script on this
> origin can read it, and so can anyone with a minute at your unlocked machine. That is worse
> than the console, which at least writes a mode 0600 file. Use a throwaway key and a local
> relay. The real answer is NIP-46 — a remote signer holds the key and signs on request — and
> it is M9. `Signer` is an interface for exactly this reason; swapping `identity.ts` out
> touches nothing else.

## Running it

You need a relay, a group, and a key the relay will admit. The console does all three.

```bash
# 1. a key to own the workspace, and a key for the browser
node --experimental-strip-types apps/console/src/main.ts keygen ada
node --experimental-strip-types apps/console/src/main.ts keygen web

# 2. the relay, with ada as the only key allowed to create groups
cd apps/relay && make build
QUORUM_DATA_DIR=/tmp/quorum-run QUORUM_OWNER_PUBKEYS=<ada's pubkey> ./bin/quorum-relay

# 3. the group, and the browser key admitted to it
q workspace create demo
q workspace add web

# 4. the client
pnpm --filter @quorum/web dev     # http://localhost:5173
```

On first load, paste `web`'s secret (`.quorum/web.key`) into the setup form, set the group to
`demo`, and connect. Generating a fresh key in the page works too — copy the pubkey it shows
in the header and run `q workspace add <pubkey>` before it can post.

To have something to approve, run an agent that asks:

```bash
QUORUM_AGENT_KEY=$(cat .quorum/bot.key) \
QUORUM_APPROVERS=<the browser's pubkey> \
QUORUM_TRUSTED_ISSUERS=<ada's pubkey> \
QUORUM_GROUP=demo \
pnpm --filter @quorum/deploy-agent start

q grant bot action:deploy --scope env=production
q say "deploy api 1.4.2 to production with 3 replicas" --to bot
```

The card appears in the browser within a second.

## What each screen is for

**Setup** — key, relay, group. Changing the relay does not re-derive the identity: every
grant already issued names the old pubkey, and silently minting a new one would break them all
for no visible reason.

**Waiting on you** — the queue, from `inbox()` in the SDK. Not reimplemented here: the console
and this client must answer "is this waiting on me" identically, and the direction two
implementations would eventually disagree in decides whether a human sees a production deploy.

**A card** shows the title, the summary, the risk, who asked, how long is left, and the
payload as editable fields. Three rules it follows:

- *It shows what is being approved, not what it is called.* A card that shows `deploy api` and
  a green button is a card people click.
- *It cannot invent a field.* The form is generated from the proposal's own fields, so there is
  no input for a field the agent never proposed — and `applyEdits` in the SDK refuses one
  anyway. That is the same guarantee, and the same code, as `approve --set`.
- *It does not offer a button it cannot honour.* Expired, already answered, or a proposal the
  relay does not hold: the reason is shown and the buttons are not. Somebody who clicks and
  gets an error has already decided, and the decision is what we are recording.

Edited fields keep their type. An `<input>` yields a string; if the agent proposed
`replicas: 30` and you type `3`, what gets signed is the number `3`. `"3"` would be different
bytes, a different digest, and an action that fails validation *after* a human signed it.

The digest under the buttons is recomputed on every keystroke, so it is always the digest of
what is on screen. You must never be able to see one payload and sign another.

**Tasks** — every thread as a unit of work, with its status, assignee and last activity. The
badge beside each one is the part worth explaining, because it is a security claim rather than
a decoration. Kind 38101 is signed by the relay, and the relay is the one party with both the
motive and the position to misstate what a task says; `folded_from` lists the op ids it folded
*in the order it folded them*, so `threads()` replays those ops here and compares. `checked`
means this browser recomputed the status from signed ops and got the same answer. `disagrees`
has no innocent explanation, and what is displayed is then our fold rather than the relay's.
`unverified` means the relay folded ops outside our backfill window, which is ordinary.
`local` means no projection at all — the generic-relay case, which is supposed to work.

Nothing had ever read `folded_from` before this screen, and nothing in TypeScript had ever
*published* an op for it to fold.

**One task** — its state, its actions, and its whole timeline oldest-first. The status and
assignee controls publish kind 8109 ops, which are requests rather than writes: the reference
relay folds them into the 38101 it signs, a generic relay folds nothing and every reader folds
them locally, and both arrive at the same answer. `set_budget` is deliberately not offered — a
spending ceiling is authority rather than coordination, the relay gates it on a
`thread:budget` grant, and a control most members' requests would be refused for is worse than
no control.

The controls do not move until the op comes back through the subscription. An optimistic
select would show `done` for a request the relay rejected.

**Agents** — presence, in the header. Kind 28103 is ephemeral: relays store nothing, so this
only ever shows agents that have beaten since you connected. **An empty row means nobody has
*said* anything. It never means nobody is running**, and an agent absent from it may be midway
through a production deploy. The lease (28102) is what stops two agents working one thread;
this is a status light. A beat expires at its own `created_at + ttl_seconds` — the author's
clock, so every reader agrees on the moment and a skewed agent looks stale to everybody rather
than fresh to some. That is only acceptable because nothing is ever authorised on a heartbeat.

**Capabilities** — every current grant and delegation, with membership first. `group:join` is
the coarsest capability in the system and was the only one nobody had to be granted until M4's
gap was closed, so burying it among the `action:deploy` rows would hide the answer to "who is
in this workspace". Revoked and expired rows stay on screen: "this was revoked" and "this was
never issued" are different facts, and an operator who cannot tell them apart re-issues
capabilities somebody took away on purpose. `max_uses` is labelled *not enforced*, because
nothing counts uses — there is no caller to ask.

Read the scope column, not the resource name. Authority is `action:deploy` with
`{env: production}`, never a resource called `action:deploy.production`: names match exactly
and never narrow, scopes intersect, and a delegation can only ever cut one down.

**Actions** — every action chain, verified in the browser by `verifyActionChains`, the same
function the offline auditor runs over a JSON dump with no relay and no network. The relay
served these bytes and is the one party with both the motive and the position to substitute an
approval, so displaying its account of who approved what would be asking the suspect for an
alibi. The verdict line comes from `conclusion()` in the SDK — it used to be composed
per client, and both copies claimed a *denied* action had been approved and run.

**Channel** — every event, rendered through its NIP-31 `alt` tag, including the kinds this
client understands perfectly well. `alt` is required on every Quorum kind so a reader that has
never heard of kind 8106 still produces a usable line; the way to know that holds is to depend
on it rather than keep a fallback nobody exercises. When a new kind lands, this feed renders it
on the day it is invented.

**Composer** — a kind 11 with a `to`-marked `p` tag, or a NIP-22 kind 1111 comment when a task
is open. Unaddressed, the warning stays up: `to` is the only addressing signal there is, and an
agent that acted on prose naming it would be the exact failure this project exists to avoid.

That a top-level message opens a *task* and not a conversation is the whole of "a thread is a
unit of work". Every one gets its own status, assignee and budget, so a client that quietly
made everything a reply — or everything a new task — would be lying about what the workspace
contains.

## Notes for the next person

**`@quorum/sdk` is isomorphic; `@quorum/sdk/node` is not.** `FileStore` lives behind the
subpath because it imports `node:fs`. Reaching for it from the browser fails at build time,
which is the failure you want — the alternative is a bundler polyfill and a blank page.

**Counters must survive a reload.** `LocalStore` is a `Store` over `localStorage` for exactly
one reason: the `counter` tag is monotonic per author, and a counter that resets to zero on
reload makes every message you send afterwards look, to anyone watching for gaps, like a replay
of messages they have already seen. The keys are namespaced by pubkey, because two identities
in one browser profile sharing a sequence produces the same symptom from the other direction.

**CLOSED is handled, and must stay handled.** A relay that refuses a filter and a relay with
nothing to say look identical unless you read CLOSED. "Nothing is waiting on you" and "you are
not subscribed to anything" must never render the same.

**The event list is in arrival order, and something depends on that.** Everything else is
derived from it by sorting, so arrival order looks like an implementation detail — but
`presence()` settles two heartbeats sharing a second on which arrived first, deliberately the
opposite call from `threads()`. An agent that finishes a job inside one second publishes `busy`
and then `online` with the same `created_at`, and NIP-01's lowest-id tiebreak would leave it
stuck on the wrong badge until the next beat. A projection is folded from stored history nobody
can replay identically; a heartbeat is only ever read as the live stream the reader is watching.

**The relay's 38101 carries `d`, `h` and `alt`, and no `E` tag.** So a thread-scoped
`{"#E": [id]}` query returns every op and none of the projections, and `threads()` would report
`local` against a relay that had in fact folded and signed the lot. This client subscribes to
the whole channel, which is why it does not notice; anything narrowing its filters has to.

## Tests

```bash
pnpm --filter @quorum/web test        # the pure modules
pnpm --filter @quorum/web typecheck
pnpm --filter @quorum/web build       # proves the SDK bundles for a browser
```

There is no DOM test runner here yet. The logic worth asserting on — type-preserving field
edits, finding the proposal behind a request, and saying when something happened — is in plain
modules that Node can run, and the rest is markup best checked by clicking it. Everything the
components *decide* lives in the SDK (`inbox`, `threads`, `presence`, `summariseGrants`,
`verifyActionChains`, `conclusion`) and is tested there, which is also why the console agrees
with this client rather than merely resembling it.

The loop these screens show is tested end to end in another language:
`pnpm --filter @quorum/deploy-agent live` runs it over a socket against the Go relay, including
the thread ops this client publishes and the projection it checks them against.
