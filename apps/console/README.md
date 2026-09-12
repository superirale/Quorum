# `quorum` — the operator console

A Quorum workspace has two kinds of participant, and until this existed only one of them had a
way in. An agent is a process you start. A human has to create the workspace, hand out a
capability, ask for something, and then sign or refuse what comes back — and all of that lived
only as library calls inside the example scripts, which play every part themselves and exit.

This is the human half, as a CLI. It is deliberately thin: every command is a few lines over
`@quorum/sdk`, holds no state the relay does not hold, and makes no decision the protocol does
not already define. When the reference client lands in M5 it will do the same work behind
buttons, and this stays as the headless path — nobody scripts a workspace from a web UI.

## Why not just use a Nostr client

M4's README suggested posting to the agent "from any Nostr client". That does not work, and the
reasons are the protocol rather than a missing feature:

- **Addressing.** A generic client writes `["p", "<pubkey>"]`. Quorum addressing is the `to`
  marker in position 4 — `["p", "<pubkey>", "", "to"]` — and an agent that answered an unmarked
  `p` would be answering a mention, which is the loop this project exists to prevent. So the
  agent correctly ignores anything a generic client sends it.
- **Approval.** Consent is a kind 8103 `e`-tagged at the request and carrying the exact
  `input_digest` it approves. There is no way to type that by hand and no generic client builds
  it.

So a human could watch a Quorum workspace from a generic client, and could not participate in
one. That gap is what this closes.

## Install

Nothing to install — it runs from the repo.

```bash
q() { node --experimental-strip-types apps/console/src/main.ts "$@"; }
q help
```

State lives in `./.quorum`, or wherever `$QUORUM_HOME` points.

> **Keys are stored in plaintext, mode 0600.** This is a development tool and that is a real
> compromise, called out rather than hidden. NIP-46 lands in M9 and removes secret keys from
> this process entirely; until then, do not point `$QUORUM_HOME` at a key that controls
> anything you care about.

## The whole loop, by hand

Start a relay (`cd apps/relay && make run`, listening on `:3334`), then:

```bash
export QUORUM_HOME=/tmp/quorum-demo QUORUM_RELAY=ws://localhost:3334

q keygen ada                 # you
q keygen bot                 # the agent
q workspace create ops       # you are its admin, and #ops becomes the default
q workspace add bot
q workspace members          # the relay's own signed 39002, not a scan of who has posted
```

`add` works here because you made the bot's key yourself a moment ago. The usual case is the
opposite — an agent somebody else will run, whose key does not exist yet — and for that there
is an invitation:

```bash
q workspace invite bot --expires 3600   # a group:join grant, signed by ada
q workspace join --as bot               # bot presents it; the relay admits it
```

Getting in is a capability like any other, which is the point of doing it this way rather than
with a membership table. The relay refuses a join request from anyone holding no grant, the
invitation can be handed over with a key that has not been generated yet, and `q revoke bot
group:join` withdraws it. Revoking does not put an existing member out, though — that is
`q workspace remove bot`, and an operator who means both has to do both.

Give the agent a capability. Note the shape: `action:deploy` narrowed by a **scope**, never
`action:deploy.production` — a resource name matches exactly and never narrows, so encoding the
environment in the name leaves a delegation nothing to intersect with.

```bash
q grant bot action:deploy --scope env=production
q grants bot
#   2ebfa99b… in #ops
#     active  grant      action:deploy invoke {"env":"production"} by 55f74c6c…
```

Start the agent with its own key, naming you as its approver:

```bash
QUORUM_AGENT_KEY=$(cat $QUORUM_HOME/bot.key) \
QUORUM_APPROVERS=<ada's hex pubkey> \
QUORUM_GROUP=ops QUORUM_RELAY=ws://localhost:3334 \
  pnpm --filter @quorum/deploy-agent start
```

Then ask it for something, and answer what comes back:

```bash
q say "deploy api 1.4.2 to production with 3 replicas" --to bot

q inbox
#   fd908596… Deploy api 1.4.2  risk=high
#     deploy api 1.4.2 to production on 3 replicas
#     from 2ebfa99b… at 3:35:04 PM
#     {"env":"production","replicas":3,"service":"api","version":"1.4.2"}

q approve fd908596 --set replicas=5
#   proposed {"env":"production","replicas":3,…}
#   approving {"env":"production","replicas":5,…}
#   ✓ ada approved Deploy api 1.4.2
#     digest  cc553490… (the edit, not the proposal)
```

The agent's log then reads:

```
[action] deploy ran the approver's edited input, not the proposal (cc553490…)
```

Which is the point of the digest binding. The agent did not run what it proposed; it ran what
was signed, because it re-derived the digest from the approval rather than trusting its own
copy of the payload.

## Checking the work

```bash
q audit
q export /tmp/transcript.json
pnpm --filter @quorum/deploy-agent verify /tmp/transcript.json
```

`audit` fetches events from the relay and verifies them **locally** — the relay is a source of
bytes, never a source of truth. `export` then writes those bytes out so the same questions can
be asked with no relay at all, which is the claim M4 actually rests on. Both print the same
verdict sentence, composed by `conclusion()` in the SDK rather than by each renderer, after a
manual run caught both copies reporting a *denied* action as "approved exactly this, and
exactly this ran".

Three chains from a real session, all verifying, all saying different things:

```
✓ deploy  b377acce…  succeeded
  → 55f74c6c… approved exactly this, and exactly this ran.

✓ deploy  dca2fb8d…  denied
  → 55f74c6c… denied this, and it never ran.

✓ deploy  36e7c877…  failed
  → 55f74c6c… approved exactly this; it was attempted under those bytes and failed.
```

The third is worth understanding. Between the approval and the execution the grant was revoked:

```bash
q revoke bot action:deploy --scope env=production --reason "rotating the agent key"
```

The already-running agent re-checked at execution time and refused, with the revocation's own
reason attached:

```
[action] deploy failed: action:deploy refused: no capability
         — grant 704fac95…: revoked — rotating the agent key
```

**A signed human approval is not a capability.** They are separate questions asked at separate
moments, and a system that conflates them cannot revoke anything from an agent that is already
mid-flight.

## Commands

| | |
| --- | --- |
| `keygen <name>` · `use <name>` · `whoami [--all]` | identities on this machine |
| `workspace create\|add\|remove\|members\|use` | NIP-29 group membership, which is the relay's business |
| `workspace invite <who> [--expires]` · `workspace join` | the same thing as a capability: sign an invitation, or present one |
| `grant <who> <resource>` | `--scope k=v` (repeatable) · `--actions` · `--expires` · `--max-uses` |
| `revoke <who> <resource>` | same `--scope` as the grant: it identifies the coordinate |
| `grants [who]` | what a key currently holds, revocations and expiries applied |
| `say <text> --to <who>` | a kind-11 thread with the `to` marker set |
| `watch` | tail the group; every event renders through its `alt` tag |
| `inbox [--all]` | approval requests addressed to you and still open |
| `approve <id> [--set k=v]` · `deny <id> [--reason r]` | sign a decision |
| `audit [--thread <id>]` · `export <file>` | verify, and take the evidence elsewhere |

`--as <name>` signs as another saved identity for one command. `--relay` and `--group` override
the saved defaults; both are folded into the environment on the way in, so there is one
precedence rule (env beats file beats default) rather than two that can disagree.

Ids are matched by prefix, and an ambiguous prefix is an error rather than a guess — approving
the wrong action because two ids shared four characters is not something a signature can be
taken back from.

## Tests

```bash
pnpm --filter @quorum/console test
```

34 tests over the parts where being wrong is quiet: argument parsing and `--set` edits
(`args.test.ts`), what counts as waiting on you (`inbox.test.ts`), key file permissions and
path traversal (`config.test.ts`), and what a grant listing claims a capability covers
(`grants.test.ts`).

Everything that talks to a relay is left to the integration suites in `examples/`, which run
against the real Go relay — a mocked socket would only assert that the mock behaves as this
package expects, which is the thing worth doubting.

Two product bugs came out of writing these, both fixed where they originated rather than worked
around here:

- `build()` silently dropped a `parent` given without a `thread`, emitting an event with no `e`
  tag at all. Every downstream layer rejected the result, which is exactly why it survived —
  each rejection surfaced far from the line that built it. It now throws.
- `conclusion()` did not exist; the sentence was written twice, and both copies said a denied
  action had been approved and had run.
