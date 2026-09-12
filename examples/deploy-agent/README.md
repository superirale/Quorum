# deploy-agent

A gated action worth approving. The echo agent showed an agent that can be reached; this one
shows an agent that can do something you would not want it doing unsupervised, and everything
that has to be true before it does.

```sh
pnpm --filter @quorum/deploy-agent demo     # the whole thing, no infrastructure
pnpm --filter @quorum/deploy-agent verify   # then audit it with no relay at all
```

## The claim

> Ada approved this exact deploy, and you can check that with a signature and no server.

The demo is the product; `verify` is the claim. Everything the demo shows could be built on a
database in an afternoon — an approval queue, a permissions table, an audit log. What could not
is a file of events that anyone can check, later, without asking the people who ran the system
whether their own log is honest. There is no audit table here to corrupt, because the audit
trail and the data are the same object.

Try it: edit `transcript.json` by hand and run `verify` again.

## What the demo shows

Five acts, each with the mechanism doing its job and the failure it exists to prevent.

**1. The loop.** Ada asks for a deploy in a thread. The agent proposes, publishes an
`approval_request` naming the exact arguments by digest, and stops. Ada signs. The deploy runs,
once, and the chain records it.

**2. Consent.** Mallory — a member of the workspace with a perfectly valid key — approves the
same deploy. Nothing happens. Then Ada, who *was* asked, says no, and the action is recorded
`denied`. A signature is not authority; being asked is. Mallory's attempt stays in the log
rather than being dropped, because an auditor wants to see it.

**3. The edit.** Ada asks for thirty replicas by mistake, then approves three. The agent runs
the edit, not the proposal, and the chain carries both digests — so nobody has to take either
party's word for which one ran.

**4. Capability.** Ada revokes the grant, then approves the deploy anyway. It is refused. A
human's yes cannot confer authority that human has not been given, and the refusal is recorded
as a signed `failed` rather than a line in the agent's stderr.

**5. Delegation.** Ada delegates to the agent, but only for staging. A production deploy is
refused even though the agent's *own* grant covers production, because the effective permission
is the intersection. Delegation narrows; it never widens. That rule is what makes "give the
agent admin so it can help" avoidable.

## The three questions the resource asks

`src/deploy.ts` is not part of the agent, and that separation is the point. The agent asked a
human, got a signature and concluded it was allowed to proceed — but the agent is the party with
an interest in the answer, so its conclusion is worth nothing. The deploy tool re-derives
everything from signed events it was handed:

1. **A capability.** Somebody it trusts signed a grant of `action:deploy` to this pubkey, scoped
   to this environment, unexpired, unrevoked, within its use count.
2. **Consent.** The chain verifies and at least one person the agent actually asked said yes.
3. **The same bytes.** What is about to run hashes to the digest the chain says was approved.

Any of the three alone is a hole. A grant with no approval is an agent working unsupervised; an
approval with no grant is a human's yes standing in for authority they may not have; either
without the digest check is consent to a payload nobody saw.

The environment lives in the grant's *scope*, not in a resource named `action:deploy.production`.
Resource strings are matched exactly and never narrowed; scopes intersect. Encode the environment
in the name and act five has nothing to narrow.

## Against the real relay

```sh
cd apps/relay && make run                      # :3334, in another terminal
pnpm --filter @quorum/deploy-agent live
```

M4 is enforced in two places written separately: the SDK refuses to *act* without a signed
approval bound to the right digest, and the Go relay separately refuses to *store* an approval
from someone nobody asked, or a transition to an action somebody else proposed. Each has its own
tests, and neither suite can catch the failure that matters most — a relay policy strict enough
to reject honest SDK traffic looks like a green board on both sides and a hung agent in
production. `live.ts` runs the loop over a socket and checks both directions.

It opens with the coarsest capability of the lot. Mallory asks to join a workspace nobody
invited her to and the relay refuses; Ada then admits her with a put-user, because the
interesting thing about mallory is what she can do once she is inside. The bot gets in the other
way — Ada signs it a `group:join` grant and it presents itself.

The relay is defence in depth and never the authority. It refuses what it can prove wrong from
events it holds, and **fails open on what it cannot see**: events legitimately travel between
relays, so a relay that rejected every approval whose request it has not got would break
federation to catch nothing. The resource makes no such allowance, because it is the one being
asked to act.

## As a real process

```sh
export QUORUM_AGENT_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
export QUORUM_APPROVERS=<hex pubkey>,<hex pubkey>
pnpm --filter @quorum/deploy-agent start
```

| | |
| --- | --- |
| `QUORUM_AGENT_KEY` | 32-byte hex or an `nsec`. Required — the key *is* the identity. |
| `QUORUM_APPROVERS` | Comma-separated hex pubkeys. Required; there is no default, because defaulting it to "anyone" is the bug this example is about. |
| `QUORUM_TRUSTED_ISSUERS` | Whose grants the deploy tool honours. Defaults to the approvers, which is convenient and is not the same claim — being asked to consent and being allowed to delegate authority are different powers. |
| `QUORUM_ON_BEHALF_OF` | A 38106 coordinate to act under. Whatever it says, it can only narrow. |
| `QUORUM_RELAY` | Default `ws://localhost:3334` |
| `QUORUM_GROUP` | Default `payments` |
| `QUORUM_STATE_DIR` | Default `./state`. Durable: a human asked at 18:00 may answer at 09:00, and a memory store would mean the agent came back with no idea it had ever asked. |

It will refuse every deploy until somebody it trusts has issued it a grant. That is the intended
first-run experience — an agent with a key and no capability can talk, and can do nothing.

## Two things worth knowing if you build on this

**An action chain is ordered by its parent links, never by `created_at`.** The whole loop
completes inside one second, and `created_at` has one-second resolution, so ordering by it falls
through to the id tiebreak — a hash — and the state machine rejects honest chains about half the
time. Millisecond resolution would not fix it either: `created_at` is a client-supplied wall
clock, and the ordering that decides whether an execution was legal must not be a field the
executing party picks. `verifyActionChain` orders by `e`-tag depth.

**A stranger's event can never make a chain invalid.** Only the proposer's transitions count,
and only the proposer's approval request names the approvers — but events from anyone else are
recorded as *warnings*, not errors. Counting them would let any member forge an outcome; erroring
on them would let any member veto any action forever with one junk event the proposer cannot
retract. On a generic relay there is nothing to stop them publishing it. So: a chain is invalid
only when the party doing the work did something illegitimate.
