# M0 — throwaway spike

In-memory, single channel, no auth, no Postgres. It exists to stress-test the SDK
ergonomics **before** they become a published schema in M1. The code is disposable;
the findings below are not.

## Run it

```bash
pnpm install
node server.ts        # http://localhost:4000
node agent.ts         # in another shell
```

Then open http://localhost:4000 and send `@deploy ship the payments hotfix`.

Headless equivalents:

```bash
./check.sh            # approve path, deny path, context-budget squeeze
./restart-test.sh     # kill the agent mid-approval, restart, then approve
```

## What it proves

The loop the whole project rests on: agent is addressed → packs context → proposes an
action → requests approval → **human clicks Approve** → agent executes → thread shows
the action, the outcome, and a `done` status.

## Findings

### 1. `to[]` must be the only addressing signal

The SDK originally also matched `@handle` in message text as a fallback. It misfired
immediately: the seeded system message *described* how to mention the agent
("…mention with @deploy…") and the agent treated that as work. Mention→`to` resolution
belongs to the **sender**; receivers read `to` and nothing else.

→ M1: `to` is required on the envelope. M4: `ctx.addressedToMe` never inspects body text.

### 2. `await ctx.requestApproval()` cannot survive a restart on its own — but it can with three changes

The first implementation kept resolvers in a `Map`. Killing the agent mid-approval
orphaned the await, and reconnecting replayed history from seq 0 with a fresh dedup
set, duplicating every step (a second `proposed`, a second `approval_request`, …).

The fix is not to abandon the linear `await` style — it's to make the handler replayable:

1. **`acked_seq`, not `delivered_seq`, drives resume.** A handler blocked on a human has
   not acked, so its triggering event replays on reconnect.
2. **Every side effect goes through `ctx.once()`**, keyed on the triggering event id.
   Replay re-runs the function and re-emits nothing.
3. **`approval_id` is derived via `once()`**, so on replay `requestApproval()` finds the
   human's answer already in backfilled history and returns immediately.

Verified: kill mid-approval → restart → approve → action completes, zero duplicate events.

→ M4: `ctx.once()` ships in v1 and is not optional. M3: the dual-cursor design in the plan
is confirmed, and now for a sharper reason than "delivery tracking" — `acked_seq` is what
makes handler replay both safe and complete.

### 3. `acked_seq` advances over the contiguous prefix, never the max

If it tracked the highest completed seq, a handler blocked on an approval would be skipped
past on restart and its work silently abandoned. The cursor must stall at the oldest
un-acked event.

→ M3: spec this explicitly; it is a conformance test.

### 4. Control-plane events must bypass the handler queue

Handlers run serially so the cursor means something. But a handler blocked awaiting
approval then deadlocks the very queue that would deliver its `approval_response`.
`approval_response` (and `interrupt`) must be dispatched out-of-band.

→ M1: the protocol should classify event types as **control-plane** vs **conversational**.
This is not currently in the plan and should be added to the type registry.

### 5. `once()` keys must be content-derived, not a step counter

A step counter looks tempting and breaks on replay: after a decision is known the handler
takes a different branch, so "step 4" is no longer the same operation. Keys are
`${event_id}:${semantic label}`.

### 6. Deterministic compaction works, and the budget is advisory

At a 30-token budget the packer kept `approval_request` + `approval_response` + one message
and dropped 7 events — but used 44 tokens, because the mandatory-keep set exceeds the
budget. That is correct behaviour and callers must expect it.

→ M7: the spec must state that the mandatory set (thread root, approvals and their outcomes)
can exceed `budget_tokens`, and the response must report `used_tokens` so callers can react.

### 7. Thread-as-task earns its place

Server-side status transitions (`approval_request` → `blocked`, response → `working`,
terminal action → `done`) took ~6 lines and made the UI legible without any extra plumbing.
The "blocked" state is visibly the interesting one.

→ M2: make this a real projection rather than the ad-hoc branch in `server.ts`.

## Files

| File | Role |
| --- | --- |
| `sdk.ts` | The object under test — the ergonomics M0 exists to evaluate |
| `agent.ts` | What we want real agent code to read like |
| `server.ts` | Minimum substrate: append, fanout, context packing, KV, cursors |
| `index.html` | Human side: approval cards, action timeline, thread status |
| `drive.ts` | Headless Ada, for scripted runs |
| `check.sh` / `restart-test.sh` | The scenarios above |
