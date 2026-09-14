# auditor

Catching a relay that withholds an event, and then proving it to somebody else.

```sh
pnpm --filter @quorum/auditor demo      # a relay that withholds, caught and proven
pnpm --filter @quorum/auditor verify    # the proof, checked with no relay and no network
pnpm --filter @quorum/auditor live      # the real Go relay's own checkpoints, held to
```

This is not an agent. It is the reader's half of ordering integrity: everything else in the
repository is about getting events published and acted on, and this is about what you can say
when the relay does not give them back.

## The claim

> A relay can withhold events and nothing in Nostr prevents it. A relay that publishes signed
> checkpoints can still withhold events — but it can no longer do so *and* be believed, because
> it has already signed a commitment to the set it holds.

Layers 1 and 2 — per-author `counter` tags and causal `e` tags — let a reader notice gaps in
what it already holds. Neither can see an event that was never served. Layer 3 does not add an
obligation the relay could simply ignore; it makes the relay's own claim checkable.

## What the demo shows

**1. The commitment.** Ada posts five messages. The relay signs a kind 8108 over the window:
an algorithm name, a count, the window bounds, and a Merkle root over the ids it holds. It
cannot retract that; it is signed and content-addressed and now in the channel.

**2. Caught.** The relay stops serving one of the five — it still holds it, it just will not
hand it over. A reader refetches the closed window, recomputes the root, and gets `short`.

That is deliberately *not* an accusation, and the demo says so at the point where it would be
most tempting to claim otherwise. A reader that only backfilled half the window sees exactly the
same verdict. Completeness says something is missing; it cannot say whose fault that is.

**3. Proven.** Ada still has her own copy of the message the relay will not serve. Put it back
and recompute:

```
root(served ∪ held) == the root the relay signed
```

There is no innocent reading of that. The relay committed to an event it is not serving, and the
three pieces — the signed checkpoint, the ids it served, the events from elsewhere — say so to
anybody. Act 3 writes `proof.json`; `pnpm --filter @quorum/auditor verify` reads it back with no
relay, no keys and no network. Edit a byte of it first if you like.

**4. The controls.** The acts that keep the mechanism honest, and the reason the demo is worth
running rather than just reading:

- an honest relay, serving the whole window, produces no proof at all
- a client that backfilled only part of the window gets `short` and still no proof — it is short
  of its own accord
- a fabricated event is rejected *as a fabrication*, naming the unsigned event, rather than as
  arithmetic that did not add up
- an event the relay never committed to does not close the gap, so nothing is emitted

A mechanism that cries withholding at an honest relay is worse than no mechanism, because the
first false accusation is the last time anybody reads the output.

**5. The chain.** Windows are contiguous and each names the previous checkpoint's **event id**.
Remove one from the log and the next is left pointing at nothing. The id rather than the root,
because a root commits only to the set: an id commits to the window bounds and the count too, so
a relay cannot re-cut the same events into different windows — and two quiet windows, which have
identical roots, stay distinguishable.

## What `live` adds

```sh
cd apps/relay && QUORUM_CHECKPOINT_EVERY=5 QUORUM_CHECKPOINT_LAG=10 \
  QUORUM_CLOCK_SKEW_SECONDS=10 make run
pnpm --filter @quorum/auditor live
```

The three settings move together, and the relay refuses to boot if the lag is shorter than the
clock skew — see `apps/relay/README.md` for why that is fatal rather than clamped. The defaults
(a window every five minutes, closing fifteen minutes back) are right for a workspace and wrong
for a script you are watching.

Against the real relay this checks the things a fake one cannot: that a signed 8108 appears at
all, under the key in the relay's NIP-11 document; that recomputing its root from what the relay
serves *agrees*, which is the Go tree and the TypeScript tree meeting over the wire; and that
consecutive windows chain.

Act 4 is the one worth waiting for. A checkpoint commits to **regular events only**. Commit to
an addressable one and the relay fails its own checkpoint the first time a task changes status,
because the store drops the superseded copy and the next reader recomputes a root short by one —
the relay manufacturing evidence against itself, on a schedule. So: a thread op is folded into a
38101, a window closes over it, the 38101 is replaced by a second op, and the old window is
verified again. It agrees. Delete the addressable case from `Committed` in the relay and both
assertions in act 4 fail.

## Where the code is

`packages/sdk/src/checkpoints.ts` is the whole reader side, and `packages/protocol/src/merkle.ts`
the tree. `packages/protocol/fixtures/merkle-v1.json` is the cross-language conformance vector —
21 roots and 31 audit paths, generated by TypeScript and consumed by
`apps/relay/internal/checkpoint`. The relay's side is `apps/relay/internal/checkpoint/`.

The honest limits are documented where the code is, not only here: a relay that publishes no
checkpoints is not caught by any of this, a relay honouring a NIP-09 deletion after committing
will fail its own checkpoint, and a checkpoint says nothing about authenticity — authorship is
still the author's signature. The relay is not a trust anchor here. It is a party that has been
made to commit.
