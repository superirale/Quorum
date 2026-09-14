/**
 * Ordering integrity, layer 3: reading the relay's checkpoints and holding it
 * to them.
 *
 * Layers 1 and 2 — per-author `counter` tags and causal `e` tags — let a reader
 * notice gaps in what it already holds. Neither can see an event that was never
 * served. Nothing in NIP-01 obliges a relay to admit what it has, and a relay
 * quietly serving a smaller world is, from the protocol's point of view,
 * behaving perfectly.
 *
 * A checkpoint does not add an obligation. It makes the relay's own claim
 * checkable: having signed "these are the ids I held for this group up to T",
 * the relay cannot later serve a set missing one of them without handing the
 * reader a signed contradiction. Two things follow, and they are different in
 * kind:
 *
 * - **Completeness.** Refetch a closed window, recompute the root, compare. A
 *   mismatch says something is missing. This is the check any client can run
 *   against any checkpoint, and it names nothing.
 * - **Naming the event.** If you separately hold an event the relay is not
 *   serving — from a mirror, or from before it started withholding — then
 *   adding it back is decisive: if the served set *plus that event* reproduces
 *   the signed root, the relay committed to it and is not serving it, and there
 *   is no innocent reading. {@link withholdingProof} builds that artifact and
 *   {@link verifyWithholdingProof} checks it, offline, from the events alone.
 *
 * Note which direction the asymmetry runs. An **inclusion proof** — the
 * `merkleProof` in `@quorum/protocol` — can only be produced by someone holding
 * the whole leaf set, which is the relay. It is what the relay offers to prove
 * it is *not* withholding a particular event, cheaply, without reserving the
 * window. A client cannot produce one for an event it never received, which is
 * exactly why the client's side of this is the completeness check.
 *
 * ## The honest limits
 *
 * A relay that publishes no checkpoints is not caught by any of this. Its
 * silence is at least visible, which silent withholding is not — but a reader
 * on a generic relay degrades to layers 1 and 2 and that is the normal case,
 * not a failure.
 *
 * A relay that honours a NIP-09 deletion after committing to the deleted event
 * will fail its own checkpoint. That is arguably correct — it signed a claim
 * and no longer serves what it claimed — but an operator should know the
 * accusation has a mundane explanation available.
 *
 * And a checkpoint says nothing about authenticity. Authorship is still the
 * author's signature. The relay is not a trust anchor here; it is a party that
 * has been made to commit.
 */

import {
  CheckpointBody,
  Kinds,
  MERKLE_ALGORITHM,
  TagName,
  isAddressable,
  isEphemeral,
  isReplaceable,
  merkleRoot,
  tagValue,
  verifyEvent,
  type Filter,
  type NostrEvent,
} from '@quorum/protocol'

/** A parsed, relay-signed kind 8108. */
export interface Checkpoint {
  event: NostrEvent
  body: CheckpointBody
  /** The relay that signed it. */
  relay: string
  group: string
}

/**
 * Whether an event of this kind belongs in a checkpoint.
 *
 * Only regular events do. A replaceable or addressable event is *superseded* —
 * the store drops the old copy — so a relay committing to one would guarantee
 * that a later reader comes up short and concludes it withheld something. The
 * relay would be manufacturing evidence against itself on a schedule. Ephemeral
 * events are never stored at all.
 *
 * This must match `Committed` in the relay's checkpoint package exactly. It is
 * a protocol rule for that reason: a client recomputing a root applies the same
 * filter, or it is computing a different tree.
 */
export function isCommittedKind(kind: number): boolean {
  return !isReplaceable(kind) && !isEphemeral(kind) && !isAddressable(kind)
}

/** A filter for a group's checkpoints. */
export function checkpointFilter(group: string, relay?: string): Filter {
  return {
    kinds: [Kinds.Checkpoint],
    [`#${TagName.Group}`]: [group],
    ...(relay ? { authors: [relay] } : {}),
  }
}

/** A filter for everything a checkpoint's window covers. */
export function windowFilter(checkpoint: Checkpoint): Filter {
  return {
    [`#${TagName.Group}`]: [checkpoint.group],
    since: checkpoint.body.from,
    until: checkpoint.body.to,
  }
}

/**
 * Every valid checkpoint in `events`, oldest window first.
 *
 * Signatures are verified here rather than trusted, because the whole value of
 * a checkpoint is that it is a *signed* commitment — an unverified one is a
 * suggestion from whoever was on the socket. Bodies that do not parse are
 * dropped: a malformed checkpoint commits to nothing and is not worth an
 * exception, since anyone may publish garbage to a generic relay.
 */
export function checkpoints(events: readonly NostrEvent[], relay?: string): Checkpoint[] {
  const out: Checkpoint[] = []
  for (const event of events) {
    if (event.kind !== Kinds.Checkpoint) continue
    if (relay && event.pubkey !== relay) continue
    const group = tagValue(event.tags, TagName.Group)
    if (!group) continue

    let body: CheckpointBody
    try {
      body = CheckpointBody.parse(JSON.parse(event.content))
    } catch {
      continue
    }
    if (body.algorithm !== MERKLE_ALGORITHM) continue
    if (!verifyEvent(event)) continue

    out.push({ event, body, relay: event.pubkey, group })
  }
  return out.sort((a, b) => a.body.to - b.body.to || (a.event.id < b.event.id ? -1 : 1))
}

/** What walking a chain of checkpoints found. */
export interface ChainCheck {
  ok: boolean
  /** Checkpoints whose `prev` is not the id of the one before it. */
  broken: Checkpoint[]
  /** Seconds covered by no checkpoint, between two that are otherwise linked. */
  gaps: { after: Checkpoint; before: Checkpoint; seconds: number }[]
  /** Windows that overlap, which a relay cutting history to suit itself needs. */
  overlaps: { after: Checkpoint; before: Checkpoint }[]
}

/**
 * Walk a chain and report where it is not a chain.
 *
 * `prev` is the previous checkpoint's **event id**, not its root, and this is
 * the function that shows why. An id commits to the window bounds and the count
 * as well as the set, so a relay cannot re-cut the same events into different
 * windows and present either version as the one it signed. It also keeps two
 * quiet windows distinguishable: consecutive empty windows have identical roots
 * and would chain ambiguously if `prev` were one.
 *
 * A removed link shows up as a broken `prev`, and removing the *first*
 * checkpoint shows up too, because only the first for a group may omit `prev`.
 */
export function checkChain(chain: readonly Checkpoint[]): ChainCheck {
  const broken: Checkpoint[] = []
  const gaps: ChainCheck['gaps'] = []
  const overlaps: ChainCheck['overlaps'] = []

  for (const [index, link] of chain.entries()) {
    const previous = chain[index - 1]
    if (!previous) {
      // Only the oldest checkpoint we hold may lack a `prev`, and even then it
      // may simply be the oldest we fetched. Nothing to conclude either way.
      continue
    }
    if (link.body.prev !== previous.event.id) {
      broken.push(link)
      continue
    }
    if (link.body.from > previous.body.to + 1) {
      gaps.push({
        after: previous,
        before: link,
        seconds: link.body.from - previous.body.to - 1,
      })
    } else if (link.body.from <= previous.body.to) {
      overlaps.push({ after: previous, before: link })
    }
  }

  return { ok: broken.length === 0 && gaps.length === 0 && overlaps.length === 0, broken, gaps, overlaps }
}

/** The events in `events` that a checkpoint's window covers. */
export function inWindow(
  events: readonly NostrEvent[],
  checkpoint: Checkpoint,
): NostrEvent[] {
  const { from, to } = checkpoint.body
  return events.filter(
    (event) =>
      isCommittedKind(event.kind) &&
      event.created_at >= from &&
      event.created_at <= to &&
      tagValue(event.tags, TagName.Group) === checkpoint.group,
  )
}

/** The checkpoint whose window covers an event, if we hold one. */
export function checkpointFor(
  chain: readonly Checkpoint[],
  event: NostrEvent,
): Checkpoint | undefined {
  return chain.find(
    (c) => event.created_at >= c.body.from && event.created_at <= c.body.to && c.group === tagValue(event.tags, TagName.Group),
  )
}

export type WindowVerdict =
  /** The set we hold for this window is exactly the set that was committed to. */
  | { verdict: 'agrees'; count: number }
  /**
   * We hold fewer events than the relay committed to. Either it is withholding
   * some, or we never asked for all of them — this function cannot tell those
   * apart, and says so rather than accusing. {@link withholdingProof} is how
   * the difference gets settled.
   */
  | { verdict: 'short'; held: number; committed: number }
  /**
   * We hold as many as it committed to, or more, and the root still differs.
   * The sets are not the same set. There is no reading of this in which both
   * parties are looking at the same window.
   */
  | { verdict: 'disagrees'; held: number; committed: number }

/**
 * Recompute a window's root from the events we hold and compare.
 *
 * `events` may be anything — the caller's whole store, a fresh query — since
 * everything outside the window and every kind that is not committed to is
 * filtered out here rather than assumed away.
 */
export function verifyWindow(
  checkpoint: Checkpoint,
  events: readonly NostrEvent[],
): WindowVerdict {
  const held = inWindow(events, checkpoint)
  const ids = held.map((event) => event.id)
  const committed = checkpoint.body.count

  if (merkleRoot(ids) === checkpoint.body.merkle_root) {
    return { verdict: 'agrees', count: committed }
  }
  const distinct = new Set(ids).size
  if (distinct < committed) return { verdict: 'short', held: distinct, committed }
  return { verdict: 'disagrees', held: distinct, committed }
}

/**
 * The artifact that turns a suspicion into a proof.
 *
 * `served` is what the relay gave us for the window. `held` is events we have
 * from somewhere else. If putting the held events back reproduces the root the
 * relay signed, then the relay committed to them and is not serving them, and
 * the three pieces together say so to anybody, offline, forever.
 *
 * Returns `undefined` when the arithmetic does not work out — the held events
 * do not close the gap, so whatever is wrong is not exactly this. A function
 * that returned a "proof" it could not complete would be worse than useless in
 * the one place where being wrong is expensive.
 */
export interface WithholdingProof {
  /** The relay's signed commitment. */
  checkpoint: NostrEvent
  /** Ids the relay served for the window, in canonical order. */
  served: string[]
  /** Events it committed to and did not serve. */
  withheld: NostrEvent[]
}

export function withholdingProof(
  checkpoint: Checkpoint,
  served: readonly NostrEvent[],
  held: readonly NostrEvent[],
): WithholdingProof | undefined {
  const inside = inWindow(served, checkpoint)
  const servedIds = new Set(inside.map((event) => event.id))
  const withheld = inWindow(held, checkpoint).filter((event) => !servedIds.has(event.id))
  if (withheld.length === 0) return undefined

  const all = [...servedIds, ...withheld.map((event) => event.id)]
  if (merkleRoot(all) !== checkpoint.body.merkle_root) return undefined

  return {
    checkpoint: checkpoint.event,
    served: [...servedIds].sort(),
    withheld,
  }
}

export type ProofVerdict =
  | { proven: true; relay: string; group: string; withheld: string[] }
  | { proven: false; reason: string }

/**
 * Check a withholding proof from the bytes alone.
 *
 * No relay, no network, no trust in whoever assembled it. Every step is
 * something the verifier redoes: the checkpoint's signature, that each withheld
 * event is itself validly signed and falls inside the committed window, that it
 * is not in the served set, and that the two sets together reproduce the root.
 *
 * The withheld events must be verified too, and it is the step easiest to skip.
 * Without it anyone could forge an event, claim the relay is hiding it, and the
 * root check would fail — but it would fail as "the proof does not add up",
 * which reads as an accusation that went wrong rather than as a fabrication.
 */
export function verifyWithholdingProof(proof: WithholdingProof): ProofVerdict {
  const [parsed] = checkpoints([proof.checkpoint])
  if (!parsed) return { proven: false, reason: 'the checkpoint is not a valid signed kind 8108' }

  const { from, to, merkle_root } = parsed.body
  const served = new Set(proof.served)

  for (const event of proof.withheld) {
    if (served.has(event.id)) {
      return { proven: false, reason: `${event.id.slice(0, 8)} is in the served set` }
    }
    if (!verifyEvent(event)) {
      return { proven: false, reason: `${event.id.slice(0, 8)} is not validly signed` }
    }
    if (!isCommittedKind(event.kind)) {
      return { proven: false, reason: `kind ${event.kind} is never committed to` }
    }
    if (tagValue(event.tags, TagName.Group) !== parsed.group) {
      return { proven: false, reason: `${event.id.slice(0, 8)} is in another group` }
    }
    if (event.created_at < from || event.created_at > to) {
      return { proven: false, reason: `${event.id.slice(0, 8)} is outside the committed window` }
    }
  }

  const all = [...served, ...proof.withheld.map((event) => event.id)]
  if (merkleRoot(all) !== merkle_root) {
    return { proven: false, reason: 'the served and withheld events do not reproduce the signed root' }
  }

  return {
    proven: true,
    relay: parsed.relay,
    group: parsed.group,
    withheld: proof.withheld.map((event) => event.id),
  }
}
