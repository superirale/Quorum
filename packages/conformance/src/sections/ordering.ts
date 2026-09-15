/**
 * Layer 3: the commitments a relay makes about what it holds.
 *
 * Layers 1 and 2 — per-author `counter` tags and causal `e` tags — are checked
 * in `interop`, because they are properties of events and work on any relay.
 * This section is about the layer that needs the relay's cooperation, and
 * therefore the one it is free not to offer. A relay publishing no checkpoints
 * is conformant; its readers degrade to layers 1 and 2, which is the normal
 * case rather than a failure.
 *
 * **A fresh workspace will usually see nothing here, and that is arithmetic
 * rather than a defect.** A window may only be signed once it can no longer
 * receive an honest event, so the reference relay closes windows a clock-skew
 * behind the present — 900 seconds by default — and cuts one every 300. A whole
 * run takes a few seconds, so a run against a workspace it created itself is
 * asking about a window that has not closed yet, and will still be asking about
 * one however long it waits. `--patience` cannot fix that and neither can
 * polling, which is why this section asks once.
 *
 * What does fix it is `--group` with `--key`: a second run as a key that is
 * already a member of a workspace with some history behind it. Both flags, or
 * neither — a freshly generated key is not a member of an existing workspace,
 * and the relay refuses everything it publishes.
 *
 * Reporting `n/a` with that written out is the honest answer; reporting a
 * failure would be the suite blaming a relay for the suite's own hurry.
 */

import { Kinds } from '@quorum/protocol'
import {
  checkChain,
  checkpointFilter,
  checkpoints as parseCheckpoints,
  verifyWindow,
  windowFilter,
  type Checkpoint,
} from '@quorum/sdk'
import { now, type Session } from '../harness.ts'
import { held, section, type Ctx } from '../section.ts'
import type { Section } from '../report.ts'

export async function ordering(session: Session, group: string, ctx: Ctx): Promise<Section> {
  const run = section(
    'ordering',
    'Relay-signed checkpoints, and the refusal that keeps them the relay’s own word.',
    ctx,
  )

  await run.check(
    {
      id: 'forgery',
      what: 'refuses a kind 8108 signed by a member rather than by itself',
      level: 'MUST',
      profile: 'quorum',
    },
    async () =>
      // The whole value of a checkpoint is that the relay cannot retract it. A
      // member-authored one is the opposite: anybody could sign "these are the
      // ids held for this group", and a reader with no way to tell the two
      // apart would be auditing the relay against a stranger's claim.
      session.refuses(
        await session.craft(session.owner, {
          kind: Kinds.Checkpoint,
          group,
          counter: session.next(),
          body: {
            from: now() - 3600,
            to: now() - 1800,
            count: 0,
            merkle_root: '0'.repeat(64),
            algorithm: 'sha256-merkle-sorted-v1',
          },
        }),
      ),
  )

  // Asked once rather than polled, unlike everything else that waits on the
  // relay. A checkpoint is cut on a cadence measured in minutes, so a checkpoint
  // that is going to exist for this workspace already does; waiting the
  // patience budget out would cost the run twenty seconds to learn nothing.
  const chain: Checkpoint[] = parseCheckpoints(await session.query(checkpointFilter(group)))
  const newest = chain[chain.length - 1]

  const noService = newest
    ? false
    : 'no kind 8108 for this workspace. Checkpoints are an optional relay service, and a ' +
      'window cannot be signed until it can no longer receive an honest event — so a run ' +
      'against a workspace it created seconds ago sees none even from a relay that signs ' +
      `them. Run again with \`--group ${group} --key <the key this run used>\` once this ` +
      'workspace has some history behind it, and these become real checks.'

  await run.check(
    {
      id: 'checkpoints',
      what: 'signs a kind 8108 committing to what it holds for a window',
      level: 'MAY',
      profile: 'service',
      unless: noService,
    },
    async () => ({
      ok: true,
      why: `${chain.length} checkpoint${chain.length === 1 ? '' : 's'}, newest covering ${
        newest!.body.to - newest!.body.from + 1
      }s and committing to ${newest!.body.count} events`,
    }),
  )

  await run.check(
    {
      id: 'author',
      what: 'signs its checkpoints with the pubkey its NIP-11 document names',
      level: 'MUST',
      profile: 'service',
      unless:
        noService ||
        (session.info.pubkey
          ? false
          : 'the relay publishes no pubkey, so a checkpoint cannot be attributed to it'),
    },
    async () => {
      const wrong = chain.filter((c) => c.event.pubkey !== session.info.pubkey)
      return held(
        wrong.length === 0,
        `${wrong.length} of ${chain.length} checkpoints are signed by a key this relay does ` +
          'not claim; an unattributable commitment binds nobody',
      )
    },
  )

  await run.check(
    {
      id: 'window',
      what: 'serves back every event it committed to for a closed window',
      level: 'MUST',
      profile: 'service',
      unless: noService,
    },
    async () => {
      const events = await session.query({ ...windowFilter(newest!), limit: 500 })
      const verdict = verifyWindow(newest!, events)
      switch (verdict.verdict) {
        case 'agrees':
          // Which also settles the committed-kinds rule: an addressable or
          // ephemeral event in the commitment would not be in the recomputed
          // set, so the roots could not match.
          return { ok: true, why: `${verdict.count} events, root recomputed and equal` }
        case 'short':
          return {
            ok: false,
            why:
              `committed to ${verdict.committed} events and serves ${verdict.held}. The ` +
              'mundane readings are a NIP-09 deletion honoured after the commitment, or an ' +
              'event this key is not permitted to read; neither is available to a reader who ' +
              'holds the missing event and can reproduce the signed root with it added back',
          }
        case 'disagrees':
          return {
            ok: false,
            why:
              `serves ${verdict.held} events for a window it committed ${verdict.committed} ` +
              'to and the roots differ: these are not the same set, and there is no reading ' +
              'in which both parties are looking at the same window',
          }
      }
    },
  )

  await run.check(
    {
      id: 'chain',
      what: 'links each checkpoint to the previous one by event id, with no gap or overlap',
      level: 'MUST',
      profile: 'service',
      unless:
        noService ||
        (chain.length > 1
          ? false
          : 'only one checkpoint is held, and the first for a group may name no predecessor'),
    },
    async () => {
      const verdict = checkChain(chain)
      if (verdict.ok) return { ok: true, why: `${chain.length} checkpoints, linked` }
      const said: string[] = []
      if (verdict.broken.length > 0) {
        said.push(`${verdict.broken.length} with a \`prev\` that is not the id of the one before`)
      }
      if (verdict.gaps.length > 0) {
        said.push(`${verdict.gaps.length} uncovered gap${verdict.gaps.length === 1 ? '' : 's'}`)
      }
      if (verdict.overlaps.length > 0) {
        said.push(
          `${verdict.overlaps.length} overlapping window${verdict.overlaps.length === 1 ? '' : 's'}` +
            ' — history re-cut into different windows is what a relay choosing its own account ' +
            'of events looks like',
        )
      }
      return { ok: false, why: said.join('; ') }
    },
  )

  return run.done()
}
