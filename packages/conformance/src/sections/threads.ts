/**
 * A thread is a task, which means two different things have to be checked.
 *
 * The first is NIP-22 root scope — `E`/`K` on everything in a thread, `e`/`k`
 * on everything that answers something — and it is a `quorum` rule the relay
 * either enforces or does not.
 *
 * The second is the projection, and it is a **service**. Kind 38101 is folded
 * from kind 8109 ops by a relay that has been configured to do it; a relay that
 * has not is perfectly conformant and its clients fold the ops themselves. So
 * absence is reported as `n/a`, and the checks that do run are about whether
 * the projection can be *checked* rather than whether it exists: `folded_from`
 * names the ops, the client replays them, and the relay's answer either matches
 * or it does not. Without that, 38101 is the relay telling you a fact you have
 * no way to verify — which is the one thing building on Nostr is supposed to
 * avoid.
 */

import { Kinds, TagName, refTo, type NostrEvent } from '@quorum/protocol'
import { thread as readThread } from '@quorum/sdk'
import { now, replaceTag, withoutTag, type Session } from '../harness.ts'
import { held, section, type Ctx } from '../section.ts'
import type { Section } from '../report.ts'
import type { SpecimenSet } from '../specimens.ts'

export async function threads(
  session: Session,
  group: string,
  set: SpecimenSet,
  ctx: Ctx,
): Promise<Section> {
  const run = section(
    'threads',
    'NIP-22 root scope, and the thread-state projection if this relay does one.',
    ctx,
  )
  const { owner, member } = session

  await run.check(
    {
      id: 'root',
      what: 'refuses a threaded kind with no `E` tag naming its thread root',
      level: 'MUST',
      profile: 'quorum',
    },
    async () => {
      const summary = await summaryOf(session, group, set)
      return session.refuses(await owner.sign(withoutTag(summary, TagName.RootEvent)))
    },
  )

  await run.check(
    {
      id: 'root-kind',
      what: 'refuses a `K` tag that does not say the root is a kind 11',
      level: 'MUST',
      profile: 'quorum',
    },
    async () => {
      const summary = await summaryOf(session, group, set)
      return session.refuses(
        await owner.sign(replaceTag(summary, [TagName.RootKind, String(Kinds.ChatMessage)])),
      )
    },
  )

  await run.check(
    {
      id: 'parent-kind',
      what: 'refuses an approval response that answers something other than a request',
      level: 'MUST',
      profile: 'quorum',
    },
    async () => {
      const request = set.stored.find((s) => s.kind === Kinds.ApprovalRequest)?.event
      if (!request) return { ok: false, why: 'the approval request specimen was never built' }
      const response = await session.craft(member, {
        kind: Kinds.ApprovalResponse,
        group,
        thread: set.thread,
        parent: refTo(request),
        counter: session.next(member),
        body: { decision: 'approved', input_digest: 'a'.repeat(64) },
      })
      // Only the `k` tag moved. The `e` tag still names the real request, so
      // what the relay is being asked is whether it reads the tag at all —
      // which matters because `k` is how a reader decides an event is a
      // response to consent rather than a comment that happens to reply.
      return session.refuses(
        await member.sign(replaceTag(response, [TagName.ParentKind, String(Kinds.ChatMessage)])),
      )
    },
  )

  await run.check(
    {
      id: 'forgery',
      what: 'refuses a kind 38101 signed by a member rather than by itself',
      level: 'MUST',
      profile: 'quorum',
    },
    async () =>
      session.refuses(
        await session.craft(owner, {
          kind: Kinds.ThreadState,
          group,
          d: set.thread.id,
          counter: session.next(),
          body: { status: 'done', folded_from: [], updated_at: now() },
        }),
      ),
  )

  // --- the projection, if there is one ---------------------------------------

  const op = await session.craft(owner, {
    kind: Kinds.ThreadOp,
    group,
    thread: set.thread,
    counter: session.next(),
    body: { op: 'set_status', status: 'blocked', reason: 'a conformance run' },
  })
  const published = await session.accepts(op)

  // Six seconds, not the run's full patience. A relay that projects does it in
  // the same call that stored the op — khatru runs `OnEventSaved` synchronously
  // inside `AddEvent` — so this is waiting on a round trip, not on a scheduler,
  // and the twenty-second budget exists for services that run on a clock.
  const waitMs = 6000
  const projection = published.ok
    ? await session.waitFor(async () => {
        const [state] = await session.query({
          kinds: [Kinds.ThreadState],
          '#d': [set.thread.id],
          '#h': [group],
          limit: 1,
        })
        return state && foldedFrom(state).includes(op.id) ? state : undefined
      }, waitMs)
    : undefined

  const noService = projection
    ? false
    : published.ok
      ? `no kind 38101 folding this run’s thread op appeared within ${waitMs / 1000}s; ` +
        'projecting thread state is an optional relay service, and a client that folds the ' +
        'ops itself reads the same task state'
      : `the thread op was refused (${published.why}), so there was nothing to fold`

  await run.check(
    {
      id: 'projection',
      what: 'folds a kind 8109 op into a relay-signed kind 38101',
      level: 'SHOULD',
      profile: 'service',
      unless: noService,
    },
    async () =>
      held(
        status(projection!) === 'blocked',
        `the projection says ${status(projection!) ?? 'nothing'} after an op setting it to blocked`,
      ),
  )

  await run.check(
    {
      id: 'projection-author',
      what: 'signs its projection with the pubkey its NIP-11 document names',
      level: 'MUST',
      profile: 'service',
      unless:
        noService ||
        (session.info.pubkey
          ? false
          : 'the relay publishes no pubkey, so a projection cannot be attributed to it'),
    },
    async () =>
      held(
        projection!.pubkey === session.info.pubkey,
        'the 38101 is signed by a key the relay does not claim; a reader has no way to ' +
          'tell this projection from one a member wrote about their own task',
      ),
  )

  await run.check(
    {
      id: 'folded-from',
      what: 'lists the ops it folded, and replaying them gives the same answer',
      level: 'MUST',
      profile: 'service',
      unless: noService,
    },
    async () => {
      const events = await gather(session, group, set)
      const seen = readThread(events, set.thread.id)
      if (!seen) return { ok: false, why: 'the thread root is no longer being served' }
      switch (seen.check.verdict) {
        case 'agrees':
          return { ok: true }
        case 'disagrees':
          return {
            ok: false,
            why: `replaying the ops it says it folded disagrees on ${seen.check.fields.join(', ')}`,
          }
        case 'unverifiable':
          return {
            ok: false,
            why:
              `claims to have folded ${seen.check.missing} op` +
              `${seen.check.missing === 1 ? '' : 's'} it does not serve, so its projection ` +
              'cannot be checked against anything',
          }
        case 'local':
          return { ok: false, why: 'the projection went away between one query and the next' }
      }
    },
  )

  return run.done()
}

/** A valid summary in the run's thread, for a check to then damage. */
async function summaryOf(
  session: Session,
  group: string,
  set: SpecimenSet,
): Promise<NostrEvent> {
  return session.craft(session.owner, {
    kind: Kinds.Summary,
    group,
    thread: set.thread,
    counter: session.next(),
    body: {
      text: 'a summary built so that one of its threading tags can be taken off',
      from_event: set.thread.id,
      to_event: set.thread.id,
      covers: 1,
      method: 'extractive',
    },
  })
}

/**
 * Everything the SDK needs to judge the projection.
 *
 * Three filters, because a 38101 carries no `E` tag — it is not *in* the
 * thread, it is *about* it — so a thread-scoped `#E` query returns every op and
 * none of the projections, and the reader then reports that a relay which
 * folded the lot has folded nothing.
 */
async function gather(
  session: Session,
  group: string,
  set: SpecimenSet,
): Promise<NostrEvent[]> {
  const [root, inThread, state] = await Promise.all([
    session.query({ ids: [set.thread.id], limit: 1 }),
    session.query({ '#E': [set.thread.id], '#h': [group], limit: 200 }),
    session.query({ kinds: [Kinds.ThreadState], '#d': [set.thread.id], '#h': [group], limit: 5 }),
  ])
  return [...root, ...inThread, ...state]
}

function foldedFrom(state: NostrEvent): string[] {
  try {
    const body = JSON.parse(state.content) as { folded_from?: unknown }
    return Array.isArray(body.folded_from) ? body.folded_from.map(String) : []
  } catch {
    return []
  }
}

function status(state: NostrEvent | undefined): string | undefined {
  if (!state) return undefined
  try {
    return (JSON.parse(state.content) as { status?: string }).status
  } catch {
    return undefined
  }
}
