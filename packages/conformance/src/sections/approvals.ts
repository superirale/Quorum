/**
 * Consent, and the two ways a relay can help protect it.
 *
 * The audit trail here is the signatures, so almost nothing in this section is
 * the relay's job: an auditor verifies an approval chain offline, with no relay
 * and no keys, and that is the property the design rests on. What the relay
 * adds is defence in depth against the two forgeries that are cheap to publish
 * and expensive to notice — an approval from somebody the request never asked,
 * and a transition in an action chain signed by somebody who did not propose
 * it. Both are valid Nostr events that any generic relay will store, which is
 * why the SDK refuses to count them too, and why these checks are `quorum`
 * rather than `any`.
 *
 * The third check is the budget backstop, and it comes with its own workspace.
 * Pausing the run's main thread to see whether the relay refuses work in it
 * would leave every later section publishing into a paused thread — the suite
 * manufacturing the refusals it then reports.
 */

import { Kinds, buildThread, digest, refTo, type NostrEvent } from '@quorum/protocol'
import { section, type Ctx } from '../section.ts'
import { type Session } from '../harness.ts'
import type { Section } from '../report.ts'
import type { SpecimenSet } from '../specimens.ts'

export async function approvals(
  session: Session,
  group: string,
  set: SpecimenSet,
  ctx: Ctx,
): Promise<Section> {
  const run = section(
    'approvals',
    'The two forgeries a relay can catch, and the budget stop that follows them.',
    ctx,
  )
  const { owner, member } = session

  await run.check(
    {
      id: 'unasked',
      what: 'refuses an approval response from somebody the request did not address',
      level: 'MUST',
      profile: 'quorum',
    },
    async () => {
      const request = set.stored.find((s) => s.kind === Kinds.ApprovalRequest)?.event
      if (!request) return { ok: false, why: 'the approval request specimen was never built' }
      // Signed by the owner, who wrote the request and addressed it to the
      // member. Honouring this is how Mallory asks Mallory: a request names its
      // own approvers, so a response from anyone else is consent nobody gave.
      return session.refuses(
        await session.craft(owner, {
          kind: Kinds.ApprovalResponse,
          group,
          thread: set.thread,
          parent: refTo(request),
          counter: session.next(),
          body: { decision: 'approved', input_digest: digest({ env: 'staging', replicas: 2 }) },
        }),
      )
    },
  )

  await run.check(
    {
      id: 'foreign-transition',
      what: 'refuses an action transition signed by somebody other than the proposer',
      level: 'MUST',
      profile: 'quorum',
    },
    async () => {
      const proposed = set.stored.find((s) => s.kind === Kinds.Action)?.event
      if (!proposed) return { ok: false, why: 'the action specimen was never built' }
      // A forged `succeeded` is worse than it looks in both directions. Counted,
      // it lets any member fake an outcome; treated as an error, it lets any
      // member veto every action forever with one junk event the proposer
      // cannot retract. The relay refuses it and the SDK ignores it.
      return session.refuses(
        await session.craft(member, {
          kind: Kinds.Action,
          group,
          thread: set.thread,
          parent: refTo(proposed),
          action: proposed.id,
          counter: session.next(member),
          body: {
            name: 'deploy.staging',
            status: 'succeeded',
            summary: 'claiming somebody else’s deploy finished',
          },
        }),
      )
    },
  )

  // --- the budget backstop, in a workspace of its own ------------------------

  const paused = await session.workspace('paused')
  const root = await owner.sign(
    buildThread({
      pubkey: owner.publicKey,
      group: paused,
      title: 'A thread that gets paused',
      text: 'Opened so that the relay can be asked what it refuses in a paused thread.',
      counter: session.next(),
    }),
  )
  const opened = await session.accepts(session.vet(root))
  const pausedRef = refTo(root)

  const stopped = opened.ok
    ? await session.accepts(
        await session.craft(owner, {
          kind: Kinds.ThreadOp,
          group: paused,
          thread: pausedRef,
          counter: session.next(),
          body: { op: 'set_status', status: 'paused', reason: 'a conformance run' },
        }),
      )
    : { ok: false, why: `the thread root was refused: ${opened.why}` }

  // The relay refuses work in a paused thread by reading its *own* projection,
  // so this pair of checks rests on a service the relay is free not to offer. A
  // relay that folds no ops has no paused thread to know about, and reporting
  // that as a missing refusal would be recording one optional service's absence
  // twice, the second time as a fault.
  const projected =
    stopped.ok &&
    (await session.waitFor(async () => {
      const [state] = await session.query({
        kinds: [Kinds.ThreadState],
        '#d': [pausedRef.id],
        '#h': [paused],
        limit: 1,
      })
      return state && statusOf(state) === 'paused' ? state : undefined
    }, 6000)) !== undefined

  const noThread = projected
    ? false
    : stopped.ok
      ? 'this relay folds no kind 38101, so it holds no thread state in which a thread is paused'
      : `could not pause a thread to ask about (${stopped.why})`

  await run.check(
    {
      id: 'paused',
      what: 'refuses a proposed action in a paused thread',
      level: 'MUST',
      profile: 'quorum',
      unless: noThread,
    },
    async () => {
      const input = { page: 4 }
      return session.refuses(
        await session.craft(owner, {
          kind: Kinds.Action,
          group: paused,
          thread: pausedRef,
          counter: session.next(),
          body: {
            name: 'crawl.page',
            status: 'proposed',
            summary: 'more work in a thread that has been stopped',
            input,
            input_digest: digest(input),
          },
        }),
      )
    },
  )

  await run.check(
    {
      id: 'paused-talk',
      what: 'still accepts chat in a paused thread',
      level: 'MUST',
      profile: 'quorum',
      unless: noThread,
    },
    async () =>
      // The control, and the more important half. A pause is a budget alert,
      // and a relay that silenced the thread would turn it into an outage in
      // the one place people need to talk about it — including to say what the
      // new ceiling should be.
      session.accepts(
        await session.craft(member, {
          kind: Kinds.ChatMessage,
          group: paused,
          text: 'this thread is paused, and saying so must still be possible',
          counter: session.next(member),
        }),
      ),
  )

  return run.done()
}

function statusOf(state: NostrEvent): string | undefined {
  try {
    return (JSON.parse(state.content) as { status?: string }).status
  } catch {
    return undefined
  }
}
