/**
 * The whole suite, in the one order the sections can be run in.
 *
 * Almost nothing here is arrangeable to taste, and the constraints are worth
 * stating because the obvious orderings are each wrong in a way that produces a
 * confident, false report.
 *
 * **Interop first, and its result decides whether anything else runs.** "The
 * relay refused X" and "the relay is unreachable, misconfigured, or has this
 * key rate-limited" produce the same observation from out here, and most of
 * this suite is refusal checks — so a dead relay scores a perfect run. Interop
 * publishes one honest event of every kind and reads them back; if not one of
 * them lands, the run stops and says so rather than converting a broken
 * connection into forty passes.
 *
 * **The profile is detected after interop and before everything else**, because
 * detection is itself a refusal check (a Quorum kind with no `alt`) and carries
 * the same ambiguity. Running it against a relay already shown to be storing
 * events is what makes its answer mean anything.
 *
 * **Encryption and MLS run last, in workspaces of their own.** A channel policy
 * is addressable on the group id, so a section that seals a channel changes the
 * rules for every event published into it afterwards — every plaintext specimen
 * would start being refused, correctly, and this suite would record it as the
 * relay's fault. They take their own workspaces for that reason, and they still
 * run last, because a relay that gets those wrong is one whose main workspace
 * is best examined first.
 *
 * Sections do not run in parallel, and that is not laziness either. khatru's
 * filter limiter closes the subscription rather than queueing, three sections
 * of polling at once is how a run trips it, and a closed subscription reads
 * from here as a relay that serves nothing.
 */

import { PROTOCOL_VERSION } from '@quorum/protocol'
import { Session, detectProfile, type SessionOptions } from './harness.ts'
import { specimens } from './specimens.ts'
import type { Check, Profile, Report, Section } from './report.ts'
import type { Ctx } from './section.ts'
import { discovery } from './sections/discovery.ts'
import { interop, usable } from './sections/interop.ts'
import { envelope } from './sections/envelope.ts'
import { crossfield } from './sections/crossfield.ts'
import { threads } from './sections/threads.ts'
import { ordering } from './sections/ordering.ts'
import { capabilities } from './sections/capabilities.ts'
import { approvals } from './sections/approvals.ts'
import { context } from './sections/context.ts'
import { encryption } from './sections/encryption.ts'
import { mls } from './sections/mls.ts'

export interface RunOptions extends SessionOptions {
  /** Called as each check settles, so a run that takes a minute is watchable. */
  onCheck?: (check: Check) => void
  /** Called as each section closes. */
  onSection?: (section: Section) => void
}

export async function run(options: RunOptions): Promise<Report> {
  const session = await Session.open(options)
  try {
    return await conduct(session, options)
  } finally {
    session.close()
  }
}

async function conduct(session: Session, options: RunOptions): Promise<Report> {
  const sections: Section[] = []
  const emit = (section: Section) => {
    sections.push(section)
    options.onSection?.(section)
  }

  const report = (profiles: Profile[]): Report => ({
    url: session.url,
    relay: session.info,
    implements: profiles,
    sections,
    suite: PROTOCOL_VERSION,
  })

  // Everything below is published into this one workspace except where a
  // section says otherwise, and the `unless` reasons are written to be read by
  // somebody who has never seen this file.
  const group = await session.workspace()
  const set = await specimens(session, group)

  // The provisional context. Every interop check is `any` — deliberately, since
  // interop *is* the Option A claim — so running it before the profile is known
  // costs nothing and skips nothing.
  const provisional: Ctx = { profiles: ['any'], absent: {}, onCheck: options.onCheck }

  const first = await interop(session, group, set, provisional)
  emit(first)

  if (!usable(first)) {
    emit({
      name: 'run',
      about: 'Why the rest of this run did not happen.',
      checks: [
        {
          id: 'run/reachable',
          what: 'stores at least one honest Quorum event',
          level: 'MUST',
          profile: 'any',
          section: 'run',
          outcome: 'fail',
          detail:
            'not one specimen was stored and served back, so every refusal check below would ' +
            'have passed for the wrong reason. Check the URL, whether this relay requires ' +
            'AUTH or an allow-list, and whether `QUORUM_OWNER_PUBKEYS` permits a new group',
        },
      ],
    })
    return report(['any'])
  }

  const detected = await detectProfile(session, set.thread)
  const ctx: Ctx = {
    profiles: detected.profiles,
    absent: detected.profiles.includes('quorum') ? {} : { quorum: detected.why },
    onCheck: options.onCheck,
  }
  // `service` is never in `profiles`, and that is on purpose: "does this relay
  // project threads" and "does this relay sign checkpoints" are separately
  // configurable, so a single detected answer would be wrong for most
  // deployments. Each service section probes for itself and reports `n/a` with
  // its own reason — which is why `service` is added unconditionally here and
  // the *sections* do the ruling out.
  ctx.profiles = [...detected.profiles, 'service']

  emit(await discovery(session, ctx))
  emit(await envelope(session, group, set, ctx))
  emit(await crossfield(session, group, set, ctx))
  emit(await threads(session, group, set, ctx))
  emit(await ordering(session, group, ctx))
  emit(await capabilities(session, group, set, ctx))
  emit(await approvals(session, group, set, ctx))
  emit(await context(session, group, set, ctx))
  emit(await encryption(session, group, ctx))
  emit(await mls(session, ctx))

  // Reported as detected, without `service`. A relay is not "a service relay";
  // it offers some services and not others, and the section-by-section `n/a`
  // lines are the honest version of that answer.
  return report(detected.profiles)
}
