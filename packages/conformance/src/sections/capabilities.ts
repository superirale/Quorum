/**
 * The three things the relay is the resource for.
 *
 * Almost every capability in Quorum is checked where the work happens — the
 * deploy tool verifies the grant before it deploys, and the relay never learns
 * what `action:deploy` means. These three are the exceptions, because there is
 * no other resource to check them at: membership is decided by whatever admits
 * you, a thread's budget is a number the relay projects, and the encryption
 * policy is the one event the relay must read on a channel it otherwise cannot.
 *
 * **Every refusal here is published beside its positive control**, in the same
 * run against the same relay. A suite that only publishes ungranted requests
 * and watches them bounce passes identically against a relay that refuses
 * everyone — including the members it is supposed to admit — and that relay is
 * broken in the direction an operator notices at three in the morning rather
 * than the direction this suite is looking. The control needs a key the relay
 * has never seen, which is why {@link Session.newcomer} exists and why the
 * stranger is never granted anything: a granted stranger would leave every
 * later refusal check quietly testing a member.
 */

import { INVOKE, Kinds, Resource, SCOPE_GROUP } from '@quorum/protocol'
import { grant } from '@quorum/sdk'
import { NIP29, now, type Session } from '../harness.ts'
import { section, type Ctx } from '../section.ts'
import type { Section } from '../report.ts'
import type { SpecimenSet } from '../specimens.ts'

export async function capabilities(
  session: Session,
  group: string,
  set: SpecimenSet,
  ctx: Ctx,
): Promise<Section> {
  const run = section(
    'capabilities',
    'Membership, budgets and the encryption policy: the grants the relay itself checks.',
    ctx,
  )
  const { owner, member, stranger } = session

  const joinRequest = (who: { publicKey: string }) => ({
    pubkey: who.publicKey,
    created_at: now(),
    kind: NIP29.join,
    tags: [['h', group]],
    content: 'a conformance run asking to be let in',
  })

  await run.check(
    {
      id: 'join',
      what: 'refuses a join request from a key holding no `group:join` grant',
      level: 'MUST',
      profile: 'quorum',
    },
    async () => session.refuses(await stranger.sign(joinRequest(stranger))),
  )

  await run.check(
    {
      id: 'join-granted',
      what: 'admits a key an owner has signed a `group:join` grant to',
      level: 'MUST',
      profile: 'quorum',
    },
    async () => {
      const newcomer = session.newcomer()
      const issued = await session.accepts(
        await session.craft(owner, {
          ...grant({
            grantee: newcomer.publicKey,
            resource: Resource.Join,
            actions: [INVOKE],
            scope: { [SCOPE_GROUP]: group },
            issuedAt: now(),
          }),
          group,
          counter: session.next(),
        }),
      )
      if (!issued.ok) return { ok: false, why: `the grant itself was refused: ${issued.why}` }
      const bounced = await session.refuses(await newcomer.sign(joinRequest(newcomer)))
      if (bounced.ok) {
        return {
          ok: false,
          why:
            'refused a join request backed by a grant from the workspace owner: ' +
            `${bounced.why}. An invitation nobody can present is not an invitation`,
        }
      }
      // Taking the 9021 is not the same as admitting them, and the difference
      // is visible: a non-member's `h`-tagged event is refused by NIP-29's own
      // rules, so a chat message that lands is the membership the grant bought.
      return session.accepts(
        await session.craft(newcomer, {
          kind: Kinds.ChatMessage,
          group,
          text: 'hello — published by a key that joined with a capability grant',
          counter: session.next(newcomer),
        }),
      )
    },
  )

  await run.check(
    {
      id: 'budget',
      what: 'refuses a `set_budget` op from a member holding no `thread:budget` grant',
      level: 'MUST',
      profile: 'quorum',
    },
    async () =>
      session.refuses(
        await session.craft(member, {
          kind: Kinds.ThreadOp,
          group,
          thread: set.thread,
          counter: session.next(member),
          body: { op: 'set_budget', budget: { tokens: 1_000_000 } },
        }),
      ),
  )

  await run.check(
    {
      id: 'budget-granted',
      what: 'accepts the same op once that grant has been issued',
      level: 'MUST',
      profile: 'quorum',
    },
    async () => {
      const issued = await session.accepts(
        await session.craft(owner, {
          ...grant({
            grantee: member.publicKey,
            resource: Resource.ThreadBudget,
            actions: [INVOKE],
            scope: { [SCOPE_GROUP]: group },
            issuedAt: now(),
          }),
          group,
          counter: session.next(),
        }),
      )
      if (!issued.ok) return { ok: false, why: `the grant itself was refused: ${issued.why}` }
      // A ceiling far above anything this run spends. A budget the run then
      // exhausts would pause the thread, and every later section would be
      // publishing into a paused one — the suite manufacturing the refusals it
      // goes on to report.
      return session.accepts(
        await session.craft(member, {
          kind: Kinds.ThreadOp,
          group,
          thread: set.thread,
          counter: session.next(member),
          body: { op: 'set_budget', budget: { tokens: 100_000_000 } },
        }),
      )
    },
  )

  await run.check(
    {
      id: 'policy',
      what: 'refuses a channel policy from a member holding no `channel:encrypt` grant',
      level: 'MUST',
      profile: 'quorum',
    },
    async () =>
      // The dangerous direction is *off*: anyone who can publish a policy
      // saying `plaintext` has turned a private channel public for every
      // message after it, with no ciphertext failing and no MAC complaining.
      // The specimen says `plaintext` for exactly that reason — it is the
      // downgrade, and it is the one this check wants refused.
      session.refuses(
        await session.craft(member, {
          kind: Kinds.ChannelPolicy,
          group,
          d: group,
          counter: session.next(member),
          body: { enc: 'plaintext', reason: 'a conformance run', changed_at: now() },
        }),
      ),
  )

  return run.done()
}
