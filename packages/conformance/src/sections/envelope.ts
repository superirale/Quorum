/**
 * The tags, and the two NIP-01 facts underneath them.
 *
 * Every check here publishes an event that is correct in every respect but one.
 * That is the whole method: an event assembled by hand to be wrong is usually
 * wrong in several ways, so a refusal proves only that *something* was wrong
 * with it, and the check's name then claims a rule the relay may not actually
 * have. Each specimen below starts from something `build()` produced and breaks
 * exactly one thing, so the relay's "no" is an answer to the question asked.
 *
 * Two of the checks are profile `any`. A bad signature and a bad id are NIP-01,
 * not Quorum, and a relay that stores either is not a relay this protocol can
 * be built on at all — the audit trail is the signatures, so a relay that does
 * not check them is serving an audit trail that means nothing. They are here
 * rather than in `interop` because they are envelope facts, and because a
 * section that reported `n/a` for everything against a generic relay would tell
 * its operator nothing.
 */

import {
  Kinds,
  TagName,
  computeId,
  type NostrEvent,
  type UnsignedEvent,
} from '@quorum/protocol'
import {
  altless,
  now,
  replaceTag,
  withoutTag,
  type Session,
} from '../harness.ts'
import { section, type Ctx } from '../section.ts'
import type { Section } from '../report.ts'
import type { SpecimenSet } from '../specimens.ts'

export async function envelope(
  session: Session,
  group: string,
  set: SpecimenSet,
  ctx: Ctx,
): Promise<Section> {
  const run = section(
    'envelope',
    'What the relay refuses: one honest event with one thing wrong with it, each time.',
    ctx,
  )
  const { owner } = session

  /** A summary that is correct apart from whatever `damage` does to it. */
  const damaged = async (
    damage: (event: UnsignedEvent) => UnsignedEvent,
  ): Promise<NostrEvent> => {
    const good = stripSignature(await altless(session, set.thread))
    const whole: UnsignedEvent = {
      ...good,
      tags: [...good.tags, [TagName.Alt, 'Summary: a conformance probe']],
    }
    return owner.sign(damage(whole))
  }

  await run.check(
    {
      id: 'alt',
      what: 'refuses a Quorum event with no `alt` tag',
      level: 'MUST',
      profile: 'quorum',
    },
    async () => session.refuses(await altless(session, set.thread)),
  )

  await run.check(
    {
      id: 'alt-length',
      what: 'refuses an `alt` longer than 280 characters',
      level: 'MUST',
      profile: 'quorum',
    },
    async () =>
      session.refuses(
        await damaged((e) => replaceTag(e, [TagName.Alt, 'x'.repeat(281)])),
      ),
  )

  await run.check(
    {
      id: 'group',
      what: 'refuses a Quorum event with no `h` tag naming its channel',
      level: 'MUST',
      profile: 'quorum',
    },
    async () =>
      session.refuses(await damaged((e) => withoutTag(e, TagName.Group))),
  )

  await run.check(
    {
      id: 'enc',
      what: 'refuses an `enc` value that is not one of the three modes',
      level: 'MUST',
      profile: 'quorum',
    },
    async () =>
      session.refuses(await damaged((e) => replaceTag(e, [TagName.Enc, 'rot13']))),
  )

  await run.check(
    {
      id: 'counter',
      what: 'refuses a `counter` that is not a non-negative integer',
      level: 'MUST',
      profile: 'quorum',
    },
    async () =>
      session.refuses(await damaged((e) => replaceTag(e, [TagName.Counter, 'seven']))),
  )

  await run.check(
    {
      id: 'identifier',
      what: 'refuses an addressable Quorum kind with no `d` tag',
      level: 'MUST',
      profile: 'quorum',
    },
    async () => {
      const manifest = await session.craft(owner, {
        kind: Kinds.AgentManifest,
        group,
        d: 'conformance-no-d',
        counter: session.next(),
        body: {
          name: 'conformance',
          description: 'a manifest published to have its `d` tag taken off',
          operator: owner.publicKey,
        },
      })
      return session.refuses(
        await owner.sign(withoutTag(manifest, TagName.Identifier)),
      )
    },
  )

  await run.check(
    {
      id: 'body',
      what: 'refuses a body that does not match its kind’s schema',
      level: 'MUST',
      profile: 'quorum',
    },
    async () => {
      // The action specimen with a status the state machine does not have.
      // A schema violation and nothing else, which is the point: the rules that
      // span two fields are asked separately, in the cross-field section, and a
      // check that conflated them would report "this relay validates bodies"
      // about a relay that only has half of it.
      //
      // `succeeding` rather than a nonsense string, because a plausible typo is
      // what actually reaches a relay — and a status outside the machine is not
      // cosmetic: every reader deciding whether an action is still running
      // matches on this field, so one nobody knows is an action that is neither
      // finished nor in flight.
      const action = set.stored.find((s) => s.kind === Kinds.Action)?.event
      if (!action) return { ok: false, why: 'the action specimen was never built' }
      const body = JSON.parse(action.content) as Record<string, unknown>
      body['status'] = 'succeeding'
      return session.refuses(
        await owner.sign({ ...stripSignature(action), content: JSON.stringify(body) }),
      )
    },
  )

  await run.check(
    {
      id: 'timestamp',
      what: 'refuses an event dated a week into the future',
      level: 'MUST',
      profile: 'quorum',
    },
    async () =>
      session.refuses(
        await session.craft(owner, {
          kind: Kinds.ChatMessage,
          group,
          text: 'a message dated next week, to see whether the relay bounds its clock',
          counter: session.next(),
          created_at: now() + 7 * 24 * 3600,
        }),
      ),
  )

  await run.check(
    {
      id: 'kinds',
      what: 'restricts writes to the kinds the NIP defines',
      // MAY, and both answers are conformant, which is why this reports what
      // the relay does rather than judging it. Refusing is what the reference
      // relay does and what a workspace operator usually wants. Carrying an
      // unknown kind is *also* right: `alt` exists so that an agent meeting
      // kind 8199 from a newer peer has a sentence to work from, and a relay
      // that refuses every future kind is the thing that stops the protocol
      // from ever gaining one.
      level: 'MAY',
      profile: 'quorum',
    },
    async () => {
      const future = session.vet(
        await owner.sign({
          pubkey: owner.publicKey,
          created_at: now(),
          kind: 8199,
          tags: [
            [TagName.Group, group],
            [TagName.Alt, 'An event of a kind this NIP does not define'],
          ],
          content: '{}',
        }),
      )
      const verdict = await session.refuses(future)
      return verdict.ok
        ? { ok: true, why: `refuses kind 8199 — ${verdict.why}` }
        : {
            ok: true,
            why:
              'carries kind 8199, a kind this NIP does not define; a client that meets one ' +
              'has its `alt` tag to render, which is what that rule is for',
          }
    },
  )

  // --- NIP-01, and therefore true of every relay -----------------------------

  await run.check(
    {
      id: 'id',
      what: 'refuses an event whose `id` is not the hash of its own fields',
      level: 'MUST',
      profile: 'any',
    },
    async () => {
      const honest = await honestChat(session, group)
      // The id left stale, which is the easy half. Leave it alone on every
      // tamper case and the id check catches everything, and the suite proves
      // only that sha256 works — see the M1 note. The next check is the other
      // half.
      return session.refuses({ ...honest, content: `${honest.content} (tampered)` })
    },
  )

  await run.check(
    {
      id: 'signature',
      what: 'refuses an event whose signature does not cover its contents',
      level: 'MUST',
      profile: 'any',
    },
    async () => {
      const honest = await honestChat(session, group)
      // Id recomputed over the tampered content, signature left as it was.
      // This is the realistic attack: recomputing an id is free for anyone
      // relaying an event, and only the signature stops them.
      const tampered = { ...honest, content: `${honest.content} (tampered)` }
      return session.refuses({ ...tampered, id: computeId(stripSignature(tampered)) })
    },
  )

  return run.done()
}

/** An ordinary chat message, signed and valid, for a check to then damage. */
async function honestChat(session: Session, group: string): Promise<NostrEvent> {
  return session.craft(session.owner, {
    kind: Kinds.ChatMessage,
    group,
    text: 'a message published only so that something can be done to it',
    counter: session.next(),
  })
}

function stripSignature(event: NostrEvent): UnsignedEvent {
  return {
    pubkey: event.pubkey,
    created_at: event.created_at,
    kind: event.kind,
    tags: event.tags,
    content: event.content,
  }
}
