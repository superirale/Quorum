/**
 * Option A, which is the only section that applies to every relay alive.
 *
 * *Every Quorum event is valid on any generic relay.* That sentence is the
 * reason this protocol is a set of kind numbers rather than a server, and it is
 * the one claim whose failure is a fault in the **protocol** rather than in the
 * relay under test. A plain strfry that has never heard of a kind 8102 should
 * pass every check here and report `n/a` for most of the rest of the suite.
 *
 * So this section runs first, unconditionally, and every check is a MUST. If it
 * cannot get a single honest event stored, {@link run} stops: at that point
 * every refusal the later sections observe is equally well explained by a relay
 * that is simply not accepting traffic, and reporting forty refusals as forty
 * passes is worse than reporting nothing.
 */

import { addressees, counter } from '@quorum/protocol'
import { type Session } from '../harness.ts'
import { held, section, type Ctx } from '../section.ts'
import type { Section } from '../report.ts'
import { republish, type SpecimenSet } from '../specimens.ts'

export async function interop(
  session: Session,
  group: string,
  set: SpecimenSet,
  ctx: Ctx,
): Promise<Section> {
  const run = section(
    'interop',
    'Option A: every Quorum event is valid on any relay, generic or not.',
    ctx,
  )

  for (const specimen of set.stored) {
    await run.check(
      {
        id: `stores-${specimen.kind}`,
        what: `stores and serves back a kind ${specimen.kind} ${specimen.name}, unchanged`,
        level: 'MUST',
        profile: 'any',
      },
      () => session.accepts(specimen.event),
    )
  }

  for (const specimen of set.ephemeral) {
    await run.check(
      {
        id: `routes-${specimen.kind}`,
        what: `routes a kind ${specimen.kind} ${specimen.name} and does not store it`,
        level: 'MUST',
        profile: 'any',
      },
      async () => {
        const accepted = await session.refuses(specimen.event)
        // A refusal is legitimate — NIP-01 lets a relay decline anything — but
        // "stored it" is not, because an ephemeral event a reader can backfill
        // is a cancel that can be replayed onto next week's work.
        if (accepted.ok) return { ok: true, why: `refused rather than routed: ${accepted.why}` }
        const [held_] = await session.query({ ids: [specimen.event.id], limit: 1 })
        return held(
          held_ === undefined,
          'stored an event in the 20000–29999 range; a stored interrupt or lease can be ' +
            'replayed by a reader backfilling history, onto work that is not the work it named',
        )
      },
    )
  }

  // The one check in this section that is not a MUST, and the level is NIP-09's
  // rather than a concession to the relay under test.
  //
  // NIP-09: *"Relays SHOULD continue to publish/share the deletion request
  // events indefinitely, as clients may already have the event that's intended
  // to be deleted."* A relay that drops the request has not broken interop —
  // nothing addressed the request, nothing replies to it, and a reader that
  // never sees one is in exactly the state of a reader whose relay honoured it.
  // What it costs is narrower and worth naming: a redaction leaves no signed
  // record that anybody asked for it, so "this was deleted" and "this was never
  // published" become the same observation, and on a relay that also signs
  // checkpoints the request is a regular event inside a committed window —
  // dropping it is indistinguishable, to an auditor, from withholding.
  //
  // Reported as its own check rather than folded into the `stores-*` loop
  // because a SHOULD failing is a note and a MUST failing is a verdict, and a
  // suite that files a recommendation under "this relay does not conform to
  // Option A" has given an operator a reason to ignore the whole report.
  await run.check(
    {
      id: 'keeps-deletions',
      what: `serves back a kind ${set.deletion.kind} deletion request it accepted`,
      level: 'SHOULD',
      profile: 'any',
    },
    async () => {
      const accepted = await session.accepts(set.deletion.event)
      if (accepted.ok) return accepted
      // "Accepted and then not served back" is the honoured-it case as well as
      // the dropped-it case, and this suite cannot tell them apart from the
      // outside. Both are the recommendation not being followed, so the detail
      // says what was observed rather than what was decided.
      return {
        ok: false,
        why:
          `${accepted.why}; NIP-09 recommends a relay keep serving the request, so that a ` +
          'reader can tell a redaction from an event that never existed',
      }
    },
  )

  const addressed = set.stored.find((s) => addressees(s.event.tags).length > 0)?.event

  await run.check(
    {
      id: 'to-marker',
      what: 'preserves the `to` marker in position 4 of a `p` tag',
      level: 'MUST',
      profile: 'any',
      unless: addressed ? false : 'no addressed specimen was accepted',
    },
    async () => {
      const [back] = await session.query({ ids: [addressed!.id], limit: 1 })
      if (!back) return { ok: false, why: 'the addressed specimen is not being served back' }
      return held(
        addressees(back.tags).length === addressees(addressed!.tags).length,
        'the marker did not survive: addressing is the only signal an agent acts on, so a ' +
          'relay that normalises it away turns every addressed event into a mention',
      )
    },
  )

  await run.check(
    {
      id: 'counter',
      what: 'preserves the `counter` tag, which is how a reader detects a gap',
      level: 'MUST',
      profile: 'any',
    },
    async () => {
      const first = set.stored.find((s) => counter(s.event.tags) !== undefined)
      if (!first) return { ok: false, why: 'the suite published no counter at all' }
      const [back] = await session.query({ ids: [first.event.id], limit: 1 })
      if (!back) return { ok: false, why: 'the specimen is not being served back' }
      return held(
        counter(back.tags) === counter(first.event.tags),
        `counter ${counter(first.event.tags)} came back as ${counter(back.tags)}`,
      )
    },
  )

  await run.check(
    {
      id: 'filter-p',
      what: 'answers a `#p` filter, which is how an agent finds what is addressed to it',
      level: 'MUST',
      profile: 'any',
      unless: addressed ? false : 'no addressed specimen was accepted',
    },
    async () => {
      // `#h` alongside, always: relay29 closes a tag-filtered subscription that
      // does not also name a group, and a CLOSED read as an empty result is a
      // false accusation this suite would have no way to notice.
      const found = await session.query({
        '#h': [group],
        '#p': [session.member.publicKey],
        kinds: [addressed!.kind],
        limit: 20,
      })
      return held(
        found.some((e) => e.id === addressed!.id),
        `the filter matched ${found.length} events and none of them was the addressed specimen`,
      )
    },
  )

  await run.check(
    {
      id: 'filter-root',
      what: 'answers a `#E` filter, which is how a thread is read back',
      level: 'MUST',
      profile: 'any',
    },
    async () => {
      const found = await session.query({ '#h': [group], '#E': [set.thread.id], limit: 50 })
      return held(
        found.length > 0,
        'nothing came back for the thread root every threaded specimen names; a thread ' +
          'that cannot be queried by its root is a thread no client can open',
      )
    },
  )

  await run.check(
    {
      id: 'dedupe',
      what: 'dedupes by event id — the same bytes twice are one event',
      level: 'MUST',
      profile: 'any',
    },
    async () => {
      const original = set.stored.find((s) => s.kind === 9)?.event
      if (!original) return { ok: false, why: 'the chat specimen was never published' }
      const again = await republish(session.owner, original)
      if (again.id !== original.id) {
        return { ok: false, why: 'suite error: the rebuild produced a different id' }
      }
      try {
        await (await session.client(session.owner)).publish(again)
      } catch {
        // A `duplicate:` refusal is NIP-01's own answer and is a pass, not a
        // failure: both spellings say the relay holds one copy.
      }
      const found = await session.query({ ids: [original.id] })
      return held(
        found.length === 1,
        `${found.length} copies of one id came back; idempotency in this protocol is the ` +
          'relay deduping by id, and every retry in the SDK rests on it',
      )
    },
  )

  await run.check(
    {
      id: 'addressable',
      what: 'keeps only the newest event per (pubkey, kind, `d`)',
      level: 'MUST',
      profile: 'any',
    },
    async () => {
      const memory = set.stored.find((s) => s.kind === 38104)?.event
      if (!memory) return { ok: false, why: 'the agent_memory specimen was never published' }
      const replacement = await session.craft(session.owner, {
        kind: 38104,
        group,
        d: 'conformance/last-run',
        counter: session.next(),
        body: { value: { relay: session.url, pass: 2 }, updated_at: memory.created_at + 1 },
        created_at: memory.created_at + 1,
      })
      const took = await session.accepts(replacement)
      if (!took.ok) return { ok: false, why: `refused the replacement: ${took.why}` }
      const found = await session.query({
        authors: [session.owner.publicKey],
        kinds: [38104],
        '#d': ['conformance/last-run'],
        '#h': [group],
        limit: 10,
      })
      return held(
        found.length === 1 && found[0]!.id === replacement.id,
        `${found.length} events came back for one coordinate` +
          (found[0]?.id === memory.id ? ', and the newest is not the one served' : '') +
          '; revocation of a capability grant is republication, so a relay that keeps the ' +
          'old one keeps the revoked grant',
      )
    },
  )

  return run.done()
}

/** Did the interop section find a relay that is accepting traffic at all? */
export function usable(interopSection: Section): boolean {
  return interopSection.checks.some((c) => c.id.startsWith('interop/stores-') && c.outcome === 'pass')
}
