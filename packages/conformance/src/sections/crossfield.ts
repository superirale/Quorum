/**
 * The rules a JSON Schema cannot carry, asked one at a time.
 *
 * `schemas/index.json` publishes a `cross_field_rules` table: the names of the
 * rules that span a field and a tag, or two fields, and therefore cannot be
 * written into any of the committed schemas. `z.toJSONSchema()` emits nothing
 * for a Zod refinement, so before that table existed these rules were enforced
 * by the TypeScript package and by nothing else — with no error anywhere to say
 * so. This suite is what found the last two of them, which is why the table
 * exists and why this section is driven by it rather than by a list written
 * here.
 *
 * So the loop is over the *published* codes. A rule added to the protocol with
 * no probe in this file fails the section rather than quietly going unasked,
 * which is the same discipline `assertComplete` applies to the specimens: a
 * conformance tool that silently stops asking a question reports good news.
 *
 * Every probe damages a specimen that the relay has already accepted, so a
 * refusal is an answer to the question asked rather than to some other thing
 * wrong with a hand-built event. The exception is `bad_thread_d`, which is a
 * rule about a kind no client may publish; it reports `n/a` with that reason.
 */

import { CROSS_FIELD_RULES, Kinds, TagName, type NostrEvent, type UnsignedEvent } from '@quorum/protocol'
import { now, withTag, type Session, type Verdict } from '../harness.ts'
import { section, type Ctx } from '../section.ts'
import type { Section } from '../report.ts'
import type { SpecimenSet } from '../specimens.ts'

export async function crossfield(
  session: Session,
  group: string,
  set: SpecimenSet,
  ctx: Ctx,
): Promise<Section> {
  const run = section(
    'cross-field',
    'The rules no JSON Schema can express, which is why they have to be published as a list.',
    ctx,
  )
  const { owner } = session

  const specimen = (kind: number): NostrEvent => {
    const found = set.stored.find((s) => s.kind === kind)?.event
    if (!found) throw new Error(`the kind ${kind} specimen was never published`)
    return found
  }

  /**
   * The specimen for `kind`, re-signed with one thing changed.
   *
   * Re-signed by *its own author*, which is not always the owner: the approval
   * response is the member's, because a response is signed by whoever the
   * request addressed. Signing it as the owner produces a different event with
   * a second thing wrong with it, and this suite's own signer refuses to — so
   * the check reported `could not ask` about a rule the relay enforces.
   */
  const bend = async (
    kind: number,
    damage: (event: UnsignedEvent, body: Record<string, unknown>) => UnsignedEvent,
  ): Promise<NostrEvent> => {
    const original = strip(specimen(kind))
    const author = [owner, session.member, session.stranger].find(
      (who) => who.publicKey === original.pubkey,
    )
    if (!author) throw new Error(`the kind ${kind} specimen was signed by nobody this suite holds`)
    const body = JSON.parse(original.content) as Record<string, unknown>
    const damaged = damage(original, body)
    // Re-serialised from `body` unless the damage already replaced `content`,
    // so a probe that only edits the body does not have to remember to.
    const content = damaged.content === original.content ? JSON.stringify(body) : damaged.content
    return author.sign({ ...damaged, content, created_at: now() })
  }

  /**
   * One violation per published code.
   *
   * A string instead of a builder means the question cannot be asked from out
   * here, with the reason — reported as `n/a`, never as a pass, because a rule
   * nobody checked is not a rule anybody has been shown to enforce.
   */
  const probes: Record<string, (() => Promise<NostrEvent>) | string> = {
    missing_input_digest: () =>
      bend(Kinds.Action, (event, body) => {
        delete body['input_digest']
        return event
      }),

    missing_action_tag: () =>
      bend(Kinds.Action, (event, body) => {
        // The proposal specimen carries no `action` tag, because its own id is
        // the action id. Advance its status and that absence becomes the
        // defect: a transition that names no chain is an outcome attached to
        // nothing, which an agent matching on action name alone would honour.
        body['status'] = 'running'
        return event
      }),

    unreachable_quorum: () =>
      bend(Kinds.ApprovalRequest, (event, body) => {
        // Addressed to one approver, asking for two. Nobody can ever satisfy
        // it, and the request looks pending forever rather than impossible.
        body['required'] = 2
        return event
      }),

    missing_modified_digest: () =>
      bend(Kinds.ApprovalResponse, (event, body) => {
        body['modified_input'] = { env: 'staging', replicas: 4 }
        return event
      }),

    many_recipients: () =>
      bend(Kinds.ChannelKey, (event) =>
        withTag(event, [TagName.Pubkey, session.stranger.publicKey, '', 'to']),
      ),

    recipient_mismatch: () =>
      bend(Kinds.ChannelKey, (event, body) => {
        body['recipient'] = session.stranger.publicKey
        return event
      }),

    mls_policy_epoch: () =>
      bend(Kinds.ChannelPolicy, (event) => ({
        ...event,
        content: JSON.stringify({ enc: 'mls', epoch: 1, changed_at: now() }),
      })),

    missing_epoch: () =>
      bend(Kinds.ChannelPolicy, (event) => ({
        ...event,
        content: JSON.stringify({ enc: 'nip44', changed_at: now() }),
      })),

    bad_thread_d:
      'thread state is relay-signed, so no client can publish one to ask this with; the rule ' +
      'guards a relay against its own projection, and this suite is outside it',
  }

  for (const rule of CROSS_FIELD_RULES) {
    const probe = probes[rule.code]
    await run.check(
      {
        id: rule.code,
        what: `refuses a kind ${rule.kinds.join('/')} event where ${rule.what}`,
        level: 'MUST',
        profile: 'quorum',
        unless: typeof probe === 'string' ? probe : false,
      },
      async (): Promise<Verdict> => {
        if (typeof probe !== 'function') {
          // Unreachable while `unless` is set above; here because the protocol
          // publishing a code this file has never heard of is the failure this
          // section exists to make loud.
          return {
            ok: false,
            why:
              `the protocol publishes ${rule.code} and this suite has no event that violates ` +
              'it, so no relay has been asked whether it enforces the rule',
          }
        }
        return session.refuses(await probe())
      },
    )
  }

  // Both channel-policy probes are events that would change this workspace's
  // encryption mode if a relay took them, and every section after this one
  // publishes plaintext. A relay that failed those two checks has already been
  // reported; what must not also happen is forty later checks failing because
  // the channel went dark behind them and this suite blaming the relay for it.
  //
  // Addressable replacement is the repair: the same `d`, a newer timestamp,
  // `plaintext` again. Reported as a check of its own so that a repair which
  // did not take is visible rather than inferred from the wreckage below.
  await run.check(
    {
      id: 'workspace-still-plaintext',
      what: 'is left with the plaintext policy this run started from',
      level: 'MUST',
      profile: 'quorum',
    },
    async () => {
      const policy = specimen(Kinds.ChannelPolicy)
      await session.accepts(
        await owner.sign({
          ...strip(policy),
          created_at: now() + 1,
          content: JSON.stringify({
            enc: 'plaintext',
            reason: 'restoring the workspace after the cross-field probes',
            changed_at: now(),
          }),
        }),
      )
      const [current] = await session.query({
        kinds: [Kinds.ChannelPolicy],
        '#h': [group],
        '#d': [group],
        limit: 1,
      })
      if (!current) return { ok: true, why: 'this relay keeps no channel policy to restore' }
      const mode = (JSON.parse(current.content) as { enc?: string }).enc
      return mode === 'plaintext'
        ? { ok: true }
        : {
            ok: false,
            why:
              `this workspace is now \`${mode}\`: a policy this suite expected to be refused was ` +
              'stored, and the plaintext policy that would undo it was not. Every check after ' +
              'this one is being asked of an encrypted channel and its answers say nothing',
          }
    },
  )

  return run.done()
}

function strip(event: NostrEvent): UnsignedEvent {
  return {
    pubkey: event.pubkey,
    created_at: event.created_at,
    kind: event.kind,
    tags: event.tags,
    content: event.content,
  }
}
