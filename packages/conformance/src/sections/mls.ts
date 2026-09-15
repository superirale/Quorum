/**
 * The delivery service, which is all a relay is on an `mls` channel.
 *
 * RFC 9420 assumes something that stores, routes and orders messages it cannot
 * read, and says nothing about how. Quorum's answer is that a relay hosting an
 * `mls` channel contains **no MLS code at all** — every rule below is decided
 * from the envelope and from one JSON field deliberately left in the clear. That
 * is a property worth protecting rather than a limitation to apologise for: a
 * relay that parsed MLSMessages would be a second implementation of a wire
 * format, in a second language, that has to agree with the first forever, and
 * the first disagreement would present as a workspace whose members cannot talk
 * to each other.
 *
 * So there are four rules here and there is not going to be a fifth:
 *
 * - a KeyPackage lands in the slot that will retire it;
 * - a Welcome names exactly one member, so the addressing filter finds it;
 * - at most one commit per channel per epoch, so the members do not split;
 * - an `mls` policy states no epoch, because no number written there could be
 *   true for longer than it takes somebody to commit.
 *
 * Everything else — whether the ciphertext opens, whether the committer was in
 * the tree, whether the credential matches the pubkey — is checked by members,
 * because only members can check it.
 *
 * **Two of the specimens here are opaque by construction and one is real.** A
 * Welcome's `invite` and a commit's `commit` are ciphertext that no conformant
 * relay may read, so a placeholder is indistinguishable from the genuine article
 * to every party this section is testing. A KeyPackage is not: its content is a
 * public MLSMessage anyone can decode, so this section generates a real one with
 * real key material. A relay refusing a placeholder would otherwise look exactly
 * like a relay enforcing the rule, and the control would fail for a reason that
 * is the suite's fault.
 *
 * The channel is a workspace of its own and nobody is in its ratchet, which is
 * what makes publishing an undecodable commit into it harmless.
 */

import { Kinds, TagName, build, type NostrEvent, type UnsignedEvent } from '@quorum/protocol'
import { LocalSigner, mlsCiphersuite, mlsKeyPackage, mlsKeyPackageEvent } from '@quorum/sdk'
import { now, replaceTag, type Session } from '../harness.ts'
import { section, type Ctx } from '../section.ts'
import type { Section } from '../report.ts'
import { freeEpoch } from '../specimens.ts'

export async function mls(session: Session, ctx: Ctx): Promise<Section> {
  const run = section(
    'mls',
    'Storing, routing and ordering a channel the relay cannot read a word of.',
    ctx,
  )
  const { owner, member, stranger } = session
  const group = await session.workspace('mls')

  /**
   * Sign an event the local validator would refuse, which is the point of it.
   *
   * Three of the four rules below are enforced in `@quorum/protocol` as well as
   * at the relay, so `Session.craft` cannot build their specimens — it validates
   * first and would record this suite's own correctness as a `skip`. Going round
   * it is deliberate and is confined to these call sites, each of which starts
   * from an event `build()` produced and breaks exactly one thing about it.
   */
  const unvetted = (who: LocalSigner, unsigned: UnsignedEvent): Promise<NostrEvent> =>
    who.sign(unsigned)

  const settled = await run.check(
    {
      id: 'policy',
      what: 'stores a kind 38107 saying `mls`, which states no epoch',
      level: 'MUST',
      profile: 'any',
    },
    async () =>
      session.accepts(
        await session.craft(owner, {
          kind: Kinds.ChannelPolicy,
          group,
          d: group,
          counter: session.next(),
          body: { enc: 'mls', reason: 'a conformance run', changed_at: now() },
        }),
      ),
  )

  const notMls = settled.ok
    ? false
    : `the channel could not be turned mls (${settled.why}), so nothing below is being asked ` +
      'of an mls channel'

  // --- the KeyPackage slot ---------------------------------------------------

  // Real key material, generated once and published twice: into the slot the
  // rule requires, and into another. The only difference between the two events
  // is the `d` tag, which is what makes the second one a test of the rule
  // rather than a test of whether this relay likes MLS.
  const suite = await mlsCiphersuite()
  const identity = await mlsKeyPackage(owner.publicKey, suite)
  const keyPackage = await mlsKeyPackageEvent({ group, identity, ciphersuite: suite })

  const offered = await run.check(
    {
      id: 'key-package',
      what: 'accepts a kind 30443 KeyPackage in its own channel’s slot',
      level: 'MUST',
      profile: 'quorum',
      unless: notMls,
    },
    async () =>
      session.accepts(
        await session.craft(owner, { ...keyPackage, group, counter: session.next() }),
      ),
  )

  await run.check(
    {
      id: 'key-package-slot',
      what: 'refuses a KeyPackage whose `d` is not the channel it is published in',
      level: 'MUST',
      profile: 'quorum',
      unless: notMls,
    },
    async () =>
      // Not untidiness. A package in another slot still answers the `#h` query
      // an inviter makes, so it looks fetchable and usable — but the member's
      // *next* package lands somewhere else and never replaces it. The spent
      // one stays live forever, an inviter commits an Add against a private
      // half the joiner discarded months ago, and the result is a member
      // sitting in the ratchet tree who can never read a word of the channel
      // they were told they had joined. Nothing reports it at any other layer.
      session.refuses(
        await unvetted(
          owner,
          replaceTag(
            build({
              ...keyPackage,
              pubkey: owner.publicKey,
              group,
              counter: session.next(),
            }),
            [TagName.Identifier, `${group}-elsewhere`],
          ),
        ),
      ),
  )

  // --- the Welcome -----------------------------------------------------------

  const spent = offered.ok ? await keyPackageId(session, group) : undefined

  const welcomeBody = async (): Promise<Record<string, unknown>> => ({
    epoch: 0,
    // A NIP-44 payload from the inviter to the recipient, which is what an
    // honest Welcome carries. What it wraps here is a placeholder rather than a
    // framed MLS Welcome and a ratchet tree, because nothing outside the
    // recipient's own client may open this — the relay least of all.
    invite: await owner.nip44Encrypt(
      member.publicKey,
      JSON.stringify({ welcome: 'AA==', ratchet_tree: 'AA==' }),
    ),
    recipient: member.publicKey,
    key_package: spent ?? '0'.repeat(64),
  })

  await run.check(
    {
      id: 'welcome',
      what: 'accepts a kind 8111 Welcome addressed to one member',
      level: 'MUST',
      profile: 'quorum',
      unless: notMls,
    },
    async () =>
      session.accepts(
        await session.craft(owner, {
          kind: Kinds.MlsWelcome,
          group,
          to: [member.publicKey],
          counter: session.next(),
          body: await welcomeBody(),
        }),
      ),
  )

  await run.check(
    {
      id: 'welcome-recipients',
      what: 'refuses a Welcome addressed to more than one member',
      level: 'MUST',
      profile: 'quorum',
      unless: notMls,
    },
    async () =>
      // Built by hand rather than through `craft`, because the protocol package
      // refuses to produce one — which is the point of asking the relay too. A
      // Welcome carries key material sealed to a single member's KeyPackage, so
      // the second addressee fetches it, fails to find their own package among
      // its secrets, and is required by the spec to read that as "not mine"
      // rather than as an error. They are told nothing, and the member who was
      // owed a Welcome waits forever for one that was, from their side, never
      // sent.
      session.refuses(
        await unvetted(
          owner,
          build({
            kind: Kinds.MlsWelcome,
            pubkey: owner.publicKey,
            group,
            to: [member.publicKey, stranger.publicKey],
            counter: session.next(),
            body: await welcomeBody(),
          }),
        ),
      ),
  )

  // --- and the one ordering decision only a delivery service can make --------

  // The same epoch for both checks below — the second one is a deliberate
  // collision with the first — and it has to be an epoch this channel holds no
  // commit for, or a re-run against an existing workspace reports the relay's
  // correct refusal as a failure. See `freeEpoch`.
  const epoch = await freeEpoch(session, group)

  const commitBody = (adds: string[]) => ({
    epoch,
    // Opaque to everyone but the members, by design: this is where the relay's
    // refusal to parse MLS is load-bearing rather than convenient.
    commit: `AA==${adds.length}`,
    adds,
  })

  const first = await run.check(
    {
      id: 'commit',
      what: 'accepts a kind 8112 commit for an epoch it holds none for',
      level: 'MUST',
      profile: 'quorum',
      unless: notMls,
    },
    async () =>
      session.accepts(
        await session.craft(owner, {
          kind: Kinds.MlsCommit,
          group,
          counter: session.next(),
          body: commitBody([member.publicKey]),
        }),
      ),
  )

  await run.check(
    {
      id: 'commit-epoch',
      what: 'refuses a second commit for an epoch that already has one',
      level: 'SHOULD',
      profile: 'quorum',
      unless:
        notMls ||
        (first.ok ? false : `no first commit was stored (${first.why}), so there is no epoch to collide with`),
    },
    async () => {
      // Two members holding the same epoch may both commit, having neither seen
      // the other, and MLS allows exactly one of those to become the group's
      // next epoch. Nothing in the protocol picks the winner; a delivery service
      // does. First stored wins, which is arbitrary and meant to be — what
      // matters is that every member sees the same one, not which. The loser is
      // stranded at their old epoch by the ordinary "a commit was missed" rule
      // and has to be re-added, which is the correct outcome rather than a
      // degradation of it: a committer whose commit was refused has not moved,
      // and knows it.
      //
      // SHOULD rather than MUST, and the reason is Option A. A generic relay
      // serialises nothing at all, so every receiver has to settle the tie
      // deterministically regardless of who is carrying the channel; a relay
      // that does this is sparing its members a repair, not supplying a
      // guarantee anything rests on.
      const verdict = await session.refuses(
        await session.craft(owner, {
          kind: Kinds.MlsCommit,
          group,
          counter: session.next(),
          body: commitBody([stranger.publicKey]),
        }),
      )
      return verdict.ok
        ? verdict
        : {
            ok: false,
            why:
              `stored a second commit for epoch ${epoch}. Members reading this channel will apply ` +
              'whichever they see first and diverge; a relay that declines to serialise should ' +
              'say so in its NIP-11 document rather than by storing both',
          }
    },
  )

  await run.check(
    {
      id: 'policy-epoch',
      what: 'refuses an `mls` channel policy that states an epoch',
      level: 'MUST',
      profile: 'quorum',
      unless: notMls,
    },
    async () =>
      // Last, because an accepted one would replace the policy every check
      // above depends on. The rule is cross-field — `epoch` is legal on a
      // `nip44` policy and mandatory there — which is exactly why it is worth
      // asking a relay about: it cannot be expressed in the JSON Schema the
      // committed table publishes, so an implementation that validates from the
      // schema alone does not have it. Accepting one bricks the channel in the
      // quietest way available: every Quorum client refuses to parse the event,
      // so the workspace reads as having no encryption policy at all.
      session.refuses(
        await unvetted(
          owner,
          build({
            kind: Kinds.ChannelPolicy,
            pubkey: owner.publicKey,
            group,
            d: group,
            counter: session.next(),
            body: { enc: 'mls', epoch: 1, changed_at: now() },
          }),
        ),
      ),
  )

  return run.done()
}

/** The id of the KeyPackage the relay is holding in this channel's slot. */
async function keyPackageId(session: Session, group: string): Promise<string | undefined> {
  const [found] = await session.query({
    kinds: [Kinds.MlsKeyPackage],
    '#d': [group],
    '#h': [group],
    limit: 1,
  })
  return found?.id
}
