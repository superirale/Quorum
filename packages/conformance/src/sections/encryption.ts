/**
 * A relay enforcing a confidentiality it cannot verify.
 *
 * This is the oddest section in the suite, and the reason is worth stating
 * before any of the checks make sense. Every other rule here is about something
 * the relay can read: a tag, a signature, a role, a number. On a `nip44` channel
 * the relay can read none of the payload and cannot tell a NIP-44 v2 ciphertext
 * from a paragraph of base64 noise. What it *can* read is the kind 38107 policy,
 * because that event is deliberately left in the clear, and the `enc` tag,
 * because tags are never sealed — and that turns out to be enough for the check
 * that matters: on a channel whose policy says `nip44`, a content-bearing event
 * that is not tagged `enc=nip44` is plaintext, whatever else it is.
 *
 * So these checks are all about the envelope, and every one of them is a
 * `quorum` rule. A generic relay stores the policy, stores the wraps, stores the
 * sealed messages and stores the leak, and is conformant while doing it: Option
 * A says every Quorum event is valid on any relay, and the price of that is that
 * only a relay reading the policy can refuse the one event that contradicts it.
 *
 * **Both directions are checked, and the less obvious one is the more dangerous.**
 * A sealed event on a *plaintext* channel is a one-tag bypass of body validation
 * — setting `enc` is what tells a validator to skip the schema — so a relay that
 * only looked for leaks would accept any content at all under a kind it believes
 * it is checking.
 *
 * **Who may publish a policy is asked once, in `capabilities`.** It belongs
 * there rather than here — it is a grant check, and the dangerous edit is
 * `plaintext` on a channel that was encrypted — and asking it twice would give
 * one rule two rows in the report, which for a failing relay means two entries
 * to fix and one bug.
 *
 * The channel gets a workspace of its own. A policy is addressable on the group
 * id, so encrypting the run's main workspace would invalidate every plaintext
 * specimen published after it and the refusals would be recorded against the
 * relay.
 */

import {
  EncMode,
  Kinds,
  TagName,
  build,
  conversationKeyToHex,
  randomConversationKey,
  sealEvent,
  type BuildOptions,
  type NostrEvent,
} from '@quorum/protocol'
import { LocalSigner } from '@quorum/sdk'
import { now, type Session } from '../harness.ts'
import { section, type Ctx } from '../section.ts'
import type { Section } from '../report.ts'

/** The epoch this section's channel is minted at. A `nip44` channel starts at 1. */
const EPOCH = 1

export async function encryption(session: Session, group: string, ctx: Ctx): Promise<Section> {
  const run = section(
    'encryption',
    'The `nip44` policy, and the two events it lets a relay refuse without reading either.',
    ctx,
  )
  const { owner, member } = session
  const key = randomConversationKey()

  /** Build, seal under the channel key, sign, and refuse to publish an invalid one. */
  const seal = async (
    who: LocalSigner,
    options: Omit<BuildOptions, 'pubkey' | 'enc'>,
  ): Promise<NostrEvent> =>
    session.vet(
      await who.sign(
        sealEvent(
          build({ ...options, pubkey: who.publicKey, enc: EncMode.Nip44 }),
          key,
        ),
      ),
    )

  // --- the one check that belongs in the plaintext workspace -----------------

  await run.check(
    {
      id: 'enc-without-policy',
      what: 'refuses an event tagged `enc=nip44` on a channel with no encryption policy',
      level: 'MUST',
      profile: 'quorum',
    },
    async () =>
      // Genuinely sealed, under a key nobody in this channel holds, so that the
      // refusal is unambiguously about the missing policy rather than about the
      // content — the relay cannot tell the difference and must not need to.
      // Without this rule, `enc` is a tag that switches body validation off:
      // anything at all can be published under any Quorum kind by claiming to
      // be ciphertext on a channel where nothing is encrypted.
      session.refuses(
        await seal(member, {
          kind: Kinds.ChatMessage,
          group,
          epoch: EPOCH,
          text: 'sealed, on a channel whose policy says nothing about encryption',
          counter: session.next(member),
        }),
      ),
  )

  // --- and a channel of its own for the rest ---------------------------------

  const sealedGroup = await session.workspace('sealed')

  const settled = await run.check(
    {
      id: 'policy',
      what: 'stores a kind 38107 turning a channel encrypted',
      level: 'MUST',
      profile: 'any',
    },
    async () =>
      // The bootstrap event, and the control everything below rests on. The
      // policy is published before the key wraps here, which is the opposite of
      // the order a real admin uses — `rotateChannelKey` wraps first, because
      // otherwise every writer is told to seal under an epoch that has reached
      // nobody. This run's two members are handed the key in process, so the
      // ordering that protects a real channel would only cost this one a check.
      session.accepts(
        await session.craft(owner, {
          kind: Kinds.ChannelPolicy,
          group: sealedGroup,
          d: sealedGroup,
          counter: session.next(),
          body: {
            enc: EncMode.Nip44,
            epoch: EPOCH,
            reason: 'a conformance run',
            changed_at: now(),
          },
        }),
      ),
  )

  const unsealed = settled.ok
    ? false
    : `the channel could not be made encrypted (${settled.why}), so there is no policy to enforce`

  await run.check(
    {
      id: 'key-wrap',
      what: 'accepts a kind 8110 channel key in the clear on an encrypted channel',
      level: 'MUST',
      profile: 'quorum',
      unless: unsealed,
    },
    async () =>
      // The positive control for `over-seal`, and a requirement in its own
      // right: a channel key sealed under the channel key is a locked box
      // containing its own key, so a relay that demanded every event on an
      // encrypted channel be sealed would make the channel unjoinable.
      session.accepts(
        await session.craft(owner, {
          kind: Kinds.ChannelKey,
          group: sealedGroup,
          to: [member.publicKey],
          counter: session.next(),
          body: {
            epoch: EPOCH,
            key: await owner.nip44Encrypt(member.publicKey, conversationKeyToHex(key)),
            recipient: member.publicKey,
          },
        }),
      ),
  )

  await run.check(
    {
      id: 'sealed',
      what: 'accepts a properly sealed message on an encrypted channel',
      level: 'MUST',
      profile: 'quorum',
      unless: unsealed,
    },
    async () =>
      // The control for `leak`. Without it, a relay that refused every event on
      // an encrypted channel — which is a real failure, and the kind an
      // operator meets at three in the morning — would pass this section
      // perfectly.
      session.accepts(
        await seal(member, {
          kind: Kinds.ChatMessage,
          group: sealedGroup,
          epoch: EPOCH,
          text: 'sealed under the channel key this channel says to write with',
          counter: session.next(member),
        }),
      ),
  )

  await run.check(
    {
      id: 'leak',
      what: 'refuses a plaintext message on a channel whose policy says `nip44`',
      level: 'MUST',
      profile: 'quorum',
      unless: unsealed,
    },
    async () =>
      // The same sentence as the check above, in the clear. This is the
      // accident the rule exists for: one client with encryption misconfigured,
      // or a build that predates the policy, publishing into a channel where
      // everyone else believes the relay is holding ciphertext. Nothing else
      // reports it — `openEvent` passes an untagged event straight through, so
      // every reader renders it normally and the channel is simply less private
      // than it says it is.
      session.refuses(
        await session.craft(member, {
          kind: Kinds.ChatMessage,
          group: sealedGroup,
          text: 'sealed under the channel key this channel says to write with',
          counter: session.next(member),
        }),
      ),
  )

  await run.check(
    {
      id: 'epoch',
      what: 'refuses a sealed event that does not say which key sealed it',
      level: 'MUST',
      profile: 'quorum',
      unless: unsealed,
    },
    async () =>
      // Built with no epoch rather than stripped of one, so the nonce is still
      // derived over the event as published and a member could open it — the
      // single thing wrong with this event is that nobody can be told which key
      // to ask for. That is the whole point of the tag: without it "I hold no
      // key for epoch 3" and "this ciphertext was tampered with" are the same
      // MAC failure, and they send an operator to opposite ends of the building.
      session.refuses(
        await seal(member, {
          kind: Kinds.ChatMessage,
          group: sealedGroup,
          text: 'sealed, with nothing saying under which key',
          counter: session.next(member),
        }),
      ),
  )

  await run.check(
    {
      id: 'over-seal',
      what: 'refuses a sealed kind 8110, which must stay readable',
      level: 'MUST',
      profile: 'quorum',
      unless: unsealed,
    },
    async () =>
      // Key management, authorization and the records the relay signs itself
      // stay in the clear on an encrypted channel, and that list is not a
      // convenience. A capability nobody can audit is not a capability, and a
      // channel policy nobody can read is a channel nobody can join. Encrypting
      // one of those does not make a workspace more private; it makes it
      // unadministrable, in a way that looks fine until an owner asks who may
      // deploy to production.
      session.refuses(
        await seal(owner, {
          kind: Kinds.ChannelKey,
          group: sealedGroup,
          to: [member.publicKey],
          epoch: EPOCH,
          counter: session.next(),
          body: {
            epoch: EPOCH,
            key: await owner.nip44Encrypt(member.publicKey, conversationKeyToHex(key)),
            recipient: member.publicKey,
          },
        }),
      ),
  )

  await run.check(
    {
      id: 'policy-identifier',
      what: 'refuses a channel policy whose `d` is not the channel it is published in',
      level: 'MUST',
      profile: 'quorum',
      unless: unsealed,
    },
    async () =>
      // A policy is located by its `d`, so one keyed on anything else is an
      // event that exists, validates, is stored, and governs nothing — while
      // reading to whoever published it as though the channel were now
      // encrypted. The failure is silent and it is in the unsafe direction.
      session.refuses(
        await session.craft(owner, {
          kind: Kinds.ChannelPolicy,
          group: sealedGroup,
          d: `${sealedGroup}-elsewhere`,
          counter: session.next(),
          body: { enc: EncMode.Nip44, epoch: EPOCH, changed_at: now() },
        }),
      ),
  )

  run.note(
    {
      id: 'metadata',
      what: 'still sees who is in the channel, who answered whom, and when',
      level: 'MAY',
      profile: 'any',
    },
    'pass',
    'not a defect and not fixable at this layer: `nip44` encrypts `content` and nothing else, ' +
      `so ${TagName.Group}, ${TagName.Pubkey}, ${TagName.RootEvent} and ${TagName.Counter} ` +
      'stay in the clear — which is what keeps routing, rate limits, NIP-29 membership and ' +
      'checkpoints working. The social graph is the stated price, and `mls` does not pay it off',
  )

  return run.done()
}
