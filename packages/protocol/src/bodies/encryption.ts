/**
 * The kinds that make an encrypted channel possible.
 *
 * NIP-44 is pairwise by construction: its conversation key is an ECDH between
 * exactly two keys. A Quorum channel has N members, so "an encrypted channel"
 * needs a group story layered on top of it, and there are only two shapes.
 *
 * **Per-recipient fan-out** — encrypt every message N times, once to each
 * member. Cost is linear in members per message, a late joiner can read
 * nothing that was said before they arrived, and every membership change is
 * free. Forward secrecy is still absent.
 *
 * **A shared channel key** — one random 32-byte secret per channel, handed to
 * each member as a pairwise NIP-44 payload. Constant cost per message
 * regardless of size, history readable by anyone handed the key, and removal
 * becomes a ceremony: the departing member keeps every byte they already hold,
 * so the only honest response is to rotate.
 *
 * Quorum takes the shared key, because the thing being protected is a
 * *workspace* — a hundred-message thread that a newly hired agent must be able
 * to read from the top, in a channel whose membership changes weekly. Fan-out
 * makes the common operation expensive to buy a property (removal is free)
 * that it does not actually deliver, since the removed member still holds the
 * plaintext of everything sent while they were there.
 *
 * Neither shape has forward secrecy and neither pretends to. That is what M10
 * and Marmot are for, and it is the honest reason `mls` is still on the plan
 * rather than being declared unnecessary once this shipped.
 */

import { z } from 'zod'
import { ENC_MODES } from '../tags.ts'
import { EventId, Pubkey, UnixSeconds } from './common.ts'

/** Epochs start at 1. Zero would be indistinguishable from a missing field. */
export const Epoch = z.int().positive().describe('key generation; increments on every rotation')

/**
 * `channel_policy` (38107) — what this channel encrypts, and under which epoch.
 *
 * Addressable with `d` = the group id, published by an owner or admin. The
 * relay keeps the newest and enforces it: on a channel whose policy says
 * `nip44` it refuses any content-bearing event that is not sealed.
 *
 * That is worth sitting with, because it is the nicest property in this
 * milestone. **The relay cannot read the channel and can still stop somebody
 * leaking it.** Confidentiality is normally the one guarantee you give up all
 * server-side help with; here the server keeps enforcing the policy precisely
 * because the policy is about the envelope, which stays in the clear. A member
 * whose client is misconfigured, or whose SDK is out of date, or who pasted
 * into the wrong window, gets a refusal instead of a disclosure.
 *
 * It is defence in depth and not a guarantee: the relay can only refuse what it
 * is asked to store, and every Quorum event is valid on a generic relay that
 * will happily take the plaintext. The client is still the thing that has to be
 * right. But a policy nobody can check is a preference, and this one is
 * checkable by the one party that sees every message.
 */
export const ChannelPolicyBody = z.object({
  enc: z.enum(ENC_MODES as [string, ...string[]]).describe('plaintext | nip44 | mls'),

  /**
   * The epoch a writer should be encrypting under right now.
   *
   * Readers must still accept older epochs — history does not re-encrypt, and
   * a message sent one second before a rotation is not invalid. The epoch says
   * which key to *write* with, which is a different question from which keys to
   * keep around.
   */
  epoch: Epoch.optional().describe('required when enc is not plaintext'),

  /**
   * Why the epoch last changed, in the clear.
   *
   * Deliberately readable by the relay and by anyone watching. A rotation is
   * almost always a removal, and "who lost access when" is exactly the fact an
   * audit needs and the fact an encrypted channel would otherwise destroy.
   */
  reason: z.string().optional().describe('e.g. "rotated after removing 2ebfa99b…"'),

  changed_at: UnixSeconds.optional(),
})
export type ChannelPolicyBody = z.infer<typeof ChannelPolicyBody>

/**
 * `channel_key` (8110) — one member's copy of the shared secret.
 *
 * `key` is a NIP-44 payload from the issuer to the recipient, whose plaintext
 * is the 64-character hex channel key. The recipient is named by a `to`-marked
 * `p` tag, so the usual addressing filter finds it.
 *
 * **The body is not sealed and the wrapping is not hidden.** Anyone can see
 * that this admin gave this member this epoch at this time — they simply cannot
 * read the secret. That is a feature and it is the same stance the plan takes
 * on backchannels: membership of an encrypted channel stays auditable by the
 * workspace owner. A design that hid the grants would make "who can read this
 * thread" unanswerable by anyone, including the people responsible for it.
 */
export const ChannelKeyBody = z.object({
  epoch: Epoch,

  /** NIP-44 v2 payload, issuer → recipient, containing the channel key as hex. */
  key: z.string().min(132).describe('base64 NIP-44 payload; plaintext is 64 hex characters'),

  /**
   * The epoch this one replaces, if any.
   *
   * Lets a member notice they were skipped: holding epoch 2 and being handed
   * epoch 4 with `supersedes: 3` says a rotation happened that nobody wrapped
   * for them, which on an encrypted channel is indistinguishable from silence
   * unless somebody says it.
   */
  supersedes: Epoch.optional(),

  /** The member this copy is for. Duplicates the `to` tag, which is the routing one. */
  recipient: Pubkey,
})
export type ChannelKeyBody = z.infer<typeof ChannelKeyBody>

/**
 * MLS epochs start at **0**, which is the one place `mls` and `nip44` disagree
 * about a field they share a name for.
 *
 * {@link Epoch} above is positive because a `nip44` channel mints its first key
 * as epoch 1 and zero would be indistinguishable from a missing field. RFC 9420
 * does not get that choice: a group's first epoch is 0 by specification, so the
 * first messages of every MLS channel carry `epoch: 0`. `epoch()` in `tags.ts`
 * required `n > 0` until the M10 step-1 pass and would have read every one of
 * them as "no epoch", collapsing "I cannot read this" and "I am missing epoch 4"
 * back into the single sentence the tag exists to split apart.
 */
export const MlsEpoch = z.int().nonnegative().describe('MLS group epoch; the first one is 0')

/**
 * What a Welcome's NIP-44 payload decrypts to: the Welcome and the tree.
 *
 * Two fields rather than one because RFC 9420 lets the ratchet tree travel
 * either inside the Welcome, as a `ratchet_tree` group-context extension, or out
 * of band — and `ts-mls` takes it as a separate argument to `joinGroup`, which
 * is the out-of-band path. Sending it here keeps the choice in one place instead
 * of making every group's extension list load-bearing at join time.
 *
 * The tree is encrypted along with the Welcome even though it is not secret in
 * any strong sense: it carries every member's leaf node, so publishing it in the
 * clear would hand the relay the exact membership of the ratchet — the one list
 * that Quorum's two-lists rule says may legitimately differ from the NIP-29 one.
 * Encrypting it costs nothing, since there is already a payload to put it in.
 */
export const MlsInvite = z.object({
  /** base64 of a framed `mls_welcome` MLSMessage. */
  welcome: z.string().min(1),
  /** base64 of the TLS-encoded `RatchetTree` the committer held. */
  ratchet_tree: z.string().min(1),
})
export type MlsInvite = z.infer<typeof MlsInvite>

/**
 * `mls_welcome` (8111) — one member's way into the ratchet.
 *
 * `invite` is a NIP-44 payload from the inviter to the recipient whose plaintext
 * is an {@link MlsInvite}. The recipient is named by a `to`-marked `p` tag, so
 * `inbox()` finds it with the addressing filter every other kind uses.
 *
 * See the comment on `RegularKinds.MlsWelcome` for why this is a Quorum kind
 * rather than NIP-59's gift-wrapped 444, and what that costs.
 */
export const MlsWelcomeBody = z.object({
  /** The epoch the group is at as of this Welcome's commit. */
  epoch: MlsEpoch,

  /** NIP-44 v2 payload, inviter → recipient; plaintext is an {@link MlsInvite} JSON object. */
  invite: z.string().min(132).describe('base64 NIP-44 payload wrapping the Welcome'),

  /** The member this Welcome is for. Duplicates the `to` tag, which is the routing one. */
  recipient: Pubkey,

  /**
   * The kind 30443 event whose KeyPackage this Welcome consumed.
   *
   * By id and not by addressable coordinate, because a KeyPackage is
   * single-use: the coordinate `30443:<pubkey>:<group>` names the recipient's
   * current publication slot, which by the time this arrives may already hold
   * the *replacement* they published after being added. The id names the one
   * that was actually spent, which is what a recipient needs in order to work
   * out whether this Welcome is for a key they still hold.
   */
  key_package: EventId,
})
export type MlsWelcomeBody = z.infer<typeof MlsWelcomeBody>
