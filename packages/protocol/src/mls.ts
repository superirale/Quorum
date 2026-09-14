/**
 * The `mls` envelope — where an MLSMessage goes, and what it must agree with.
 *
 * There is no RFC 9420 in this file and there is not going to be. MLS is
 * *stateful*: sealing a message advances a secret tree, which means it cannot
 * be a pure function of an event the way `sealEvent` is under `nip44`. The
 * ratchet, the ratchet tree, the epoch secrets and their storage belong to the
 * SDK, which drives `ts-mls`. What belongs here is the part a second
 * implementation would have to agree with to interoperate, and every one of
 * those is a binding between the MLS message and the Nostr event carrying it:
 *
 * - the MLS `group_id` and the NIP-29 `h` tag are one identifier;
 * - the MLS credential identity and the event `pubkey` are one author;
 * - the MLS epoch and the `epoch` tag are one number.
 *
 * Each is a MUST in the spec and each fails silently if it is only checked in
 * one implementation, so all three are enforced in one place and the SDK passes
 * its opener through it rather than around it. That is the same shape M9 landed
 * on with `ChannelCrypto.opener()`, for the same reason: a rule about
 * encrypted content that two clients enforce separately is a rule they will
 * eventually disagree about, and the disagreement surfaces as an unreadable
 * channel rather than as an error.
 *
 * ## Sealing here is not idempotent, and nothing can make it so
 *
 * Under `nip44` a retry re-seals to byte-identical ciphertext, because the
 * nonce is derived from the plaintext event. That is what lets `once()` lean on
 * the relay's `id`-is-a-content-hash dedupe. MLS advances the secret tree per
 * message: seal the same body twice and you get two ciphertexts, two ids, two
 * messages in the channel, and a consumed generation you cannot get back.
 *
 * So a sender MUST persist the sealed envelope **before** publishing it and
 * MUST republish the stored bytes on a retry rather than calling
 * {@link sealMlsEvent} again. This file cannot enforce that — it never sees the
 * second call — which is exactly why it is written down at the top of it.
 */

import { utf8ToBytes } from '@noble/hashes/utils.js'
import { base64 } from '@scure/base'
import type { NostrEvent, UnsignedEvent } from './event.ts'
import { EncMode, enc, epoch as epochTag, group as groupTag } from './tags.ts'

/**
 * The MLS `group_id` for a NIP-29 group: the UTF-8 bytes of the group id.
 *
 * The spec draft said "the 32 bytes of the NIP-29 group id", which assumed a
 * group id is 32-byte hex. It is not — NIP-29 places no constraint on the
 * string, relay29 accepts anything, and the ids this repo's console mints are
 * human-chosen names. Hashing to a fixed 32 bytes was the alternative and was
 * rejected: it buys nothing MLS needs (`group_id` is `opaque group_id<V>`, of
 * variable length by specification) and costs the property the rule exists for,
 * which is that one channel has exactly one identifier a human can read in both
 * places without a lookup table.
 */
export function mlsGroupId(group: string): Uint8Array {
  if (group === '') throw new Error('mls: a channel needs a group id; the `h` tag is empty')
  return utf8ToBytes(group)
}

/**
 * Does this MLS `group_id` belong to this event's channel?
 *
 * Worth checking on the way in and not only on the way out. A group whose
 * `group_id` does not match the `h` tag it arrived under is a message from
 * another channel replayed into this one: the relay routed it by `h`, the
 * ratchet opened it because the reader is in both groups, and the body lands in
 * a thread it was never sent to. Byte comparison rather than constant-time —
 * a group id is public, it is in a tag on the same event.
 */
export function isMlsGroupId(groupId: Uint8Array, group: string): boolean {
  const expected = mlsGroupId(group)
  if (groupId.length !== expected.length) return false
  return groupId.every((b, i) => b === expected[i])
}

/** What an opener hands back once it has run the message through the ratchet. */
export interface MlsOpened {
  /** The application message's plaintext: the body that would otherwise be `content`. */
  plaintext: string
  /**
   * The identity in the sender's MLS credential, lowercase hex.
   *
   * Not optional, and not merely informational. This is the field
   * {@link openMlsEvent} checks the event's `pubkey` against, and an opener
   * that cannot produce it cannot satisfy the rule.
   */
  credential: string
  /** The epoch the ciphertext was actually encrypted under, per its own header. */
  epoch: number
}

/**
 * Run one MLSMessage through the group state and say what came out.
 *
 * Supplied by the SDK, which holds the ratchet. It receives the event too,
 * because an opener needs the `h` tag to pick the right group state and the
 * `pubkey` to report a useful error.
 */
export type MlsOpener = (message: Uint8Array, event: NostrEvent | UnsignedEvent) => MlsOpened

/**
 * Put a sealed MLSMessage into an event built with `enc: 'mls'`.
 *
 * `at` is the epoch the message was encrypted under, read from the group state
 * the caller just ratcheted — not from the tag. It is compared with the tag
 * rather than written into it, because the tag was fixed when the event was
 * built and the event id already commits to it. A mismatch means the group
 * state moved between `build()` and here, which is a rotation racing a publish,
 * and the resulting event would tell every reader to reach for a key that
 * cannot open it.
 */
export function sealMlsEvent(
  unsigned: UnsignedEvent,
  message: Uint8Array,
  at: number,
): UnsignedEvent {
  if (enc(unsigned.tags) !== EncMode.Mls) {
    throw new Error(
      `mls: refusing to seal an event tagged enc=${enc(unsigned.tags)}; build it with enc: 'mls'`,
    )
  }
  if (unsigned.content === '') return unsigned
  if (message.length === 0) {
    throw new Error('mls: refusing to seal an empty MLSMessage over a non-empty body')
  }

  const tagged = epochTag(unsigned.tags)
  if (tagged === undefined) {
    throw new Error('mls: a sealed event needs an `epoch` tag; build it with `epoch`')
  }
  if (tagged !== at) {
    throw new Error(
      `mls: the event says epoch ${tagged} and the group sealed under ${at}. ` +
        'Rebuild the event at the current epoch rather than relabelling it.',
    )
  }

  return { ...unsigned, content: base64.encode(message) }
}

/**
 * The MLSMessage bytes carried by a sealed event.
 *
 * Throws on anything that is not base64, rather than handing back a shorter
 * array. A truncated MLSMessage fails inside the ratchet as a decryption
 * error, which reads as "somebody tampered with this" — a much more alarming
 * sentence than "this client wrote the content field wrong".
 */
export function mlsMessage(event: NostrEvent | UnsignedEvent): Uint8Array {
  if (enc(event.tags) !== EncMode.Mls) {
    throw new Error(`mls: this event is tagged enc=${enc(event.tags)}, not mls`)
  }
  try {
    return base64.decode(event.content)
  } catch (error) {
    throw new Error(`mls: content is not base64: ${(error as Error).message}`)
  }
}

/**
 * Open a sealed `mls` event, enforcing the three bindings on the way through.
 *
 * Returns the plaintext string rather than a patched event, for the reason
 * `openEvent` does: an object with plaintext `content` and the sealed event's
 * `id` fails `verifyEvent` and looks signed, and republishing one would leak
 * the channel.
 *
 * The credential check is the load-bearing one. MLS authenticates a sender to
 * whoever holds the ratchet tree; the Nostr signature authenticates them to
 * everybody, forever, which is what an approval has to be. Skip the comparison
 * and the two claims drift apart in the direction that matters: a member can
 * take another member's application message off the wire, wrap it in an event
 * signed by their own key, and the group will open it happily under the
 * original author's ratchet. The body is then attributed, by signature, to
 * somebody who did not write it.
 */
export function openMlsEvent(event: NostrEvent | UnsignedEvent, open: MlsOpener): string {
  if (enc(event.tags) !== EncMode.Mls) return event.content
  if (event.content === '') return ''

  const opened = open(mlsMessage(event), event)

  if (opened.credential.toLowerCase() !== event.pubkey.toLowerCase()) {
    throw new Error(
      `mls: the MLS credential says ${opened.credential} and the event is signed by ` +
        `${event.pubkey}. One of them is republishing the other's message.`,
    )
  }

  const tagged = epochTag(event.tags)
  if (tagged !== undefined && tagged !== opened.epoch) {
    throw new Error(
      `mls: the event is tagged epoch ${tagged} and the ciphertext is epoch ${opened.epoch}`,
    )
  }

  return opened.plaintext
}

/** True if this event's content is an MLSMessage and needs the group state to mean anything. */
export function isMlsSealed(event: NostrEvent | UnsignedEvent): boolean {
  return enc(event.tags) === EncMode.Mls && event.content !== ''
}

/**
 * The `group_id` an event's channel expects, from the event itself.
 *
 * A convenience with a sharp edge attached: an event with no `h` tag has no
 * channel, and on an `mls` channel that is not a degenerate case to shrug at.
 * The group id is what selects the ratchet state, so a missing one means
 * guessing which group to try — and trial decryption against every group this
 * client is in is exactly the behaviour the Quorum-native profile exists to
 * avoid.
 */
export function mlsGroupIdOf(event: NostrEvent | UnsignedEvent): Uint8Array {
  const h = groupTag(event.tags)
  if (h === undefined) throw new Error('mls: event has no `h` tag, so it names no group')
  return mlsGroupId(h)
}
