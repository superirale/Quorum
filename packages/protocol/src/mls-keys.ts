/**
 * The `mls` bootstrap: kind 30443, and where Quorum parts company with Marmot.
 *
 * `mls.ts` is the envelope for a message an MLS group can already open. This is
 * the event that gets you into the group in the first place, and — like that
 * file — it holds no RFC 9420 code. What is here is the tag layer: what a second
 * implementation must write so that a Quorum member can find its KeyPackage,
 * check who published it, and commit an Add.
 *
 * ## What is borrowed
 *
 * The kind number and the content. `content` is base64 of a framed
 * `mls_key_package` MLSMessage, which any RFC 9420 library can decode, and the
 * tag *names* are Marmot's: `d`, `mls_protocol_version`, `i`, and the three id
 * lists. A Marmot tool pointed at a Quorum 30443 reads a real KeyPackage out of
 * it.
 *
 * ## What is not, and why
 *
 * **No `app_components`, and no account-identity-proof.** Marmot requires a
 * `marmot.member.account-identity-proof.v2` entry in the leaf's
 * `app_data_dictionary`, and the reason is specific to Marmot's transport: its
 * group messages are published under a per-message *ephemeral* key, so the Nostr
 * layer carries no statement at all about who authored anything, and the proof
 * is how the credential gets tied back to a Nostr account. Quorum's 30443 is
 * signed by the account. The signature over this event, whose content contains
 * the credential, *is* that proof — it is the same statement by the same key
 * over the same bytes, with one fewer format to get wrong. Requiring the
 * dictionary entry as well would be asking an implementer to write the claim
 * twice and would invite the two copies to disagree.
 *
 * This is the whole reason the plan's "borrow Marmot's kinds and get interop"
 * framing was wrong. Marmot's validity rules for a KeyPackage go well past RFC
 * 9420 — identity proof, app components, an `app_data_update` capability — and
 * none of them can be satisfied by an event that keeps the Quorum envelope. The
 * kind number is worth keeping because the *payload* is genuinely the same
 * object; the rules around it are not, and pretending otherwise would produce a
 * client that claims Marmot compatibility and fails a Marmot receiver.
 *
 * **An `h` tag, and `d` is the group id.** Marmot's 30443 is global and its `d`
 * is a random 32-byte publication slot, explicitly never derived from anything,
 * because a derived `d` would leak which groups a member is trying to join.
 * Quorum's carries `h` in the clear — it has to, so the workspace relay routes
 * and admits it — so there is nothing left for a random `d` to protect, and a
 * predictable one buys something real: `30443:<pubkey>:<group>` names exactly
 * one member's current KeyPackage for exactly one channel, so an inviter can
 * fetch a specific member's package instead of scanning every package in the
 * workspace and filtering. Addressable replacement then does the single-use
 * bookkeeping for free: publishing the next KeyPackage into the same slot
 * retires the one that was just spent.
 *
 * **No `encoding` tag.** The machine-readable registry of kinds lists one as
 * required; Marmot's current document does not list it at all, and the same
 * registry entry is missing `app_components`, so it is the older of the two
 * sources. Quorum's spec fixes the encoding at base64 for every kind, so a tag
 * restating it would be a third place to keep in step.
 */

import { base64 } from '@scure/base'
import type { NostrEvent, UnsignedEvent } from './event.ts'
import { BorrowedKinds } from './kinds.ts'
import { TagName, group as groupTag, tagValue, type Tag } from './tags.ts'

/** The only MLS protocol version there is; RFC 9420 fixes it. */
export const MLS_PROTOCOL_VERSION = '1.0'

/**
 * What a publisher advertises it can do, as the three id-list tags carry it.
 *
 * Numbers here, hex on the wire. The conversion is in one place because the
 * format is easy to write four different ways — `1`, `0x1`, `0001`, `0x0001` —
 * and a reader that accepts only its own spelling silently ignores every
 * capability an otherwise-compatible client advertises, which surfaces much
 * later as "that member cannot be added" with nothing saying why.
 */
export interface MlsCapabilities {
  ciphersuites: readonly number[]
  extensions: readonly number[]
  proposals: readonly number[]
}

/** Everything a kind 30443 says, once the tags are read. */
export interface MlsKeyPackageEvent extends MlsCapabilities {
  /** The channel this KeyPackage is offered to, from the `h` tag. */
  group: string
  /** The publication slot, from `d`. Equal to `group` for a Quorum publisher. */
  slot: string
  /** The MLS protocol version tag; anything but `1.0` is refused. */
  version: string
  /** The KeyPackageRef, lowercase hex. */
  ref: string
  /** The framed `mls_key_package` MLSMessage. */
  message: Uint8Array
}

/**
 * One id-list tag: every value in a single tag array, `0x`-prefixed 4-digit hex.
 *
 * Marmot's shape, and the one place this format is produced. Note that it is
 * *not* the usual Nostr convention of one tag per value — a reader looking for
 * `mls_ciphersuite` must read the rest of the array rather than collecting
 * repeated tags, which is exactly the mistake {@link parseIdList} exists to stop
 * anyone making twice.
 */
export function idListTag(name: string, values: readonly number[]): Tag {
  return [name, ...values.map(toIdHex)]
}

function toIdHex(value: number): string {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
    throw new Error(`mls: ${value} is not a 16-bit id and cannot go in an id list`)
  }
  return `0x${value.toString(16).padStart(4, '0')}`
}

/**
 * Read an id list back, refusing anything that is not the canonical spelling.
 *
 * Strict on purpose. A lenient reader here is worse than a strict one, because
 * the failure it hides is asymmetric: accepting `0x1` from a client that writes
 * it that way means Quorum reads that client's capabilities and that client
 * never reads Quorum's, so the pair works in one direction and looks like a
 * problem with whichever end happens to be committing the Add.
 */
export function parseIdList(tags: readonly Tag[], name: string): number[] {
  const tag = tags.find((t) => t[0] === name)
  if (tag === undefined) throw new Error(`mls: a KeyPackage event needs a \`${name}\` tag`)
  return tag.slice(1).map((value) => {
    if (!/^0x[0-9a-f]{4}$/.test(value)) {
      throw new Error(`mls: "${value}" in \`${name}\` is not a 0x-prefixed lowercase 4-digit hex id`)
    }
    return Number.parseInt(value.slice(2), 16)
  })
}

/**
 * The tags a kind 30443 carries, beyond the ones `build()` adds for every event.
 *
 * `d` is passed separately to `build()` rather than returned here, because
 * `build()` owns the addressable-identifier rule and a `d` arriving through two
 * routes is a duplicate tag waiting to happen.
 */
export function mlsKeyPackageTags(options: MlsCapabilities & { ref: string }): Tag[] {
  if (!/^[0-9a-f]{64}$/.test(options.ref)) {
    throw new Error(`mls: a KeyPackageRef is 32 bytes of lowercase hex, got "${options.ref}"`)
  }
  return [
    [TagName.MlsProtocolVersion, MLS_PROTOCOL_VERSION],
    [TagName.MlsKeyPackageRef, options.ref],
    idListTag(TagName.MlsCiphersuite, options.ciphersuites),
    idListTag(TagName.MlsExtensions, options.extensions),
    idListTag(TagName.MlsProposals, options.proposals),
  ]
}

/**
 * Read a kind 30443, or throw saying which rule it broke.
 *
 * Throws rather than returning `undefined`, because every caller is an inviter
 * about to commit an Add and there is no useful "skip it quietly" branch: a
 * KeyPackage this client cannot parse is a member this client is about to leave
 * out of the group, and doing that in silence is how somebody ends up unable to
 * read a channel they were told they had been added to.
 */
export function parseMlsKeyPackageEvent(event: NostrEvent | UnsignedEvent): MlsKeyPackageEvent {
  if (event.kind !== BorrowedKinds.MlsKeyPackage) {
    throw new Error(`mls: kind ${event.kind} is not a KeyPackage event`)
  }

  const group = groupTag(event.tags)
  if (group === undefined) throw new Error('mls: a KeyPackage event needs an `h` tag')

  const slot = tagValue(event.tags, TagName.Identifier)
  if (slot === undefined) throw new Error('mls: a KeyPackage event needs a `d` tag')
  // The divergence from Marmot is only worth anything if it is enforced. A
  // Quorum `d` is the channel id so that `30443:<pubkey>:<channel>` names
  // exactly one member's current KeyPackage — which is where the single-use
  // bookkeeping comes from, since publishing the next one into that slot
  // retires the spent one by addressable replacement.
  //
  // A package in some other slot still answers the `#h` query an inviter makes,
  // so it looks fetchable and usable; what it does not do is get retired. The
  // member's next KeyPackage lands elsewhere, the spent one stays live forever,
  // and an inviter picks it up and commits an Add against a private half the
  // joiner may have discarded — producing a member in the tree who can never
  // read the channel, which is the failure this whole section exists to avoid.
  if (slot !== group) {
    throw new Error(
      `mls: a KeyPackage's \`d\` must be the channel id, but this one says "${slot}" in ${group}; ` +
        'a package in another slot is never retired by the one that replaces it',
    )
  }

  const version = tagValue(event.tags, TagName.MlsProtocolVersion)
  if (version !== MLS_PROTOCOL_VERSION) {
    throw new Error(
      `mls: this KeyPackage says protocol version ${version ?? '(none)'} and Quorum speaks ` +
        `${MLS_PROTOCOL_VERSION}`,
    )
  }

  const ref = tagValue(event.tags, TagName.MlsKeyPackageRef)
  if (ref === undefined || !/^[0-9a-f]{64}$/.test(ref)) {
    throw new Error('mls: a KeyPackage event needs an `i` tag holding a 32-byte lowercase hex ref')
  }

  let message: Uint8Array
  try {
    message = base64.decode(event.content)
  } catch (error) {
    throw new Error(`mls: KeyPackage content is not base64: ${(error as Error).message}`)
  }
  if (message.length === 0) throw new Error('mls: KeyPackage content is empty')

  return {
    group,
    slot,
    version,
    ref,
    message,
    ciphersuites: parseIdList(event.tags, TagName.MlsCiphersuite),
    extensions: parseIdList(event.tags, TagName.MlsExtensions),
    proposals: parseIdList(event.tags, TagName.MlsProposals),
  }
}
