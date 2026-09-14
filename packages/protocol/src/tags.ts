/**
 * Tag conventions.
 *
 * Two rules shape everything here:
 *
 * 1. Relays index single-letter tags only (NIP-01). Anything Quorum needs to
 *    filter on server-side must therefore ride on a single-letter tag, even
 *    where a descriptive name would read better. Multi-character tags
 *    (`counter`, `enc`, `action`) are for readers who already have the event.
 *
 * 2. Tags are metadata; `content` is the body. Tags carry addressing,
 *    threading and anything a relay must index. Everything else lives in the
 *    JSON body. This is what makes encryption a per-channel switch rather than
 *    a redesign: encrypting `content` leaves routing intact. The cost — tags
 *    stay readable to the relay even on encrypted channels — is a deliberate,
 *    documented metadata leak.
 */

/**
 * A tag is `[name, ...values]`. Mutable rather than `readonly` so it assigns
 * directly to the NIP-01 event's `tags` field; readers below take
 * `readonly Tag[]` so callers keep the guarantee where it is useful.
 */
export type Tag = string[]

export const TagName = {
  /** NIP-29 group id. Required on every event inside a channel. */
  Group: 'h',
  /** NIP-31 human-readable fallback. Required on every Quorum kind. */
  Alt: 'alt',
  /** Pubkey reference. Addressing, mentions, and NIP-22 parent authorship. */
  Pubkey: 'p',
  /** Root-scope pubkey (NIP-22 uppercase). */
  RootPubkey: 'P',
  /** Parent event id (NIP-22 lowercase). */
  Event: 'e',
  /** Root-scope event id (NIP-22 uppercase) — the thread root. */
  RootEvent: 'E',
  /** Parent kind (NIP-22). MUST accompany `e`. */
  ParentKind: 'k',
  /** Root-scope kind (NIP-22). MUST accompany `E`. */
  RootKind: 'K',
  /** Addressable event coordinate `<kind>:<pubkey>:<d>`. */
  Address: 'a',
  /** Addressable identifier. */
  Identifier: 'd',
  /** NIP-7D thread title. */
  Title: 'title',
  /** NIP-29 timeline references: first 8 hex chars of recently seen events. */
  Previous: 'previous',
  /** Per-author monotonic counter. Ordering layer 1. */
  Counter: 'counter',
  /** Content encryption mode for this event. */
  Enc: 'enc',
  /**
   * Which channel-key generation sealed this event's content.
   *
   * Multi-character on purpose, like `counter`: relays index single-letter tags
   * and nothing needs to filter on this one. A reader who holds epochs 1 and 2
   * and meets an event tagged epoch 4 can then say *which* key it is missing,
   * instead of reporting a MAC failure that looks identical to tampering.
   */
  Epoch: 'epoch',
  /** Id of the `proposed` event that opened an action chain. */
  Action: 'action',
  /** Quorum protocol version the author wrote against. */
  Version: 'quorum',

  // --- kind 30443, borrowed from Marmot along with the kind number ----------

  /** MLS protocol version a KeyPackage is for. One value exists: `1.0`. */
  MlsProtocolVersion: 'mls_protocol_version',
  /** The KeyPackageRef of the KeyPackage in this event, lowercase hex. */
  MlsKeyPackageRef: 'i',
  /** Ciphersuites the publisher supports, as an id list. */
  MlsCiphersuite: 'mls_ciphersuite',
  /** MLS extensions the publisher supports, as an id list. */
  MlsExtensions: 'mls_extensions',
  /** Proposal types the publisher supports, as an id list. */
  MlsProposals: 'mls_proposals',
} as const

/**
 * Marker placed in position 4 of a `p` tag to mean "this event is addressed to
 * this pubkey", as distinct from "this pubkey is merely referenced".
 *
 * This exists because of a genuine collision. Quorum wants `p` for addressing so
 * that an agent can subscribe with the indexed filter `{"#p": [<mypubkey>]}` and
 * have the relay do the routing. But NIP-22 also uses `p` for the *author of the
 * parent comment*, which for a chatty thread means every agent that ever spoke
 * gets p-tagged on every subsequent message.
 *
 * M0 finding #1 was that ambiguous addressing makes agents fire on things not
 * meant for them — there, an agent deployed to production because a system
 * message *described* how to mention it. Losing the distinction here would
 * reintroduce exactly that bug at protocol level.
 *
 * So: the `#p` filter stays a cheap coarse prefilter (a superset), and
 * `isAddressedTo` does exact matching locally on the marker. Generic clients,
 * which ignore position 4, still see an ordinary mention.
 */
export const ADDRESS_MARKER = 'to'

/** Content encryption mode. A per-channel policy, present from day one. */
export const EncMode = {
  /** Relay can read bodies, so it can pack context, project state, rate-limit. */
  Plaintext: 'plaintext',
  /** NIP-44 to each recipient. Relay sees tags only. */
  Nip44: 'nip44',
  /** Marmot/MLS group messaging. Relay sees nothing useful. */
  Mls: 'mls',
} as const

export type EncMode = (typeof EncMode)[keyof typeof EncMode]

export const ENC_MODES: readonly EncMode[] = Object.freeze(Object.values(EncMode))

// --- readers ----------------------------------------------------------------

/** All values of the first matching tag, minus the tag name. */
export function tagValues(tags: readonly Tag[], name: string): string[] {
  const tag = tags.find((t) => t[0] === name)
  return tag ? tag.slice(1) : []
}

/** The first value of the first matching tag. */
export function tagValue(tags: readonly Tag[], name: string): string | undefined {
  return tags.find((t) => t[0] === name)?.[1]
}

/** Every tag with this name. */
export function allTags(tags: readonly Tag[], name: string): Tag[] {
  return tags.filter((t) => t[0] === name)
}

/** First values of every tag with this name. */
export function allTagValues(tags: readonly Tag[], name: string): string[] {
  return tags.flatMap((t) => (t[0] === name && t[1] !== undefined ? [t[1]] : []))
}

export function group(tags: readonly Tag[]): string | undefined {
  return tagValue(tags, TagName.Group)
}

export function alt(tags: readonly Tag[]): string | undefined {
  return tagValue(tags, TagName.Alt)
}

export function enc(tags: readonly Tag[]): EncMode {
  const value = tagValue(tags, TagName.Enc)
  return (ENC_MODES as string[]).includes(value ?? '') ? (value as EncMode) : EncMode.Plaintext
}

/**
 * The epoch this event's content was sealed under, if it says.
 *
 * Zero is valid, which it was not until M10. A `nip44` channel key generation
 * is minted from 1, but an MLS epoch is 0 at group creation and counts commits
 * from there, so rejecting 0 would have made the first messages of an `mls`
 * group report "no epoch" — and "I cannot read this" and "I am missing epoch 4"
 * being different sentences is the entire reason this tag exists.
 */
export function epoch(tags: readonly Tag[]): number | undefined {
  const value = tagValue(tags, TagName.Epoch)
  if (value === undefined) return undefined
  const n = Number(value)
  return Number.isInteger(n) && n >= 0 ? n : undefined
}

export function counter(tags: readonly Tag[]): number | undefined {
  const raw = tagValue(tags, TagName.Counter)
  if (raw === undefined) return undefined
  const n = Number(raw)
  return Number.isInteger(n) && n >= 0 ? n : undefined
}

/** The thread this event belongs to: the id of its NIP-7D kind-11 root. */
export function threadId(tags: readonly Tag[]): string | undefined {
  return tagValue(tags, TagName.RootEvent)
}

/** The event this one is a direct reply to, if any. */
export function parentId(tags: readonly Tag[]): string | undefined {
  return tagValue(tags, TagName.Event)
}

/**
 * Pubkeys this event is addressed to — `p` tags carrying the `to` marker.
 * Deliberately NOT "every p tag": see ADDRESS_MARKER.
 */
export function addressees(tags: readonly Tag[]): string[] {
  return tags.flatMap((t) =>
    t[0] === TagName.Pubkey && t[3] === ADDRESS_MARKER && t[1] ? [t[1]] : [],
  )
}

/**
 * The addressing predicate. This is the only question an agent should ask to
 * decide whether an event is work for it. It never inspects body text.
 */
export function isAddressedTo(tags: readonly Tag[], pubkey: string): boolean {
  return addressees(tags).includes(pubkey)
}

/** The action chain this event belongs to: the id of its `proposed` event. */
export function actionId(tags: readonly Tag[]): string | undefined {
  return tagValue(tags, TagName.Action)
}

// --- writers ----------------------------------------------------------------

export function groupTag(id: string): Tag {
  return [TagName.Group, id]
}

export function altTag(text: string): Tag {
  return [TagName.Alt, text]
}

export function encTag(mode: EncMode): Tag {
  return [TagName.Enc, mode]
}

export function epochTag(n: number): Tag {
  return [TagName.Epoch, String(n)]
}

export function counterTag(n: number): Tag {
  return [TagName.Counter, String(n)]
}

/** An addressing `p` tag. Use this, not a bare `p`, when you want a response. */
export function toTag(pubkey: string, relayHint = ''): Tag {
  return [TagName.Pubkey, pubkey, relayHint, ADDRESS_MARKER]
}

/** A non-addressing `p` tag: a mention, or a NIP-22 parent author. */
export function mentionTag(pubkey: string, relayHint = ''): Tag {
  return [TagName.Pubkey, pubkey, relayHint]
}

export function actionTag(proposedEventId: string): Tag {
  return [TagName.Action, proposedEventId]
}

/**
 * NIP-22 scope tags placing an event inside a thread.
 *
 * `root` is the kind-11 thread; `parent` is what this event directly answers,
 * which for a top-level reply is the thread itself.
 */
export function scopeTags(
  root: { id: string; kind: number; pubkey: string },
  parent: { id: string; kind: number; pubkey: string } = root,
  relayHint = '',
): Tag[] {
  return [
    [TagName.RootEvent, root.id, relayHint, root.pubkey],
    [TagName.RootKind, String(root.kind)],
    [TagName.RootPubkey, root.pubkey, relayHint],
    [TagName.Event, parent.id, relayHint, parent.pubkey],
    [TagName.ParentKind, String(parent.kind)],
    [TagName.Pubkey, parent.pubkey, relayHint],
  ]
}

/** Addressable coordinate for an `a` tag. */
export function address(kind: number, pubkey: string, d: string): string {
  return `${kind}:${pubkey}:${d}`
}
