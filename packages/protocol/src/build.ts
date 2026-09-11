/**
 * Event construction.
 *
 * This lives in the protocol package rather than the SDK because the tag rules
 * *are* the protocol. If the SDK assembled tags on its own, "valid Quorum
 * event" would have two definitions — one enforced by `validate.ts`, one
 * implied by whatever the SDK happens to emit — and they would drift. Here,
 * anything `build()` produces is something `validateEnvelope()` accepts, and
 * the test suite asserts exactly that.
 *
 * These return *unsigned* events. Signing needs a key, and key handling
 * (local nsec, NIP-07, NIP-46 bunker) is an SDK concern with real security
 * consequences that this package deliberately stays out of.
 */

import { defaultAlt, isValidAlt, redactedAlt } from './alt.ts'
import { bodySchema } from './bodies/index.ts'
import { canonicalJson } from './digest.ts'
import type { UnsignedEvent } from './event.ts'
import { Kinds, isQuorumKind } from './kinds.ts'
import {
  ADDRESS_MARKER,
  EncMode,
  TagName,
  altTag,
  counterTag,
  encTag,
  groupTag,
  scopeTags,
  tagValue,
  toTag,
  type Tag,
} from './tags.ts'
import { PROTOCOL_NAME, PROTOCOL_VERSION } from './version.ts'

export interface EventRef {
  id: string
  kind: number
  pubkey: string
}

export interface BuildOptions {
  kind: number
  pubkey: string
  /** NIP-29 group id. */
  group: string
  /** The JSON body. Omit for the plain-text kinds (9, 11, 1111). */
  body?: unknown
  /** Plain text content, for kinds that do not take a JSON body. */
  text?: string
  /** The kind:11 thread root this event belongs to. */
  thread?: EventRef
  /** What this event directly answers. Defaults to `thread`. */
  parent?: EventRef
  /** Pubkeys addressed with the `to` marker. The only addressing signal. */
  to?: string[]
  /** Pubkeys merely mentioned. Never treated as addressing. */
  mention?: string[]
  /** The `proposed` event id, for events in an action chain. */
  action?: string
  /** Addressable identifier. Required for 3xxxx kinds. */
  d?: string
  /** Per-author monotonic counter. Supply it; gap detection depends on it. */
  counter?: number
  enc?: EncMode
  /** Override the generated `alt`. */
  alt?: string
  created_at?: number
  /** Extra tags, appended verbatim. */
  tags?: Tag[]
  relayHint?: string
}

/**
 * Build an unsigned Quorum event with every required tag in place.
 *
 * Throws rather than producing a subtly wrong event: a missing `d` on an
 * addressable kind, or a body that does not match its schema, is a programming
 * error and the sooner it surfaces the less log there is to explain later.
 */
export function build(options: BuildOptions): UnsignedEvent {
  const {
    kind,
    pubkey,
    group,
    body,
    text,
    thread,
    parent,
    to = [],
    mention = [],
    action,
    d,
    counter,
    enc = EncMode.Plaintext,
    created_at = Math.floor(Date.now() / 1000),
    relayHint = '',
  } = options

  const schema = bodySchema(kind)
  if (schema && body === undefined) {
    throw new Error(`kind ${kind} requires a JSON body`)
  }
  if (!schema && body !== undefined) {
    throw new Error(`kind ${kind} takes plain text content, not a JSON body`)
  }

  const parsedBody = schema ? schema.parse(body) : undefined

  const tags: Tag[] = [groupTag(group)]

  if (thread) {
    tags.push(...scopeTags(thread, parent ?? thread, relayHint))
  }

  for (const pk of to) tags.push(toTag(pk, relayHint))
  for (const pk of mention) tags.push([TagName.Pubkey, pk, relayHint])

  // The NIP-22 parent-author `p` and an addressing `p` collide whenever an
  // agent answers the person who asked — which is the common case, not an edge
  // one. Both tags are legal and mean different things, but emitting the pair
  // leaves a reader holding two `p` tags for one pubkey where only one carries
  // the marker, and any reader that checks the wrong one gets the wrong answer.
  // The marked tag strictly subsumes the plain one, so keep it and drop the
  // duplicate.
  dedupePubkeyTags(tags)

  if (d !== undefined) tags.push([TagName.Identifier, d])
  if (action !== undefined) tags.push([TagName.Action, action])
  if (counter !== undefined) tags.push(counterTag(counter))
  if (enc !== EncMode.Plaintext) tags.push(encTag(enc))

  if (isQuorumKind(kind)) {
    const altText =
      options.alt ??
      (enc === EncMode.Plaintext ? defaultAlt(kind, parsedBody ?? { text }) : redactedAlt(kind))
    if (!isValidAlt(altText)) {
      throw new Error(`alt text is not valid for kind ${kind}: ${JSON.stringify(altText)}`)
    }
    tags.push(altTag(altText))
    tags.push([TagName.Version, `${PROTOCOL_NAME}/${PROTOCOL_VERSION}`])
  } else if (options.alt !== undefined) {
    tags.push(altTag(options.alt))
  }

  if (options.tags) tags.push(...options.tags)

  return {
    pubkey,
    created_at,
    kind,
    tags,
    // Canonical JSON, not JSON.stringify: two agents publishing the same body
    // should produce the same bytes and therefore the same event id, which is
    // what makes relay-level dedup do idempotency work for free.
    content: parsedBody !== undefined ? canonicalJson(parsedBody) : (text ?? ''),
  }
}

/**
 * Drop unmarked `p` tags for pubkeys that also have a `to`-marked one, in place.
 * Also collapses exact duplicates, which `scopeTags` produces when the parent
 * is the thread root.
 */
function dedupePubkeyTags(tags: Tag[]): void {
  const addressed = new Set(
    tags.flatMap((t) => (t[0] === TagName.Pubkey && t[3] === ADDRESS_MARKER && t[1] ? [t[1]] : [])),
  )
  const seen = new Set<string>()
  for (let i = tags.length - 1; i >= 0; i--) {
    const tag = tags[i]!
    if (tag[0] !== TagName.Pubkey || !tag[1]) continue
    const marked = tag[3] === ADDRESS_MARKER
    if (!marked && addressed.has(tag[1])) {
      tags.splice(i, 1)
      continue
    }
    const key = `${tag[1]}:${marked}`
    if (seen.has(key)) tags.splice(i, 1)
    else seen.add(key)
  }
}

/** This event, as something another event can point at. */
export function refTo(event: { id: string; kind: number; pubkey: string }): EventRef {
  return { id: event.id, kind: event.kind, pubkey: event.pubkey }
}

/**
 * The thread root an event sits in, read back out of its NIP-22 scope tags.
 *
 * The inverse of {@link scopeTags}, and it lives beside it so the two cannot
 * disagree about which tag holds what. A kind-11 event is its own root — that
 * is what "the thread id is the root event's id" means — and an event with no
 * `E` tag is not in a thread at all, which is normal for channel-level chat.
 */
export function threadRef(event: {
  id: string
  kind: number
  pubkey: string
  tags: readonly Tag[]
}): EventRef | undefined {
  if (event.kind === Kinds.Thread) return refTo(event)

  const root = event.tags.find((t) => t[0] === TagName.RootEvent)
  const kind = tagValue(event.tags, TagName.RootKind)
  const pubkey = root?.[3] ?? tagValue(event.tags, TagName.RootPubkey)
  if (!root?.[1] || kind === undefined || !pubkey) return undefined
  return { id: root[1], kind: Number(kind), pubkey }
}

/** A NIP-7D thread root. Its id becomes the thread id for everything after it. */
export function buildThread(options: {
  pubkey: string
  group: string
  title: string
  text: string
  to?: string[]
  counter?: number
  created_at?: number
}): UnsignedEvent {
  const tags: Tag[] = [groupTag(options.group), [TagName.Title, options.title]]
  for (const pk of options.to ?? []) tags.push(toTag(pk))
  if (options.counter !== undefined) tags.push(counterTag(options.counter))
  dedupePubkeyTags(tags)

  return {
    pubkey: options.pubkey,
    created_at: options.created_at ?? Math.floor(Date.now() / 1000),
    kind: Kinds.Thread,
    tags,
    content: options.text,
  }
}

/** A NIP-22 comment: an utterance inside a thread, by a human or an agent. */
export function buildComment(options: {
  pubkey: string
  group: string
  text: string
  thread: EventRef
  parent?: EventRef
  to?: string[]
  counter?: number
  created_at?: number
}): UnsignedEvent {
  const tags: Tag[] = [
    groupTag(options.group),
    ...scopeTags(options.thread, options.parent ?? options.thread),
  ]
  for (const pk of options.to ?? []) tags.push(toTag(pk))
  if (options.counter !== undefined) tags.push(counterTag(options.counter))
  dedupePubkeyTags(tags)

  return {
    pubkey: options.pubkey,
    created_at: options.created_at ?? Math.floor(Date.now() / 1000),
    kind: Kinds.Comment,
    tags,
    content: options.text,
  }
}
