/**
 * Encrypted channels — the policy, the keyring, and the two rotations.
 *
 * `@quorum/protocol` knows how to seal one event under one key. This is the
 * part that decides *which* key, gets it to the people entitled to it, and
 * takes it away from the people who are not.
 *
 * ## The three events
 *
 * A kind 38107 `channel_policy`, addressable on the group id, says what this
 * channel encrypts and which epoch a writer should use. A kind 8110
 * `channel_key` hands one member the secret for one epoch, wrapped with
 * pairwise NIP-44 so only they can open it. Everything else in the channel is
 * sealed under that secret with the `enc` and `epoch` tags saying so.
 *
 * ## Removal is a ceremony, and pretending otherwise would be dishonest
 *
 * Taking someone out of an encrypted channel cannot un-give them the bytes they
 * already hold. `rotate()` therefore does not *revoke* anything — it mints a
 * new epoch, wraps it for everyone who is still a member, and publishes a
 * policy pointing at it. The departed member can still read every message sent
 * before the rotation, forever, and no protocol can change that. What rotation
 * buys is that they cannot read what is said next.
 *
 * There is a window, and it is worth naming rather than hiding: between the
 * removal and the rotation, the channel is still readable by the person who was
 * removed. `rotate()` publishes the policy **last**, after every wrap is on the
 * relay, because the opposite order tells everyone to start writing under an
 * epoch half of them cannot read yet — which is a much longer outage than a
 * few hundred milliseconds of stale access.
 */

import { hexToBytes } from '@noble/hashes/utils.js'
import {
  AddressableKinds,
  BorrowedKinds,
  ChannelKeyBody,
  ChannelPolicyBody,
  EncMode,
  RegularKinds,
  TagName,
  addressees,
  conversationKeyFromHex,
  conversationKeyToHex,
  enc as encOf,
  epoch as epochOf,
  isSealed,
  mustSeal,
  openEvent,
  randomConversationKey,
  sealEvent,
  tagValue,
  type NostrEvent,
  type UnsignedEvent,
} from '@quorum/protocol'
import type { RelayClient } from './client.ts'
import type { Publisher } from './publish.ts'
import type { Signer } from './signer.ts'

/** Thrown when an event is sealed under an epoch this identity was never given. */
export class MissingChannelKey extends Error {
  readonly epoch: number | undefined
  readonly eventId: string | undefined

  constructor(epoch: number | undefined, eventId?: string) {
    super(
      epoch === undefined
        ? 'this event is sealed and carries no epoch tag, so there is no way to say which key is missing'
        : `no channel key for epoch ${epoch}: this identity was never handed one, or the wrap has not arrived yet`,
    )
    this.name = 'MissingChannelKey'
    this.epoch = epoch
    this.eventId = eventId
  }
}

/** What a channel's policy says right now. */
export interface ChannelPolicy {
  enc: EncMode
  epoch: number | undefined
  reason?: string
  /** Who signed it. An unexpected author here is worth a second look. */
  author?: string
}

/** The plaintext default, used when a channel has never published a policy. */
export const PLAINTEXT_POLICY: ChannelPolicy = Object.freeze({
  enc: EncMode.Plaintext,
  epoch: undefined,
})

/**
 * Read a channel's encryption policy.
 *
 * Absent a 38107 the channel is plaintext, which is the right default for two
 * reasons: it is what every channel from M2 to M8 already is, and the opposite
 * default would make a relay that failed to serve one event turn a working
 * channel into an unreadable one.
 */
export async function channelPolicy(
  client: RelayClient,
  group: string,
): Promise<ChannelPolicy> {
  const events = await client.query([
    { kinds: [AddressableKinds.ChannelPolicy], '#d': [group], '#h': [group], limit: 1 },
  ])
  const latest = events.sort((a, b) => b.created_at - a.created_at)[0]
  if (!latest) return PLAINTEXT_POLICY

  const body = ChannelPolicyBody.safeParse(JSON.parse(latest.content))
  if (!body.success) return PLAINTEXT_POLICY
  return {
    enc: body.data.enc as EncMode,
    epoch: body.data.epoch,
    reason: body.data.reason,
    author: latest.pubkey,
  }
}

/** The relay's own signed member list, which is the only authority on membership. */
export async function channelMembers(client: RelayClient, group: string): Promise<string[]> {
  const [members] = await client.query([
    { kinds: [BorrowedKinds.GroupMembers], '#d': [group], limit: 1 },
  ])
  if (!members) return []
  return members.tags.flatMap((t) => (t[0] === TagName.Pubkey && t[1] ? [t[1]] : []))
}

/**
 * Every channel key this identity can open, by epoch.
 *
 * Built by fetching the 8110s addressed to us and unwrapping each with the
 * signer. A wrap that fails to open is skipped with a warning rather than
 * thrown, because one bad wrap — an admin who used a stale pubkey, say — must
 * not make the other nine unreadable.
 */
export async function channelKeyring(
  client: RelayClient,
  signer: Signer,
  pubkey: string,
  group: string,
  onProblem?: (message: string) => void,
): Promise<Map<number, Uint8Array>> {
  const wraps = await client.query([
    { kinds: [RegularKinds.ChannelKey], '#h': [group], '#p': [pubkey], limit: 500 },
  ])

  const keys = new Map<number, Uint8Array>()
  for (const wrap of wraps) {
    // The `#p` filter is a coarse prefilter — it matches a mention as readily
    // as an addressing tag — so the exact check happens here, as everywhere.
    if (!addressees(wrap.tags).includes(pubkey)) continue
    const body = ChannelKeyBody.safeParse(JSON.parse(wrap.content))
    if (!body.success) {
      onProblem?.(`channel key ${wrap.id.slice(0, 8)}… has a malformed body`)
      continue
    }
    if (keys.has(body.data.epoch)) continue
    try {
      const hex = await signer.nip44Decrypt(wrap.pubkey, body.data.key)
      keys.set(body.data.epoch, conversationKeyFromHex(hex))
    } catch (error) {
      onProblem?.(
        `could not unwrap epoch ${body.data.epoch} from ${wrap.pubkey.slice(0, 8)}…: ${(error as Error).message}`,
      )
    }
  }
  return keys
}

export interface ChannelCryptoDeps {
  client: RelayClient
  signer: Signer
  pubkey: string
  group: string
  log?: { warn(message: string, ...rest: unknown[]): void }
}

/**
 * One channel's encryption state, loaded once and refreshable.
 *
 * Held by the `Agent`, which seals on the way out and opens on the way in. A
 * plaintext channel gets one of these too and it does nothing — that keeps the
 * caller free of `if (encrypted)` branches, which is where this sort of thing
 * usually goes wrong.
 */
export class ChannelCrypto {
  private readonly deps: ChannelCryptoDeps
  private policyState: ChannelPolicy = PLAINTEXT_POLICY
  private keys = new Map<number, Uint8Array>()

  constructor(deps: ChannelCryptoDeps) {
    this.deps = deps
  }

  get policy(): ChannelPolicy {
    return this.policyState
  }

  get encrypted(): boolean {
    return this.policyState.enc === EncMode.Nip44
  }

  /** Epochs this identity can read, ascending. */
  get epochs(): number[] {
    return [...this.keys.keys()].sort((a, b) => a - b)
  }

  /** Fetch the policy and unwrap every key addressed to us. Safe to call again. */
  async load(): Promise<void> {
    const { client, signer, pubkey, group, log } = this.deps
    this.policyState = await channelPolicy(client, group)
    if (this.policyState.enc === EncMode.Plaintext) {
      this.keys = new Map()
      return
    }
    this.keys = await channelKeyring(client, signer, pubkey, group, (message) =>
      (log ?? console).warn(`[channel] ${message}`),
    )

    const writing = this.policyState.epoch
    if (writing !== undefined && !this.keys.has(writing)) {
      // Not thrown. An agent in this state can still read history and still
      // publish the unsealed kinds — a `channel_key` request, a join — and a
      // human can still see it is stuck. Throwing here would take the agent
      // down at startup for a condition an admin fixes with one command.
      ;(log ?? console).warn(
        `[channel] ${group} writes under epoch ${writing} and this identity holds ${
          this.epochs.length ? `only ${this.epochs.join(', ')}` : 'no keys'
        }; ask an admin to wrap it`,
      )
    }
  }

  /**
   * Seal an event if the channel says to, and leave it alone otherwise.
   *
   * `build()` has already decided the `alt` and the tags, including `enc` and
   * `epoch`, so this only replaces the content — see `seal.ts` on why the
   * ordering matters and why the nonce is derived rather than random.
   */
  seal(unsigned: UnsignedEvent): UnsignedEvent {
    if (encOf(unsigned.tags) !== EncMode.Nip44) return unsigned
    const at = epochOf(unsigned.tags)
    if (at === undefined) throw new Error('channel: refusing to seal an event with no epoch tag')
    const key = this.keys.get(at)
    if (!key) throw new MissingChannelKey(at)
    return sealEvent(unsigned, key)
  }

  /**
   * The plaintext content of an event, sealed or not.
   *
   * Returns a string, never a patched event. An event object carrying plaintext
   * content under the sealed event's id is a forgery that `verifyEvent()` would
   * catch and most callers would not.
   */
  open(event: NostrEvent): string {
    if (!isSealed(event)) return event.content
    const at = epochOf(event.tags)
    const key = at === undefined ? undefined : this.keys.get(at)
    if (!key) throw new MissingChannelKey(at, event.id)
    return openEvent(event, key)
  }

  /**
   * The event with its content replaced by the plaintext. **Read this comment.**
   *
   * The result is not a valid Nostr event: its `id` commits to the ciphertext,
   * so `verifyEvent()` on it returns false and publishing it would leak the
   * channel. It exists for exactly one caller — the context packer, which reads
   * bodies and never re-verifies or re-publishes — because the alternative is
   * threading an `open` callback through `packContext`, and a packer that takes
   * a decryption hook is a packer that can give two different answers for one
   * thread. `extractive-v1` producing byte-identical output in two languages is
   * the property M6 exists to have; opening the events *before* the pure
   * function keeps it pure.
   */
  opened(event: NostrEvent): NostrEvent {
    if (!isSealed(event)) return event
    return { ...event, content: this.open(event) }
  }

  /** True if this event is sealed under an epoch we do not hold. */
  unreadable(event: NostrEvent): boolean {
    if (!isSealed(event)) return false
    const at = epochOf(event.tags)
    return at === undefined || !this.keys.has(at)
  }

  /**
   * The `open` hook the verifiers take: a readable copy, or nothing.
   *
   * One function rather than one per caller. `act()`, the offline auditor and
   * every console command that reads a body all need the same three-line
   * closure, and three copies of "what counts as readable" is how the agent
   * comes to act on an approval the auditor will not count. Note that it
   * returns `undefined` rather than throwing: a missing epoch costs that one
   * event, never the whole check.
   */
  opener(): (event: NostrEvent) => NostrEvent | undefined {
    return (event) => (this.unreadable(event) ? undefined : this.opened(event))
  }

  /**
   * What `build()` needs so the event comes out correctly tagged.
   *
   * Spread into a publish call. On a plaintext channel it is empty, which is
   * how callers stay branch-free.
   */
  buildOptions(kind: number): { enc?: EncMode; epoch?: number } {
    if (!this.encrypted || !mustSeal(kind)) return {}
    const at = this.policyState.epoch
    if (at === undefined) throw new Error('channel: policy says nip44 but names no epoch')
    return { enc: EncMode.Nip44, epoch: at }
  }

  /** Add a key we already hold — used by the admin path, which mints before it reads. */
  remember(epoch: number, key: Uint8Array): void {
    this.keys.set(epoch, key)
  }

  /**
   * The raw secret for one epoch, for the one caller that needs it.
   *
   * That caller is {@link wrapChannelKey}: handing an existing epoch to a new
   * member means re-wrapping bytes this identity already holds, and there is no
   * way to do it without them. Everything else — sealing, opening, deciding
   * what to tag — is a method on this class precisely so the key never has to
   * leave it.
   *
   * Named for what it returns rather than `get key`, because a property that
   * silently yields secret bytes is a property that ends up in a debug dump.
   */
  keyFor(epoch: number): Uint8Array | undefined {
    return this.keys.get(epoch)
  }
}

/**
 * Open every event we can and drop the ones we cannot, telling the caller how
 * many went.
 *
 * The alternative — letting `MissingChannelKey` out — means a reader that
 * joined a channel one epoch late cannot render *any* thread containing a
 * single older message, so one unreadable event takes away the whole view
 * rather than itself. Dropping is the smaller lie, but it is still a lie by
 * omission: the result looks complete and nothing in it says otherwise. Hence
 * `onMissing`, which is not optional in spirit even though it is in the type.
 *
 * Shared rather than written per client for the reason the audit verdict and
 * `applyEdits` are shared: the agent packs a prompt from this, the console
 * prints a feed from it, and the browser draws a timeline. Three implementations
 * of "what can I read" would disagree about how many messages there are.
 */
export function openReadable(
  crypto: ChannelCrypto,
  events: readonly NostrEvent[],
  onMissing?: (missing: number, held: number[]) => void,
): NostrEvent[] {
  const opened: NostrEvent[] = []
  let missing = 0
  for (const event of events) {
    try {
      opened.push(crypto.opened(event))
    } catch (error) {
      if (!(error instanceof MissingChannelKey)) throw error
      missing += 1
    }
  }
  if (missing) onMissing?.(missing, crypto.epochs)
  return opened
}

// --- the admin half ---------------------------------------------------------

export interface RotateOptions {
  publisher: Publisher
  client: RelayClient
  signer: Signer
  group: string
  /** Who should be able to read from the new epoch on. Defaults to the relay's member list. */
  members?: string[]
  reason?: string
  /** Supply the key for a deterministic test. Otherwise 32 fresh random bytes. */
  key?: Uint8Array
}

export interface Rotation {
  epoch: number
  key: Uint8Array
  wraps: NostrEvent[]
  policy: NostrEvent
}

/**
 * Mint the next epoch, wrap it for every member, and publish the policy.
 *
 * Also how a channel becomes encrypted in the first place: with no previous
 * policy this publishes epoch 1 and flips `enc` to `nip44`.
 *
 * The order is wraps first, policy last, and it is the only order that does not
 * break the channel for somebody. Publishing the policy first tells every
 * writer to start sealing under an epoch that has not reached anyone yet.
 */
export async function rotateChannelKey(options: RotateOptions): Promise<Rotation> {
  const { publisher, client, signer, group } = options

  const current = await channelPolicy(client, group)
  const epoch = (current.epoch ?? 0) + 1
  const key = options.key ?? randomConversationKey()
  const members = options.members ?? (await channelMembers(client, group))
  if (members.length === 0) {
    throw new Error(
      `refusing to rotate ${group}: the relay lists no members, so nobody would be able to read it`,
    )
  }

  const keyHex = conversationKeyToHex(key)
  const wraps: NostrEvent[] = []
  for (const member of members) {
    wraps.push(
      await publisher.publish({
        kind: RegularKinds.ChannelKey,
        group,
        to: [member],
        body: {
          epoch,
          key: await signer.nip44Encrypt(member, keyHex),
          recipient: member,
          ...(current.epoch !== undefined ? { supersedes: current.epoch } : {}),
        },
      }),
    )
  }

  const policy = await publisher.publish({
    kind: AddressableKinds.ChannelPolicy,
    group,
    d: group,
    body: {
      enc: EncMode.Nip44,
      epoch,
      ...(options.reason ? { reason: options.reason } : {}),
      changed_at: Math.floor(Date.now() / 1000),
    },
  })

  return { epoch, key, wraps, policy }
}

/**
 * Hand an existing epoch to one member, without rotating.
 *
 * The join path: a new member needs every epoch they are allowed to read, and
 * *which* epochs those are is a judgement nobody else can make for the admin.
 * Handing over only the current one is the conservative answer and handing over
 * all of them is the useful one, so the caller says.
 */
export async function wrapChannelKey(options: {
  publisher: Publisher
  signer: Signer
  group: string
  member: string
  epoch: number
  key: Uint8Array
  supersedes?: number
}): Promise<NostrEvent> {
  const { publisher, signer, group, member, epoch, key } = options
  return publisher.publish({
    kind: RegularKinds.ChannelKey,
    group,
    to: [member],
    body: {
      epoch,
      key: await signer.nip44Encrypt(member, conversationKeyToHex(key)),
      recipient: member,
      ...(options.supersedes !== undefined ? { supersedes: options.supersedes } : {}),
    },
  })
}

/** Turn a hex channel key back into bytes. Re-exported so callers need one import. */
export function channelKeyFromHex(hex: string): Uint8Array {
  return conversationKeyFromHex(hex)
}

/** Only used where a key crosses a process boundary on purpose, such as a test. */
export function channelKeyToHex(key: Uint8Array): string {
  return conversationKeyToHex(key)
}

/** `hexToBytes`, narrowed, so this module owns every hex→key conversion. */
export function assertChannelKey(value: string): Uint8Array {
  const bytes = hexToBytes(value)
  if (bytes.length !== 32) throw new Error('a channel key is 32 bytes')
  return bytes
}

/** Read the `d` of a policy event. Small, but wrong twice is one too many. */
export function policyGroup(event: NostrEvent): string | undefined {
  return tagValue(event.tags, TagName.Identifier)
}
