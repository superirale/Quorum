/**
 * The ratchet: `ts-mls` driven from behind the `mls` envelope.
 *
 * `@quorum/protocol` owns the three bindings between an MLSMessage and the
 * Nostr event carrying it and deliberately holds no RFC 9420 code. This file is
 * the other half — the stateful part — and it is the only place in the repo
 * that imports an MLS library. The relay imports none, because on an `mls`
 * channel it reads nothing.
 *
 * Three properties shape everything below, and each one is a departure from how
 * `nip44` works rather than a detail of how this happens to be written.
 *
 * ## 1. Sealing consumes something, so it cannot be retried
 *
 * `sealEvent` is a pure function: the same body and key give the same bytes
 * every time, which is what lets `once()` buy exactly-once delivery from the
 * relay's id-is-a-content-hash dedupe. A secret tree advances per message. Seal
 * twice and you have two ciphertexts, two ids, two messages in the channel, and
 * a generation nobody can give back. So {@link MlsCrypto.seal} goes through
 * {@link SealedEnvelopes}, and the ratcheted state is persisted **before** the
 * caller is allowed to publish.
 *
 * The order of those two writes is a real decision. State first, envelope
 * second: a crash in the gap leaves a consumed generation with no cached
 * envelope, the retry seals again, and the channel gets the same sentence twice
 * under one `counter` — which is *detectable*, and the spec already says what it
 * means. Envelope first would leave the persisted state one generation behind,
 * so the agent's next message would reuse a generation every receiver has
 * already spent and would be silently dropped by all of them. A duplicate
 * somebody can see beats a message nobody gets.
 *
 * ## 2. Opening consumes something too, so it happens exactly once
 *
 * Decryption deletes the key it used — that is what forward secrecy *is*. Feed
 * `ts-mls` the same application message twice and the second call throws
 * `Desired gen in the past`. An agent that restarts and backfills its channel
 * re-sees every event it has ever opened, so "open on arrival, read from the
 * record afterwards" is not a cache policy, it is the only thing that works.
 * {@link MlsCrypto.open} therefore consults the {@link Archive} before the
 * ratchet, and {@link MlsCrypto.opener} — the synchronous hook the approval
 * verifier, the packer and the console all take — reads *only* what has already
 * been opened. See the comment on it; that narrowness is the point.
 *
 * ## 3. Authorship travels in `authenticated_data`, not in the credential
 *
 * The spec's second binding says the MLS credential identity and the event
 * `pubkey` are one author. `ts-mls` will not tell us the credential:
 * `processPrivateMessage` verifies the sender's signature and then returns
 * `{ message, newState }` with no sender in it, and RFC 9420 encrypts the sender
 * index precisely so that it is not casually available. Rather than reach into
 * the library's internals for a value it has decided not to publish, an `mls`
 * application message carries the sender's pubkey as its MLS
 * `authenticated_data`, and that is now the spec rule.
 *
 * It is not a weaker check. `authenticated_data` is covered by the AEAD and by
 * the sender's FramedContent signature, so a third party cannot alter it —
 * tampering with it fails decryption outright, which is asserted in the tests.
 * Admitting a message therefore requires the same principal to control both the
 * inner assertion and the Nostr key, which is exactly what the credential
 * binding was for. The credential↔pubkey check does not disappear; it moves to
 * where the credential is actually legible, which is the moment a KeyPackage is
 * added to the tree. And it costs nothing on the wire: the pubkey is already in
 * the clear in the event's own `pubkey` field.
 *
 * ## The attack that made a one-line ordering decision load-bearing
 *
 * The reason the credential check exists is that a member can lift another
 * member's MLSMessage off the wire and republish it under their own signature.
 * Rejecting that is straightforward. What is not obvious is what to do with the
 * ratchet step it took to *find out*: commit it and Mallory has a denial of
 * service, because republishing every message a moment before its author does
 * burns each generation and leaves the honest event permanently unopenable. So a
 * binding failure discards the new state, which is safe because `ts-mls` is
 * functional — the old state still opens the honest copy. There is a test for
 * exactly that.
 */

import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js'
import { base64 } from '@scure/base'
import {
  EncMode,
  computeId,
  enc as encOf,
  isMlsGroupId,
  isMlsSealed,
  mlsMessage,
  mustSeal,
  openMlsEvent,
  sealMlsEvent,
  type NostrEvent,
  type UnsignedEvent,
} from '@quorum/protocol'
import {
  createApplicationMessage,
  createCommit,
  createGroup,
  decodeGroupState,
  decodeMlsMessage,
  defaultCapabilities,
  defaultLifetime,
  encodeGroupState,
  encodeMlsMessage,
  emptyPskIndex,
  generateKeyPackage,
  getCiphersuiteFromName,
  getCiphersuiteImpl,
  joinGroup,
  makePskIndex,
  processPrivateMessage,
  type CiphersuiteImpl,
  type CiphersuiteName,
  type ClientState,
  type KeyPackage,
  type PrivateKeyPackage,
  type RatchetTree,
  type Welcome,
} from 'ts-mls'
// Not re-exported from `ts-mls`'s curated index, but a published entry point:
// the package's `exports` map exposes `./*.js`. Needed because
// `decodeGroupState` returns a `GroupState` *without* the `clientConfig` that a
// `ClientState` carries, so restoring from disk has to supply one.
import { defaultClientConfig } from 'ts-mls/clientConfig.js'
import { Archive, SealedEnvelopes } from './archive.ts'
import type { ChannelSealer } from './publish.ts'
import type { Store } from './store.ts'

/**
 * The one ciphersuite a Quorum workspace uses, and why there is only one.
 *
 * MLS negotiates nothing at the message level: a group has a ciphersuite and
 * every member must implement it. Letting a workspace choose would mean any two
 * clients that picked differently cannot talk, discovered at join time rather
 * than at configuration time. This one is RFC 9420's mandatory-to-implement
 * suite, it is the one `ts-mls` exercises against the reference test vectors,
 * and its signature scheme resolves to WebCrypto in both Node and the browser —
 * so it is also the only one that does not drag an optional dependency into the
 * reference client's bundle.
 */
export const MLS_CIPHERSUITE: CiphersuiteName = 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519'

/** MLS's own version label; there is exactly one and RFC 9420 fixes it. */
const MLS10 = 'mls10' as const

/** A member's MLS key material: the half that is published, and the half that is not. */
export interface MlsIdentity {
  publicPackage: KeyPackage
  privatePackage: PrivateKeyPackage
}

/** The ciphersuite implementation, resolved once and shared. */
export async function mlsCiphersuite(
  name: CiphersuiteName = MLS_CIPHERSUITE,
): Promise<CiphersuiteImpl> {
  return getCiphersuiteImpl(getCiphersuiteFromName(name))
}

/**
 * A KeyPackage whose credential identity is this agent's Nostr pubkey.
 *
 * The credential is where the spec's second binding is *established*: this
 * KeyPackage is published as a kind 30443 signed by the same pubkey, so a member
 * committing an Add has a signed statement that the identity in the tree and the
 * identity on the relay are the same principal. Per-message authorship is bound
 * separately and cheaply — see the note on `authenticated_data` at the top of
 * this file — because the credential is not visible to a receiver.
 *
 * The identity is the **32 raw bytes** of the x-only pubkey, not its hex. One
 * encoding for one fact: `authenticated_data` already carries the pubkey that
 * way, and two encodings of the same value in one protocol is a comparison
 * somebody eventually gets wrong in the direction that admits a message. It is
 * also what Marmot specifies, which costs nothing here and is the only part of
 * its KeyPackage rules Quorum can adopt unchanged.
 */
export async function mlsKeyPackage(
  pubkey: string,
  cs: CiphersuiteImpl,
): Promise<MlsIdentity> {
  return generateKeyPackage(
    { credentialType: 'basic', identity: hexToBytes(pubkey.toLowerCase()) },
    defaultCapabilities(),
    defaultLifetime,
    [],
    cs,
  )
}

/** The pubkey in a KeyPackage's basic credential, lowercase hex, or `undefined`. */
export function credentialPubkey(keyPackage: KeyPackage): string | undefined {
  return basicIdentity(keyPackage.leafNode.credential)
}

/** The 32 bytes of a `basic` credential as lowercase hex; `undefined` for any other type. */
function basicIdentity(credential: { credentialType: string; identity?: Uint8Array }): string | undefined {
  if (credential.credentialType !== 'basic' || credential.identity === undefined) return undefined
  if (credential.identity.length !== 32) return undefined
  return bytesToHex(credential.identity)
}

export interface MlsCryptoDeps {
  store: Store
  /** This agent's Nostr pubkey, hex. Goes in the credential and in every message's AAD. */
  pubkey: string
  group: string
  ciphersuite: CiphersuiteImpl
  /**
   * The durable record. Not optional in spirit: without it a restart loses the
   * channel, because the ratchet cannot open anything twice.
   */
  archive: Archive
  envelopes: SealedEnvelopes
  log?: { warn(message: string, ...rest: unknown[]): void }
}

/** What `MlsCrypto.open` did with an event, for a caller that wants to know. */
export class MlsBindingError extends Error {
  readonly eventId: string

  constructor(eventId: string, message: string) {
    super(message)
    this.name = 'MlsBindingError'
    this.eventId = eventId
  }
}

/** Raised when a caller asks for group state this client does not have. */
export class NotInMlsGroup extends Error {
  constructor(group: string) {
    super(`mls: this identity holds no group state for ${group}; create or join it first`)
    this.name = 'NotInMlsGroup'
  }
}

/**
 * One channel's MLS state: the ratchet, its persistence, and the two seams.
 *
 * The counterpart of `ChannelCrypto` and deliberately *not* a subclass of it.
 * They share two method names and nothing else: `nip44` holds a map of epoch
 * keys that opens any message from any epoch it has, in any order, as many times
 * as asked. This holds a single evolving state that opens each message once.
 * Pretending those are the same object behind one interface is how a caller ends
 * up replaying a decryption and losing a message.
 */
export class MlsCrypto implements ChannelSealer {
  private readonly deps: MlsCryptoDeps
  private state: ClientState | undefined
  /**
   * Plaintexts this session can serve synchronously — see {@link opener}.
   *
   * Bounded by what has been opened since start plus whatever {@link warm} was
   * asked to load, which for a long-lived agent is the channel. That is the
   * archive's size in memory and it is a real cost; it is also the cost of the
   * design, because the alternative is an asynchronous opener and the verifiers
   * that take one are synchronous by construction.
   */
  private readonly plaintexts = new Map<string, string>()
  /** Serialises every ratchet step. Two concurrent steps would fork the state. */
  private queue: Promise<unknown> = Promise.resolve()

  constructor(deps: MlsCryptoDeps) {
    this.deps = deps
  }

  /** Build one and restore its group state from the store, if there is any. */
  static async open(deps: MlsCryptoDeps): Promise<MlsCrypto> {
    const crypto = new MlsCrypto(deps)
    await crypto.load()
    return crypto
  }

  /** True once this client is a member and holds the ratchet. */
  get joined(): boolean {
    return this.state !== undefined
  }

  /** The epoch this client would write under right now. */
  get epoch(): number {
    return epochNumber(this.require().groupContext.epoch)
  }

  /** Every member's pubkey as its credential states it, lowercase hex. */
  get members(): string[] {
    const out: string[] = []
    for (const node of this.require().ratchetTree) {
      if (node?.nodeType !== 'leaf') continue
      const pubkey = basicIdentity(node.leaf.credential)
      if (pubkey !== undefined) out.push(pubkey)
    }
    return out
  }

  // --- membership -----------------------------------------------------------

  /**
   * Start the group. The `group_id` is the channel's, which is the first binding.
   */
  async create(identity: MlsIdentity): Promise<void> {
    await this.serial(async () => {
      const state = await createGroup(
        utf8ToBytes(this.deps.group),
        identity.publicPackage,
        identity.privatePackage,
        [],
        this.deps.ciphersuite,
      )
      await this.commit(state)
    })
  }

  /**
   * Add members and return the Welcome they need, or nothing if nobody was added.
   *
   * Delivering that Welcome is the Nostr half and lives elsewhere; this is the
   * ratchet half. Note what it does *not* do: adding a member here does not add
   * them to the NIP-29 group, and removing them there does not remove them here.
   * The two lists answer different questions — "may this key talk to the relay"
   * and "can this key open the ciphertext" — and a member holding current epoch
   * secrets reads the channel from any relay that carries it. Both acts are
   * required and neither may be inferred from the other.
   */
  async add(keyPackages: readonly KeyPackage[]): Promise<Welcome | undefined> {
    if (keyPackages.length === 0) return undefined
    return this.serial(async () => {
      const result = await createCommit(
        { state: this.require(), cipherSuite: this.deps.ciphersuite },
        {
          extraProposals: keyPackages.map((keyPackage) => ({
            proposalType: 'add' as const,
            add: { keyPackage },
          })),
        },
      )
      await this.commit(result.newState)
      return result.welcome
    })
  }

  /** Join from a Welcome, with the ratchet tree the committer published. */
  async join(
    welcome: Welcome,
    identity: MlsIdentity,
    ratchetTree?: RatchetTree,
  ): Promise<void> {
    await this.serial(async () => {
      const state = await joinGroup(
        welcome,
        identity.publicPackage,
        identity.privatePackage,
        emptyPskIndex,
        this.deps.ciphersuite,
        ratchetTree,
      )
      if (!isMlsGroupId(state.groupContext.groupId, this.deps.group)) {
        throw new Error(
          `mls: this Welcome is for group_id "${new TextDecoder().decode(state.groupContext.groupId)}" ` +
            `and this channel is ${this.deps.group}. Joining it would file another channel's messages here.`,
        )
      }
      await this.commit(state)
    })
  }

  /** The ratchet tree, for publishing alongside a Welcome. */
  get ratchetTree(): RatchetTree {
    return this.require().ratchetTree
  }

  // --- the ChannelSealer seam ----------------------------------------------

  /**
   * What `build()` needs so the event comes out correctly tagged.
   *
   * Empty when this client is not in the group, which is not an error: the
   * key-management kinds are on `UNSEALED_KINDS` for exactly this moment, and an
   * agent that cannot yet seal must still be able to publish its KeyPackage and
   * ask to be let in.
   */
  buildOptions(kind: number): { enc?: EncMode; epoch?: number } {
    if (!this.joined || !mustSeal(kind)) return {}
    return { enc: EncMode.Mls, epoch: this.epoch }
  }

  /**
   * Seal an event, or return the stored envelope if this body was sealed before.
   *
   * Keyed on the id of the event *in the clear*, which is stable across retries
   * because `once()` fixes `created_at` and reuses the reserved counter. The
   * `Publisher` calls this between `build()` and `sign()`, so what is cached is
   * unsigned — sufficient, because the relay dedupes on the id and the id
   * commits to everything but the signature.
   */
  async seal(unsigned: UnsignedEvent): Promise<UnsignedEvent> {
    if (encOf(unsigned.tags) !== EncMode.Mls) return unsigned
    if (unsigned.content === '') return unsigned
    const plaintextId = computeId(unsigned)
    return this.deps.envelopes.sealOnce<UnsignedEvent>(plaintextId, () =>
      this.serial(() => this.ratchetSeal(unsigned)),
    )
  }

  private async ratchetSeal(unsigned: UnsignedEvent): Promise<UnsignedEvent> {
    const state = this.require()
    const at = epochNumber(state.groupContext.epoch)
    const { newState, privateMessage } = await createApplicationMessage(
      state,
      utf8ToBytes(unsigned.content),
      this.deps.ciphersuite,
      // The author, authenticated but not hidden. See the header: this is the
      // per-message half of the second binding, and it leaks nothing the event's
      // own `pubkey` field does not already publish.
      hexToBytes(this.deps.pubkey.toLowerCase()),
    )

    // Built before the state is committed, so that the rotation-race check
    // inside `sealMlsEvent` — the event was tagged at one epoch and the group
    // has since moved to another — throws without having spent a generation.
    const sealed = sealMlsEvent(
      unsigned,
      encodeMlsMessage({ version: MLS10, wireformat: 'mls_private_message', privateMessage }),
      at,
    )
    await this.commit(newState)
    return sealed
  }

  // --- reading --------------------------------------------------------------

  /**
   * The plaintext of an event: from the record if it is there, from the ratchet
   * once and only once if it is not.
   *
   * The archive lookup is not an optimisation. A second trip through the ratchet
   * for the same message throws, and the ordinary way to make that happen is a
   * reconnect: restart, backfill, re-see the last month of a channel. Everything
   * this opens is recorded on the way past, including what it could not read, so
   * that a gap in the thread is visible rather than absent.
   */
  async open(event: NostrEvent): Promise<string> {
    if (!isMlsSealed(event)) {
      await this.deps.archive.record(event, event.content)
      return event.content
    }

    const remembered = this.plaintexts.get(event.id)
    if (remembered !== undefined) return remembered

    const archived = await this.deps.archive.get(this.deps.group, event.id)
    if (archived?.plaintext !== undefined) {
      this.plaintexts.set(event.id, archived.plaintext)
      return archived.plaintext
    }

    try {
      const plaintext = await this.serial(() => this.ratchetOpen(event))
      this.plaintexts.set(event.id, plaintext)
      await this.deps.archive.record(event, plaintext)
      return plaintext
    } catch (error) {
      // Recorded with no plaintext rather than dropped. An event this client
      // could not read is still part of the channel's history, and an archive
      // that silently held only the readable ones would present a
      // complete-looking thread with messages missing from it.
      await this.deps.archive.record(event)
      throw error
    }
  }

  private async ratchetOpen(event: NostrEvent): Promise<string> {
    const state = this.require()
    const decoded = decodeMlsMessage(mlsMessage(event), 0)
    if (decoded === undefined) {
      throw new MlsBindingError(event.id, 'mls: content is not a decodable MLSMessage')
    }
    const [message] = decoded
    if (message.wireformat !== 'mls_private_message') {
      throw new MlsBindingError(
        event.id,
        `mls: expected an application message and got a ${message.wireformat}`,
      )
    }
    const pm = message.privateMessage

    // The first binding, checked before anything is decrypted. The ratchet would
    // also refuse — `group_id` is in the AEAD's associated data — but it would
    // refuse with a decryption error, which reads as tampering rather than as
    // "somebody replayed a message from another channel into this one".
    if (!isMlsGroupId(pm.groupId, this.deps.group)) {
      throw new MlsBindingError(
        event.id,
        `mls: this message names group_id "${new TextDecoder().decode(pm.groupId)}" and arrived ` +
          `in ${this.deps.group}; it belongs to another channel`,
      )
    }

    const result = await processPrivateMessage(
      state,
      pm,
      makePskIndex(state, {}),
      this.deps.ciphersuite,
    )
    if (result.kind !== 'applicationMessage') {
      // A commit or proposal: it advances the group rather than saying
      // anything, so the state *is* the result and has to be kept.
      await this.commit(result.newState)
      throw new MlsBindingError(event.id, 'mls: this event carries a handshake message, not a body')
    }

    // `openMlsEvent` enforces the other two bindings and throws if either fails.
    // Deliberately before `commit`: a rejected message must leave the generation
    // unspent, or republishing each message a moment before its author does
    // becomes a way to make the whole channel unreadable. `ts-mls` is functional,
    // so discarding `newState` really does leave the old one able to open the
    // honest copy — there is a test for it.
    const plaintext = openMlsEvent(event, () => ({
      plaintext: new TextDecoder().decode(result.message),
      author: bytesToHex(pm.authenticatedData),
      epoch: epochNumber(pm.epoch),
    }))
    await this.commit(result.newState)
    return plaintext
  }

  /**
   * Open everything the archive holds into memory, so {@link opener} can answer.
   *
   * Called at start. It touches no keys and cannot fail on a missing epoch,
   * because everything it reads was decrypted when it arrived.
   */
  async warm(): Promise<number> {
    for (const record of await this.deps.archive.all(this.deps.group)) {
      if (record.plaintext !== undefined) this.plaintexts.set(record.event.id, record.plaintext)
    }
    return this.plaintexts.size
  }

  /**
   * The synchronous hook every verifier takes — and it reads the record, never
   * the ratchet.
   *
   * `tallyApprovals`, `verifyActionChain`, the context packer and three console
   * commands all want `(event) => NostrEvent | undefined`. That signature cannot
   * drive MLS, and the reflex fix — make them all async — would be the wrong
   * change even if it were free, because it would let a verifier walking a chain
   * of forty events *decrypt* them, and decrypting one twice throws. So this
   * answers from what has already been opened: {@link warm} at start,
   * {@link open} on arrival.
   *
   * The consequence is worth stating plainly rather than discovering: on an
   * `mls` channel, an event this client never saw arrive and never archived is
   * not readable, by anyone, ever. That is not a limitation of this function. It
   * is what forward secrecy means, and the same is true of the relay's copy.
   */
  opener(): (event: NostrEvent) => NostrEvent | undefined {
    return (event) => {
      if (!isMlsSealed(event)) return event
      const plaintext = this.plaintexts.get(event.id)
      // Same caveat as `ChannelCrypto.opened()`: the id commits to the
      // ciphertext, so this is not a valid event. Do not re-verify or publish it.
      return plaintext === undefined ? undefined : { ...event, content: plaintext }
    }
  }

  /** True if this event is sealed and this client has no plaintext for it. */
  unreadable(event: NostrEvent): boolean {
    return isMlsSealed(event) && !this.plaintexts.has(event.id)
  }

  // --- persistence ----------------------------------------------------------

  private async load(): Promise<void> {
    const stored = await this.deps.store.get<string>(this.stateKey())
    if (stored === undefined) return
    const decoded = decodeGroupState(base64.decode(stored), 0)
    if (decoded === undefined) {
      throw new Error(`mls: the stored group state for ${this.deps.group} did not decode`)
    }
    // `decodeGroupState` returns a `GroupState`, which is a `ClientState`
    // without its `clientConfig` — the config is policy (key retention,
    // lifetimes, padding) rather than group state, so it is not on the wire and
    // has to be supplied here.
    this.state = { ...decoded[0], clientConfig: defaultClientConfig }
  }

  /**
   * Persist first, then publish the new state to this object.
   *
   * That order is the same argument as `SealedEnvelopes.sealOnce` awaiting its
   * write: a state advanced in memory and not on disk is a generation this
   * process has spent and its replacement will spend again.
   */
  private async commit(state: ClientState): Promise<void> {
    await this.deps.store.set(this.stateKey(), base64.encode(encodeGroupState(state)))
    this.state = state
  }

  private stateKey(): string {
    return `mls:${encodeURIComponent(this.deps.group)}:state`
  }

  private require(): ClientState {
    if (this.state === undefined) throw new NotInMlsGroup(this.deps.group)
    return this.state
  }

  /**
   * One ratchet step at a time.
   *
   * Every step reads the current state and produces a successor; two in flight
   * at once both read the same predecessor and one of them is thrown away, which
   * loses either a sent message or a received one with nothing to show for it.
   * A promise chain rather than a lock because it cannot deadlock and the work is
   * always short.
   */
  private serial<T>(work: () => Promise<T>): Promise<T> {
    const next = this.queue.then(work, work)
    this.queue = next.then(
      () => undefined,
      () => undefined,
    )
    return next
  }
}

/**
 * An MLS epoch is a `uint64` and the `epoch` tag is a JSON number.
 *
 * Refused rather than rounded above 2^53. A group would need nine quadrillion
 * commits to get there, so this will not fire — but the failure it prevents is
 * two different epochs tagged with the same number, and that reads to every
 * receiver as the sender writing a wrong tag on purpose.
 */
function epochNumber(epoch: bigint): number {
  if (epoch > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(`mls: epoch ${epoch} is too large to carry in an \`epoch\` tag`)
  }
  return Number(epoch)
}
