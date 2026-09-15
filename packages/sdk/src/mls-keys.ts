/**
 * Key establishment: how a pubkey becomes a leaf in the ratchet tree.
 *
 * `mls.ts` is the ratchet and `@quorum/protocol`'s `mls-keys.ts` is the tag
 * layer. This is the part that puts them on the wire, and it is four acts in a
 * fixed order:
 *
 * 1. the joiner publishes a KeyPackage — {@link publishKeyPackage};
 * 2. an existing member reads it — {@link fetchKeyPackages};
 * 3. that member commits an Add and hands over a Welcome — {@link inviteToMls};
 * 4. the joiner opens the Welcome and holds the ratchet — {@link acceptMlsInvite}.
 *
 * ## Two lists, in one order
 *
 * NIP-29 membership comes first and the ratchet second, and that ordering is
 * not a convenience. Step 1 publishes an event carrying an `h` tag, and the
 * workspace relay refuses those from non-members — so a joiner who is not
 * already in the NIP-29 group cannot even *offer* a KeyPackage. That is the
 * design working: admission is a capability decision an owner makes (M5's
 * `group:join` grant), and the ratchet records the consequence rather than
 * making the decision.
 *
 * It does not collapse the two lists into one. They still answer different
 * questions — "may this key talk to the relay" and "can this key open the
 * ciphertext" — and they can still disagree in both directions. Removing a
 * member at the relay leaves them holding epoch secrets that open the channel
 * from any other relay carrying it, which only an MLS Remove commit ends;
 * adding them at the relay gives them nothing to read until somebody commits an
 * Add. Both acts are required and neither may be inferred from the other.
 *
 * ## What the inviter must check before committing
 *
 * A KeyPackage carries a credential, and the credential is the *only* place the
 * pubkey↔MLS-identity binding is legible — a receiver of an application message
 * never sees one, which is why per-message authorship moved to
 * `authenticated_data` (see `mls.ts`). So the check has to happen here, at the
 * one moment it is possible, and {@link fetchKeyPackages} refuses a 30443 whose
 * credential names anybody but the pubkey that signed it. Skip it and a member
 * can publish a KeyPackage whose credential claims another member's identity;
 * every message they then send arrives with `authenticated_data` matching their
 * own signature, so nothing downstream ever notices, and the tree quietly says
 * two leaves belong to one person.
 */

import { bytesToHex } from '@noble/hashes/utils.js'
import { base64 } from '@scure/base'
import {
  BorrowedKinds,
  MlsCommitBody,
  MlsInvite,
  MlsWelcomeBody,
  RegularKinds,
  addressees,
  mlsKeyPackageTags,
  parseMlsKeyPackageEvent,
  type NostrEvent,
} from '@quorum/protocol'
import {
  ciphersuites,
  decodeMlsMessage,
  encodeMlsMessage,
  type CiphersuiteImpl,
  type CiphersuiteName,
  type KeyPackage,
  type Welcome,
} from 'ts-mls'
// Published entry points, not internals: `ts-mls`'s `exports` map is
// `{".": …, "./*.js": …}`. The curated root index re-exports the high-level
// operations and not the codecs, and a KeyPackage on the wire needs both.
import { makeKeyPackageRef, verifyKeyPackage } from 'ts-mls/keyPackage.js'
import { decodeRatchetTree, encodeRatchetTree } from 'ts-mls/ratchetTree.js'
import type { RelayClient } from './client.ts'
import { MLS_CIPHERSUITE, credentialPubkey, type MlsCrypto, type MlsIdentity } from './mls.ts'
import type { Publisher, PublishOptions } from './publish.ts'
import type { Signer } from './signer.ts'

/** MLS's own version label; there is exactly one and RFC 9420 fixes it. */
const MLS10 = 'mls10' as const

/**
 * A KeyPackage as it arrived: the event, the decoded package, and who signed it.
 *
 * The event is kept rather than discarded because {@link inviteToMls} has to
 * name it in the Welcome by id — a KeyPackage is single-use and the addressable
 * coordinate may already hold its replacement.
 */
export interface PublishedKeyPackage {
  event: NostrEvent
  keyPackage: KeyPackage
  /** The pubkey that signed the event *and* is named by the credential; they agree. */
  pubkey: string
}

/** Why a 30443 was not usable, for a caller that wants to report rather than throw. */
export type KeyPackageProblem = (event: NostrEvent, reason: string) => void

/**
 * Publish this identity's KeyPackage into a channel, replacing any earlier one.
 *
 * Addressable with `d` = the group, so this *is* the retirement of the previous
 * package as well as the offer of a new one. RFC 9420 makes an ordinary
 * KeyPackage single-use — its `init_key` is deleted once a Welcome built from it
 * is accepted — and an addressable slot means the two facts are one write
 * instead of a publish and a NIP-09 deletion that a relay may decline to honour.
 *
 * Call it again after {@link acceptMlsInvite} succeeds. Do *not* call it after a
 * Welcome that failed to open: the old package's private half is still the only
 * thing that can open a Welcome already in flight, and replacing it turns a
 * retryable delivery problem into a member who can never be added.
 */
export async function publishKeyPackage(options: {
  publisher: Publisher
  group: string
  identity: MlsIdentity
  ciphersuite: CiphersuiteImpl
}): Promise<NostrEvent> {
  const { publisher, ...rest } = options
  return publisher.publish(await mlsKeyPackageEvent(rest))
}

/**
 * The same event, built and not published.
 *
 * Split out for the one caller that must not hold a `Publisher`: the
 * conformance suite allocates its own `counter` values, and a second publisher
 * over the same key would diverge from them on its first write and emit a
 * duplicate — which says "this key is in two places", the most alarming thing
 * this protocol can say about an agent. It also needs the *correct* KeyPackage,
 * with real key material, because that is the control its wrong-slot check is
 * measured against: a relay refusing a placeholder would look exactly like a
 * relay enforcing the rule.
 */
export async function mlsKeyPackageEvent(options: {
  group: string
  identity: MlsIdentity
  ciphersuite: CiphersuiteImpl
}): Promise<PublishOptions> {
  const { group, identity, ciphersuite } = options
  const { publicPackage } = identity
  const ref = bytesToHex(await makeKeyPackageRef(publicPackage, ciphersuite.hash))
  const capabilities = publicPackage.leafNode.capabilities

  return {
    kind: BorrowedKinds.MlsKeyPackage,
    group,
    d: group,
    text: base64.encode(
      encodeMlsMessage({ version: MLS10, wireformat: 'mls_key_package', keyPackage: publicPackage }),
    ),
    tags: mlsKeyPackageTags({
      ref,
      ciphersuites: capabilities.ciphersuites.map(suiteId),
      extensions: capabilities.extensions,
      proposals: capabilities.proposals,
    }),
  }
}

/**
 * The number a capability list must carry for a ciphersuite the leaf names.
 *
 * `Capabilities.ciphersuites` is typed `CiphersuiteName[]` and is not one.
 * `ts-mls` appends GREASE values — RFC 9420 §13.2's exercise of unallocated
 * code points, so that a receiver refusing an unknown value is caught early —
 * as decimal *strings*, each included with probability 0.1, so roughly four
 * KeyPackages in five advertise at least one suite that is in no registry.
 * Looking those up gives `undefined`, which the id-list writer correctly
 * refuses; the effect was that publishing a KeyPackage failed most of the time
 * with a message about 16-bit ids and nothing pointing at GREASE.
 *
 * Passing them through rather than dropping them is the point of the exercise:
 * these values are advertised precisely so that somebody's reader meets one.
 */
function suiteId(name: string): number {
  const known = ciphersuites[name as CiphersuiteName]
  if (known !== undefined) return known
  const grease = Number(name)
  if (Number.isInteger(grease)) return grease
  throw new Error(`mls: "${name}" is neither a known ciphersuite nor a numeric id`)
}

/**
 * Every usable KeyPackage offered to a channel, one per publisher.
 *
 * A package that fails any check is dropped with a reason rather than thrown,
 * because the caller is an inviter adding several members at once and one
 * malformed package must not cost the other four their invitation. The reason
 * is reported rather than swallowed, though — a member silently missing from a
 * commit is a member who will be waiting for a Welcome that is never coming.
 */
export async function fetchKeyPackages(
  client: RelayClient,
  group: string,
  options: { ciphersuite: CiphersuiteImpl; onProblem?: KeyPackageProblem; limit?: number },
): Promise<PublishedKeyPackage[]> {
  const events = await client.query([
    { kinds: [BorrowedKinds.MlsKeyPackage], '#h': [group], limit: options.limit ?? 500 },
  ])

  const found: PublishedKeyPackage[] = []
  const seen = new Set<string>()
  for (const event of events) {
    const usable = await readKeyPackage(event, group, options.ciphersuite, options.onProblem)
    if (usable === undefined) continue
    // Addressable, so the relay already keeps one per (pubkey, d) — but a
    // generic relay need not, and a client that merged two stores could hold
    // both. Newest first is how a relay serves, so the first is the current one.
    if (seen.has(usable.pubkey)) continue
    seen.add(usable.pubkey)
    found.push(usable)
  }
  return found
}

async function readKeyPackage(
  event: NostrEvent,
  group: string,
  ciphersuite: CiphersuiteImpl,
  onProblem?: KeyPackageProblem,
): Promise<PublishedKeyPackage | undefined> {
  const reject = (reason: string) => {
    onProblem?.(event, reason)
    return undefined
  }

  let parsed: ReturnType<typeof parseMlsKeyPackageEvent>
  try {
    parsed = parseMlsKeyPackageEvent(event)
  } catch (error) {
    return reject((error as Error).message)
  }
  if (parsed.group !== group) return reject(`it names group ${parsed.group}, not ${group}`)

  const decoded = decodeMlsMessage(parsed.message, 0)
  if (decoded === undefined) return reject('its content is not a decodable MLSMessage')
  const [message] = decoded
  if (message.wireformat !== 'mls_key_package') {
    return reject(`it frames a ${message.wireformat}, not an mls_key_package`)
  }
  const keyPackage = message.keyPackage

  // The ciphersuite check is here rather than at join time for the reason the
  // spec gives: MLS negotiates nothing at the message level, so a member added
  // under a suite this workspace does not speak is a member who reads nothing,
  // discovered later and looking like a delivery problem.
  if (keyPackage.cipherSuite !== MLS_CIPHERSUITE) {
    return reject(`it is for ciphersuite ${keyPackage.cipherSuite}, and this workspace speaks ${MLS_CIPHERSUITE}`)
  }

  // Self-signed, so this only says the package is internally consistent. It is
  // still worth doing before the credential check: an unverified KeyPackage's
  // credential is an unauthenticated string, and rejecting on it would produce
  // a confusing message about identity for what is really a corrupt package.
  if (!(await verifyKeyPackage(keyPackage, ciphersuite.signature))) {
    return reject('its own signature does not verify')
  }

  // The ref is advisory — it is derivable from the package — but a mismatch
  // means the publisher computed it against different bytes from the ones they
  // sent, which is worth refusing rather than recomputing over.
  const ref = bytesToHex(await makeKeyPackageRef(keyPackage, ciphersuite.hash))
  if (ref !== parsed.ref) return reject(`its \`i\` tag says ${parsed.ref} and the package hashes to ${ref}`)

  const claimed = credentialPubkey(keyPackage)
  if (claimed === undefined) return reject('it has no 32-byte `basic` credential')
  if (claimed !== event.pubkey.toLowerCase()) {
    return reject(
      `its credential claims ${claimed} and the event is signed by ${event.pubkey}. ` +
        'Committing it would put one member in the tree under another member\'s name.',
    )
  }

  return { event, keyPackage, pubkey: claimed }
}

/** What an invitation produced: the commit, the Welcome events, and the epoch they lead to. */
export interface MlsInvitation {
  epoch: number
  /** The kind 8112 every existing member needs in order to follow the group. */
  commit: NostrEvent
  welcomes: NostrEvent[]
}

/**
 * Add members to the ratchet and hand each of them their Welcome.
 *
 * One commit, one Welcome, N events — the same Welcome wrapped separately to
 * each recipient. That is deliberate and costs almost nothing: RFC 9420's
 * Welcome already contains a per-recipient `EncryptedGroupSecrets` entry, so the
 * bytes are shared and only the NIP-44 wrapping is repeated. What the N events
 * buy is addressing. A single Welcome `p`-tagged to five people would be a
 * five-way broadcast that `inbox()` cannot route and that no recipient can tell
 * is for them without decrypting, which on a channel with a hundred members is
 * ninety-nine wasted trial decryptions per invitation.
 *
 * **Three writes in a fixed order: the commit, the ratchet, then the Welcomes.**
 * The commit goes out first because the delivery service is what decides whether
 * this member's commit is the group's next epoch at all — see
 * {@link MlsCrypto.add}. The Welcomes go out last because the group must have
 * actually moved before anyone is handed a way in: publishing them first would
 * hand out entry to an epoch that may never exist, which is unrecoverable,
 * because the recipient's KeyPackage is spent either way. A crash between the
 * ratchet and the last Welcome costs the missed invitee their invitation — they
 * are in the tree, can read nothing, and must be removed and re-added — which is
 * the cheapest of the three failures and the only one that is recoverable.
 */
export async function inviteToMls(options: {
  publisher: Publisher
  signer: Signer
  crypto: MlsCrypto
  group: string
  packages: readonly PublishedKeyPackage[]
}): Promise<MlsInvitation | undefined> {
  const { publisher, signer, crypto, group, packages } = options
  if (packages.length === 0) return undefined

  let commit: NostrEvent | undefined
  const welcome = await crypto.add(
    packages.map((p) => p.keyPackage),
    async (message, at) => {
      commit = await publisher.publish({
        kind: RegularKinds.MlsCommit,
        group,
        body: {
          epoch: at,
          commit: base64.encode(message),
          adds: packages.map((p) => p.pubkey),
        } satisfies MlsCommitBody,
      })
    },
  )
  if (welcome === undefined || commit === undefined) return undefined

  const invite: MlsInvite = {
    welcome: base64.encode(encodeMlsMessage({ version: MLS10, wireformat: 'mls_welcome', welcome })),
    ratchet_tree: base64.encode(encodeRatchetTree(crypto.ratchetTree)),
  }
  const plaintext = JSON.stringify(invite)
  const epoch = crypto.epoch

  const welcomes: NostrEvent[] = []
  for (const target of packages) {
    welcomes.push(
      await publisher.publish({
        kind: RegularKinds.MlsWelcome,
        group,
        to: [target.pubkey],
        body: {
          epoch,
          invite: await signer.nip44Encrypt(target.pubkey, plaintext),
          recipient: target.pubkey,
          key_package: target.event.id,
        } satisfies MlsWelcomeBody,
      }),
    )
  }

  return { epoch, commit, welcomes }
}

/**
 * Commits published to this channel, oldest first.
 *
 * Sorted by the epoch in the body rather than by `created_at` or by arrival,
 * for the reason the M4 action chain was sorted by its `e`-tags: the ordering
 * that decides whether state advances must not be a field the publisher picks.
 * A relay also serves a filter newest-first, so the arrival order is the
 * reverse of the order these must be applied in — which would fail as
 * "a commit was missed" on the very first one.
 *
 * Two commits at one epoch are settled by event id, low first. The workspace
 * relay will not store the second one, so this only ever arises on a generic
 * relay carrying the channel — and there the tiebreak's job is to make every
 * reader pick the *same* winner, not to pick the right one. Whoever loses has
 * already advanced its own ratchet and is stranded either way.
 */
export async function fetchMlsCommits(client: RelayClient, group: string): Promise<NostrEvent[]> {
  const events = await client.query([
    { kinds: [RegularKinds.MlsCommit], '#h': [group], limit: 500 },
  ])
  // A commit nobody can parse is dropped rather than thrown on. It is not
  // addressed to this reader in particular, every member meets it, and one
  // malformed 8112 — which anyone at all can publish onto a generic relay
  // carrying the channel — that halted catch-up would take the channel down for
  // every member at once.
  const rows: { event: NostrEvent; epoch: number }[] = []
  for (const event of events) {
    const body = commitBody(event)
    if (body !== undefined) rows.push({ event, epoch: body.epoch })
  }
  rows.sort((a, b) => a.epoch - b.epoch || (a.event.id < b.event.id ? -1 : 1))
  return rows.map((row) => row.event)
}

/** The body of an 8112, or `undefined` if this event is not a readable one. */
function commitBody(event: NostrEvent): MlsCommitBody | undefined {
  try {
    return MlsCommitBody.parse(JSON.parse(event.content))
  } catch {
    return undefined
  }
}

/**
 * Apply every commit this member has not yet seen. Returns how many advanced the group.
 *
 * This is what a member calls on start and after a reconnect, and it is the
 * only reason an `mls` channel survives its third member. Commits already
 * applied are skipped silently — a backfill re-serves them and re-applying one
 * is not an error but the normal case.
 *
 * A commit for an epoch *ahead* of this member throws, and that is the honest
 * answer rather than a gap: MLS has no way to catch up a ratchet across a
 * commit it never held, so the member must be removed and re-added. Catching it
 * here means the channel says so once, rather than every subsequent message
 * failing to decrypt with `CryptoError: OperationError` from four frames inside
 * a library nobody in this repo wrote.
 */
export async function catchUpMls(
  client: RelayClient,
  crypto: MlsCrypto,
  group: string,
): Promise<number> {
  let applied = 0
  for (const event of await fetchMlsCommits(client, group)) {
    const body = commitBody(event)
    if (body !== undefined && (await crypto.applyCommit(event, body))) applied += 1
  }
  return applied
}

/** Welcomes addressed to this identity in this channel, newest first. */
export async function fetchMlsWelcomes(
  client: RelayClient,
  pubkey: string,
  group: string,
): Promise<NostrEvent[]> {
  const events = await client.query([
    { kinds: [RegularKinds.MlsWelcome], '#h': [group], '#p': [pubkey], limit: 100 },
  ])
  // The `#p` filter is a coarse prefilter — it matches a mention as readily as
  // an addressing tag — so the exact check happens here, as everywhere.
  return events.filter((event) => addressees(event.tags).includes(pubkey))
}

/**
 * Open a Welcome and join the ratchet.
 *
 * Returns `false` when this Welcome is not for the KeyPackage this identity
 * currently holds, which is an ordinary thing to meet rather than an error: a
 * member who was added, removed and re-added has two Welcomes in the channel,
 * and only the newer one matches the package they now hold. Everything else
 * throws, because it means the Welcome is for this identity and could not be
 * used — and an invitation that silently does nothing leaves somebody watching
 * an empty channel they believe they have joined.
 */
export async function acceptMlsInvite(options: {
  signer: Signer
  crypto: MlsCrypto
  identity: MlsIdentity
  event: NostrEvent
  ciphersuite: CiphersuiteImpl
}): Promise<boolean> {
  const { signer, crypto, identity, event, ciphersuite } = options

  const body = MlsWelcomeBody.parse(JSON.parse(event.content))
  const ref = bytesToHex(await makeKeyPackageRef(identity.publicPackage, ciphersuite.hash))

  const invite = MlsInvite.parse(JSON.parse(await signer.nip44Decrypt(event.pubkey, body.invite)))
  const decoded = decodeMlsMessage(base64.decode(invite.welcome), 0)
  if (decoded === undefined) throw new Error('mls: this Welcome is not a decodable MLSMessage')
  const [message] = decoded
  if (message.wireformat !== 'mls_welcome') {
    throw new Error(`mls: expected a Welcome and got a ${message.wireformat}`)
  }

  const tree = decodeRatchetTree(base64.decode(invite.ratchet_tree), 0)
  if (tree === undefined) throw new Error('mls: this Welcome carries an undecodable ratchet tree')

  // Checked *after* the payload parses and *before* the ratchet is touched. The
  // cheap ordering would be to compare refs first, but the inviter names the
  // KeyPackage event, not the ref, so working out whether this Welcome is stale
  // means reading the body — and doing anything to the ratchet on a Welcome
  // that turns out not to be ours is how a member loses the state that opens the
  // real one.
  const mine = welcomeMatches(message.welcome, ref)
  if (!mine) return false

  await crypto.join(message.welcome, identity, tree[0])
  return true
}

/**
 * Does this Welcome carry an entry for the KeyPackage we hold?
 *
 * RFC 9420 puts one `EncryptedGroupSecrets` per new member in the Welcome, each
 * labelled with the KeyPackageRef it is for, so this is a lookup rather than a
 * decryption attempt. Doing it by ref rather than by trying to join is the
 * difference between "this one is not for me" and a failed join, which
 * `ts-mls` reports as a decryption error — indistinguishable, at the call site,
 * from a Welcome somebody tampered with.
 */
function welcomeMatches(welcome: Welcome, ref: string): boolean {
  return welcome.secrets.some((secret) => bytesToHex(secret.newMember) === ref)
}
