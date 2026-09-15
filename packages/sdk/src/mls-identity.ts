/**
 * The half of a KeyPackage that is never published, kept where a restart finds it.
 *
 * A 30443 offers the *public* half of a KeyPackage. The private half — the init
 * key an inviter's HPKE seals to, the leaf HPKE key, and the signature key that
 * becomes this member's identity inside the ratchet tree — stays on the joiner's
 * disk, and RFC 9420 gives it no second copy anywhere. Lose it and the Welcome
 * built against it is permanently unopenable.
 *
 * That window is not a corner case; it is the ordinary shape of joining a
 * channel. A joiner publishes a KeyPackage and then *waits* — for a member to
 * notice it, check it, commit an Add, and publish a Welcome — which is a human
 * or agent turnaround measured in minutes or days, not milliseconds. Every
 * restart, deploy and crash in that window falls inside it. Before this file,
 * `publishKeyPackage` took an `MlsIdentity` the caller had generated in memory
 * and the caller had nowhere to put it, so the failure was not "sometimes":
 * a console command that generated, published and exited could never have
 * joined anything.
 *
 * The failure is also silent on both sides, which is why it gets a module rather
 * than a line in a command. The inviter's commit succeeds, the Add lands in the
 * tree, every other member moves to the new epoch and counts the joiner among
 * them; the joiner sees a Welcome it cannot open and a channel it cannot read.
 * Nobody is holding an error that names the cause, and the only cure is a Remove
 * commit followed by a fresh invitation.
 *
 * ## Once, and then deliberately
 *
 * {@link mlsIdentity} creates one on first call and returns that same one
 * forever after. Regenerating is the dangerous direction and it is dangerous in
 * a way that reads as helpful: a Welcome in flight was sealed to the package the
 * joiner *had*, so replacing it after publishing turns a retryable delivery
 * problem into a member who can never be added. The spec states this as a MUST
 * NOT for the failed-Welcome case; here it is the default for every case, and
 * {@link renewMlsIdentity} is the one way past it — named for the single moment
 * it is correct, which is immediately after a join succeeded and the package has
 * actually been spent.
 *
 * ## What is written down
 *
 * Three private keys, in the clear, in the `Store`. There is no version of this
 * that avoids that: the point of the file is to survive a process, so the bytes
 * have to be somewhere a process can read without a human present. `FileStore`
 * writes 0600 for this reason among others.
 */

import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import { base64 } from '@scure/base'
import type { CiphersuiteImpl, KeyPackage, PrivateKeyPackage } from 'ts-mls'
// Not on `ts-mls`'s curated index, but a published entry point via its
// `./*.js` exports map — the same door `mls.ts` uses for `clientConfig.js`.
import { decodeKeyPackage, encodeKeyPackage } from 'ts-mls/keyPackage.js'
import { credentialPubkey, mlsKeyPackage, type MlsIdentity } from './mls.ts'
import type { Store } from './store.ts'

/**
 * The stored shape, written out field by field rather than by structured clone.
 *
 * A `Uint8Array` does not survive `JSON.stringify` — it becomes `{"0":12,…}`,
 * which parses back as an object every crypto call then rejects with something
 * about a length. Naming the four fields means a store that changes its backing
 * (a file today, SQLite when the file stops scaling) cannot change what a
 * restored identity *is*.
 */
interface StoredIdentity {
  /** The public KeyPackage, TLS-encoded then base64 — the same bytes the 30443 carries. */
  package: string
  init: string
  hpke: string
  signature: string
}

function identityKey(group: string): string {
  return `mls:${encodeURIComponent(group)}:identity`
}

/** Write an identity down, replacing whatever was there. */
export async function saveMlsIdentity(
  store: Store,
  group: string,
  identity: MlsIdentity,
): Promise<void> {
  const stored: StoredIdentity = {
    package: base64.encode(encodeKeyPackage(identity.publicPackage)),
    init: bytesToHex(identity.privatePackage.initPrivateKey),
    hpke: bytesToHex(identity.privatePackage.hpkePrivateKey),
    signature: bytesToHex(identity.privatePackage.signaturePrivateKey),
  }
  await store.set(identityKey(group), stored)
}

/**
 * Read one back, or `undefined` if this identity has never made one here.
 *
 * Throws when the stored package's credential names a different pubkey than the
 * caller expects, which is the one corruption worth refusing rather than
 * reporting. A `Store` shared by two identities — two agents pointed at one
 * state file, the usual way this happens — would otherwise hand the second one
 * the first one's package, and it would *work*: the 30443 publishes, signed by
 * B, carrying a credential that says A. An inviter checking the binding rejects
 * it and B is never added, with the reason sitting in the inviter's log and B
 * staring at a channel it cannot read. Caught here it is one sentence naming
 * both keys.
 */
export async function loadMlsIdentity(
  store: Store,
  group: string,
  pubkey: string,
): Promise<MlsIdentity | undefined> {
  const stored = await store.get<StoredIdentity>(identityKey(group))
  if (stored === undefined) return undefined

  const decoded = decodeKeyPackage(base64.decode(stored.package), 0)
  if (decoded === undefined) {
    throw new Error(`mls: the stored KeyPackage for ${group} did not decode`)
  }
  const publicPackage: KeyPackage = decoded[0]

  const named = credentialPubkey(publicPackage)
  if (named !== pubkey.toLowerCase()) {
    throw new Error(
      `mls: the KeyPackage stored for ${group} belongs to ${named ?? 'an unreadable credential'}, ` +
        `not to ${pubkey.toLowerCase()}. Two identities are sharing one store; give each its own, ` +
        'or this one will publish a package nobody can add.',
    )
  }

  const privatePackage: PrivateKeyPackage = {
    initPrivateKey: hexToBytes(stored.init),
    hpkePrivateKey: hexToBytes(stored.hpke),
    signaturePrivateKey: hexToBytes(stored.signature),
  }
  return { publicPackage, privatePackage }
}

/**
 * The KeyPackage this identity holds for this channel, made on first call.
 *
 * Idempotent on purpose, and that is the whole interface: calling it twice gives
 * the same package twice, so a command that runs `publishKeyPackage` on every
 * invocation republishes the *same* offer rather than invalidating the one an
 * inviter may already be committing against. Publishing the same one again is
 * free — the 30443 is addressable, so it replaces itself with itself.
 */
export async function mlsIdentity(options: {
  store: Store
  group: string
  pubkey: string
  ciphersuite: CiphersuiteImpl
}): Promise<MlsIdentity> {
  const { store, group, pubkey, ciphersuite } = options
  const held = await loadMlsIdentity(store, group, pubkey)
  if (held !== undefined) return held

  const fresh = await mlsKeyPackage(pubkey, ciphersuite)
  await saveMlsIdentity(store, group, fresh)
  return fresh
}

/**
 * Replace it, because the one we held has been spent.
 *
 * Call this **after** a join succeeds and not before. An accepted Welcome
 * consumes the init key it was sealed to, so the published 30443 is from that
 * moment an offer that cannot be honoured: an inviter who fetches it commits an
 * Add against a private half this member no longer has, and the member it adds
 * reads nothing. Renewing and republishing is what closes that, and the
 * addressable `d` means the stale offer is retired by the same write.
 *
 * Never call it on a Welcome that failed to open. That Welcome may still be
 * openable — a delivery problem, a wrong-order read — and the package it was
 * sealed to is the only thing that can ever open it.
 */
export async function renewMlsIdentity(options: {
  store: Store
  group: string
  pubkey: string
  ciphersuite: CiphersuiteImpl
}): Promise<MlsIdentity> {
  const { store, group, pubkey, ciphersuite } = options
  const fresh = await mlsKeyPackage(pubkey, ciphersuite)
  await saveMlsIdentity(store, group, fresh)
  return fresh
}

/**
 * Throw the stored package away.
 *
 * For leaving a channel, and for the operator who has decided a joiner is stuck
 * and is starting over. Separate from {@link renewMlsIdentity} because it makes
 * no new offer: after this the identity holds nothing for this channel and the
 * next {@link mlsIdentity} call mints one.
 */
export async function forgetMlsIdentity(store: Store, group: string): Promise<void> {
  await store.delete(identityKey(group))
}
