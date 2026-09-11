/**
 * The NIP-01 event: shape, id computation, signature verification.
 *
 * Kept dependency-light on purpose. This package is what a third party reads to
 * implement Quorum in another language, so it should not require them to adopt
 * a particular Nostr library — only sha256 and secp256k1 schnorr.
 */

import { schnorr } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import { z } from 'zod'

const HEX32 = /^[0-9a-f]{64}$/
const HEX64 = /^[0-9a-f]{128}$/

export const hex32 = z.string().regex(HEX32, 'must be 64 lowercase hex characters')
export const hex64 = z.string().regex(HEX64, 'must be 128 lowercase hex characters')

export const TagSchema = z.array(z.string())

/** A signed NIP-01 event. */
export const NostrEventSchema = z.object({
  id: hex32,
  pubkey: hex32,
  created_at: z.int().nonnegative(),
  kind: z.int().min(0).max(65535),
  tags: z.array(TagSchema),
  content: z.string(),
  sig: hex64,
})

export type NostrEvent = z.infer<typeof NostrEventSchema>

/** An event before signing. `id` and `sig` are derived, so they are absent. */
export const UnsignedEventSchema = NostrEventSchema.omit({ id: true, sig: true })

export type UnsignedEvent = z.infer<typeof UnsignedEventSchema>

/**
 * NIP-01 serialisation. The exact array, in this exact order, with JSON's
 * standard escaping — the id is a hash of this string, so any deviation
 * produces a different id and an event nobody else will accept.
 */
export function serializeEvent(event: UnsignedEvent): string {
  return JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content,
  ])
}

export function computeId(event: UnsignedEvent): string {
  return bytesToHex(sha256(new TextEncoder().encode(serializeEvent(event))))
}

/** True if `id` is the hash of the event's own contents. */
export function hasValidId(event: NostrEvent): boolean {
  return computeId(event) === event.id
}

/**
 * Full verification: the id matches the contents AND the signature matches the
 * id under the claimed pubkey.
 *
 * Both halves matter. Checking only the signature lets an attacker keep a valid
 * signature while swapping the id for one that points at a different event in
 * an `e` tag — which in Quorum would mean an approval that appears to authorise
 * something the human never saw.
 */
export function verifyEvent(event: NostrEvent): boolean {
  if (!hasValidId(event)) return false
  try {
    return schnorr.verify(event.sig, event.id, event.pubkey)
  } catch {
    return false
  }
}

/** Assert form of {@link verifyEvent}, for code paths where a bad event is a bug. */
export function assertVerified(event: NostrEvent): void {
  if (!hasValidId(event)) {
    throw new Error(`event id mismatch: claimed ${event.id}, computed ${computeId(event)}`)
  }
  if (!verifyEvent(event)) {
    throw new Error(`invalid signature on event ${event.id}`)
  }
}
