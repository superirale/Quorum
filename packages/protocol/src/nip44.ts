/**
 * NIP-44 v2 — versioned encryption, as the rest of Nostr already defines it.
 *
 * This is a plain implementation of somebody else's specification and there is
 * nothing Quorum-specific in it. That is the point: an encrypted Quorum channel
 * should be readable by any Nostr library that has already done this work, and
 * the payloads a bunker signs for us in NIP-46 are the same construction. The
 * Quorum-specific part — which key, over what, with which nonce — lives in
 * `seal.ts` next door.
 *
 * ## The shape
 *
 * ```
 * conversation_key = hkdf_extract(ikm = ecdh_x(privA, pubB), salt = "nip44-v2")
 * chacha_key, chacha_nonce, hmac_key = hkdf_expand(conversation_key, info = nonce, 76)
 * ciphertext = chacha20(chacha_key, chacha_nonce, pad(plaintext))
 * mac = hmac_sha256(hmac_key, nonce || ciphertext)
 * payload = base64(0x02 || nonce || ciphertext || mac)
 * ```
 *
 * Two properties of that shape matter to the layer above:
 *
 * **The conversation key is 32 bytes and the ECDH is only how NIP-44 happens to
 * derive one.** `encrypt`/`decrypt` take the key directly, so any 32 random
 * bytes work — which is exactly what a shared channel key is. NIP-44 is
 * pairwise by construction only in `conversationKey()`; the cipher underneath
 * is symmetric and has no opinion about how many people hold it.
 *
 * **The nonce is an argument, not a side effect.** The reference implementation
 * generates 32 random bytes and never lets a caller supply them, which is the
 * correct default and the wrong one for us — see `seal.ts` for why a random
 * nonce breaks `once()`. Passing a nonce in is therefore supported, and the
 * responsibility that comes with it is stated there rather than here.
 *
 * ## What is not authenticated
 *
 * The MAC covers the nonce and the ciphertext. It does not cover the event, the
 * sender, or anything else — a NIP-44 payload on its own proves only that
 * somebody holding the key produced it. On a shared-key channel that is *every
 * member*, so confidentiality comes from here and authorship comes from the
 * event's schnorr signature. Neither substitutes for the other.
 */

import { chacha20 } from '@noble/ciphers/chacha.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { extract, expand } from '@noble/hashes/hkdf.js'
import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, hexToBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils.js'
import { base64 } from '@scure/base'

/** The only version this implements. v1 was withdrawn; v0 never existed. */
export const NIP44_VERSION = 2

const SALT = utf8ToBytes('nip44-v2')

/** Smallest and largest plaintext, in bytes, that NIP-44 will carry. */
export const NIP44_MIN_PLAINTEXT = 1
export const NIP44_MAX_PLAINTEXT = 65535

/** The three keys one message uses, all derived from the conversation key and the nonce. */
export interface MessageKeys {
  chachaKey: Uint8Array
  chachaNonce: Uint8Array
  hmacKey: Uint8Array
}

/**
 * The pairwise key shared by two Nostr identities.
 *
 * Symmetric in the pair: `conversationKey(a.sec, b.pub)` equals
 * `conversationKey(b.sec, a.pub)`, which is what makes it usable as a channel
 * without either side publishing anything first.
 *
 * Only the x-coordinate of the ECDH point is used. Dropping the parity byte is
 * deliberate in NIP-44 and interoperable implementations must do the same.
 */
export function conversationKey(privkey: string | Uint8Array, pubkey: string): Uint8Array {
  const priv = typeof privkey === 'string' ? hexToBytes(privkey) : privkey
  // A Nostr pubkey is x-only. `02` is the even-y lift, which is the convention
  // NIP-44 fixes; the choice is arbitrary but must be the same on both sides.
  const shared = secp256k1.getSharedSecret(priv, `02${pubkey}`)
  return extract(sha256, shared.subarray(1, 33), SALT)
}

/** Per-message keys. Exported because the official vectors test it directly. */
export function messageKeys(conversationKey: Uint8Array, nonce: Uint8Array): MessageKeys {
  if (conversationKey.length !== 32) throw new Error('nip44: conversation key must be 32 bytes')
  if (nonce.length !== 32) throw new Error('nip44: nonce must be 32 bytes')
  const derived = expand(sha256, conversationKey, nonce, 76)
  return {
    chachaKey: derived.subarray(0, 32),
    chachaNonce: derived.subarray(32, 44),
    hmacKey: derived.subarray(44, 76),
  }
}

/**
 * The padded length NIP-44 rounds a plaintext up to.
 *
 * Padding is a privacy measure and a weak one, stated as such in the NIP: it
 * hides the exact length of a message, not its rough size. Everything at or
 * under 32 bytes looks the same; above that, lengths are quantised to a
 * one-eighth-of-a-power-of-two grid, so a long message still leaks its
 * magnitude. On an encrypted Quorum channel the relay also sees every tag, so
 * length hiding is the least of what it can infer.
 */
export function calcPaddedLen(length: number): number {
  if (!Number.isInteger(length) || length < 1) throw new Error('nip44: length must be positive')
  if (length <= 32) return 32
  const nextPower = 1 << (Math.floor(Math.log2(length - 1)) + 1)
  const chunk = nextPower <= 256 ? 32 : nextPower / 8
  return chunk * (Math.floor((length - 1) / chunk) + 1)
}

function pad(plaintext: string): Uint8Array {
  const unpadded = utf8ToBytes(plaintext)
  const length = unpadded.length
  if (length < NIP44_MIN_PLAINTEXT || length > NIP44_MAX_PLAINTEXT) {
    throw new Error(`nip44: plaintext must be 1..${NIP44_MAX_PLAINTEXT} bytes, got ${length}`)
  }
  const padded = new Uint8Array(2 + calcPaddedLen(length))
  new DataView(padded.buffer).setUint16(0, length, false)
  padded.set(unpadded, 2)
  return padded
}

function unpad(padded: Uint8Array): string {
  const length = new DataView(padded.buffer, padded.byteOffset, padded.byteLength).getUint16(0)
  const unpadded = padded.subarray(2, 2 + length)
  // All three checks matter. The length prefix is inside the ciphertext but the
  // MAC covers the ciphertext, not the plaintext's self-consistency, so a
  // padding oracle is the shape of bug to avoid here: refuse anything whose
  // declared length does not reconstruct the exact buffer we were handed.
  if (
    length < NIP44_MIN_PLAINTEXT ||
    unpadded.length !== length ||
    padded.length !== 2 + calcPaddedLen(length)
  ) {
    throw new Error('nip44: invalid padding')
  }
  return new TextDecoder().decode(unpadded)
}

/**
 * Encrypt `plaintext` under a 32-byte conversation key.
 *
 * `nonce` defaults to 32 fresh random bytes, which is what NIP-44 says and what
 * any caller outside this repository should use. Quorum supplies its own; the
 * rule that makes that safe is in `seal.ts`.
 */
export function nip44Encrypt(
  plaintext: string,
  conversationKey: Uint8Array,
  nonce: Uint8Array = randomBytes(32),
): string {
  const keys = messageKeys(conversationKey, nonce)
  const ciphertext = chacha20(keys.chachaKey, keys.chachaNonce, pad(plaintext))
  const mac = hmac(sha256, keys.hmacKey, concat(nonce, ciphertext))
  return base64.encode(concat(Uint8Array.of(NIP44_VERSION), nonce, ciphertext, mac))
}

/** Decrypt a base64 NIP-44 payload. Throws on any failure, never returns a guess. */
export function nip44Decrypt(payload: string, conversationKey: Uint8Array): string {
  // NIP-04 payloads end in `?iv=…` and NIP-44 reserves a leading `#` for future
  // non-base64 versions. Both are worth naming, because "invalid base64" sends
  // an operator looking at the wrong layer.
  if (payload.startsWith('#')) throw new Error('nip44: unsupported payload version')
  if (payload.length < 132 || payload.length > 87472) {
    throw new Error(`nip44: payload length ${payload.length} out of range`)
  }

  const data = base64.decode(payload)
  if (data[0] !== NIP44_VERSION) throw new Error(`nip44: unknown version ${data[0]}`)
  if (data.length < 99 || data.length > 65603) {
    throw new Error(`nip44: decoded length ${data.length} out of range`)
  }

  const nonce = data.subarray(1, 33)
  const ciphertext = data.subarray(33, data.length - 32)
  const mac = data.subarray(data.length - 32)

  const keys = messageKeys(conversationKey, nonce)
  const expected = hmac(sha256, keys.hmacKey, concat(nonce, ciphertext))
  if (!equalBytes(mac, expected)) throw new Error('nip44: invalid MAC')

  return unpad(chacha20(keys.chachaKey, keys.chachaNonce, ciphertext))
}

/** A fresh 32-byte symmetric key. Used as a channel key, which is a conversation key. */
export function randomConversationKey(): Uint8Array {
  return randomBytes(32)
}

/** Hex for the places a key crosses a JSON boundary. */
export function conversationKeyToHex(key: Uint8Array): string {
  return bytesToHex(key)
}

export function conversationKeyFromHex(hex: string): Uint8Array {
  const key = hexToBytes(hex)
  if (key.length !== 32) throw new Error('nip44: conversation key must be 32 bytes')
  return key
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let at = 0
  for (const part of parts) {
    out.set(part, at)
    at += part.length
  }
  return out
}

/** Constant-time-ish compare. The MAC is the only thing checked with it. */
function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!
  return diff === 0
}
