/**
 * Sealing a Quorum event — NIP-44 applied to `content`, and nothing else.
 *
 * `nip44.ts` is somebody else's specification implemented faithfully. This file
 * is the Quorum part: which key seals a channel, what the nonce is, and what
 * survives sealing.
 *
 * ## Only `content` is encrypted, and that is a stated trade
 *
 * Every tag stays in the clear: `h`, `p`, `e`, `E`, `counter`, `enc`, `alt`.
 * The relay therefore still routes, still rate-limits, still enforces NIP-29
 * membership, still folds nothing it cannot read, and still signs checkpoints —
 * because a checkpoint commits to event ids and an id is a hash of bytes it
 * does not need to understand. What the relay loses is everything that reads a
 * *body*: the 8109→38101 projection, the context-packing DVM, the approval and
 * action-transition policies, and budget enforcement. M9 is partly a
 * subtraction milestone and the demo says so out loud.
 *
 * What an observer keeps is the social graph: who is in the channel, who
 * answered whom, when, and how often. That is a lot, it is inherent in
 * encrypting only the payload, and it is the reason `mls` is still on the plan.
 *
 * ## The nonce is derived, not random, and this is the one novel rule here
 *
 * NIP-44 says to use 32 random bytes and every other implementation does. We
 * cannot, and the reason is `once()`.
 *
 * The SDK's exactly-once property is not a lock or a ledger lookup — it is that
 * a retried effect rebuilds a **byte-identical event**, whose id the relay
 * already holds, so the relay discards it. That is why `once()` hands back the
 * reserved `created_at` and why a retry reuses its reserved `counter` instead
 * of allocating a fresh one. A random nonce breaks exactly the same way: same
 * message, different ciphertext, different id, and the agent has now said the
 * same thing twice on an encrypted channel and once on a plaintext one.
 * Idempotency would silently become a property of unencrypted channels only.
 *
 * So the nonce is a function of the message:
 *
 * ```
 * nonce = hmac_sha256(key = channel key, data = id of the event in the clear)
 * ```
 *
 * Deterministic, so a retry reproduces it. Unique per distinct event, because
 * the id covers pubkey, created_at, kind, every tag and the plaintext — and two
 * events agreeing on all of those *are* the same event, whose ciphertext should
 * be identical so the relay can dedupe it.
 *
 * **It is a MAC and not a plain hash, and that is load-bearing.** A bare
 * `sha256` of the plaintext event would be a public commitment to the
 * plaintext, published in the clear inside every payload. A relay that wanted
 * to know whether Ada said "approved" could hash the guess and compare — a
 * confirmation attack against every low-entropy message in the workspace, which
 * on a task-tracking protocol is most of them. Keying the derivation with the
 * channel key means only a member can build the nonce, so only a member can
 * make the comparison, and a member can already read the message.
 *
 * This is the synthetic-IV construction from deterministic AEAD, arrived at for
 * a different reason. The security cost is the one SIV always has and it is
 * worth stating: identical plaintexts produce identical ciphertexts, so an
 * observer sees repetition. Here that is not a leak so much as the point.
 */

import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { hexToBytes } from '@noble/hashes/utils.js'
import { computeId, type NostrEvent, type UnsignedEvent } from './event.ts'
import { nip44Decrypt, nip44Encrypt } from './nip44.ts'
import { EncMode, enc } from './tags.ts'

/**
 * The nonce for one event under one channel key.
 *
 * `unsigned` must be the event **in the clear** — tags final, `content` still
 * plaintext. Sealing after any tag changes would derive a nonce for an event
 * that no longer exists, which decrypts fine and defeats the retry property.
 */
export function sealNonce(unsigned: UnsignedEvent, key: Uint8Array): Uint8Array {
  return hmac(sha256, key, hexToBytes(computeId(unsigned)))
}

/**
 * Encrypt an event's content under a channel key.
 *
 * Returns a new event; the input is untouched, because the caller usually still
 * needs the plaintext (to log it, to hand it to a local handler, or to derive
 * the nonce again on a retry).
 *
 * The `enc` tag is not added here. `build()` adds it, because it also decides
 * the `alt` text — a sealed event whose `alt` still summarises its body would
 * publish in the clear exactly the sentence the body was hidden to protect, and
 * that decision belongs where the `alt` is generated rather than here, one
 * layer too late to fix it.
 */
export function sealEvent(unsigned: UnsignedEvent, key: Uint8Array): UnsignedEvent {
  if (enc(unsigned.tags) !== EncMode.Nip44) {
    throw new Error(
      `seal: refusing to encrypt an event tagged enc=${enc(unsigned.tags)}; build it with enc: 'nip44'`,
    )
  }
  if (unsigned.content === '') return unsigned
  return { ...unsigned, content: nip44Encrypt(unsigned.content, key, sealNonce(unsigned, key)) }
}

/**
 * Decrypt a sealed event's content. Throws if the key is wrong or it was tampered with.
 *
 * Returns the plaintext string rather than a patched event, deliberately. An
 * event object with plaintext `content` and the sealed event's `id` is a lie
 * that `verifyEvent()` would catch and most callers would not: it looks like a
 * signed event, it is not one, and republishing it would leak the channel.
 * Handing back a string makes the caller decide what to do with it.
 */
export function openEvent(event: NostrEvent | UnsignedEvent, key: Uint8Array): string {
  // An `mls` event is refused rather than passed through, and the difference
  // matters. Passing it through returns the base64 of an MLSMessage as though
  // it were the body — which is the M9 keyless-packer failure exactly: not an
  // error, a success full of nonsense, handed to a model or rendered to a human
  // as the conversation. `openMlsEvent` in `mls.ts` is the other half.
  if (enc(event.tags) === EncMode.Mls) {
    throw new Error('seal: this event is sealed with mls; open it with openMlsEvent, not a key')
  }
  if (enc(event.tags) !== EncMode.Nip44) return event.content
  if (event.content === '') return ''
  return nip44Decrypt(event.content, key)
}

/**
 * True if this event's content is sealed and needs something before it means anything.
 *
 * Both encrypted modes, not just `nip44`. A reader that answered `false` for an
 * `mls` event would treat base64 as a body everywhere this is used — feeds,
 * packers, the auditor, `unreadable()` — and none of those would report a
 * problem. What "something" means differs: a key for `nip44`, the group's
 * ratchet state for `mls`.
 */
export function isSealed(event: NostrEvent | UnsignedEvent): boolean {
  const mode = enc(event.tags)
  return (mode === EncMode.Nip44 || mode === EncMode.Mls) && event.content !== ''
}

// --- which kinds an encrypted channel seals ---------------------------------

/**
 * The kinds that stay in the clear on an encrypted channel, and why.
 *
 * The list is written as **exceptions** rather than as an allowlist of sealed
 * kinds, so that a kind added in some later milestone is sealed by default. Get
 * that polarity backwards and the failure mode is a new event type quietly
 * published in plaintext into channels that believe they are private, with
 * nothing anywhere reporting it.
 *
 * There are four reasons to be on this list and no fifth:
 *
 * **Key management** (8110, 38107, and under `mls` 30443 and 8111). A channel
 * key wrapped under the channel key is a locked box containing its own key. The
 * policy is what tells a writer to encrypt, so it must be readable by someone who
 * cannot yet decrypt anything. The two `mls` entries are the same argument at
 * the other end of the bootstrap: a KeyPackage is read by people who are *not*
 * in the group, and a Welcome is already encrypted to exactly one recipient —
 * sealing it to the group as well would mean the one member who needs to read it
 * is the one member who cannot.
 *
 * Those were written into the spec during the M10 spec pass and were missing
 * from this table for two commits, which is the drift the note at the bottom of
 * this comment is about — the prose and the enforced list disagreed and nothing
 * failed. Sealing a 30443 would have refused honest traffic in the one moment an
 * agent has no key at all: it could not have joined the channel it was
 * publishing the KeyPackage to join.
 *
 * The spec pass also put 1059 and 10050 on this list, and step 4 of the build
 * took them off again. Quorum's Welcome is a signed 8111 rather than a NIP-59
 * gift wrap — see `RegularKinds.MlsWelcome` for the relay policy that forces
 * that — so no 1059 is ever published here, and with the recipient already a
 * NIP-29 member of the group being invited to, a NIP-17 inbox list has no
 * reader. An exceptions table earns its polarity by every entry having a reason;
 * two entries kept against a transport that was never built would be the same
 * drift in the opposite direction.
 *
 * **Authorization** (38102 grants, 38106 delegations). Two of these the relay
 * itself enforces — `group:join` and `thread:budget` — so sealing them would
 * disarm membership control on exactly the channels that care most about it.
 * The deeper reason is the one in the plan: *a capability nobody can audit is
 * not a capability*. "Who may deploy to production" is the question an encrypted
 * channel must still be able to answer to a workspace owner, and hiding the
 * grants answers it to nobody.
 *
 * **Relay-authored records** (8108 checkpoints, 38101 thread state). The relay
 * signs these; it cannot encrypt to a key it does not hold. On an encrypted
 * channel 38101 simply stops existing — the relay cannot fold an op it cannot
 * read — and clients project locally instead. Checkpoints keep working
 * untouched, because they commit to event ids and never to content.
 *
 * **NIP-29 moderation** (9000–9030) and the relay's generated metadata (39xxx).
 * Addressed to the relay, by definition.
 *
 * Both lists are published into `schemas/index.json` and the Go relay enforces
 * them from there rather than from a second copy in Go. That is not tidiness:
 * this table decides what a relay refuses on an encrypted channel, so a relay
 * whose copy had drifted by one kind would either leak that kind in plaintext
 * or refuse honest traffic, and neither shows up as an error anywhere.
 */
export const UNSEALED_KINDS: readonly number[] = Object.freeze([
  7000, // job_feedback — NIP-90: a refusal, from anyone, to anyone
  8108, // checkpoint — relay-authored
  8110, // channel_key — the `nip44` bootstrap
  8111, // mls_welcome — the `mls` bootstrap, already encrypted to one recipient
  22242, // client_auth — NIP-42, addressed to the relay
  30443, // mls_key_package — the `mls` bootstrap: read by people who are not in the group
  38101, // thread_state — relay-authored
  38102, // capability_grant — authorization, and relay-enforced
  38106, // delegation — authorization
  38107, // channel_policy — the bootstrap
])

/** Whole kind ranges that stay in the clear, with the reason carried alongside. */
export interface UnsealedRange {
  readonly from: number
  readonly to: number
  readonly why: string
}

export const UNSEALED_KIND_RANGES: readonly UnsealedRange[] = Object.freeze([
  Object.freeze({ from: 9000, to: 9030, why: 'NIP-29 moderation, addressed to the relay' }),
  Object.freeze({ from: 39000, to: 39999, why: 'NIP-29 metadata, generated by the relay' }),
])

const unsealed = new Set(UNSEALED_KINDS)

/**
 * True if a `nip44` channel requires this kind's content to be sealed.
 *
 * Kinds with no content at all (a NIP-09 deletion request, an empty chat
 * message) pass either way — there is nothing to hide and nothing to check.
 * That is handled by the caller, which looks at the event; this function
 * answers only the question about the kind.
 */
export function mustSeal(kind: number): boolean {
  if (unsealed.has(kind)) return false
  for (const range of UNSEALED_KIND_RANGES) {
    if (kind >= range.from && kind <= range.to) return false
  }
  return true
}
