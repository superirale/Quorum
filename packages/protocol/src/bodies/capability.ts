/**
 * Capabilities and delegation.
 *
 * Grants are signed attestations, not database rows, and enforcement happens
 * **at the resource**: the deploy tool verifies the signature chain before
 * acting. The relay also enforces on plaintext channels as defence in depth,
 * but is never the only thing standing between an agent and production. That
 * ordering is deliberate — a relay compromise should cost you confidentiality,
 * not the ability to deploy.
 *
 * Three identities are kept distinct, because every existing platform conflates
 * them and then cannot revoke anything precisely:
 *
 *   app       the agent definition and its manifest (38103)
 *   principal the pubkey that holds grants
 *   instance  one running replica, so a single bad process can be revoked alone
 *
 * An instance is a subkey or a NIP-46 session listed in `instances` below.
 */

import { z } from 'zod'
import { GrantSpec, Pubkey, UnixSeconds } from './common.ts'

/** `capability_grant` (38102). `d` is a grant id chosen by the issuer. */
export const CapabilityGrantBody = z.object({
  grantee: Pubkey.describe('the agent principal receiving this capability'),
  grant: GrantSpec,

  /**
   * Address of the delegation the issuer is acting under, if they are not the
   * ultimate authority. Chains are legal; each link narrows.
   */
  via: z.string().optional().describe('addressable coordinate 38106:<pubkey>:<d>'),

  /**
   * Revocation. Because 38102 is addressable, republishing with this set to
   * true is a genuine revocation rather than a request — the newest event per
   * (pubkey, kind, d) is the only one relays keep and clients honour.
   *
   * This is one of the few places where Nostr's replaceable semantics do
   * something a plain append-only log cannot.
   */
  revoked: z.boolean().default(false),
  revoked_reason: z.string().optional(),

  issued_at: UnixSeconds.optional(),
})
export type CapabilityGrantBody = z.infer<typeof CapabilityGrantBody>

/**
 * `delegation` (38106) — a human authorising an agent to act as them.
 *
 * The effective permission of a delegated action is the **intersection** of the
 * agent's own grants and the delegating human's permissions. Never the union,
 * and never an escalation. Without this rule the only workable pattern is
 * "give the agent admin so it can help", which is how a product becomes
 * unsellable to anyone with a security team.
 */
export const DelegationBody = z.object({
  delegate: Pubkey.describe('the agent principal permitted to act on my behalf'),

  /**
   * Optional whitelist of resources. Omitted means "anything the delegate
   * already holds a grant for", which is still bounded by the intersection
   * rule — it never widens what the delegate can do.
   */
  resources: z.array(z.string().min(1)).optional(),

  scope: z.record(z.string(), z.unknown()).optional(),
  expires_at: UnixSeconds.optional(),
  revoked: z.boolean().default(false),
})
export type DelegationBody = z.infer<typeof DelegationBody>
