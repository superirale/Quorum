/**
 * Resource names the reference relay enforces itself.
 *
 * Almost every capability in Quorum is checked at the resource: the deploy tool
 * verifies the grant before it deploys, and the relay is a dumb store that never
 * learns what `action:deploy` means. These two are the exceptions, because they
 * have no resource anywhere else. Membership is decided by whatever admits you,
 * and a thread's budget is a number the relay projects into kind 38101 — so the
 * relay is the enforcement point by construction, not by preference.
 *
 * They live here, in the protocol package, rather than as a string typed into
 * the console and a matching string typed into the Go policy. A resource name is
 * matched exactly and never widened, which is the property that makes the
 * capability system safe and also makes a typo silent: a grant of
 * `group:jion` is a perfectly valid grant that authorises nothing, and the
 * operator who issued it has a green tick and no member. Both implementations
 * are checked against `relay_enforced` in `schemas/index.json`.
 */

export const Resource = {
  /**
   * Admits the grantee to a workspace. Scoped `{group: <id>}`.
   *
   * An invitation, in the form a recipient can be shown and a third party can
   * check — as distinct from a NIP-29 put-user, which is an administrator
   * asserting a fact about someone who may never have connected.
   */
  Join: 'group:join',

  /**
   * Sets a thread's spending ceiling. Scoped `{group: <id>}`.
   *
   * Budget exhaustion pauses a thread and pings a human, so this is half of the
   * runaway-agent backstop. An agent holding it can raise its own ceiling, which
   * is a thing to grant on purpose and not by default.
   */
  ThreadBudget: 'thread:budget',

  /**
   * Sets a channel's encryption policy. Scoped `{group: <id>}`.
   *
   * The relay is the enforcement point for the same structural reason as the
   * other two: kind 38107 is the one event the relay must be able to read on an
   * encrypted channel, because it is what tells the relay to start refusing
   * plaintext. Nobody else is downstream of it — there is no "resource" that
   * consults the policy before acting, only writers who obey it and a relay
   * that enforces it.
   *
   * It is gated because the dangerous direction is *off*. Anyone who can
   * publish a policy saying `plaintext` has turned a private channel public for
   * every message written after it, with no ciphertext failing and no MAC
   * complaining — the next message simply arrives readable. Turning it on is
   * the harmless direction and is gated by the same grant only because one
   * question with two answers is one capability.
   */
  ChannelEncrypt: 'channel:encrypt',
} as const

export type Resource = (typeof Resource)[keyof typeof Resource]

/**
 * The action every relay-enforced resource is granted with.
 *
 * `invoke` and nothing else. Resources the relay checks have one verb, and
 * inventing a second — `group:join` with `read` — would imply the relay
 * distinguishes them when it does not.
 */
export const INVOKE = 'invoke'

/**
 * The scope key both relay-enforced resources narrow on.
 *
 * `group:join` scoped `{group: payments}`, never a resource called
 * `group:join.payments`. The name is matched exactly and cannot be narrowed; a
 * scope can be, which is what lets a delegation hand on the right to invite into
 * one workspace and not another.
 */
export const SCOPE_GROUP = 'group'
