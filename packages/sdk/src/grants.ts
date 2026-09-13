/**
 * Capability grants — permission as a signed attestation, checked at the
 * resource.
 *
 * A grant (38102) says "this pubkey may invoke this resource, with this scope,
 * until then, N times". It is an event, not a row: nobody can add one by
 * editing a database, and revoking one is a republish that every reader sees
 * rather than a delete that only the server knows about.
 *
 * ## Enforcement belongs at the resource
 *
 * {@link authorize} is a pure function over a bag of events. It needs no relay,
 * no network and no trust in whoever served the events, because every input is
 * signed. The deploy tool calls it; the relay also calls the equivalent on
 * plaintext channels as defence in depth, but it is never the only thing
 * standing between an agent and production. A relay compromise should cost you
 * confidentiality, not the ability to deploy.
 *
 * ## Two traps worth naming
 *
 * **Revocation is a newer event, so stale data fails open.** 38102 is
 * addressable: the revocation has the same `(pubkey, kind, d)` as the grant and
 * replaces it. A resource that has both — from a file, a cache, a relay that
 * served history — and picks the wrong one has not revoked anything.
 * {@link latestAddressable} exists so that choosing is never ad hoc, and
 * {@link authorize} applies it to whatever it is given.
 *
 * **`max_uses` cannot be counted from here.** Nothing in a signed log knows how
 * many times a tool ran; the only honest counter is the resource's own. So the
 * use count is a parameter, and a caller that does not pass one gets no
 * enforcement of that field — stated in the API rather than quietly assumed.
 *
 * There are deliberately no wildcards. `action:deploy.*` is the feature that
 * turns every capability system into an ambient one, because the first time a
 * grant is inconvenient somebody widens it by a character.
 */

import {
  CapabilityGrantBody,
  DelegationBody,
  Kinds,
  TagName,
  address,
  digest,
  tagValue,
  verifyEvent,
  type GrantSpec,
  type NostrEvent,
} from '@quorum/protocol'
import type { RelayClient } from './client.ts'
import { intersect, verifyDelegation } from './delegation.ts'
import type { Publisher, PublishOptions } from './publish.ts'

// --- building ----------------------------------------------------------------

export interface GrantOptions {
  /** The agent principal receiving this capability. */
  grantee: string
  /** e.g. `action:deploy.production`. Matched exactly. */
  resource: string
  /** e.g. `['invoke']`. */
  actions: string[]
  scope?: Record<string, unknown>
  expiresAt?: number
  maxUses?: number
  /** Coordinate of the 38106 the issuer is acting under, if not a root. */
  via?: string
  /** `d`. Defaults to a digest of the grant, so re-issuing replaces. */
  id?: string
  revoked?: boolean
  revokedReason?: string
  issuedAt?: number
}

/** The `d` of a grant, derived so that issuing the same grant twice replaces it. */
export function grantId(options: Pick<GrantOptions, 'grantee' | 'resource' | 'actions' | 'scope'>): string {
  return digest({
    grantee: options.grantee,
    resource: options.resource,
    actions: [...options.actions].sort(),
    scope: options.scope ?? null,
  }).slice(0, 32)
}

export function grant(options: GrantOptions): PublishOptions {
  const spec: GrantSpec = {
    resource: options.resource,
    actions: options.actions,
    ...(options.scope ? { scope: options.scope } : {}),
    ...(options.expiresAt !== undefined ? { expires_at: options.expiresAt } : {}),
    ...(options.maxUses !== undefined ? { max_uses: options.maxUses } : {}),
  }
  return {
    kind: Kinds.CapabilityGrant,
    d: options.id ?? grantId(options),
    // Addressed, so a grantee can find what it holds with one indexed filter
    // instead of reading every grant in the channel.
    to: [options.grantee],
    body: {
      grantee: options.grantee,
      grant: spec,
      ...(options.via ? { via: options.via } : {}),
      revoked: options.revoked ?? false,
      ...(options.revokedReason ? { revoked_reason: options.revokedReason } : {}),
      ...(options.issuedAt !== undefined ? { issued_at: options.issuedAt } : {}),
    },
  }
}

// --- reading -----------------------------------------------------------------

/**
 * Keep only the current version of each addressable event.
 *
 * NIP-01's rule: newest `created_at` per `(pubkey, kind, d)`, and on a tie the
 * lowest id wins so that every implementation picks the same one. Non-
 * addressable events pass through untouched.
 */
export function latestAddressable(events: readonly NostrEvent[]): NostrEvent[] {
  return current(events, (a, b) => (a.id < b.id ? a : b))
}

/**
 * The same selection, but a tie is broken towards *less* authority.
 *
 * NIP-01 breaks a `created_at` tie by lowest id, which between a grant and its
 * revocation is a coin flip — and issuing something and withdrawing it in the
 * same second is an ordinary thing to do when the grant was a mistake. A coin
 * flip is an acceptable answer to "which copy does a relay keep"; it is not an
 * acceptable answer to "may this agent deploy to production". So where both
 * versions are in hand and neither is newer, the revocation wins.
 *
 * This does not make the tie safe — a relay storing the other one never serves
 * the revocation at all, which is why {@link Grants.revoke} also makes sure a
 * revocation is genuinely newer than what it withdraws. It makes the tie safe
 * *here*, at the resource, which is the place that must never fail open.
 */
export function effectiveAddressable(events: readonly NostrEvent[]): NostrEvent[] {
  return current(events, (a, b) => {
    if (isRevoked(a) !== isRevoked(b)) return isRevoked(a) ? a : b
    return a.id < b.id ? a : b
  })
}

function current(
  events: readonly NostrEvent[],
  tieBreak: (a: NostrEvent, b: NostrEvent) => NostrEvent,
): NostrEvent[] {
  const newest = new Map<string, NostrEvent>()
  const out: NostrEvent[] = []
  for (const event of events) {
    if (event.kind < 30000 || event.kind >= 40000) {
      out.push(event)
      continue
    }
    const key = address(event.kind, event.pubkey, tagValue(event.tags, TagName.Identifier) ?? '')
    const held = newest.get(key)
    if (!held || event.created_at > held.created_at) {
      newest.set(key, event)
    } else if (event.created_at === held.created_at) {
      newest.set(key, tieBreak(event, held))
    }
  }
  return [...out, ...newest.values()]
}

/** Kind-agnostic on purpose: both 38102 and 38106 carry a `revoked` flag. */
function isRevoked(event: NostrEvent): boolean {
  try {
    return (JSON.parse(event.content) as { revoked?: unknown }).revoked === true
  } catch {
    return false
  }
}

export interface AuthorizeRequest {
  /** The pubkey attempting the action. */
  agent: string
  resource: string
  /** The verb, e.g. `invoke`. */
  action: string
  /** What the agent is asking to do it to, e.g. `{env: 'production'}`. */
  scope?: Record<string, unknown>
  /**
   * Pubkeys this resource accepts as ultimate authority.
   *
   * Configuration, never data. A resource that reads its trust roots out of the
   * same event stream it is trying to authorise has no root at all — anyone can
   * publish an event claiming to be one.
   */
  trustedIssuers: readonly string[]
  /** Grants and delegations the resource could find. Order does not matter. */
  events: readonly NostrEvent[]
  /** Coordinate of the delegation the action claims to run under. */
  onBehalfOf?: string
  /** Times this grant has already been used. Only the resource can know. */
  uses?: number
  now?: number
}

export interface AuthorizeResult {
  allowed: boolean
  /** The grant that permitted it. */
  grant?: NostrEvent
  /** The delegation it was narrowed by, if any. */
  delegation?: NostrEvent
  /** What the agent may actually do, after every narrowing. */
  effective?: GrantSpec
  /** Why not — one line per grant that looked relevant and did not apply. */
  reasons: string[]
}

/**
 * May this agent do this? Offline, from signed events alone.
 *
 * Returns the *narrowed* spec rather than the grant as written, because after a
 * delegation has been applied those are different objects and the one that
 * matters is the narrower.
 */
export function authorize(request: AuthorizeRequest): AuthorizeResult {
  const now = request.now ?? Math.floor(Date.now() / 1000)
  const events = effectiveAddressable(request.events)
  const reasons: string[] = []

  const byAddress = new Map<string, NostrEvent>()
  for (const event of events) {
    byAddress.set(
      address(event.kind, event.pubkey, tagValue(event.tags, TagName.Identifier) ?? ''),
      event,
    )
  }

  // The delegation the *action* claims to run under, resolved once: it applies
  // to every candidate grant, and failing to resolve it must fail the whole
  // request rather than quietly falling back to the agent's own authority.
  let onBehalf: { event: NostrEvent; body: DelegationBody } | undefined
  if (request.onBehalfOf) {
    const event = byAddress.get(request.onBehalfOf)
    if (!event) {
      return { allowed: false, reasons: [`on_behalf_of ${request.onBehalfOf} was not provided`] }
    }
    if (!verifyEvent(event)) {
      return { allowed: false, reasons: [`on_behalf_of ${request.onBehalfOf} does not verify`] }
    }
    if (!request.trustedIssuers.includes(event.pubkey)) {
      return {
        allowed: false,
        reasons: [`${short(event.pubkey)} is not a trusted authority to delegate from`],
      }
    }
    const check = verifyDelegation(event, { delegate: request.agent, now })
    if (!check.ok || !check.body) {
      return { allowed: false, reasons: [`on_behalf_of delegation ${check.reason}`] }
    }
    onBehalf = { event, body: check.body }
  }

  for (const event of events) {
    if (event.kind !== Kinds.CapabilityGrant) continue

    const body = parse(CapabilityGrantBody, event)
    if (!body) continue
    if (body.grantee !== request.agent) continue
    if (body.grant.resource !== request.resource) continue

    const name = `grant ${short(event.id)}`
    if (!verifyEvent(event)) {
      reasons.push(`${name}: the id or signature does not verify`)
      continue
    }
    if (body.revoked) {
      reasons.push(`${name}: revoked${body.revoked_reason ? ` — ${body.revoked_reason}` : ''}`)
      continue
    }

    // Who says so. A grant is only as good as the authority behind it, and the
    // only two acceptable answers are "a root this resource trusts" and "someone
    // holding a delegation from one".
    let spec: GrantSpec | undefined = body.grant
    let via: NostrEvent | undefined
    if (!request.trustedIssuers.includes(event.pubkey)) {
      if (!body.via) {
        reasons.push(`${name}: issued by ${short(event.pubkey)}, who is not a trusted authority`)
        continue
      }
      const delegationEvent = byAddress.get(body.via)
      if (!delegationEvent) {
        reasons.push(`${name}: cites delegation ${body.via}, which was not provided`)
        continue
      }
      if (!verifyEvent(delegationEvent) || !request.trustedIssuers.includes(delegationEvent.pubkey)) {
        reasons.push(`${name}: its delegation is not from a trusted authority`)
        continue
      }
      const check = verifyDelegation(delegationEvent, { delegate: event.pubkey, now })
      if (!check.ok || !check.body) {
        reasons.push(`${name}: its delegation ${check.reason}`)
        continue
      }
      spec = intersect(spec, check.body)
      if (!spec) {
        reasons.push(`${name}: nothing survives the intersection with its delegation`)
        continue
      }
      via = delegationEvent
    }

    if (onBehalf) {
      spec = intersect(spec, onBehalf.body)
      if (!spec) {
        reasons.push(`${name}: nothing survives the intersection with the on_behalf_of delegation`)
        continue
      }
      via = onBehalf.event
    }

    const problem = covers(spec, request, now)
    if (problem) {
      reasons.push(`${name}: ${problem}`)
      continue
    }

    return {
      allowed: true,
      grant: event,
      ...(via ? { delegation: via } : {}),
      effective: spec,
      reasons,
    }
  }

  if (!reasons.length) {
    reasons.push(`no grant of ${request.resource} to ${short(request.agent)}`)
  }
  return { allowed: false, reasons }
}

/** Why this spec does not permit this request, or undefined if it does. */
function covers(spec: GrantSpec, request: AuthorizeRequest, now: number): string | undefined {
  if (!spec.actions.includes(request.action)) {
    return `permits ${spec.actions.join(', ')}, not ${request.action}`
  }
  if (spec.expires_at !== undefined && spec.expires_at < now) {
    return `expired at ${new Date(spec.expires_at * 1000).toISOString()}`
  }
  if (spec.max_uses !== undefined) {
    if (request.uses === undefined) {
      // Silence here would be an authorisation granted on the strength of a
      // limit nobody checked.
      return `has max_uses ${spec.max_uses} but the caller supplied no use count`
    }
    if (request.uses >= spec.max_uses) return `used ${request.uses} of ${spec.max_uses} times`
  }
  for (const [key, value] of Object.entries(spec.scope ?? {})) {
    const asked = request.scope?.[key]
    if (asked === undefined) return `is scoped to ${key}=${json(value)}, which the request omits`
    if (digest(asked) !== digest(value)) {
      return `is scoped to ${key}=${json(value)}, but the request asks for ${json(asked)}`
    }
  }
  return undefined
}

// --- describing --------------------------------------------------------------

/**
 * What a grant is, without deciding how to say it.
 *
 * Here rather than in each client for the reason `conclusion()` is: the console
 * prints these as a line of ANSI, the reference client draws them as a table,
 * and the first version of the console's renderer read `body.resource` when the
 * spec nests it under `body.grant` — so it printed a confident `?` for every
 * grant ever issued. A listing that cannot say what a capability covers is
 * worse than no listing, because it invites an operator to conclude the grant
 * is broken and issue a second one.
 *
 * Parsing happens once, through the body schemas, and both clients render the
 * result. Neither gets to hold its own opinion about what a grant says.
 */
export type GrantState = 'active' | 'revoked' | 'expired' | 'invalid'

export interface GrantSummary {
  event: NostrEvent
  kind: 'grant' | 'delegation'
  state: GrantState
  /**
   * Set when `state` is `invalid`, and worth telling apart. `unparseable` is
   * somebody publishing junk at a capability coordinate, which any member can
   * do and every relay will store; `malformed` is JSON that tried to be a grant
   * and is not, which is far more likely to be a client of ours with a bug.
   */
  problem?: 'unparseable' | 'malformed'
  /** Who signed it. Whether they are *trusted* is the resource's question. */
  issuer: string
  /** The principal it names: the grantee of a grant, the delegate of a delegation. */
  subject?: string
  /** Grants name exactly one resource; a delegation may name several, or none. */
  resources: string[]
  actions: string[]
  scope?: Record<string, unknown>
  maxUses?: number
  expiresAt?: number
  /** The delegation this was issued under, if any. It bounds the grant. */
  via?: string
  revokedReason?: string
}

/**
 * Read one 38102 or 38106.
 *
 * Expiry is reported even though {@link effectiveAddressable} does not filter
 * on it: an expired grant is still the newest event at its coordinate, so it is
 * still "current" in the replaceable-event sense while authorising nothing.
 * {@link authorize} refuses it, and a listing that called it active would be
 * describing a capability the resource will not honour.
 */
export function summariseGrant(
  event: NostrEvent,
  now = Math.floor(Date.now() / 1000),
): GrantSummary {
  const base = { event, issuer: event.pubkey, resources: [], actions: [] }
  const kind = event.kind === Kinds.Delegation ? 'delegation' : 'grant'

  if (!isJson(event.content)) return { ...base, kind, state: 'invalid', problem: 'unparseable' }

  if (event.kind === Kinds.Delegation) {
    const body = parse(DelegationBody, event)
    if (!body) return { ...base, kind: 'delegation', state: 'invalid', problem: 'malformed' }
    return {
      ...base,
      kind: 'delegation',
      state: stateOf(body.revoked, body.expires_at, now),
      subject: body.delegate,
      resources: body.resources ?? [],
      ...(body.scope ? { scope: body.scope } : {}),
      ...(body.expires_at !== undefined ? { expiresAt: body.expires_at } : {}),
    }
  }

  const body = parse(CapabilityGrantBody, event)
  if (!body) return { ...base, kind: 'grant', state: 'invalid', problem: 'malformed' }

  return {
    ...base,
    kind: 'grant',
    state: stateOf(body.revoked, body.grant.expires_at, now),
    subject: body.grantee,
    resources: [body.grant.resource],
    actions: body.grant.actions,
    ...(body.grant.scope ? { scope: body.grant.scope } : {}),
    ...(body.grant.max_uses !== undefined ? { maxUses: body.grant.max_uses } : {}),
    ...(body.grant.expires_at !== undefined ? { expiresAt: body.grant.expires_at } : {}),
    ...(body.via ? { via: body.via } : {}),
    ...(body.revoked_reason ? { revokedReason: body.revoked_reason } : {}),
  }
}

/**
 * Every capability in a bag of events, current versions only.
 *
 * `effectiveAddressable`, not `latestAddressable`: between a grant and a
 * revocation of the same coordinate published in the same second, the
 * revocation wins. A listing that showed the other one would be telling an
 * operator that a capability they withdrew is still in force.
 *
 * Sorted by subject then resource so that two readings of the same workspace
 * produce the same order, which is what makes a diff between them mean
 * something.
 */
export function summariseGrants(
  events: readonly NostrEvent[],
  now = Math.floor(Date.now() / 1000),
): GrantSummary[] {
  const capabilities = events.filter(
    (e) => e.kind === Kinds.CapabilityGrant || e.kind === Kinds.Delegation,
  )
  return effectiveAddressable(capabilities)
    .map((event) => summariseGrant(event, now))
    .sort(
      (a, b) =>
        (a.subject ?? '').localeCompare(b.subject ?? '') ||
        (a.resources[0] ?? '').localeCompare(b.resources[0] ?? '') ||
        a.event.id.localeCompare(b.event.id),
    )
}

function stateOf(revoked: boolean, expiresAt: number | undefined, now: number): GrantState {
  if (revoked) return 'revoked'
  if (expiresAt !== undefined && expiresAt < now) return 'expired'
  return 'active'
}

// --- the connected side ------------------------------------------------------

export interface GrantsDeps {
  client: RelayClient
  group: string
  /** Needed only to issue or revoke. A resource verifying grants needs no key. */
  publisher?: Publisher
}

/** Issue, revoke and fetch grants over a relay. Verification stays pure. */
export class Grants {
  private readonly deps: GrantsDeps

  constructor(deps: GrantsDeps) {
    this.deps = deps
  }

  async issue(options: GrantOptions): Promise<NostrEvent> {
    return this.publish(grant(options))
  }

  /**
   * Withdraw a grant by republishing it revoked.
   *
   * Takes the whole grant rather than its id, because a revocation must carry
   * the same `d` *and* remain a valid grant body — a bare tombstone would be a
   * second thing for every reader to understand.
   *
   * `previous` is worth passing whenever you have it. Addressable events are
   * replaced by `created_at`, which has one-second resolution, so a grant
   * issued and withdrawn inside the same second leaves a relay holding one of
   * the two by id order — and half the time that is the grant. Dated one second
   * later, the revocation replaces it everywhere rather than only in the
   * readers that happened to see both.
   */
  async revoke(options: GrantOptions, reason?: string, previous?: NostrEvent): Promise<NostrEvent> {
    const now = Math.floor(Date.now() / 1000)
    return this.publish({
      ...grant({ ...options, revoked: true, ...(reason ? { revokedReason: reason } : {}) }),
      created_at: previous ? Math.max(now, previous.created_at + 1) : now,
    })
  }

  /** Live grants and delegations naming this pubkey. Feed straight to {@link authorize}. */
  async held(grantee: string): Promise<NostrEvent[]> {
    const events = await this.deps.client.query([
      {
        kinds: [Kinds.CapabilityGrant, Kinds.Delegation],
        [`#${TagName.Group}`]: [this.deps.group],
        [`#${TagName.Pubkey}`]: [grantee],
      },
    ])
    return latestAddressable(events)
  }

  private async publish(options: PublishOptions): Promise<NostrEvent> {
    if (!this.deps.publisher) {
      throw new Error('issuing a grant needs a publisher; this Grants instance is read-only')
    }
    return this.deps.publisher.publish(options)
  }
}

// --- helpers -----------------------------------------------------------------

function parse<T>(
  schema: { safeParse(v: unknown): { success: boolean; data?: T } },
  event: NostrEvent,
): T | undefined {
  try {
    const result = schema.safeParse(JSON.parse(event.content))
    return result.success ? result.data : undefined
  } catch {
    return undefined
  }
}

function short(hex: string): string {
  return hex.length > 12 ? `${hex.slice(0, 8)}…` : hex
}

function json(value: unknown): string {
  return JSON.stringify(value)
}

function isJson(content: string): boolean {
  try {
    JSON.parse(content)
    return true
  } catch {
    return false
  }
}
