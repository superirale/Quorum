/**
 * Capability grants, checked the way a resource checks them: offline, from
 * signed events, with no relay anywhere in the test.
 *
 * The negative controls matter more than the happy path here. A permission
 * system that says yes correctly and also says yes to a revoked grant, an
 * expired one, one issued by a stranger, or one narrowed by a delegation it
 * then ignored, is not a permission system.
 */

import assert from 'node:assert/strict'
import { after, describe, it } from 'node:test'
import { Kinds, address, type GrantSpec, type NostrEvent } from '@quorum/protocol'
import {
  authorize,
  delegation,
  grant,
  grantId,
  intersect,
  latestAddressable,
  type DelegationOptions,
  type GrantOptions,
} from '../src/index.ts'
import { Actor, Keyholder, assertAllValid, harness } from './harness.ts'

const NOW = 1_800_000_000
const HOUR = 3600

/** Ada is the workspace owner; the resource is configured to trust her key. */
const ada = new Keyholder()
/** An operator Ada delegates to. Trusted by nobody by default. */
const bob = new Keyholder()
/** The agent principal that holds grants. */
const agent = new Keyholder()
const mallory = new Keyholder()

const DEPLOY = 'action:deploy.production'

const baseGrant: GrantOptions = {
  grantee: agent.pubkey,
  resource: DEPLOY,
  actions: ['invoke'],
}

function ask(
  events: NostrEvent[],
  extra: Partial<Parameters<typeof authorize>[0]> = {},
): ReturnType<typeof authorize> {
  return authorize({
    agent: agent.pubkey,
    resource: DEPLOY,
    action: 'invoke',
    trustedIssuers: [ada.pubkey],
    events,
    now: NOW,
    ...extra,
  })
}

const issue = (issuer: Keyholder, options: Partial<GrantOptions> = {}) =>
  issuer.sign(grant({ ...baseGrant, ...options }))

const delegate = (issuer: Keyholder, options: Partial<DelegationOptions> = {}) =>
  issuer.sign(delegation({ delegate: agent.pubkey, id: 'ops', ...options }))

describe('authorize', () => {
  it('allows what a trusted issuer granted, and nothing else', async () => {
    const g = await issue(ada)

    const allowed = ask([g])
    assert.equal(allowed.allowed, true)
    assert.equal(allowed.grant?.id, g.id)
    assert.equal(allowed.effective?.resource, DEPLOY)

    // The same grant, asked three slightly different questions.
    assert.equal(ask([g], { action: 'revoke' }).allowed, false, 'a verb it does not name')
    assert.equal(
      ask([g], { resource: 'action:deploy.staging' }).allowed,
      false,
      'a resource it does not name — there are no wildcards, deliberately',
    )
    assert.equal(
      ask([g], { agent: mallory.pubkey }).allowed,
      false,
      'a pubkey it was not granted to',
    )
  })

  it('refuses a grant nobody it trusts issued', async () => {
    const forged = await issue(mallory)
    const result = ask([forged])

    assert.equal(result.allowed, false, 'anyone can sign an event saying they granted themselves')
    assert.match(result.reasons.join(' '), /not a trusted authority/)
  })

  it('refuses a grant whose signature does not hold', async () => {
    const g = await issue(ada)
    // The realistic tamper: widen the grant and recompute nothing but hope.
    const tampered: NostrEvent = {
      ...g,
      content: g.content.replace('"invoke"', '"invoke","revoke"'),
    }

    const result = ask([tampered], { action: 'revoke' })
    assert.equal(result.allowed, false)
    assert.match(result.reasons.join(' '), /signature/)
  })

  it('stops honouring a grant once it is revoked', async () => {
    const g = await ada.sign({ ...grant(baseGrant), created_at: NOW - HOUR })
    const revocation = await ada.sign({
      ...grant({ ...baseGrant, revoked: true, revokedReason: 'left the team' }),
      created_at: NOW - 60,
    })

    assert.equal(ask([g]).allowed, true, 'live before the revocation')

    // Both versions, in the worst order: a resource handed history by a relay,
    // or reading a file it wrote yesterday. Picking the older one here would be
    // a revocation that revoked nothing.
    const result = ask([revocation, g])
    assert.equal(result.allowed, false)
    assert.match(result.reasons.join(' '), /revoked — left the team/)

    assert.equal(
      latestAddressable([g, revocation]).length,
      1,
      'a revocation replaces the grant; it does not sit beside it',
    )
    assert.equal(
      grantId(baseGrant),
      revocation.tags.find((t) => t[0] === 'd')?.[1],
      'which only works because the d is derived from the grant itself',
    )
  })

  it('fails closed when a grant and its revocation share a second', async () => {
    // Issued and withdrawn in the same second: an ordinary correction. NIP-01
    // breaks that tie by lowest id, so under the plain storage rule whether the
    // agent may still deploy depends on a hash — it would pass this test about
    // half the time, which is the worst kind of pass.
    const issued = await ada.sign({ ...grant(baseGrant), created_at: NOW - 60 })
    const revocation = await ada.sign({
      ...grant({ ...baseGrant, revoked: true, revokedReason: 'issued by mistake' }),
      created_at: NOW - 60,
    })

    assert.equal(issued.created_at, revocation.created_at)
    assert.equal(ask([issued, revocation]).allowed, false)
    assert.equal(ask([revocation, issued]).allowed, false, 'and the input order is not authority')
  })

  it('refuses an expired grant', async () => {
    const g = await issue(ada, { expiresAt: NOW - 1 })
    const result = ask([g])

    assert.equal(result.allowed, false)
    assert.match(result.reasons.join(' '), /expired/)
    assert.equal(ask([g], { now: NOW - HOUR }).allowed, true, 'and allowed it an hour earlier')
  })

  it('holds the request to the scope the grant names', async () => {
    const g = await issue(ada, { scope: { env: 'production', region: 'eu-west-1' } })

    assert.equal(ask([g], { scope: { env: 'production', region: 'eu-west-1' } }).allowed, true)
    assert.equal(
      ask([g], { scope: { env: 'production', region: 'us-east-1' } }).allowed,
      false,
      'a different value for a constrained key',
    )
    assert.equal(
      ask([g], { scope: { env: 'production' } }).allowed,
      false,
      'an omitted key is not a wildcard',
    )
    // Extra keys the grant says nothing about are fine: a scope is a set of
    // constraints on the request, not a description of it.
    assert.equal(
      ask([g], { scope: { env: 'production', region: 'eu-west-1', dry_run: true } }).allowed,
      true,
    )
  })

  it('refuses to enforce max_uses that nobody is counting', async () => {
    const g = await issue(ada, { maxUses: 2 })

    const uncounted = ask([g])
    assert.equal(uncounted.allowed, false, 'a limit no caller checks is not a limit')
    assert.match(uncounted.reasons.join(' '), /no use count/)

    assert.equal(ask([g], { uses: 0 }).allowed, true)
    assert.equal(ask([g], { uses: 1 }).allowed, true)
    assert.equal(ask([g], { uses: 2 }).allowed, false, 'the second use was the last one')
  })

  it('explains itself when it says no', async () => {
    const expired = await issue(ada, { expiresAt: NOW - 1 })
    const result = ask([expired])

    assert.equal(result.reasons.length, 1)
    assert.match(result.reasons[0]!, /^grant [0-9a-f]{8}…: expired/)
    assert.match(ask([]).reasons[0]!, /no grant of action:deploy\.production/)
  })
})

describe('delegation', () => {
  it('lets a delegate issue a grant, narrowed by what they were delegated', async () => {
    // Ada delegates production deploys to Bob, for one region. Bob grants the
    // agent production deploys with no region constraint at all.
    const d = await delegate(ada, {
      delegate: bob.pubkey,
      id: 'bob-ops',
      resources: [DEPLOY],
      scope: { region: 'eu-west-1' },
    })
    const via = address(Kinds.Delegation, ada.pubkey, 'bob-ops')
    const g = await issue(bob, { via })

    const allowed = ask([g, d], { scope: { region: 'eu-west-1' } })
    assert.equal(allowed.allowed, true)
    assert.equal(allowed.delegation?.id, d.id)
    assert.deepEqual(
      allowed.effective?.scope,
      { region: 'eu-west-1' },
      "the delegation's constraint applies even though the grant never mentioned it",
    )

    assert.equal(
      ask([g, d], { scope: { region: 'us-east-1' } }).allowed,
      false,
      'Bob could not hand on what Ada never gave him',
    )
    assert.equal(
      ask([g], { scope: { region: 'eu-west-1' } }).allowed,
      false,
      'and the grant alone, with the delegation missing, proves nothing',
    )
  })

  it('refuses a delegation chain that does not reach a trusted root', async () => {
    const d = await delegate(mallory, { delegate: bob.pubkey, id: 'bob-ops' })
    const g = await issue(bob, { via: address(Kinds.Delegation, mallory.pubkey, 'bob-ops') })

    const result = ask([g, d])
    assert.equal(result.allowed, false)
    assert.match(result.reasons.join(' '), /not from a trusted authority/)
  })

  it('refuses a delegation addressed to someone else', async () => {
    // Ada delegated to Bob. The agent presents it as its own.
    const d = await delegate(ada, { delegate: bob.pubkey, id: 'bob-ops' })
    const g = await issue(ada)

    const result = ask([g, d], { onBehalfOf: address(Kinds.Delegation, ada.pubkey, 'bob-ops') })
    assert.equal(result.allowed, false)
    assert.match(result.reasons.join(' '), /delegates to a different pubkey/)
  })

  it('refuses an on_behalf_of from someone with nothing to delegate', async () => {
    // Mallory signs a delegation naming the agent. It is a real event with a
    // real signature; the only thing missing is any authority behind it. If
    // this passed, "acting on behalf of" would be a self-service claim.
    const d = await delegate(mallory, { id: 'ops' })
    const g = await issue(ada)

    const result = ask([g, d], { onBehalfOf: address(Kinds.Delegation, mallory.pubkey, 'ops') })
    assert.equal(result.allowed, false)
    assert.match(result.reasons.join(' '), /not a trusted authority to delegate from/)
  })

  it('fails the whole request when on_behalf_of does not resolve', async () => {
    const g = await issue(ada)

    // The dangerous shape: an action claims delegated authority, the delegation
    // is missing, and the check quietly falls back to the agent's own grant —
    // which would authorise it under an authority nobody ever gave.
    const result = ask([g], { onBehalfOf: address(Kinds.Delegation, ada.pubkey, 'gone') })
    assert.equal(result.allowed, false)
    assert.match(result.reasons.join(' '), /was not provided/)
  })

  it('narrows by a revoked delegation to nothing', async () => {
    const live = await ada.sign({
      ...delegation({ delegate: agent.pubkey, id: 'ops', resources: [DEPLOY] }),
      created_at: NOW - HOUR,
    })
    const revoked = await ada.sign({
      ...delegation({ delegate: agent.pubkey, id: 'ops', resources: [DEPLOY], revoked: true }),
      created_at: NOW - 60,
    })
    const g = await issue(ada)
    const onBehalfOf = address(Kinds.Delegation, ada.pubkey, 'ops')

    assert.equal(ask([g, live], { onBehalfOf }).allowed, true)
    assert.equal(ask([g, live, revoked], { onBehalfOf }).allowed, false)
  })
})

describe('over a relay', () => {
  it('issues, finds and withdraws — and the withdrawal sticks', async () => {
    const h = await harness()
    after(() => h.finish())
    const issuer = await Actor.create(h.relay.url, h.group)
    h.cleanup(() => issuer.close())

    const grants = issuer.grants()
    const options: GrantOptions = { ...baseGrant, grantee: agent.pubkey }
    const issued = await grants.issue(options)

    const held = await grants.held(agent.pubkey)
    assert.deepEqual(
      held.map((e) => e.id),
      [issued.id],
      'a grantee finds what it holds with one indexed filter, because a grant is addressed',
    )
    const trustedIssuers = [issuer.pubkey]
    assert.equal(
      authorize({ agent: agent.pubkey, resource: DEPLOY, action: 'invoke', trustedIssuers, events: held }).allowed,
      true,
    )

    // Same second as the grant, which is the case that used to be a coin flip:
    // the relay keeps one version, and it has to be this one.
    const revocation = await grants.revoke(options, 'issued by mistake', issued)
    assert.ok(revocation.created_at > issued.created_at, 'a revocation must be newer, not merely later in the file')

    const after2 = await grants.held(agent.pubkey)
    assert.deepEqual(after2.map((e) => e.id), [revocation.id], 'the relay replaced the grant')
    assert.equal(
      authorize({ agent: agent.pubkey, resource: DEPLOY, action: 'invoke', trustedIssuers, events: after2 }).allowed,
      false,
    )
    assertAllValid(h.relay.received)
  })
})

describe('intersect', () => {
  const spec: GrantSpec = {
    resource: DEPLOY,
    actions: ['invoke'],
    scope: { env: 'production' },
    expires_at: NOW + HOUR,
    max_uses: 3,
  }

  it('takes the earlier expiry and both sets of constraints', () => {
    const out = intersect(spec, {
      delegate: agent.pubkey,
      scope: { region: 'eu-west-1' },
      expires_at: NOW + 60,
      revoked: false,
    })

    assert.deepEqual(out?.scope, { env: 'production', region: 'eu-west-1' })
    assert.equal(out?.expires_at, NOW + 60)
    assert.equal(out?.max_uses, 3, 'a delegation does not extend a use budget')
  })

  it('is empty when the two contradict', () => {
    assert.equal(
      intersect(spec, { delegate: agent.pubkey, scope: { env: 'staging' }, revoked: false }),
      undefined,
      'two constraints on one key can never both hold',
    )
    assert.equal(
      intersect(spec, { delegate: agent.pubkey, resources: ['action:deploy.staging'], revoked: false }),
      undefined,
    )
  })

  /**
   * The invariant, stated as the property rather than as an example: whatever
   * else `intersect` does, it must never hand back something that permits a
   * request neither input permitted. A specific expected value only shows that
   * one case came out right.
   */
  it('never widens either input', () => {
    const specs: GrantSpec[] = [
      { resource: DEPLOY, actions: ['invoke'] },
      { resource: DEPLOY, actions: ['invoke'], scope: { env: 'production' } },
      { resource: DEPLOY, actions: ['invoke'], expires_at: NOW + HOUR, max_uses: 1 },
      { resource: DEPLOY, actions: ['invoke', 'cancel'], scope: { env: 'production', tier: 1 } },
    ]
    const delegations = [
      { delegate: agent.pubkey, revoked: false },
      { delegate: agent.pubkey, revoked: false, resources: [DEPLOY] },
      { delegate: agent.pubkey, revoked: false, scope: { env: 'production' } },
      { delegate: agent.pubkey, revoked: false, scope: { region: 'eu-west-1' } },
      { delegate: agent.pubkey, revoked: false, expires_at: NOW - 1 },
      { delegate: agent.pubkey, revoked: false, expires_at: NOW + 10 * HOUR },
      { delegate: agent.pubkey, revoked: false, scope: { tier: 2 } },
    ]
    const requests = [
      { scope: undefined, at: NOW },
      { scope: { env: 'production' }, at: NOW },
      { scope: { env: 'staging' }, at: NOW },
      { scope: { env: 'production', region: 'eu-west-1' }, at: NOW },
      { scope: { env: 'production', region: 'eu-west-1', tier: 1 }, at: NOW },
      { scope: { env: 'production', region: 'us-east-1', tier: 2 }, at: NOW + 2 * HOUR },
    ]

    let narrowed = 0
    for (const from of specs) {
      for (const by of delegations) {
        const out = intersect(from, by)
        if (!out) {
          narrowed++
          continue
        }
        for (const request of requests) {
          if (!permits(out, request)) continue
          assert.ok(
            permits(from, request),
            `intersect widened the grant: ${JSON.stringify({ from, by, request })}`,
          )
          assert.ok(
            permitsDelegation(by, from.resource, request),
            `intersect widened the delegation: ${JSON.stringify({ from, by, request })}`,
          )
        }
        if (!requests.every((r) => permits(out, r) === permits(from, r))) narrowed++
      }
    }
    assert.ok(narrowed > 0, 'a test where nothing was ever narrowed proves nothing')
  })
})

interface Attempt {
  scope?: Record<string, unknown>
  at: number
}

/** Deliberately re-derived here rather than imported: a test that reuses the */
/** implementation's own predicate cannot catch the implementation being wrong. */
function permits(spec: GrantSpec, request: Attempt): boolean {
  if (spec.expires_at !== undefined && spec.expires_at < request.at) return false
  for (const [key, value] of Object.entries(spec.scope ?? {})) {
    if (JSON.stringify(request.scope?.[key]) !== JSON.stringify(value)) return false
  }
  return true
}

function permitsDelegation(
  body: { resources?: string[]; scope?: Record<string, unknown>; expires_at?: number },
  resource: string,
  request: Attempt,
): boolean {
  if (body.resources && !body.resources.includes(resource)) return false
  if (body.expires_at !== undefined && body.expires_at < request.at) return false
  for (const [key, value] of Object.entries(body.scope ?? {})) {
    if (JSON.stringify(request.scope?.[key]) !== JSON.stringify(value)) return false
  }
  return true
}
