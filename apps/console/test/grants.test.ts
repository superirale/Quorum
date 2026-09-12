/**
 * What the grant listing says a capability covers.
 *
 * This exists because the first version of `describeGrant` printed `?` for
 * every grant it was ever shown: it read `body.resource`, and the spec lives a
 * level down at `body.grant.resource`. No test caught it because there was no
 * test — the shape looked obvious enough to write from memory, and the console
 * happily rendered a grant it had entirely failed to understand.
 *
 * So these assert the field a reader would act on, not merely that a line came
 * back. A listing that renders without saying what is authorised is the failure
 * mode being guarded against.
 */

import assert from 'node:assert/strict'
import { describe as group, it } from 'node:test'
import { Kinds, build, type NostrEvent } from '@quorum/protocol'
import { LocalSigner, grant } from '@quorum/sdk'
import { describeGrant } from '../src/commands/grants.ts'

const GROUP = 'ops'
const NOW = 1_800_000_000

const ada = LocalSigner.generate()
const bot = LocalSigner.generate()

async function issued(options: Parameters<typeof grant>[0]): Promise<NostrEvent> {
  return ada.sign(build({ ...grant(options), pubkey: ada.publicKey, group: GROUP, created_at: NOW - 60 }))
}

const base = { grantee: bot.publicKey, resource: 'action:deploy', actions: ['invoke'] }

group('describeGrant', () => {
  it('names the resource, which lives under `grant`, not at the top level', async () => {
    const line = describeGrant(await issued(base), NOW)
    assert.match(line, /action:deploy/)
    assert.doesNotMatch(line, /\?/)
  })

  it('shows the scope, because that is what narrows the resource', async () => {
    // Scope not resource name is the M4 finding: `action:deploy` with
    // `{env: production}`, never `action:deploy.production`. An operator who
    // cannot see the scope cannot tell the two grants apart.
    const line = describeGrant(await issued({ ...base, scope: { env: 'production' } }), NOW)
    assert.match(line, /"env":"production"/)
  })

  it('marks a revoked grant revoked', async () => {
    const line = describeGrant(await issued({ ...base, revoked: true }), NOW)
    assert.match(line, /revoked/)
    assert.doesNotMatch(line, /active/)
  })

  it('marks an expired grant expired, though it is still the current event', async () => {
    // `effectiveAddressable` keeps it — it is the newest event at its
    // coordinate — while `verifyGrant` refuses it. The listing must agree with
    // the verifier, or it reports a capability that authorises nothing.
    const line = describeGrant(await issued({ ...base, expiresAt: NOW - 1 }), NOW)
    assert.match(line, /expired/)
    assert.doesNotMatch(line, /active/)
  })

  it('keeps an unexpired grant active and says when it lapses', async () => {
    const line = describeGrant(await issued({ ...base, expiresAt: NOW + 3600 }), NOW)
    assert.match(line, /active/)
    assert.match(line, /until 2027-01-15T/)
  })

  it('reports the delegation a grant was issued under', async () => {
    const via = `38106:${ada.publicKey}:d1`
    assert.match(describeGrant(await issued({ ...base, via }), NOW), /via 38106:/)
  })

  it('describes a delegation by its resources', async () => {
    const event = await ada.sign(
      build({
        kind: Kinds.Delegation,
        pubkey: ada.publicKey,
        group: GROUP,
        d: 'd1',
        created_at: NOW - 60,
        body: { delegate: bot.publicKey, resources: ['action:deploy'], revoked: false },
      }),
    )
    const line = describeGrant(event, NOW)
    assert.match(line, /delegation/)
    assert.match(line, /action:deploy/)
  })

  it('says a delegation with no resource list bounds nothing by name', async () => {
    // Omitted `resources` means "anything the delegate already holds a grant
    // for" — still bounded by the intersection rule, but printing an empty
    // string would read as "nothing", the exact opposite.
    const event = await ada.sign(
      build({
        kind: Kinds.Delegation,
        pubkey: ada.publicKey,
        group: GROUP,
        d: 'd2',
        created_at: NOW - 60,
        body: { delegate: bot.publicKey, revoked: false },
      }),
    )
    assert.match(describeGrant(event, NOW), /anything the delegate already holds/)
  })

  it('says so rather than throwing when the content is not JSON', async () => {
    // Any member can publish a 38102 with junk in it and every relay will
    // store it. The listing has to survive reading one.
    const event = await ada.sign({
      kind: Kinds.CapabilityGrant,
      pubkey: ada.publicKey,
      created_at: NOW,
      tags: [['h', GROUP], ['d', 'junk'], ['alt', 'a capability grant']],
      content: 'not json',
    })
    assert.match(describeGrant(event, NOW), /corrupt/)
  })

  it('says so when the body is JSON but not a grant', async () => {
    const event = await ada.sign({
      kind: Kinds.CapabilityGrant,
      pubkey: ada.publicKey,
      created_at: NOW,
      tags: [['h', GROUP], ['d', 'wrong'], ['alt', 'a capability grant']],
      content: JSON.stringify({ resource: 'action:deploy' }),
    })
    assert.match(describeGrant(event, NOW), /invalid/)
  })
})
