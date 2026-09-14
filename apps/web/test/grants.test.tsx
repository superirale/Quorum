/**
 * The capability inspector, which is a listing and must not read as a summary.
 *
 * Three claims here are the three warnings written into the top of the
 * component, and each corresponds to a decision an operator makes from this
 * screen and gets wrong if the rendering is careless:
 *
 * - A revoked grant is *listed*, with its reason, rather than filtered out.
 *   Filtering makes "this was taken away on purpose" and "this was never
 *   issued" look identical, and the operator re-issues it.
 * - `max_uses` is labelled "not enforced". Nothing in this system counts uses,
 *   so printing the number bare states a constraint no code applies.
 * - An unscoped grant says so in words. A blank scope cell reads as "nothing
 *   rendered here", and the difference between that and "applies anywhere" is
 *   the entire question with a capability.
 *
 * Plus membership: `group:join` is the coarsest capability in the system and
 * belongs in its own section rather than buried among the `action:` rows.
 */

import assert from 'node:assert/strict'
import { render, screen, within } from '@testing-library/react'
import { describe, it } from 'vitest'
import type { GrantSummary } from '@quorum/sdk'
import { Grants } from '../src/components/Grants.tsx'
import { ADA, BOT, NOW, absent, event } from './fixtures.ts'

function grant(over: Partial<GrantSummary> = {}): GrantSummary {
  return {
    event: event({ kind: 38102 }),
    kind: 'grant',
    state: 'active',
    issuer: ADA,
    subject: BOT,
    resources: ['action:deploy'],
    actions: [],
    ...over,
  }
}

/** The table under a given heading, so a row cannot be found in the wrong one. */
function section(container: HTMLElement, heading: string): HTMLElement {
  const headings = [...container.querySelectorAll('h3')]
  const found = headings.find((h) => h.textContent === heading)
  assert.ok(found, `no section headed ${heading}`)
  let node = found.nextElementSibling
  while (node && node.tagName !== 'TABLE' && node.tagName !== 'H3') node = node.nextElementSibling
  assert.ok(node && node.tagName === 'TABLE', `${heading} rendered no table`)
  return node as HTMLElement
}

describe('Grants', () => {
  it('puts membership in its own section, above the capabilities', () => {
    const { container } = render(
      <Grants
        grants={[grant({ resources: ['group:join'] }), grant({ resources: ['action:deploy'] })]}
        now={NOW}
      />,
    )
    assert.ok(within(section(container, 'Membership')).getByText('group:join'))
    assert.ok(within(section(container, 'Capabilities')).getByText('action:deploy'))
    absent(
      within(section(container, 'Capabilities')).queryByText('group:join'),
      'group:join row under Capabilities',
    )
  })

  it('lists a revoked grant with its reason rather than dropping it', () => {
    render(
      <Grants
        grants={[grant({ state: 'revoked', revokedReason: 'left the team' })]}
        now={NOW}
      />,
    )
    assert.ok(screen.getByText('revoked'))
    assert.ok(screen.getByText('left the team'))
  })

  it('says an expired grant expired, in the past tense', () => {
    render(<Grants grants={[grant({ state: 'expired', expiresAt: NOW - 7200 })]} now={NOW} />)
    assert.ok(screen.getByText(/expired 2h ago/))
  })

  it('labels max_uses as not enforced, because nothing counts uses', () => {
    render(<Grants grants={[grant({ maxUses: 5 })]} now={NOW} />)
    assert.ok(screen.getByText(/max 5 uses \(not enforced\)/))
  })

  it('says an unscoped grant applies anywhere instead of leaving the cell blank', () => {
    render(<Grants grants={[grant({ scope: undefined })]} now={NOW} />)
    assert.ok(screen.getByText('unscoped — applies anywhere'))
  })

  it('renders a scope as the key=value it will be intersected as', () => {
    // Authority is `action:deploy` with `{env: production}`, never a resource
    // named `action:deploy.production` — names match exactly and never narrow.
    render(<Grants grants={[grant({ scope: { env: 'production' } })]} now={NOW} />)
    assert.ok(screen.getByText('env=production'))
    absent(screen.queryByText('unscoped — applies anywhere'), '"unscoped" caption')
  })

  it('says a delegation naming no resource narrows nothing by name', () => {
    const { container } = render(
      <Grants grants={[grant({ kind: 'delegation', resources: [] })]} now={NOW} />,
    )
    assert.ok(within(section(container, 'Delegations')).getByText('everything the issuer holds'))
  })

  it('tells each empty section apart by what it says is missing', () => {
    render(<Grants grants={[]} now={NOW} />)
    assert.ok(screen.getByText('nobody has been granted membership'))
    assert.ok(screen.getByText('no capabilities granted'))
    assert.ok(screen.getByText('no delegations'))
  })
})
