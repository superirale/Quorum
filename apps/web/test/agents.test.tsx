/**
 * The presence list, which is mostly a test about what it refuses to say.
 *
 * Kind 28103 is ephemeral, so this screen's knowledge is bounded by how long
 * the tab has been open. Two sentences it must never render follow from that,
 * and both are the kind of wording that gets "tidied" by someone who has not
 * read the comment at the top of the component:
 *
 * - an empty list is "nobody has said", never "nobody is running";
 * - a beat that expired is "last seen", never "offline".
 *
 * The failure each prevents is the same one — starting a second replica of an
 * agent that is midway through a production deploy — and it is not a failure
 * any unit test of `presence()` can catch, because `presence()` returns the
 * right data either way.
 */

import assert from 'node:assert/strict'
import { render, screen } from '@testing-library/react'
import { describe, it } from 'vitest'
import type { Presence } from '@quorum/sdk'
import { Agents } from '../src/components/Agents.tsx'
import { BOT, NOW, absent, event } from './fixtures.ts'

function beat(over: Partial<Presence> = {}): Presence {
  return {
    pubkey: BOT,
    status: 'online',
    at: NOW,
    until: NOW + 60,
    live: true,
    event: event({ kind: 28103 }),
    ...over,
  }
}

describe('Agents', () => {
  it('an empty list says nobody has spoken, and does not claim anyone is down', () => {
    const { container } = render(<Agents agents={[]} now={NOW} />)
    assert.ok(screen.getByText('nobody has said'))
    assert.doesNotMatch(container.textContent ?? '', /offline|idle|nobody is/i)
  })

  it('a stale beat is reported as last seen, not as offline', () => {
    // We did not hear it stop. We stopped hearing it, which is also what a
    // dropped websocket looks like from here.
    render(<Agents agents={[beat({ live: false, at: NOW - 600 })]} now={NOW} />)
    assert.ok(screen.getByText('last seen 10m ago'))
    absent(screen.queryByText('signed off'), '"signed off"')
  })

  it('an agent that said it was going says so, which is a different fact', () => {
    render(<Agents agents={[beat({ status: 'offline' })]} now={NOW} />)
    assert.ok(screen.getByText('signed off'))
  })

  it('shows what a live agent said it was doing', () => {
    render(<Agents agents={[beat({ status: 'busy', activity: 'deploying api' })]} now={NOW} />)
    assert.ok(screen.getByText('busy · deploying api'))
  })
})
