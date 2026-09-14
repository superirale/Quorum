/**
 * The task list, and the badge that is the only reason to trust it.
 *
 * Everything asserted here is a *word on the screen*. `threads()` already has
 * a suite proving it folds ops correctly; what is untested until now is whether
 * the four verdicts it can return reach a human as four distinguishable
 * statements. They are not interchangeable: `agrees` means this browser
 * recomputed the relay's projection and matched it, `local` means nobody has
 * checked, and a screen that rendered both as a tick would be claiming the
 * second was the first.
 *
 * `disagrees` is the one that has to name its fields. "The relay is lying about
 * this task" with no indication of *what* it is lying about is an alarm nobody
 * can act on, and an alarm nobody can act on gets switched off.
 */

import assert from 'node:assert/strict'
import { render, screen } from '@testing-library/react'
import { describe, it } from 'vitest'
import { Tasks } from '../src/components/Tasks.tsx'
import { NOW, thread } from './fixtures.ts'

describe('Tasks', () => {
  it('says nobody has opened one, rather than rendering an empty list', () => {
    render(<Tasks threads={[]} now={NOW} onSelect={() => {}} />)
    assert.ok(screen.getByText('no threads yet'))
  })

  it('shows the status and title of each task', () => {
    render(
      <Tasks
        threads={[thread({ title: 'Ship the API', status: 'working' })]}
        now={NOW}
        onSelect={() => {}}
      />,
    )
    assert.ok(screen.getByText('Ship the API'))
    assert.ok(screen.getByText('working'))
  })

  it('only says "checked" when this browser actually checked', () => {
    // The distinction the whole badge exists for. `local` is the ordinary state
    // on a generic relay and must not read as a verification that happened.
    render(
      <Tasks
        threads={[
          thread({ title: 'verified', check: { verdict: 'agrees' } }),
          thread({ title: 'unprojected', check: { verdict: 'local' } }),
          thread({ title: 'partial', check: { verdict: 'unverifiable', missing: 3 } }),
        ]}
        now={NOW}
        onSelect={() => {}}
      />,
    )
    assert.equal(screen.getAllByText('checked').length, 1)
    assert.ok(screen.getByText('local'))
    assert.ok(screen.getByText('unverified'))
  })

  it('names the fields a disagreeing relay got wrong', () => {
    render(
      <Tasks
        threads={[thread({ check: { verdict: 'disagrees', fields: ['status', 'spent'] } })]}
        now={NOW}
        onSelect={() => {}}
      />,
    )
    assert.ok(screen.getByText('disagrees: status, spent'))
  })
})
