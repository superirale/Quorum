/**
 * One task, and the two controls that behave differently from every other
 * button in the app.
 *
 * The status select is a *request*. It publishes a kind 8109 op and then waits
 * for the relay to fold it and the subscription to bring it back, so what is on
 * screen is always a state some signed event supports. An optimistic select
 * would display `done` for an op the relay refused — which is a real outcome
 * here, since `set_budget` is gated on a grant and any op can be rate-limited.
 * The assertion is therefore that the select does *not* move.
 *
 * Stop is the other exception. Kind 28101 is ephemeral: no relay stores it, no
 * OK means anything beyond "routed to whoever was subscribed", and an agent
 * that is down hears nothing. The button has to exist only while something is
 * running, and the sentence about there being no receipt has to appear on the
 * screen — a human who believes they stopped a production deploy and walks away
 * is a worse outcome than one who knows to check.
 *
 * The budget banner is asserted against `checkBudget` rather than against a
 * comparison written here, for the same reason the component asks it: the relay
 * pauses a thread on exactly that predicate, and a screen with its own opinion
 * would eventually read "fine" over a thread the relay is refusing work in.
 */

import assert from 'node:assert/strict'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, it } from 'vitest'
import { Kinds, EphemeralKinds, TagName } from '@quorum/protocol'
import type { ActionChain } from '@quorum/sdk'
import { ThreadView } from '../src/components/ThreadView.tsx'
import { ADA, NOW, absent, event, recorder, thread, workspace } from './fixtures.ts'

function chain(threadId: string, over: Partial<ActionChain> = {}): ActionChain {
  return {
    actionId: 'act-1',
    name: 'deploy',
    status: 'running',
    ok: true,
    modified: false,
    approvals: [],
    issues: [],
    events: [event({ kind: Kinds.Action, tags: [[TagName.RootEvent, threadId]] })],
    ...over,
  }
}

describe('ThreadView controls', () => {
  it('publishes a thread op and does not move the select until one comes back', async () => {
    const task = thread({ status: 'open' })
    const rec = recorder()
    render(
      <ThreadView
        workspace={workspace({ events: [task.root], publish: rec.publish })}
        thread={task}
        me={ADA}
        onBack={() => {}}
      />,
    )

    const select = screen.getByLabelText('status') as HTMLSelectElement
    fireEvent.change(select, { target: { value: 'done' } })

    await waitFor(() => assert.equal(rec.sent.length, 1))
    const [op] = rec.sent
    assert.ok(op)
    assert.equal(op.kind, Kinds.ThreadOp)
    assert.deepEqual(op.body, { op: 'set_status', status: 'done' })
    // The thread prop has not changed, because no op has been served back.
    assert.equal(select.value, 'open')
  })

  it('shows the publish failure rather than pretending the op landed', async () => {
    const task = thread()
    render(
      <ThreadView
        workspace={workspace({
          events: [task.root],
          publish: () => Promise.reject(new Error('rate-limited')),
        })}
        thread={task}
        me={ADA}
        onBack={() => {}}
      />,
    )

    fireEvent.change(screen.getByLabelText('status'), { target: { value: 'done' } })
    await waitFor(() => assert.ok(screen.getByText('rate-limited')))
  })
})

describe('ThreadView Stop', () => {
  it('is absent when nothing is running', () => {
    const task = thread()
    render(
      <ThreadView
        workspace={workspace({ events: [task.root], chains: [chain(task.id, { status: 'succeeded' })] })}
        thread={task}
        me={ADA}
        onBack={() => {}}
      />,
    )
    absent(screen.queryByRole('button', { name: /^Stop/ }), 'Stop button')
  })

  it('appears for a running chain and names the action it would stop', () => {
    const task = thread()
    render(
      <ThreadView
        workspace={workspace({ events: [task.root], chains: [chain(task.id)] })}
        thread={task}
        me={ADA}
        onBack={() => {}}
      />,
    )
    assert.ok(screen.getByRole('button', { name: 'Stop deploy' }))
    // One running chain: no "stop everything", which would stop that same one.
    absent(screen.queryByRole('button', { name: 'Stop everything' }), '"Stop everything" button')
  })

  it('sends an interrupt and then says there is no receipt for it', async () => {
    const task = thread()
    const rec = recorder()
    const { container } = render(
      <ThreadView
        workspace={workspace({ events: [task.root], chains: [chain(task.id)], publish: rec.publish })}
        thread={task}
        me={ADA}
        onBack={() => {}}
      />,
    )

    fireEvent.click(screen.getByRole('button', { name: 'Stop deploy' }))

    await waitFor(() => assert.equal(rec.sent.length, 1))
    const [stop] = rec.sent
    assert.ok(stop)
    assert.equal(stop.kind, EphemeralKinds.Interrupt)
    assert.equal(stop.action, 'act-1')
    await waitFor(() =>
      assert.match(container.textContent ?? '', /Nothing stores an interrupt/),
    )
  })

  it('offers a stop-everything only once there is more than one thing to stop', () => {
    const task = thread()
    render(
      <ThreadView
        workspace={workspace({
          events: [task.root],
          chains: [chain(task.id), chain(task.id, { actionId: 'act-2', name: 'migrate' })],
        })}
        thread={task}
        me={ADA}
        onBack={() => {}}
      />,
    )
    assert.ok(screen.getByRole('button', { name: 'Stop deploy' }))
    assert.ok(screen.getByRole('button', { name: 'Stop migrate' }))
    assert.ok(screen.getByRole('button', { name: 'Stop everything' }))
  })
})

describe('ThreadView budget', () => {
  it('warns exactly when the ceiling is spent, and says resuming is not enough', () => {
    const task = thread({
      budget: { tokens: 30_000 },
      spent: { tokens_in: 20_000, tokens_out: 15_000 },
    })
    render(
      <ThreadView
        workspace={workspace({ events: [task.root] })}
        thread={task}
        me={ADA}
        onBack={() => {}}
      />,
    )
    assert.ok(screen.getByText(/spent its budget/))
    assert.ok(screen.getByText(/Resuming is not enough on its own/))
  })

  it('counts both token columns, so a thread under the cap on each alone is not warned twice', () => {
    // 29,000 in and 28,000 out is 57,000 against a 30,000 ceiling. Comparing
    // either column alone reads as fine.
    const under = thread({ budget: { tokens: 30_000 }, spent: { tokens_in: 1_000 } })
    const { container } = render(
      <ThreadView
        workspace={workspace({ events: [under.root] })}
        thread={under}
        me={ADA}
        onBack={() => {}}
      />,
    )
    assert.doesNotMatch(container.textContent ?? '', /spent its budget/)
    assert.match(container.textContent ?? '', /1000 tokens of 30000 tokens/)
  })

  it('says a thread with spend and no ceiling has none, rather than leaving it blank', () => {
    const task = thread({ spent: { usd: 0.42 } })
    render(
      <ThreadView
        workspace={workspace({ events: [task.root] })}
        thread={task}
        me={ADA}
        onBack={() => {}}
      />,
    )
    assert.ok(screen.getByText(/\$0\.42 · no ceiling/))
  })
})

describe('ThreadView timeline', () => {
  it('renders every event through its alt tag, oldest first', () => {
    const task = thread()
    const events = [
      task.root,
      event({
        kind: 8102,
        created_at: NOW + 2,
        tags: [[TagName.RootEvent, task.id], [TagName.Alt, 'Approval needed: deploy api']],
      }),
      event({
        kind: 9,
        created_at: NOW + 1,
        tags: [[TagName.RootEvent, task.id], [TagName.Alt, 'ada: on it']],
      }),
    ]
    const { container } = render(
      <ThreadView
        workspace={workspace({ events })}
        thread={task}
        me={ADA}
        onBack={() => {}}
      />,
    )

    const lines = [...container.querySelectorAll('.timeline .text')].map((n) => n.textContent)
    assert.deepEqual(lines.slice(1), ['ada: on it', 'Approval needed: deploy api'])
  })

  it('relays a disagreeing projection as this browser’s fold, not the relay’s', () => {
    const task = thread({ check: { verdict: 'disagrees', fields: ['status'] } })
    render(
      <ThreadView
        workspace={workspace({ events: [task.root] })}
        thread={task}
        me={ADA}
        onBack={() => {}}
      />,
    )
    assert.ok(screen.getByText(/disagrees with a replay of the ops it says it folded/))
  })
})
