/**
 * The queue.
 *
 * Empty is the normal state and it should look like it, not like a failure.
 * What it must not do is look empty for the wrong reason — which is why the
 * relay's CLOSED is surfaced as a banner above this, in `App`: "nothing waiting
 * on you" and "you are not subscribed to anything" must never render the same.
 */

import type { Pending } from '@quorum/sdk'
import { ApprovalCard } from './ApprovalCard.tsx'
import type { Workspace } from '../useWorkspace.ts'

export function Approvals({ workspace, me }: { workspace: Workspace; me: string }) {
  if (!workspace.pending.length) {
    return (
      <p className="dim empty">
        {workspace.status === 'live'
          ? 'nothing is waiting on you'
          : 'not connected, so this list means nothing yet'}
      </p>
    )
  }

  return (
    <div className="queue">
      {workspace.pending.map((item) => (
        <ApprovalCard key={item.request.id} item={item} workspace={workspace} me={me} />
      ))}
    </div>
  )
}
