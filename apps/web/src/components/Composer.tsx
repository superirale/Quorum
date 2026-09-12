/**
 * Saying something to an agent.
 *
 * The "to" field is not a nicety and not a mention. A `to`-marked `p` tag is
 * the only addressing signal in the protocol — an agent that acted on prose
 * naming it would be the exact failure this project is built to avoid, so an
 * unaddressed message is a message no agent will ever answer. The UI says that
 * out loud instead of letting you wonder why nothing happened.
 *
 * The candidate list is just the authors already in the channel, which is all a
 * client can honestly know without a directory. Pasting a hex pubkey works too.
 */

import { useMemo, useState } from 'react'
import { Kinds, type NostrEvent } from '@quorum/protocol'
import { short } from '../format.ts'
import type { Workspace } from '../useWorkspace.ts'

export function Composer({ workspace }: { workspace: Workspace }) {
  const [text, setText] = useState('')
  const [to, setTo] = useState('')
  const [busy, setBusy] = useState(false)
  const [problem, setProblem] = useState<string | undefined>()

  const candidates = useMemo(() => authors(workspace.events), [workspace.events])

  const send = async (event: React.FormEvent) => {
    event.preventDefault()
    if (!text.trim()) return
    setBusy(true)
    setProblem(undefined)
    try {
      await workspace.publish({
        kind: Kinds.Thread,
        text: text.trim(),
        to: to ? [to] : [],
        tags: [['title', text.trim().slice(0, 60)]],
      })
      setText('')
    } catch (error) {
      setProblem((error as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <form className="composer" onSubmit={send}>
      <div className="row">
        <input
          value={text}
          placeholder="say something"
          onChange={(e) => setText(e.target.value)}
        />
        <input
          className="to"
          value={to}
          placeholder="to (pubkey)"
          list="addressees"
          spellCheck={false}
          onChange={(e) => setTo(e.target.value.trim())}
        />
        <datalist id="addressees">
          {candidates.map((pubkey) => (
            <option key={pubkey} value={pubkey}>
              {short(pubkey)}
            </option>
          ))}
        </datalist>
        <button type="submit" className="primary" disabled={busy}>
          send
        </button>
      </div>
      {!to && (
        <p className="warn">
          addressed to nobody — no agent will act on this. `to` is the only addressing signal
          there is.
        </p>
      )}
      {problem && <p className="bad">{problem}</p>}
    </form>
  )
}

function authors(events: readonly NostrEvent[]): string[] {
  return [...new Set(events.map((e) => e.pubkey))].sort()
}
