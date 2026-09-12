/**
 * One decision.
 *
 * This is the screen the project exists for, so it is worth being explicit
 * about what it must and must not do.
 *
 * **It must show what is being approved, not what it is called.** A card that
 * shows "deploy api" and a green button is a card people click. The payload is
 * rendered field by field, verbatim, above the buttons.
 *
 * **It must not be able to invent a field.** The form is generated from the
 * proposal's own fields via `leaves()`, so there is no input for a field the
 * agent never proposed. `applyEdits` refuses one anyway. The guarantee is the
 * same one `approve --set` gives the console, and it is the same code.
 *
 * **It must not offer a button it cannot honour.** An expired request, an
 * already-answered one, or one whose proposal the relay does not hold are all
 * shown with the reason and no buttons — an approver who clicks and gets an
 * error has already decided, and the decision is the thing we are trying to
 * record faithfully.
 */

import { useMemo, useState } from 'react'
import { digest } from '@quorum/protocol'
import { applyEdits, approvalResponse, leaves, type Pending } from '@quorum/sdk'
import { changed, kindOf, parseField, toInput } from '../fields.ts'
import { short, when } from '../format.ts'
import { proposedInput } from '../proposal.ts'
import type { Workspace } from '../useWorkspace.ts'

export function ApprovalCard({
  item,
  workspace,
  me,
}: {
  item: Pending
  workspace: Workspace
  me: string
}) {
  const proposal = useMemo(
    () => proposedInput(workspace.events, item.request),
    [workspace.events, item.request],
  )
  const fields = useMemo(
    () => (proposal.found ? leaves(proposal.input) : []),
    [proposal],
  )

  const [typed, setTyped] = useState<Record<string, string>>({})
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [problem, setProblem] = useState<string | undefined>()

  // Recomputed on every keystroke so the digest under the buttons is always the
  // digest of what is on screen. An approver must never be able to see one
  // payload and sign another.
  const edit = useMemo(() => {
    if (!proposal.found) return undefined
    const edits: Record<string, unknown> = {}
    for (const leaf of fields) {
      const raw = typed[leaf.path]
      if (raw === undefined) continue
      const parsed = parseField(leaf.value, raw)
      if (!parsed.ok) return { problem: `${leaf.path}: ${parsed.problem}` }
      if (changed(leaf.value, parsed.value)) edits[leaf.path] = parsed.value
    }
    try {
      const input = applyEdits(proposal.input, edits)
      return { input, modified: Object.keys(edits).length > 0 }
    } catch (error) {
      return { problem: (error as Error).message }
    }
  }, [proposal, fields, typed])

  const blocked = item.expired
    ? 'this request expired; nobody can answer it now'
    : item.answered
      ? 'you have already answered this'
      : !proposal.found
        ? 'the relay does not hold the proposal this refers to, so there is nothing to show you — refusing to offer a button for a payload nobody can see'
        : edit?.problem

  const decide = async (decision: 'approved' | 'denied') => {
    setBusy(true)
    setProblem(undefined)
    try {
      await workspace.publish(
        approvalResponse({
          request: item.request,
          decision,
          ...(reason.trim() ? { reason: reason.trim() } : {}),
          ...(decision === 'approved' && edit?.modified ? { modifiedInput: edit.input } : {}),
        }),
      )
    } catch (error) {
      setProblem((error as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const remaining = item.body.expires_at ? item.body.expires_at - workspace.now : undefined

  return (
    <article className={`card risk-${item.body.risk ?? 'medium'}`}>
      <header>
        <strong>{item.body.title}</strong>
        <span className={`pill risk-${item.body.risk ?? 'medium'}`}>{item.body.risk ?? 'medium'}</span>
      </header>

      <p>{item.body.summary}</p>
      <p className="dim">
        from {short(item.request.pubkey)} at {when(item.request.created_at)}
        {item.approvers.length > 1 && ` · ${item.body.required} of ${item.approvers.length} approvers`}
        {remaining !== undefined &&
          (remaining > 0 ? ` · expires in ${remaining}s` : ' · expired')}
      </p>

      {item.body.requested_grant && (
        <div className="banner warn">
          <strong>It is also asking for a capability.</strong> {item.body.requested_grant.resource}{' '}
          <code>{JSON.stringify(item.body.requested_grant.scope ?? {})}</code>
          <div className="dim">
            Saying yes to the action and handing over a standing capability are two different
            decisions. This one outlives the action.
          </div>
        </div>
      )}

      {proposal.found ? (
        fields.length ? (
          <div className="fields">
            {fields.map((leaf) => {
              const raw = typed[leaf.path] ?? toInput(leaf.value)
              const parsed = parseField(leaf.value, raw)
              const isChanged = parsed.ok && changed(leaf.value, parsed.value)
              return (
                <label key={leaf.path} className={isChanged ? 'field edited' : 'field'}>
                  <span>{leaf.path}</span>
                  {kindOf(leaf.value) === 'boolean' ? (
                    <select
                      value={raw}
                      onChange={(e) => setTyped({ ...typed, [leaf.path]: e.target.value })}
                    >
                      <option value="true">true</option>
                      <option value="false">false</option>
                    </select>
                  ) : kindOf(leaf.value) === 'json' ? (
                    <textarea
                      rows={2}
                      value={raw}
                      spellCheck={false}
                      onChange={(e) => setTyped({ ...typed, [leaf.path]: e.target.value })}
                    />
                  ) : (
                    <input
                      value={raw}
                      spellCheck={false}
                      onChange={(e) => setTyped({ ...typed, [leaf.path]: e.target.value })}
                    />
                  )}
                  {isChanged && <em className="was">was {toInput(leaf.value)}</em>}
                  {!parsed.ok && <em className="bad">{parsed.problem}</em>}
                </label>
              )
            })}
          </div>
        ) : (
          <p className="dim">no arguments</p>
        )
      ) : (
        <p className="bad">proposal not found on this relay</p>
      )}

      {edit && 'input' in edit && (
        <p className="digest">
          signing digest <code>{short(digest(edit.input))}</code>
          {edit.modified && <span className="pill edited">edited</span>}
        </p>
      )}

      <input
        className="reason"
        value={reason}
        placeholder="reason (optional, and recorded)"
        onChange={(e) => setReason(e.target.value)}
      />

      {blocked ? (
        <p className="bad">{blocked}</p>
      ) : (
        <div className="row">
          <button className="primary" disabled={busy} onClick={() => void decide('approved')}>
            approve as {short(me)}
          </button>
          <button className="danger" disabled={busy} onClick={() => void decide('denied')}>
            deny
          </button>
        </div>
      )}

      {problem && <p className="bad">{problem}</p>}
    </article>
  )
}
