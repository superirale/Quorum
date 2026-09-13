/**
 * Every capability in the workspace, including the one that is membership.
 *
 * A capability in Quorum is a signed addressable event, not a row in anyone's
 * database, so this screen is derived entirely from events the relay served and
 * this browser verified. It is a *listing*, not an enforcement point: the deploy
 * tool checks the grant before it deploys, and nothing here gates anything.
 *
 * Three things this is careful about, each of which has already caused a real
 * defect somewhere in this repo:
 *
 * - **`group:join` is shown as membership, first.** It is the coarsest
 *   capability in the system and was the only one nobody had to be granted
 *   until M4's gap was closed. Burying it in a list of `action:deploy` rows
 *   would hide the answer to "who is in this workspace".
 * - **Revoked and expired rows are shown, not filtered out.** "This grant was
 *   revoked" and "this grant was never issued" are different facts, and an
 *   operator who cannot tell them apart re-issues capabilities that were taken
 *   away on purpose.
 * - **`max_uses` is labelled as not enforced.** Nothing in this system counts
 *   uses — there is no caller to ask — so printing it bare would be a
 *   constraint the reader believes and no code applies.
 *
 * The scope column is the one to read closely. Authority is `action:deploy` with
 * `{env: production}` and never a resource named `action:deploy.production`:
 * names match exactly and never narrow, scopes intersect, and a delegation can
 * only ever cut a scope down.
 */

import { Resource } from '@quorum/protocol'
import type { GrantSummary } from '@quorum/sdk'
import { short, until } from '../format.ts'

export function Grants({ grants, now }: { grants: GrantSummary[]; now: number }) {
  const members = grants.filter((g) => g.resources.includes(Resource.Join))
  const rest = grants.filter((g) => !g.resources.includes(Resource.Join))
  const capabilities = rest.filter((g) => g.kind === 'grant')
  const delegations = rest.filter((g) => g.kind === 'delegation')

  return (
    <div className="grants">
      <h3>Membership</h3>
      <p className="dim">
        A <code>group:join</code> grant is an invitation in a form the recipient can be shown and a
        third party can check. Revoking one stops new joins; it does not evict a member already in
        the group.
      </p>
      <Table rows={members} now={now} empty="nobody has been granted membership" />

      <h3>Capabilities</h3>
      <Table rows={capabilities} now={now} empty="no capabilities granted" />

      <h3>Delegations</h3>
      <p className="dim">
        A human's on-behalf-of grant to an agent. The effective permission is the{' '}
        <em>intersection</em> of the agent's own grant and this — a delegation can narrow authority
        and can never add any.
      </p>
      <Table rows={delegations} now={now} empty="no delegations" />
    </div>
  )
}

function Table({ rows, now, empty }: { rows: GrantSummary[]; now: number; empty: string }) {
  if (!rows.length) return <p className="dim empty">{empty}</p>

  return (
    <table className="grant-table">
      <thead>
        <tr>
          <th>who</th>
          <th>resource</th>
          <th>scope</th>
          <th>state</th>
          <th>issued by</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((grant) => (
          <tr key={grant.event.id} className={grant.state === 'active' ? undefined : 'faded'}>
            <td>{grant.subject ? short(grant.subject) : <span className="dim">—</span>}</td>
            <td>
              {grant.resources.length ? (
                grant.resources.map((r) => (
                  <code key={r} className="resource">
                    {r}
                  </code>
                ))
              ) : (
                <span className="dim" title="a delegation naming no resource narrows nothing by name">
                  everything the issuer holds
                </span>
              )}
              {grant.actions.length > 0 && <span className="dim"> · {grant.actions.join(', ')}</span>}
            </td>
            <td>
              <Scope scope={grant.scope} />
            </td>
            <td>
              <State grant={grant} now={now} />
            </td>
            <td>
              {short(grant.issuer)}
              {grant.via && (
                <span className="dim" title={`issued under delegation ${grant.via}`}>
                  {' '}
                  via {short(grant.via)}
                </span>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

/**
 * An unscoped grant says so in words.
 *
 * A blank cell reads as "no constraint I could be bothered to render", and the
 * difference between that and "this grant applies everywhere" is the whole
 * question with a capability.
 */
function Scope({ scope }: { scope?: Record<string, unknown> }) {
  const entries = Object.entries(scope ?? {})
  if (!entries.length) return <span className="dim">unscoped — applies anywhere</span>

  return (
    <>
      {entries.map(([key, value]) => (
        <code key={key} className="scope">
          {key}={typeof value === 'string' ? value : JSON.stringify(value)}
        </code>
      ))}
    </>
  )
}

function State({ grant, now }: { grant: GrantSummary; now: number }) {
  return (
    <>
      <span className={`pill grant-${grant.state}`}>{grant.state}</span>
      {grant.state === 'revoked' && grant.revokedReason && (
        <span className="dim"> {grant.revokedReason}</span>
      )}
      {grant.state === 'invalid' && (
        <span className="dim" title={reason(grant.problem)}>
          {' '}
          {grant.problem}
        </span>
      )}
      {grant.expiresAt !== undefined && (
        <span className="dim">
          {' '}
          {grant.expiresAt < now ? 'expired' : 'expires'} {until(grant.expiresAt, now)}
        </span>
      )}
      {grant.maxUses !== undefined && (
        <span
          className="dim"
          title="nothing in this system counts uses: there is no caller to ask, and a relay counting for itself would be asserting a fact nobody can check"
        >
          {' '}
          max {grant.maxUses} uses (not enforced)
        </span>
      )}
    </>
  )
}

function reason(problem: GrantSummary['problem']): string {
  return problem === 'unparseable'
    ? 'somebody published junk at a capability coordinate — any member can, and every relay will store it'
    : 'JSON that tried to be a grant and is not, which usually means a buggy client rather than an attack'
}
