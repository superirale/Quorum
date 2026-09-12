/**
 * What actually happened, verified rather than reported.
 *
 * Every chain here is checked in the browser against the signatures, by the
 * same `verifyActionChains` the offline auditor runs over a JSON dump with no
 * relay and no network. The relay served these bytes and is the one party with
 * both the motive and the position to substitute an approval, so a client that
 * displayed the relay's account of who approved what would be asking the
 * suspect for an alibi.
 *
 * The verdict line comes from `conclusion()` in the SDK. That sentence used to
 * be composed in each client, and both copies claimed a *denied* action had
 * been approved and run.
 */

import { conclusion, type ActionChain } from '@quorum/sdk'
import { short } from '../format.ts'

export function Chains({ chains }: { chains: ActionChain[] }) {
  if (!chains.length) return <p className="dim empty">no actions yet</p>

  return (
    <div className="chains">
      {[...chains].reverse().map((chain) => {
        const verdict = conclusion(chain)
        return (
          <article key={chain.actionId} className={chain.ok ? 'chain' : 'chain broken'}>
            <header>
              <strong>{chain.name}</strong>
              <span className={`pill status-${chain.status}`}>{chain.status}</span>
              {chain.modified && <span className="pill edited">edited</span>}
            </header>

            {chain.approvals.map((approval) => (
              <div key={approval.event.id} className={approval.counted ? 'vote' : 'vote uncounted'}>
                {approval.decision === 'approved' ? '✓' : '✗'} {short(approval.pubkey)}{' '}
                {approval.decision}
                {!approval.counted && <span className="dim"> (not counted)</span>}
              </div>
            ))}

            {chain.issues.map((issue, i) => (
              <div key={i} className={issue.severity === 'error' ? 'bad' : 'warn'}>
                {issue.severity}: {issue.message}
              </div>
            ))}

            {verdict && <p className="verdict">→ {verdict}</p>}
          </article>
        )
      })}
    </div>
  )
}
