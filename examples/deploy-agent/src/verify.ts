/**
 * The auditor.
 *
 * `pnpm --filter @quorum/deploy-agent verify [transcript.json]`
 *
 * This is the milestone's actual claim, and it is worth being precise about
 * what it is. Everything else in this example is a product feature: the agent
 * stops and asks, the resource checks a grant, the demo shows five ways of not
 * getting a deploy. A competent implementation of any of that could be built on
 * Postgres in an afternoon. What could not be is this file.
 *
 * It takes a JSON array of events — no relay, no keys, no session, no network,
 * no trust in whoever produced the file — and answers three questions:
 *
 *   who approved this, and were they asked
 *   what exactly did they approve, and is it what ran
 *   did the chain advance the way it claims
 *
 * The answers come from signatures over content-addressed events, so they hold
 * against the operator of the relay, the operator of the agent, and the author
 * of this file. Change one byte of one event and the id stops matching; fix the
 * id and the signature stops matching; sign it yourself and you are visibly not
 * the approver. There is no admin who can quietly make the log say otherwise,
 * because there is no log apart from the events — the audit trail and the data
 * are the same object.
 *
 * Try it: edit `transcript.json` by hand and run this again.
 */

import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { Kinds, type NostrEvent } from '@quorum/protocol'
import {
  authorize,
  effectiveAddressable,
  verifyActionChains,
  type ActionChain,
} from '@quorum/sdk'
import { RESOURCE } from './deploy.ts'

const path = process.argv[2] ?? join(import.meta.dirname, '..', 'transcript.json')

let events: NostrEvent[]
try {
  events = JSON.parse(await readFile(path, 'utf8')) as NostrEvent[]
} catch (error) {
  console.error(
    `could not read ${path}: ${(error as Error).message}\n` +
      'run `pnpm --filter @quorum/deploy-agent demo` first — act one writes it.',
  )
  process.exit(2)
}

console.log(`\n\x1b[1m${events.length} events from ${path}\x1b[0m`)
console.log('\x1b[2mno relay, no keys, no network — everything below is derived from signatures\x1b[0m')

const chains = verifyActionChains(events)
if (!chains.length) {
  console.log('\nno action chains here. Nothing was proposed, so nothing needed approving.')
  process.exit(0)
}

let bad = 0
for (const chain of chains) {
  report(chain)
  if (!chain.ok) bad += 1
}

// The grants, read the same way: whatever the log says is current right now.
// `effectiveAddressable` is not `latestAddressable` — a revocation dated after
// the grant it withdraws must win, including against a later re-issue.
const grants = effectiveAddressable(events).filter((e) => e.kind === Kinds.CapabilityGrant)
if (grants.length) {
  console.log(`\n\x1b[1mcapabilities\x1b[0m`)
  for (const chain of chains) {
    const agent = chain.events[0]?.pubkey
    if (!agent) continue
    // Deliberately asked as *this* resource would ask it, with the issuers this
    // resource trusts — and the trusted issuers come from the events only
    // because an auditor reading a stranger's transcript has nothing else. A
    // real resource has them in its config, which is the whole difference
    // between "who does this log claim is in charge" and "who is in charge".
    const issuers = [...new Set(grants.map((g) => g.pubkey))]
    const permission = authorize({
      agent,
      resource: RESOURCE,
      action: 'invoke',
      scope: { env: 'production' },
      trustedIssuers: issuers,
      events,
      uses: 0,
    })
    console.log(
      `  ${short(agent)} → ${RESOURCE} {env: production}: ` +
        (permission.allowed
          ? `\x1b[32mgranted\x1b[0m by ${short(permission.grant!.pubkey)}`
          : `\x1b[31mnot granted\x1b[0m — ${permission.reasons.join('; ')}`),
    )
    break
  }
  console.log(
    `  \x1b[2mtrusting ${grants.length} grant issuer(s) found in the file, which an auditor must; ` +
      'a resource reads its roots from config\x1b[0m',
  )
}

console.log(
  bad === 0
    ? `\n\x1b[32mall ${chains.length} chain(s) verify.\x1b[0m ` +
        'Every claim above survives the operator of the relay, the operator of\n' +
        'the agent, and the author of this file.\n'
    : `\n\x1b[31m${bad} of ${chains.length} chain(s) do not verify.\x1b[0m\n`,
)
process.exit(bad === 0 ? 0 : 1)

// --- reporting ---------------------------------------------------------------

function report(chain: ActionChain): void {
  const mark = chain.ok ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'
  console.log(`\n${mark} \x1b[1m${chain.name}\x1b[0m  \x1b[2m${short(chain.actionId)}\x1b[0m`)
  console.log(`  status      ${chain.status}`)
  console.log(`  proposed by ${short(chain.events[0]?.pubkey ?? 'unknown')}`)

  const counted = chain.approvals.filter((a) => a.counted)
  if (!counted.length) {
    console.log('  approvals   \x1b[33mnone that count\x1b[0m')
  }
  for (const approval of chain.approvals) {
    const note = approval.counted ? '' : ' \x1b[33m(not counted — nobody asked them)\x1b[0m'
    console.log(
      `  approval    ${short(approval.pubkey)} ${approval.decision}` +
        ` at ${new Date(approval.at * 1000).toISOString()}${note}`,
    )
  }

  if (chain.input !== undefined) {
    console.log(`  proposed    ${JSON.stringify(chain.input)}`)
  }
  if (chain.executedDigest) {
    console.log(
      `  ran digest  ${short(chain.executedDigest)}` +
        (chain.modified ? ' \x1b[33m(an approver edited the payload)\x1b[0m' : ''),
    )
  }

  for (const issue of chain.issues) {
    const colour = issue.severity === 'error' ? '\x1b[31m' : '\x1b[33m'
    console.log(`  ${colour}${issue.severity}\x1b[0m     ${issue.code}: ${issue.message}`)
  }

  // The sentence the milestone exists for. Not "the dashboard says so" — this
  // is a statement about which keys signed which bytes.
  if (chain.ok && counted.length) {
    const who = counted.map((a) => short(a.pubkey)).join(', ')
    console.log(`  \x1b[1m→ ${who} approved exactly this, and exactly this ran.\x1b[0m`)
  }
}

function short(hex: string): string {
  return hex.length > 12 ? `${hex.slice(0, 8)}…` : hex
}
