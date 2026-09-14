/**
 * Checking the work, and taking it somewhere the relay cannot follow.
 *
 * `audit` asks the relay for the group's events and verifies them locally —
 * note the order: the relay is a source of bytes, never a source of truth, and
 * every conclusion below comes out of `verifyActionChain` running against
 * signatures on this machine. `export` then writes those bytes to a file so the
 * same questions can be asked with no relay at all, which is the claim the
 * milestone actually rests on.
 */

import { writeFile } from 'node:fs/promises'
import { conclusion, verifyActionChains, type ActionChain } from '@quorum/sdk'
import { flag, type ParsedArgs } from '../args.ts'
import { bold, dim, green, red, short, yellow } from '../format.ts'
import { groupEvents, open, opener } from '../session.ts'

export async function audit(args: ParsedArgs): Promise<void> {
  const session = await open(flag(args, 'as'))
  try {
    const events = await groupEvents(session)
    const thread = flag(args, 'thread')
    const scoped = thread
      ? events.filter((e) => e.id.startsWith(thread) || e.tags.some((t) => t[1]?.startsWith(thread)))
      : events

    // Raw events in, an opener alongside. The signature check has to run
    // against the bytes the author signed, and on an encrypted channel those
    // bytes are the ciphertext — so the auditor opens after verifying rather
    // than being handed events that were opened first.
    const chains = verifyActionChains(scoped, { open: opener(session) })
    if (!chains.length) {
      console.log(dim(`no action chains in #${session.config.group} — nothing was proposed`))
      return
    }

    let bad = 0
    for (const chain of chains) {
      report(chain)
      if (!chain.ok) bad += 1
    }
    console.log(
      bad === 0
        ? `\n${green(`all ${chains.length} chain(s) verify`)} ${dim('from signatures, not from the relay')}`
        : `\n${red(`${bad} of ${chains.length} chain(s) do not verify`)}`,
    )
    if (bad) process.exitCode = 1
  } finally {
    session.close()
  }
}

export async function exportEvents(args: ParsedArgs): Promise<void> {
  const path = args.words[1]
  if (!path) throw new Error('usage: quorum export <file>')

  const session = await open(flag(args, 'as'))
  try {
    const events = await groupEvents(session)
    await writeFile(path, `${JSON.stringify(events, null, 2)}\n`)
    console.log(`${green('✓')} ${events.length} events → ${bold(path)}`)
    console.log(
      dim('  verify them with no relay and no keys:\n') +
        dim(`  pnpm --filter @quorum/deploy-agent verify ${path}`),
    )
    if (session.channel.encrypted) {
      // Said here rather than discovered there. The export is deliberately the
      // sealed bytes — signatures are over those — so an offline verifier can
      // check every signature in the file and read none of the bodies.
      console.log(
        yellow(`  #${session.config.group} is encrypted, so the bodies in this file are sealed.`),
      )
      console.log(
        dim('  Signatures still verify offline; what was proposed and approved does not\n') +
          dim('  without the channel key. That is what encrypting a channel costs.'),
      )
    }
  } finally {
    session.close()
  }
}

function report(chain: ActionChain): void {
  const mark = chain.ok ? green('✓') : red('✗')
  console.log(`\n${mark} ${bold(chain.name)}  ${dim(short(chain.actionId))}  ${chain.status}`)

  for (const approval of chain.approvals) {
    const note = approval.counted ? '' : yellow(' (not counted — nobody asked them)')
    console.log(`  ${short(approval.pubkey)} ${approval.decision}${note}`)
  }
  if (chain.input !== undefined) console.log(`  proposed   ${JSON.stringify(chain.input)}`)
  if (chain.executedDigest) {
    console.log(
      `  ran digest ${short(chain.executedDigest)}` +
        (chain.modified ? yellow(' (an approver edited the payload)') : ''),
    )
  }
  for (const issue of chain.issues) {
    const colour = issue.severity === 'error' ? red : yellow
    console.log(`  ${colour(issue.severity)} ${issue.code}: ${issue.message}`)
  }
  const verdict = conclusion(chain)
  if (verdict) console.log(`  ${bold(`→ ${verdict}`)}`)
}
