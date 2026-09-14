/**
 * The human half of the loop.
 *
 * Everything else in this console is administration. These three commands are
 * the product: a person reads what an agent proposes to do, and signs a
 * sentence binding their key to those exact arguments — or refuses. What makes
 * it worth anything is that the signature is over a digest of the payload, so
 * "Ada approved this deploy" cannot later be made to mean a different deploy,
 * by the agent, by the relay, or by whoever runs either.
 */

import { ActionBody, digest, type NostrEvent } from '@quorum/protocol'
import { applyEdits, approvalResponse, inbox, type Pending } from '@quorum/sdk'
import { bool, flag, flagAll, pairs, type ParsedArgs } from '../args.ts'
import { bold, cyan, dim, green, red, short, when, yellow } from '../format.ts'
import { findByPrefix } from '../inbox.ts'
import { actionOf, open, proposalOf, readableEvents, type Session } from '../session.ts'

export async function inboxCommand(args: ParsedArgs): Promise<void> {
  const session = await open(flag(args, 'as'))
  try {
    const items = inbox(await readableEvents(session), {
      me: session.me,
      now: Math.floor(Date.now() / 1000),
      all: bool(args, 'all'),
    })

    if (!items.length) {
      console.log(dim(`nothing waiting on ${session.name} in #${session.config.group}`))
      return
    }

    for (const item of items) {
      const risk = item.body.risk === 'high' ? red('high') : item.body.risk === 'medium' ? yellow('medium') : 'low'
      const state = item.expired ? red(' expired') : item.answered ? dim(' answered') : ''
      console.log(
        `\n${bold(short(item.request.id))} ${bold(item.body.title)}  ${dim(`risk=`)}${risk}${state}`,
      )
      console.log(`  ${item.body.summary}`)
      console.log(
        dim(`  from ${short(item.request.pubkey)} at ${when(item.request.created_at)}`) +
          (item.approvers.length > 1
            ? dim(`, ${item.body.required} of ${item.approvers.length} approvers needed`)
            : ''),
      )

      const proposal = await proposalFor(session, item)
      if (proposal !== undefined) console.log(`  ${cyan(JSON.stringify(proposal))}`)

      if (item.body.requested_grant) {
        // Two different asks in one event, and they should never be skimmed as
        // one. Consenting to an action is not the same as handing over a
        // standing capability.
        console.log(
          yellow(`  also asking for a capability: `) +
            `${item.body.requested_grant.resource} ${JSON.stringify(item.body.requested_grant.scope ?? {})}`,
        )
      }
    }
    console.log(dim(`\n  quorum approve ${short(items[0]!.request.id).replace('…', '')} [--set k=v]   quorum deny <id>`))
  } finally {
    session.close()
  }
}

export async function approve(args: ParsedArgs): Promise<void> {
  await decide(args, 'approved')
}

export async function deny(args: ParsedArgs): Promise<void> {
  await decide(args, 'denied')
}

async function decide(args: ParsedArgs, decision: 'approved' | 'denied'): Promise<void> {
  const prefix = args.words[1]
  if (!prefix) throw new Error(`usage: quorum ${decision === 'approved' ? 'approve' : 'deny'} <id>`)

  const session = await open(flag(args, 'as'))
  try {
    const item = findByPrefix(
      inbox(await readableEvents(session), {
        me: session.me,
        now: Math.floor(Date.now() / 1000),
        all: true,
      }),
      prefix,
    )

    if (item.answered && !bool(args, 'force')) {
      throw new Error(
        `${session.name} already answered ${short(item.request.id)}. ` +
          'Answering twice is recorded, not overwritten — `--force` if that is what you want.',
      )
    }
    if (item.expired && !bool(args, 'force')) {
      throw new Error(`${short(item.request.id)} expired. \`--force\` to sign it anyway.`)
    }

    const edits = pairs(flagAll(args, 'set'), '--set')
    let modifiedInput: unknown
    if (Object.keys(edits).length) {
      if (decision === 'denied') throw new Error('--set makes no sense with deny')
      const proposed = await proposalFor(session, item)
      if (proposed === undefined) {
        throw new Error('cannot edit: the proposal this request refers to is not on the relay')
      }
      modifiedInput = applyEdits(proposed, edits)
      console.log(`  ${dim('proposed')} ${JSON.stringify(proposed)}`)
      console.log(`  ${bold('approving')} ${cyan(JSON.stringify(modifiedInput))}`)
    }

    const event = await session.publisher.publish(
      approvalResponse({
        request: item.request,
        decision,
        ...(flag(args, 'reason') ? { reason: flag(args, 'reason')! } : {}),
        ...(modifiedInput !== undefined ? { modifiedInput } : {}),
      }),
    )

    const mark = decision === 'approved' ? green('✓') : red('✗')
    console.log(`${mark} ${bold(session.name)} ${decision} ${bold(item.body.title)}`)
    console.log(`  signed  ${dim(short(event.id))}`)
    if (modifiedInput !== undefined) {
      // Both digests are in the log now, and the agent is required to run the
      // second one. An auditor comparing them is how an edit stays honest.
      console.log(`  digest  ${short(digest(modifiedInput))} ${dim('(the edit, not the proposal)')}`)
    } else if (item.body.input_digest) {
      console.log(`  digest  ${short(item.body.input_digest)}`)
    }
  } finally {
    session.close()
  }
}

/**
 * The input the agent proposed.
 *
 * Fetched by id, because the action id *is* the id of the `proposed` event —
 * so this is an exact lookup and not a search, and there is no question of
 * which of several candidate proposals is the real one.
 */
async function proposalFor(session: Session, item: Pending): Promise<unknown> {
  const actionId = actionOf(item.request)
  if (!actionId) return undefined
  const proposal = await proposalOf(session, actionId)
  if (!proposal) return undefined
  return bodyOf(proposal)?.input
}

function bodyOf(event: NostrEvent): ActionBody | undefined {
  try {
    return ActionBody.parse(JSON.parse(event.content))
  } catch {
    return undefined
  }
}
