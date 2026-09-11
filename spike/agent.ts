// The agent-side of the M0 loop, written the way we want real agents to read.
// If this file is not obviously pleasant, the SDK shape in sdk.ts is wrong and
// we change it now — before it becomes a published schema in M1.

import { connect } from './sdk.ts'

const agent = connect({
  id: 'agt_deploy',
  name: 'Deploy Bot',
})

agent.on(async (evt, ctx) => {
  if (evt.type !== 'message') return
  if (!ctx.addressedToMe) return // addressing, not prose-sniffing, decides this

  const context = await ctx.getContext(2000)
  console.log(
    `[Deploy Bot] packed ${context.segments.length} segments, ` +
      `${context.used_tokens}/${context.budget_tokens} tokens, ${context.dropped_events} dropped`,
  )

  await ctx.say('Looking at this now.')

  const action = await ctx.startAction({
    name: 'deploy.production',
    input: { service: 'payments-api', ref: 'a1b2c3d', env: 'production' },
    summary: 'Deploy payments-api@a1b2c3d to production',
  })

  await action.awaitingApproval()

  const decision = await ctx.requestApproval({
    title: 'Deploy payments-api to production',
    summary:
      'Deploys a1b2c3d (hotfix: retry idempotency on charge capture) to production. ' +
      'Affects 3 pods, rolling. Estimated 90s of mixed-version traffic.',
    risk: 'high',
    actionId: action.id,
    grant: { resource: 'action:deploy.production', action: 'invoke', ttl_seconds: 600 },
  })

  if (!decision.approved) {
    await action.deny(decision.reason ?? 'Denied by a human.')
    await ctx.say(`Understood, standing down. ${decision.reason ?? ''}`.trim())
    return
  }

  await action.running()
  await new Promise((r) => setTimeout(r, 1500)) // pretend to deploy
  await action.succeed('Rolled out to 3/3 pods. Health checks green. 0 errors in 60s.')
  await ctx.say('Deployed and healthy. Rolling back is one word away if you need it.')
})

console.log('[Deploy Bot] waiting to be addressed')
