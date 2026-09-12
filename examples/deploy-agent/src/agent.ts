/**
 * The agent.
 *
 * Thirty lines of handler, and everything interesting about it is what it does
 * *not* do. It does not decide whether it is allowed to deploy: it proposes,
 * and `ctx.act()` publishes a signed request, waits for a signed answer and
 * only then calls the effect. It does not tell the deploy tool that a human
 * said yes: it hands over the events and lets the tool re-derive that for
 * itself. It holds no token and has no session — its identity is a keypair, so
 * there is nothing for an operator to issue and nothing to leak.
 *
 * The one piece of real work in here is gathering evidence: before running the
 * effect, the agent fetches the thread's events and the grants addressed to it
 * and passes them along. That is deliberately the agent's job rather than the
 * tool's, because the tool must work when handed a JSON file and no relay.
 */

import { type EventRef, type NostrEvent } from '@quorum/protocol'
import {
  Grants,
  createAgent,
  type ActResult,
  type Agent,
  type Logger,
  type RelayClient,
  type Signer,
  type Store,
} from '@quorum/sdk'
import { RESOURCE, type DeployInput, type Deploys } from './deploy.ts'

export interface DeployAgentOptions {
  relay: string | RelayClient
  signer: Signer
  group: string
  /** The resource. A separate object on purpose; in production, a separate host. */
  deploys: Deploys
  /** Who must sign off. Pubkeys, because that is what a signature proves. */
  approvers: string[]
  /** Coordinate of a 38106 the agent is acting under, if it has one. */
  onBehalfOf?: string
  store?: Store
  log?: Logger
  /** Seconds a request stays answerable. `Infinity` waits forever. */
  expiresInSeconds?: number
}

const DEFAULTS = { service: 'api', version: 'latest', env: 'production', replicas: 3 }

export function createDeployAgent(options: DeployAgentOptions): Agent {
  const agent = createAgent({
    relay: options.relay,
    signer: options.signer,
    group: options.group,
    leases: false,
    ...(options.store ? { store: options.store } : {}),
    ...(options.log ? { log: options.log } : {}),
  })

  agent.on(async (event, ctx) => {
    const input = parseRequest(event.content)
    if (!input) {
      await ctx.say(
        'I deploy things. Try: "deploy api 1.4.2 to production with 3 replicas".',
      )
      return
    }

    const result = await ctx.act({
      name: 'deploy',
      title: `Deploy ${input.service} ${input.version}`,
      summary: `deploy ${input.service} ${input.version} to ${input.env} on ${input.replicas} replicas`,
      input,
      approvers: options.approvers,
      risk: input.env === 'production' ? 'high' : 'low',
      ...(options.onBehalfOf ? { onBehalfOf: options.onBehalfOf } : {}),
      ...(options.expiresInSeconds !== undefined
        ? { expiresInSeconds: options.expiresInSeconds }
        : {}),
      describe: (ref: string) => `deployed as ${ref}`,

      // `approved` is the human's input, which may not be the one proposed: if
      // an approver edited the payload, this is the edit. Using the parameter
      // rather than the closed-over `input` is the difference between running
      // what was agreed and running what was asked for.
      run: async (approved, run) => {
        const evidence = await gather(ctx.client, ctx.group, ctx.me, ctx.thread)
        const outcome = options.deploys.attempt({
          agent: ctx.me,
          input: approved,
          actionId: run.actionId,
          evidence,
          ...(options.onBehalfOf ? { onBehalfOf: options.onBehalfOf } : {}),
        })
        if (!outcome.ok) {
          // Thrown, so the chain records a signed `failed` with the reason. A
          // refusal that only appeared in the agent's stderr would be a refusal
          // nobody outside the agent's host could ever see.
          throw new Error(`${RESOURCE} refused: ${outcome.refused} — ${outcome.detail.join('; ')}`)
        }
        return outcome.ref
      },
    })

    await ctx.say(describe(result), { label: `outcome:${result.actionId.slice(0, 16)}` })
  })

  return agent
}

/**
 * Everything the resource might need, fetched from the relay.
 *
 * Two queries, both on indexed single-letter tags. `#action` would be the
 * obvious filter and is not available: multi-character tags are deliberately
 * unindexed under NIP-01, which is exactly why the action id lives in one. The
 * thread is the indexable superset, and the auditor filters it down itself.
 */
async function gather(
  client: RelayClient,
  group: string,
  me: string,
  thread: EventRef | undefined,
): Promise<NostrEvent[]> {
  const chain = thread
    ? await client.query([{ '#E': [thread.id], '#h': [group] }, { ids: [thread.id] }])
    : []
  const credentials = await new Grants({ client, group }).held(me)
  return [...chain, ...credentials]
}

/** The one bit of prose-reading in the whole example, and it reads only its own reply. */
export function parseRequest(text: string): DeployInput | undefined {
  const match = /\bdeploy\s+(\S+)\s+(\S+)/i.exec(text)
  if (!match) return undefined

  const env = /\bto\s+(staging|production|prod)\b/i.exec(text)?.[1]?.toLowerCase()
  const replicas = /\b(\d+)\s+replicas?\b/i.exec(text)?.[1]

  return {
    service: match[1]!,
    version: match[2]!,
    env: env === 'prod' ? 'production' : (env ?? DEFAULTS.env),
    replicas: replicas ? Number(replicas) : DEFAULTS.replicas,
  }
}

function describe(result: ActResult<string>): string {
  switch (result.status) {
    case 'succeeded':
      return `done — ${result.output}`
    case 'denied':
      return `not deploying: ${result.reason}`
    case 'cancelled':
      return `dropping it: ${result.reason}`
    default:
      return `the deploy did not happen: ${result.error.message}`
  }
}
