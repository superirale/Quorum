/**
 * The deploy agent, long-running, against a real relay.
 *
 * `demo.ts` runs the same code over an in-process relay and is the faster way
 * to see it work. This one exists because the two halves of M4 are enforced in
 * different places and only a real socket exercises both: the SDK refuses to
 * act without a signed approval, and the Go relay separately refuses to *store*
 * an approval from someone who was never asked, or a transition to an action
 * somebody else proposed. Nothing in the in-process demo can tell you the relay
 * policies are wired up, because the fake relay has none.
 *
 *   pnpm --filter @quorum/protocol schemas
 *   cd apps/relay && make run                       # :3334
 *
 *   export QUORUM_AGENT_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
 *   export QUORUM_APPROVERS=<hex pubkey>,<hex pubkey>
 *   pnpm --filter @quorum/deploy-agent start
 *
 * Then, from any Nostr client, post a kind 11 into the group with a
 * `["p", "<the agent's pubkey>", "", "to"]` tag and the words "deploy api 1.4.2
 * to production with 3 replicas". The agent will propose, publish an
 * `approval_request` naming your pubkey, and wait. Answer it with a kind 8103
 * `e`-tagged at the request — `@quorum/sdk`'s `approvalResponse()` builds one —
 * and the deploy runs.
 *
 * Two knobs worth knowing about:
 *
 *   QUORUM_TRUSTED_ISSUERS   whose grants this deploy tool honours. Defaults to
 *                            the approvers, which is convenient and is not the
 *                            same claim: being asked to consent and being
 *                            allowed to delegate authority are different
 *                            powers, and a real deployment should set them
 *                            apart deliberately.
 *   QUORUM_ON_BEHALF_OF      a 38106 coordinate to run under. Whatever it says,
 *                            it can only narrow what the agent may already do.
 *
 * The agent will refuse every deploy until somebody the tool trusts has issued
 * it a grant of `action:deploy` scoped to the environment. That is the intended
 * first-run experience: an agent with a key and no capability can talk, and can
 * do nothing.
 */

import { Grants, LocalSigner } from '@quorum/sdk'
import { FileStore } from '@quorum/sdk/node'
import { createDeployAgent } from './agent.ts'
import { Deploys, RESOURCE } from './deploy.ts'

const relay = process.env.QUORUM_RELAY ?? 'ws://localhost:3334'
const group = process.env.QUORUM_GROUP ?? 'payments'
const stateDir = process.env.QUORUM_STATE_DIR ?? './state'

const signer = LocalSigner.fromEnv('QUORUM_AGENT_KEY')
const approvers = keys('QUORUM_APPROVERS')
if (!approvers.length) {
  console.error(
    'set QUORUM_APPROVERS to a comma-separated list of hex pubkeys.\n' +
      'An agent with no approvers would propose actions nobody can answer, and\n' +
      'defaulting it to "anyone" is the bug this whole example is about.',
  )
  process.exit(2)
}

// Configuration, never data — see the note in deploy.ts. Defaulting to the
// approvers is a convenience for a single-operator run and is called out in
// the log so it is a choice somebody made rather than one nobody noticed.
const trustedIssuers = keys('QUORUM_TRUSTED_ISSUERS')
if (!trustedIssuers.length) {
  console.warn(`⚠ QUORUM_TRUSTED_ISSUERS unset — trusting the approvers to also issue grants`)
}

const deploys = new Deploys({ trustedIssuers: trustedIssuers.length ? trustedIssuers : approvers })

const agent = createDeployAgent({
  relay,
  signer,
  group,
  deploys,
  approvers,
  // Durable. The approval wait can outlive the process: a human asked at 18:00
  // may answer at 09:00, and a memory store would mean the agent came back with
  // no idea it had ever asked.
  store: FileStore.in(stateDir, `deploy-${signer.publicKey.slice(0, 8)}`),
  ...(process.env.QUORUM_ON_BEHALF_OF ? { onBehalfOf: process.env.QUORUM_ON_BEHALF_OF } : {}),
  ...(process.env.QUORUM_APPROVAL_TIMEOUT
    ? { expiresInSeconds: Number(process.env.QUORUM_APPROVAL_TIMEOUT) }
    : {}),
  log: console,
})

await agent.start()
console.log(`deploy agent ${signer.npub} listening on ${relay} in #${group}`)
console.log(`approvers: ${approvers.map((k) => k.slice(0, 8)).join(', ')}`)

// What it can actually do right now, said out loud at startup. An agent that
// discovers it holds no capability only at the moment it tries to use one is an
// agent that wasted a human's approval to find out.
await announceCapabilities()

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.once(signal, () => {
    void agent.stop().then(() => process.exit(0))
  })
}

async function announceCapabilities(): Promise<void> {
  const held = await new Grants({ client: agent.client, group }).held(signer.publicKey)
  if (!held.length) {
    console.log(
      `no grants of ${RESOURCE} to this pubkey yet — it will propose, ask, and then refuse.\n` +
        'Issue one with Grants#issue from a pubkey in QUORUM_TRUSTED_ISSUERS.',
    )
    return
  }
  console.log(`holding ${held.length} grant(s)/delegation(s); the resource decides which apply`)
}

/** A comma-separated list of hex pubkeys from the environment. */
function keys(name: string): string[] {
  return (process.env[name] ?? '')
    .split(',')
    .map((k) => k.trim())
    .filter(Boolean)
}
