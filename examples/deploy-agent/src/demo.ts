/**
 * The M4 demo: the M0 loop for real, and then the thing M0 could not do.
 *
 * `pnpm --filter @quorum/deploy-agent demo` — no infrastructure, no keys, no
 * config. An agent picks up a task, hits a gate, a human signs, the agent
 * finishes. Then five ways of getting a deploy you did not agree to, each one
 * refused, each refusal traceable to one mechanism.
 *
 *   1. the loop        ask → propose → sign → deploy, and the signed chain
 *   2. consent         an approval from someone who was never asked
 *   3. the edit        a human changes the payload before saying yes
 *   4. capability      a human's yes is not authority the human does not have
 *   5. delegation      on-behalf-of narrows; it never widens
 *
 * Act one writes `transcript.json`. `pnpm --filter @quorum/deploy-agent verify`
 * reads it back with no relay, no keys and no trust in this process, and tells
 * you who approved what. That last step is the milestone: everything above it
 * is a product feature, and that is a cryptographic claim.
 *
 * Each act gets its own relay and its own workspace, because an agent backfills
 * its channel on startup — share one and act two answers act one's questions.
 */

import { writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { Kinds, address, digest, type NostrEvent } from '@quorum/protocol'
import {
  Counters,
  Grants,
  LocalSigner,
  MemoryStore,
  Publisher,
  RelayClient,
  approvalResponse,
  delegation,
  verifyActionChains,
  type Agent,
} from '@quorum/sdk'
import { FakeRelay, settle, waitForCount } from '@quorum/test-kit'
import { createDeployAgent } from './agent.ts'
import { Deploys, RESOURCE } from './deploy.ts'

const GROUP = 'payments'
const TRANSCRIPT = join(import.meta.dirname, '..', 'transcript.json')
const quiet = { debug() {}, info() {}, warn() {}, error() {} }

const agentKey = LocalSigner.generate()
console.log(`agent ${agentKey.npub}`)

// --- the world ---------------------------------------------------------------

interface Person {
  name: string
  pubkey: string
  client: RelayClient
  publisher: Publisher
  grants: Grants
}

async function world(options: { approvers?: (p: Record<string, Person>) => string[] } = {}) {
  const relay = await FakeRelay.start()
  const people: Record<string, Person> = {}

  const join = async (name: string): Promise<Person> => {
    const key = LocalSigner.generate()
    const client = new RelayClient({ url: relay.url, signer: key, reconnect: false, log: quiet })
    await client.connect()
    const publisher = new Publisher({
      client,
      signer: key,
      pubkey: key.publicKey,
      group: GROUP,
      counters: await Counters.load(new MemoryStore(), key.publicKey),
    })
    const person: Person = {
      name,
      pubkey: key.publicKey,
      client,
      publisher,
      grants: new Grants({ client, group: GROUP, publisher }),
    }
    people[name] = person
    return person
  }

  // Ada owns the workspace, so she is what the deploy tool is configured to
  // trust. Bob is an engineer with no such standing, and Mallory is a member of
  // the workspace with no standing at all — which, as act two shows, is exactly
  // as much as a signature by itself buys you.
  const ada = await join('ada')
  const bob = await join('bob')
  const mallory = await join('mallory')

  const deploys = new Deploys({ trustedIssuers: [ada.pubkey] })
  const agents: Agent[] = []

  return {
    relay,
    ada,
    bob,
    mallory,
    deploys,
    join,

    agent(extra: { onBehalfOf?: string } = {}): Agent {
      const agent = createDeployAgent({
        relay: relay.url,
        signer: agentKey,
        group: GROUP,
        deploys,
        approvers: options.approvers?.(people) ?? [ada.pubkey],
        expiresInSeconds: 30,
        log: quiet,
        ...extra,
      })
      agents.push(agent)
      return agent
    },

    /** Ada (or anyone) opens a thread asking the agent for something. */
    ask(who: Person, text: string): Promise<NostrEvent> {
      return who.publisher.publish({
        kind: Kinds.Thread,
        text,
        to: [agentKey.publicKey],
        tags: [['title', 'deploy']],
      })
    },

    /** The request the agent is waiting on. */
    async pendingRequest(): Promise<NostrEvent> {
      const [request] = await waitForCount(() => relay.storedOfKind(Kinds.ApprovalRequest), 1, {
        describe: 'the agent to ask for approval',
        timeoutMs: 5000,
      })
      return request!
    },

    /** The chain, as an auditor would read it. */
    chains() {
      return verifyActionChains(relay.stored)
    },

    async close() {
      for (const agent of agents) await agent.stop()
      for (const person of Object.values(people)) person.client.close()
      await relay.stop()
    },
  }
}

/** The standing grant Ada gives the agent: production deploys, nothing else. */
async function grantProduction(w: Awaited<ReturnType<typeof world>>, options: { maxUses?: number } = {}) {
  return w.ada.grants.issue({
    grantee: agentKey.publicKey,
    resource: RESOURCE,
    actions: ['invoke'],
    scope: { env: 'production' },
    ...(options.maxUses !== undefined ? { maxUses: options.maxUses } : {}),
  })
}

// --- 1. the loop -------------------------------------------------------------

{
  act('1. the loop — ask, propose, sign, deploy')
  const w = await world()
  await grantProduction(w)
  say('ada', `grants the agent ${RESOURCE} scoped to env=production`)

  await w.agent().start()
  await w.ask(w.ada, 'deploy api 1.4.2 to production with 3 replicas')
  say('ada', 'asks for a deploy in a thread addressed to the agent')

  const request = await w.pendingRequest()
  report('the agent stops', body(request).title, 'it proposed, then asked — it did not deploy')

  await w.ada.publisher.publish(approvalResponse({ request, decision: 'approved' }))
  say('ada', 'signs an approval naming the digest of exactly those arguments')
  await settle(500)

  report('deployed', w.deploys.deployed.map((d) => d.ref), 'the effect happened once')

  const [chain] = w.chains()
  report('the chain', {
    status: chain!.status,
    approvedBy: chain!.approvals.filter((a) => a.counted).map((a) => short(a.pubkey)),
    digest: short(chain!.executedDigest ?? ''),
  }, 'this is the audit trail; there is no other one')

  await writeFile(TRANSCRIPT, JSON.stringify(w.relay.stored, null, 2))
  console.log(
    `  \x1b[2m  wrote ${w.relay.stored.length} events to transcript.json — ` +
      `run \`pnpm --filter @quorum/deploy-agent verify\`\x1b[0m`,
  )
  await w.close()
}

// --- 2. consent --------------------------------------------------------------

{
  act('2. consent — a signature is not authority; being asked is')
  const w = await world()
  await grantProduction(w)
  await w.agent().start()
  await w.ask(w.ada, 'deploy api 1.4.2 to production')

  const request = await w.pendingRequest()
  await w.mallory.publisher.publish(approvalResponse({ request, decision: 'approved' }))
  say('mallory', 'a member of the workspace who was never asked, signs an approval')
  await settle(400)
  report('deployed', w.deploys.deployed.length, 'her signature is perfectly valid and counts for nothing')

  await w.ada.publisher.publish(
    approvalResponse({ request, decision: 'denied', reason: 'not on a Friday' }),
  )
  say('ada', 'who was asked, says no')
  await settle(400)

  const [chain] = w.chains()
  report('deployed', w.deploys.deployed.length, 'and the refusal is in the log, signed')
  report('the chain', {
    status: chain!.status,
    responses: chain!.approvals.map((a) => `${short(a.pubkey)} ${a.decision} (counted: ${a.counted})`),
  }, 'mallory’s attempt is recorded rather than dropped — an auditor wants to see it')
  await w.close()
}

// --- 3. the edit -------------------------------------------------------------

{
  act('3. the edit — a human changes the payload, and the log shows both')
  const w = await world()
  await grantProduction(w)
  await w.agent().start()
  await w.ask(w.ada, 'deploy api 1.4.2 to production with 30 replicas')
  say('ada', 'asks for thirty replicas, which is a typo')

  const request = await w.pendingRequest()
  await w.ada.publisher.publish(
    approvalResponse({
      request,
      decision: 'approved',
      modifiedInput: { service: 'api', version: '1.4.2', env: 'production', replicas: 3 },
    }),
  )
  say('ada', 'approves three instead, and signs the digest of the edit')
  await settle(500)

  const [chain] = w.chains()
  report('deployed', w.deploys.deployed.map((d) => d.input.replicas), 'the agent ran the edit')
  report('the chain', {
    proposed: short(digest(chain!.input)),
    executed: short(chain!.executedDigest ?? ''),
    modified: chain!.modified,
  }, 'two digests, both signed: nobody has to take either party’s word for which ran')
  await w.close()
}

// --- 4. capability -----------------------------------------------------------

{
  act('4. capability — a yes cannot grant authority the resource never gave')
  const w = await world()
  const grant = await grantProduction(w)
  say('ada', 'grants, then thinks better of it')
  await w.ada.grants.revoke(
    {
      grantee: agentKey.publicKey,
      resource: RESOURCE,
      actions: ['invoke'],
      scope: { env: 'production' },
    },
    'rotating the deploy key',
    grant,
  )
  say('ada', 'revokes the grant — a signed event, not a row in anyone’s database')

  await w.agent().start()
  await w.ask(w.ada, 'deploy api 1.4.2 to production')
  const request = await w.pendingRequest()
  await w.ada.publisher.publish(approvalResponse({ request, decision: 'approved' }))
  say('ada', 'approves anyway — she is the one who was asked, after all')
  await settle(500)

  const [chain] = w.chains()
  report('deployed', w.deploys.deployed.length, 'the resource checked the grant, not the approval')
  report('the chain', { status: chain!.status }, 'and the refusal is recorded as a signed failure')
  say('why', 'consent and capability are different questions; both are asked here')
  await w.close()
}

// --- 5. delegation -----------------------------------------------------------

{
  act('5. delegation — on-behalf-of narrows, and can only narrow')
  const w = await world({ approvers: (p) => [p.bob!.pubkey] })

  await w.ada.grants.issue({
    grantee: agentKey.publicKey,
    resource: RESOURCE,
    actions: ['invoke'],
  })
  say('ada', `grants the agent ${RESOURCE} with no scope at all — any environment`)

  const delegated = await w.ada.publisher.publish(
    delegation({
      delegate: agentKey.publicKey,
      id: 'bob-oncall',
      resources: [RESOURCE],
      scope: { env: 'staging' },
    }),
  )
  const coordinate = address(Kinds.Delegation, w.ada.pubkey, 'bob-oncall')
  say('ada', 'delegates to the agent, but only for staging')

  await w.agent({ onBehalfOf: coordinate }).start()
  await w.ask(w.bob, 'deploy api 1.4.2 to production')
  const first = await w.pendingRequest()
  await w.bob.publisher.publish(approvalResponse({ request: first, decision: 'approved' }))
  say('bob', 'approves a production deploy')
  await settle(500)
  report(
    'deployed',
    w.deploys.deployed.length,
    'the agent’s own grant covers production; the delegation does not, and the intersection wins',
  )

  await w.ask(w.bob, 'deploy api 1.4.2 to staging')
  const [, second] = await waitForCount(() => w.relay.storedOfKind(Kinds.ApprovalRequest), 2, {
    describe: 'the second request',
    timeoutMs: 5000,
  })
  await w.bob.publisher.publish(approvalResponse({ request: second!, decision: 'approved' }))
  say('bob', 'approves the same deploy to staging')
  await settle(500)
  report(
    'deployed',
    w.deploys.deployed.map((d) => `${d.ref} → ${d.input.env}`),
    'inside the delegation, it goes through',
  )
  report('the delegation', short(delegated.id), 'revoke it and both stop working, with one signed event')
  await w.close()
}

console.log(
  '\n\x1b[1mnow verify it without any of this\x1b[0m\n' +
    '  pnpm --filter @quorum/deploy-agent verify\n' +
    '  \x1b[2mno relay, no keys, no server — just the events and a signature check\x1b[0m\n',
)

// --- narration ---------------------------------------------------------------

function act(title: string): void {
  console.log(`\n\x1b[1m${title}\x1b[0m`)
}

function say(who: string, what: string): void {
  console.log(`  ${who.padEnd(10)} ${what}`)
}

function report(label: string, value: unknown, note: string): void {
  console.log(`  \x1b[2m→ ${label}:\x1b[0m ${JSON.stringify(value)}\n  \x1b[2m  ${note}\x1b[0m`)
}

function body(event: NostrEvent): { title?: string } {
  return JSON.parse(event.content)
}

function short(hex: string): string {
  return hex.length > 12 ? `${hex.slice(0, 8)}…` : hex
}
