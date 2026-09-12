/**
 * The M4 claims, as tests.
 *
 *   1. nothing consequential happens without a signed yes from someone who was
 *      asked
 *   2. the yes is bound to an exact payload, and an edit re-opens the question
 *   3. the loop survives the agent being killed while it waits
 *
 * Each has a negative control: an approval from a stranger, a response whose
 * digest does not match what it claims to approve, two approvers who signed
 * different payloads. A mechanism that is never observed failing has not been
 * shown to be load-bearing.
 */

import assert from 'node:assert/strict'
import { after, describe, it } from 'node:test'
import {
  ActionBody,
  Kinds,
  digest,
  refTo,
  tagValue,
  threadRef,
  type NostrEvent,
} from '@quorum/protocol'
import { settle, waitFor, waitForCount } from '@quorum/test-kit'
import {
  LocalSigner,
  MemoryStore,
  approvalResponse,
  createAgent,
  type ActResult,
  type Store,
} from '../src/index.ts'
import { Actor, assertAllValid, harness, type Harness } from './harness.ts'

const INPUT = { service: 'api', version: '1.4.2', replicas: 3 }
const EDITED = { service: 'api', version: '1.4.2', replicas: 1 }

/** Quiet: these tests deliberately provoke warnings the runtime should log. */
const quiet = { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} }

interface WorldOptions {
  signer?: LocalSigner
  store?: Store
  /** Defaults to Ada alone. */
  approvers?: (people: { ada: string; bob: string }) => string[]
  required?: number
  expiresInSeconds?: number
  /** Start the agent and wait for the request. Off for the restart test. */
  start?: boolean
}

interface World {
  h: Harness
  ada: Actor
  bob: Actor
  mallory: Actor
  agentKey: LocalSigner
  store: Store
  /** Inputs the effect actually executed, in order. */
  ran: unknown[]
  results: ActResult<string>[]
  request(): NostrEvent
  actions(status: string): NostrEvent[]
  start(): Promise<void>
  stop(): Promise<void>
  approve(who: Actor, options?: { modifiedInput?: unknown }): Promise<NostrEvent>
  deny(who: Actor, reason: string): Promise<NostrEvent>
}

async function world(options: WorldOptions = {}): Promise<World> {
  const h = await harness()
  const ada = await Actor.create(h.relay.url, h.group)
  const bob = await Actor.create(h.relay.url, h.group)
  const mallory = await Actor.create(h.relay.url, h.group)
  h.cleanup(() => {
    ada.close()
    bob.close()
    mallory.close()
  })

  const agentKey = options.signer ?? LocalSigner.generate()
  const store = options.store ?? new MemoryStore()
  const ran: unknown[] = []
  const results: ActResult<string>[] = []
  const approvers = options.approvers?.({ ada: ada.pubkey, bob: bob.pubkey }) ?? [ada.pubkey]

  let agent = build()
  function build() {
    const created = createAgent({
      relay: h.relay.url,
      signer: agentKey,
      group: h.group,
      store,
      leases: false,
      log: quiet,
    })
    created.on(async (_event, ctx) => {
      results.push(
        await ctx.act({
          name: 'deploy.production',
          summary: 'deploy api 1.4.2 to production',
          input: INPUT,
          approvers,
          risk: 'high',
          ...(options.required !== undefined ? { required: options.required } : {}),
          ...(options.expiresInSeconds !== undefined
            ? { expiresInSeconds: options.expiresInSeconds }
            : {}),
          run: (input) => {
            ran.push(input)
            return 'deployed'
          },
        }),
      )
    })
    return created
  }

  const request = () => {
    const [first] = h.relay.storedOfKind(Kinds.ApprovalRequest)
    assert.ok(first, 'no approval request was published')
    return first
  }

  const respond = (who: Actor, decision: 'approved' | 'denied', extra: Record<string, unknown>) =>
    who.publish(approvalResponse({ request: request(), decision, ...extra }))

  const self: World = {
    h,
    ada,
    bob,
    mallory,
    agentKey,
    store,
    ran,
    results,
    request,
    actions: (status) =>
      h.relay
        .storedOfKind(Kinds.Action)
        .filter((e) => ActionBody.safeParse(JSON.parse(e.content)).data?.status === status),
    async start() {
      agent = build()
      await agent.start()
    },
    stop: () => agent.stop(),
    approve: (who, extra = {}) => respond(who, 'approved', extra),
    deny: (who, reason) => respond(who, 'denied', { reason }),
  }

  h.cleanup(() => agent.stop())

  if (options.start !== false) {
    await agent.start()
    await ada.thread('deploy', 'please ship 1.4.2', [agentKey.publicKey])
    await waitForCount(() => h.relay.storedOfKind(Kinds.ApprovalRequest), 1, {
      describe: 'the approval request',
    })
  }

  return self
}

describe('the approval gate', () => {
  it('waits for a signed yes, then runs exactly what was approved', async () => {
    const w = await world()
    after(() => w.h.finish())

    // The request is out and the action is parked. Nothing has been deployed.
    await settle()
    assert.deepEqual(w.ran, [], 'an agent must not act before it is answered')
    assert.equal(w.actions('awaiting_approval').length, 1)

    const request = w.request()
    assert.equal(
      tagValue(request.tags, 'action'),
      w.actions('proposed')[0]!.id,
      'the request must name the action it gates',
    )
    assert.equal(
      JSON.parse(request.content).input_digest,
      digest(INPUT),
      'the request binds to a digest of the exact arguments',
    )

    await w.approve(w.ada)
    await waitFor(() => w.results.length === 1, { describe: 'the action to finish' })

    assert.deepEqual(w.ran[0], INPUT)
    assert.equal(w.results[0]?.status, 'succeeded')
    assert.equal(w.actions('succeeded').length, 1)
    assert.equal(
      JSON.parse(w.actions('running')[0]!.content).input_digest,
      digest(INPUT),
      'the running event names the digest that executed',
    )
    assertAllValid(w.h.relay.received)
  })

  it('ignores an approval from someone who was never asked', async () => {
    const w = await world()
    after(() => w.h.finish())

    // Structurally perfect: right kind, right parent, right digest, real
    // signature. The only thing wrong with it is who signed.
    await w.approve(w.mallory)
    await settle()

    assert.deepEqual(w.ran, [], 'only the addressed approvers can authorise anything')

    await w.approve(w.ada)
    await waitFor(() => w.results.length === 1, { describe: 'the action to finish' })
    assert.equal(w.results[0]?.status, 'succeeded')
  })

  it('does not read the answer as a new instruction', async () => {
    // A response is `to`-addressed back to the agent that asked, which is the
    // one piece of addressing in the protocol that points at a handler already
    // waiting for it. Delivering it to the handler as well starts a second copy
    // of the same work — with its own approval request, asked of the same human,
    // forever. See the note on `WORK_KINDS`.
    const w = await world()
    after(() => w.h.finish())

    await w.approve(w.ada)
    await waitFor(() => w.results.length === 1, { describe: 'the action to finish' })
    await settle()

    assert.deepEqual(w.ran, [INPUT], 'the effect ran once')
    assert.equal(w.actions('proposed').length, 1, 'and the answer opened no second action')
    assert.equal(w.h.relay.storedOfKind(Kinds.ApprovalRequest).length, 1)
  })

  it('stops on a denial and records it as a denied action', async () => {
    const w = await world()
    after(() => w.h.finish())

    await w.deny(w.ada, 'not during the freeze')
    await waitFor(() => w.results.length === 1, { describe: 'the decision' })

    assert.deepEqual(w.ran, [])
    assert.equal(w.results[0]?.status, 'denied')
    assert.equal(
      (w.results[0] as { reason: string }).reason,
      'not during the freeze',
      'the human\'s words, not a generic refusal',
    )
    assert.equal(w.actions('denied').length, 1)
    assert.equal(w.actions('running').length, 0)
    assertAllValid(w.h.relay.received)
  })
})

describe('binding to the payload', () => {
  it('runs the human\'s edit, and says so in the chain', async () => {
    const w = await world()
    after(() => w.h.finish())

    await w.approve(w.ada, { modifiedInput: EDITED })
    await waitFor(() => w.results.length === 1, { describe: 'the action to finish' })

    assert.deepEqual(w.ran[0], EDITED, 'the approved payload is the one that runs')
    const running = w.actions('running')[0]!
    assert.equal(JSON.parse(running.content).input_digest, digest(EDITED))
    assert.notEqual(
      JSON.parse(running.content).input_digest,
      JSON.parse(w.actions('proposed')[0]!.content).input_digest,
      'the edit must be visible as a digest change, not applied silently',
    )
    assertAllValid(w.h.relay.received)
  })

  it('refuses an edit whose digest does not match its own payload', async () => {
    const w = await world()
    after(() => w.h.finish())

    const request = w.request()
    // The dangerous shape: the log would show `replicas: 1` approved while the
    // agent was handed a digest covering something else. Caught by rehashing
    // the payload rather than trusting the field next to it.
    await w.ada.publish({
      kind: Kinds.ApprovalResponse,
      thread: threadRef(request)!,
      parent: refTo(request),
      action: tagValue(request.tags, 'action')!,
      to: [w.agentKey.publicKey],
      body: {
        decision: 'approved',
        input_digest: digest(INPUT),
        modified_input: EDITED,
        modified_input_digest: digest({ service: 'api', version: '9.9.9', replicas: 99 }),
      },
    })
    await settle()

    assert.deepEqual(w.ran, [], 'a response that lies about its own digest counts for nothing')

    await w.approve(w.ada)
    await waitFor(() => w.results.length === 1, { describe: 'the honest approval' })
    assert.deepEqual(w.ran[0], INPUT)
  })

  it('refuses a response that echoes the wrong input digest', async () => {
    const w = await world()
    after(() => w.h.finish())

    const request = w.request()
    await w.ada.publish({
      kind: Kinds.ApprovalResponse,
      thread: threadRef(request)!,
      parent: refTo(request),
      action: tagValue(request.tags, 'action')!,
      to: [w.agentKey.publicKey],
      body: { decision: 'approved', input_digest: digest(EDITED) },
    })
    await settle()

    assert.deepEqual(w.ran, [], 'an approval of a different payload is not an approval of this one')
  })
})

describe('more than one approver', () => {
  it('needs the quorum it asked for', async () => {
    const w = await world({ approvers: (p) => [p.ada, p.bob], required: 2 })
    after(() => w.h.finish())

    await w.approve(w.ada)
    await settle()
    assert.deepEqual(w.ran, [], 'one of two is not two')

    await w.approve(w.bob)
    await waitFor(() => w.results.length === 1, { describe: 'the action to finish' })
    assert.equal(w.results[0]?.status, 'succeeded')
  })

  it('lets one denial stop an action two people were asked about', async () => {
    const w = await world({ approvers: (p) => [p.ada, p.bob], required: 2 })
    after(() => w.h.finish())

    await w.approve(w.ada)
    await w.deny(w.bob, 'the version is wrong')
    await waitFor(() => w.results.length === 1, { describe: 'the decision' })

    assert.equal(w.results[0]?.status, 'denied')
    assert.deepEqual(w.ran, [])
  })

  it('cancels when approvers sign different payloads', async () => {
    const w = await world({ approvers: (p) => [p.ada, p.bob], required: 2 })
    after(() => w.h.finish())

    // Ada approves what was proposed; Bob approves something else. Counting
    // that as a quorum would mean acting on a payload only one of them saw.
    await w.approve(w.ada)
    await w.approve(w.bob, { modifiedInput: EDITED })
    await waitFor(() => w.results.length === 1, { describe: 'the decision' })

    assert.equal(w.results[0]?.status, 'cancelled')
    assert.deepEqual(w.ran, [])
    assert.equal(w.actions('cancelled').length, 1)
    assertAllValid(w.h.relay.received)
  })
})

describe('surviving the wait', () => {
  it('finds an approval that arrived while the agent was dead', async () => {
    // The M0 scenario, and the reason `act()` queries before it subscribes: a
    // human answering an hour later is the normal case, and agents get
    // restarted in that hour.
    const store = new MemoryStore()
    const signer = LocalSigner.generate()
    const w = await world({ store, signer })
    after(() => w.h.finish())

    const request = w.request()
    const proposedId = w.actions('proposed')[0]!.id

    await w.stop()
    await settle()

    // Nobody is listening. The subscription is gone.
    await w.approve(w.ada)
    await settle()
    assert.deepEqual(w.ran, [], 'no agent, no deploy')

    await w.start()
    await waitFor(() => w.results.length === 1, {
      describe: 'the replayed handler to catch up',
    })

    assert.equal(w.results.at(-1)?.status, 'succeeded')
    assert.deepEqual(w.ran, [INPUT], 'the effect ran once, not once per life')
    assert.equal(
      w.actions('proposed').length,
      1,
      'the replay must reuse its action id, not open a second action',
    )
    assert.equal(w.actions('proposed')[0]!.id, proposedId)
    assert.equal(
      w.h.relay.storedOfKind(Kinds.ApprovalRequest).length,
      1,
      'and must not ask the human a second time',
    )
    assert.equal(w.request().id, request.id)
    assert.equal(w.actions('succeeded').length, 1)
    assertAllValid(w.h.relay.received)
  })

  it('cancels when nobody answers before the request expires', async () => {
    const w = await world({ expiresInSeconds: 1 })
    after(() => w.h.finish())

    await waitFor(() => w.results.length === 1, {
      describe: 'the request to expire',
      timeoutMs: 5000,
    })

    assert.equal(w.results[0]?.status, 'cancelled')
    assert.deepEqual(w.ran, [])
    assert.equal(w.actions('cancelled').length, 1)
  })
})
