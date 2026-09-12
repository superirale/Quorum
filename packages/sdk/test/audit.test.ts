/**
 * The claim this milestone rests on, checked the way someone else would check
 * it: from a pile of events, with no relay, no server, and no trust in whoever
 * handed them over.
 *
 * The first tests audit a chain the real runtime produced. The rest tamper with
 * that chain in every way that would let an agent do something nobody agreed
 * to, and require each one to be caught. A verifier that has never been
 * observed rejecting anything is a function that returns true.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import {
  ActionBody,
  Kinds,
  TagName,
  digest,
  refTo,
  tagValue,
  threadRef,
  type NostrEvent,
} from '@quorum/protocol'
import { waitFor, waitForCount } from '@quorum/test-kit'
import {
  LocalSigner,
  MemoryStore,
  approvalResponse,
  createAgent,
  verifyActionChain,
  verifyActionChains,
  type ActResult,
  type ActionChain,
} from '../src/index.ts'
import { Actor, Keyholder, harness } from './harness.ts'

const INPUT = { service: 'api', version: '1.4.2', replicas: 3 }
const EDITED = { service: 'api', version: '1.4.2', replicas: 1 }
const quiet = { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} }

interface Run {
  /** Everything the relay holds, which is all an auditor ever gets. */
  events: NostrEvent[]
  actionId: string
  agent: Keyholder
  ada: string
  chain(): ActionChain
  finish(): Promise<void>
}

/**
 * The whole loop, for real: a human asks, an agent proposes, the human signs,
 * the agent deploys. What comes back is the log a relay would have.
 */
async function deployed(options: { modifiedInput?: unknown } = {}): Promise<Run> {
  const h = await harness()
  const ada = await Actor.create(h.relay.url, h.group)
  const agentKey = LocalSigner.generate()

  const agent = createAgent({
    relay: h.relay.url,
    signer: agentKey,
    group: h.group,
    store: new MemoryStore(),
    leases: false,
    log: quiet,
  })

  const results: ActResult<string>[] = []
  agent.on(async (_event, ctx) => {
    results.push(
      await ctx.act({
        name: 'deploy.production',
        summary: 'deploy api 1.4.2 to production',
        input: INPUT,
        approvers: [ada.pubkey],
        risk: 'high',
        run: () => 'deployed',
      }),
    )
  })
  await agent.start()
  await ada.thread('deploy', 'please ship 1.4.2', [agentKey.publicKey])

  const [request] = await waitForCount(() => h.relay.storedOfKind(Kinds.ApprovalRequest), 1, {
    describe: 'the approval request',
  })
  await ada.publish(
    approvalResponse({
      request: request!,
      decision: 'approved',
      ...(options.modifiedInput !== undefined ? { modifiedInput: options.modifiedInput } : {}),
    }),
  )
  await waitFor(() => results.length === 1, { describe: 'the action to finish' })

  const events = [...h.relay.stored]
  const actionId = events.find(isStatus('proposed'))!.id

  return {
    events,
    actionId,
    agent: new Keyholder(h.group, agentKey),
    ada: ada.pubkey,
    chain() {
      const chains = verifyActionChains(events)
      assert.equal(chains.length, 1, 'the run produced exactly one action chain')
      return chains[0]!
    },
    async finish() {
      ada.close()
      await agent.stop()
      await h.finish()
    },
  }
}

// --- reading the log ---------------------------------------------------------

const body = (e: NostrEvent) => ActionBody.safeParse(JSON.parse(e.content)).data

const isStatus = (status: string) => (e: NostrEvent) =>
  e.kind === Kinds.Action && body(e)?.status === status

const find = (events: NostrEvent[], status: string) => events.find(isStatus(status))!

/** Everything except the events this predicate matches. */
const without = (events: NostrEvent[], drop: (e: NostrEvent) => boolean) => events.filter((e) => !drop(e))

/** Error codes only. Warnings are asserted explicitly where they matter. */
const codes = (chain: ActionChain) =>
  chain.issues.filter((i) => i.severity === 'error').map((i) => i.code)

/**
 * Warning codes.
 *
 * Worth its own helper because the difference between these two lists is the
 * substance of several tests below: an error says the party doing the work
 * misbehaved, a warning says somebody else published something and it was
 * disregarded. Anyone can produce the second, so only the first may make a
 * chain invalid.
 */
const warnings = (chain: ActionChain) =>
  chain.issues.filter((i) => i.severity === 'warning').map((i) => i.code)

/**
 * Sign a transition into a chain, offline.
 *
 * `after` is the event this one claims to follow, and giving the forgeries an
 * honest-looking parent is the point: an attacker who bothers at all will point
 * at the right place, so a test that pointed them somewhere implausible would
 * be catching sloppiness rather than the attack.
 */
function transition(
  who: Keyholder,
  run: Run,
  after: NostrEvent,
  fields: { status: string; input_digest?: string },
): Promise<NostrEvent> {
  return who.sign({
    kind: Kinds.Action,
    thread: threadRef(find(run.events, 'proposed'))!,
    parent: refTo(after),
    action: run.actionId,
    created_at: after.created_at,
    body: { name: 'deploy.production', summary: 'deploy api 1.4.2 to production', ...fields },
  })
}

describe('auditing a real run', () => {
  it('says who approved what', async (t) => {
    const run = await deployed()
    t.after(() => run.finish())

    const chain = run.chain()
    assert.equal(chain.ok, true, chain.issues.map((i) => i.message).join('; '))
    assert.deepEqual(chain.issues, [])
    assert.equal(chain.status, 'succeeded')
    assert.equal(chain.name, 'deploy.production')
    assert.equal(chain.actionId, run.actionId)
    assert.deepEqual(chain.input, INPUT)
    assert.equal(chain.executedDigest, digest(INPUT))
    assert.equal(chain.modified, false)

    // The sentence the whole milestone exists so that someone can say.
    assert.deepEqual(
      chain.approvals.map((a) => [a.pubkey, a.decision, a.counted]),
      [[run.ada, 'approved', true]],
    )
  })

  it("shows a human's edit as an edit, not as the proposal", async (t) => {
    const run = await deployed({ modifiedInput: EDITED })
    t.after(() => run.finish())

    const chain = run.chain()
    assert.equal(chain.ok, true, chain.issues.map((i) => i.message).join('; '))
    assert.deepEqual(chain.input, INPUT, 'the proposal is still there, verbatim')
    assert.equal(chain.executedDigest, digest(EDITED), 'and what ran is visibly something else')
    assert.equal(chain.modified, true)
  })

  it('needs no relay and no live process', async (t) => {
    const run = await deployed()
    t.after(() => run.finish())

    // Round-tripped through JSON, as if read off disk in another process next
    // year. Nothing in the verifier may depend on object identity or on the
    // events having come from anywhere in particular.
    const dump = JSON.parse(JSON.stringify(run.events)) as NostrEvent[]
    const chain = verifyActionChain(run.actionId, dump)

    assert.equal(chain.ok, true)
    assert.equal(chain.status, 'succeeded')
    assert.equal(chain.approvals[0]!.pubkey, run.ada)
  })
})

describe('tampering with a chain', () => {
  it('catches an input swapped underneath its signature', async (t) => {
    const run = await deployed()
    t.after(() => run.finish())

    // Three replicas become three hundred. The id is left stale on purpose:
    // recomputing it is free for anyone relaying events, so the signature is
    // the only thing that actually stops this — but the digest catches it too,
    // and both saying so is the point.
    const events = run.events.map((e) =>
      isStatus('proposed')(e) ? { ...e, content: e.content.replace('"replicas":3', '"replicas":300') } : e,
    )

    assert.deepEqual(codes(verifyActionChain(run.actionId, events)), [
      'bad_signature',
      'input_digest_mismatch',
    ])
  })

  it('will not let a stranger write the outcome of someone else’s action', async (t) => {
    // Mallory declares the deploy a success. The forgery is well-formed and
    // signed; only its author is wrong. It must not become the chain's outcome
    // — and it must not become an outcome at all, because nothing the proposer
    // signed says the work finished.
    const run = await deployed()
    t.after(() => run.finish())

    const forged = await transition(new Keyholder(), run, find(run.events, 'running'), {
      status: 'succeeded',
    })
    const chain = verifyActionChain(run.actionId, [...without(run.events, isStatus('succeeded')), forged])

    assert.equal(chain.status, 'running', 'the last thing the proposer actually signed')
    assert.deepEqual(warnings(chain), ['foreign_transition'])
  })

  it('will not let a stranger invalidate an honest chain', async (t) => {
    // The same forgery, this time *added* rather than swapped in. Nobody
    // removed anything; Mallory published one junk event into a deploy that
    // completed correctly.
    //
    // Getting this wrong is the expensive direction, and it is the direction a
    // careful implementation drifts toward: treat the forgery as an error and
    // any member of the workspace can veto any action, permanently, with one
    // event the proposer cannot retract. It is also not hypothetical — the
    // relay refuses these, but every event here is valid on a generic relay
    // that has never heard of Quorum, which is the whole point of Option A.
    const run = await deployed()
    t.after(() => run.finish())

    const forged = await transition(new Keyholder(), run, find(run.events, 'running'), {
      status: 'failed',
    })
    const chain = verifyActionChain(run.actionId, [...run.events, forged])

    assert.equal(chain.ok, true, codes(chain).join(', '))
    assert.equal(chain.status, 'succeeded')
    assert.deepEqual(warnings(chain), ['foreign_transition'])
    assert.ok(
      chain.events.some((e) => e.id === forged.id),
      'and it is still in the record — disregarded is not the same as deleted',
    )
  })

  it('will not let a stranger ask themselves for permission', async (t) => {
    // The reason a foreign `approval_request` cannot be a warning-and-ignore
    // the way a foreign transition is: a request names its own approvers. Count
    // Mallory's and she asks Mallory, answers herself, and the chain tallies as
    // approved by someone the agent never consulted.
    const run = await deployed()
    t.after(() => run.finish())

    const mallory = new Keyholder()
    const real = run.events.find((e) => e.kind === Kinds.ApprovalRequest)!
    const fake = await mallory.sign({
      kind: Kinds.ApprovalRequest,
      thread: threadRef(real)!,
      parent: refTo(find(run.events, 'awaiting_approval')),
      action: run.actionId,
      to: [mallory.pubkey],
      body: {
        title: 'Deploy api 1.4.2',
        summary: 'deploy api 1.4.2 to production',
        approvers: [mallory.pubkey],
        risk: 'high',
        input_digest: digest(INPUT),
      },
    })
    const selfApproval = await mallory.sign(approvalResponse({ request: fake, decision: 'approved' }))

    // Ada's real approval removed, so the only yes on offer is Mallory's own.
    const chain = verifyActionChain(run.actionId, [
      ...without(run.events, (e) => e.kind === Kinds.ApprovalResponse),
      fake,
      selfApproval,
    ])

    assert.deepEqual(codes(chain), ['unapproved_execution'])
    assert.deepEqual(
      chain.approvals.map((a) => [a.pubkey === mallory.pubkey, a.counted]),
      [[true, false]],
      'her yes is on the record, answering nothing, counting for nothing',
    )
    assert.ok(warnings(chain).includes('foreign_request'))
  })

  it('catches the agent running something other than what was approved', async (t) => {
    // The agent's own key, used honestly to ask and dishonestly to run. Nothing
    // outside the digests distinguishes these two events.
    const run = await deployed()
    t.after(() => run.finish())

    const swapped = await transition(run.agent, run, find(run.events, 'awaiting_approval'), {
      status: 'running',
      input_digest: digest(EDITED),
    })
    const chain = verifyActionChain(run.actionId, [
      ...without(run.events, (e) => isStatus('running')(e) || isStatus('succeeded')(e)),
      swapped,
    ])

    assert.deepEqual(codes(chain), ['executed_unapproved_input'])
    assert.equal(chain.approvals[0]!.counted, true, 'Ada really did approve — just not this')
  })

  it('catches an execution whose approval has been deleted', async (t) => {
    const run = await deployed()
    t.after(() => run.finish())

    const chain = verifyActionChain(
      run.actionId,
      without(run.events, (e) => e.kind === Kinds.ApprovalResponse),
    )

    assert.deepEqual(codes(chain), ['unapproved_execution'])
  })

  it('catches an approval from someone who was never asked', async (t) => {
    const run = await deployed()
    t.after(() => run.finish())

    const request = run.events.find((e) => e.kind === Kinds.ApprovalRequest)!
    const mallory = new Keyholder()
    const forged = await mallory.sign(approvalResponse({ request, decision: 'approved' }))
    const chain = verifyActionChain(run.actionId, [
      ...without(run.events, (e) => e.kind === Kinds.ApprovalResponse),
      forged,
    ])

    assert.deepEqual(codes(chain), ['unapproved_execution'], 'a signature is not authority; being asked is')
    assert.ok(chain.issues.some((i) => i.code === 'response_not_counted'))
    assert.deepEqual(
      chain.approvals.map((a) => [a.pubkey, a.counted]),
      [[mallory.pubkey, false]],
      'and it is reported rather than dropped — an attempt is a thing an auditor wants to see',
    )
  })

  it('catches a transition the state machine does not allow', async (t) => {
    const run = await deployed()
    t.after(() => run.finish())

    const revived = await transition(run.agent, run, find(run.events, 'succeeded'), {
      status: 'running',
    })

    assert.deepEqual(
      codes(verifyActionChain(run.actionId, [...run.events, revived])),
      ['illegal_transition'],
      'succeeded is terminal; retrying means proposing a new action',
    )
  })

  it('catches a chain with no proposal to anchor it', async (t) => {
    const run = await deployed()
    t.after(() => run.finish())

    const chain = verifyActionChain(run.actionId, without(run.events, isStatus('proposed')))

    assert.deepEqual(codes(chain), ['no_proposal'])
    assert.equal(chain.status, 'unknown')
  })
})

describe('the order the events came in', () => {
  it('does not matter', async (t) => {
    const run = await deployed()
    t.after(() => run.finish())

    // A relay returns what it likes in whatever order it likes, and a JSON dump
    // has whatever order somebody's script wrote. Every rotation of the chain
    // must read the same.
    for (let i = 0; i < run.events.length; i++) {
      const rotated = [...run.events.slice(i), ...run.events.slice(0, i)]
      const chain = verifyActionChain(run.actionId, rotated)
      assert.deepEqual(chain.issues, [], `rotation ${i} disagreed`)
      assert.equal(chain.status, 'succeeded')
    }
  })

  it('is not read from the clock, which has nothing to say here', async (t) => {
    const run = await deployed()
    t.after(() => run.finish())

    // The clock genuinely cannot order these. `created_at` has one-second
    // resolution and the loop finishes in milliseconds, so sorting by it falls
    // through to the id tiebreak — a hash, i.e. a shuffle. This assertion is
    // what makes the next one mean something.
    const stamps = run.events.filter((e) => e.kind === Kinds.Action).map((e) => e.created_at)
    assert.ok(Math.max(...stamps) - Math.min(...stamps) <= 1, 'the whole chain is one second wide')

    const chain = run.chain()
    assert.deepEqual(
      chain.events.filter((e) => e.kind === Kinds.Action).map((e) => body(e)!.status),
      ['proposed', 'awaiting_approval', 'running', 'succeeded'],
      'and the parent links put them back in order anyway',
    )
  })
})

describe('what is not tampering', () => {
  it('warns, but does not fail, on an action nobody had to approve', async (t) => {
    const run = await deployed()
    t.after(() => run.finish())

    // Dropping the request as well as the response leaves a chain that never
    // asked. That is a legal thing to publish — plenty of actions need no gate
    // — so it is a warning, and the warning carries the entire difference
    // between "nobody approved this" and "this did not need approving".
    const chain = verifyActionChain(
      run.actionId,
      without(run.events, (e) => e.kind === Kinds.ApprovalRequest || e.kind === Kinds.ApprovalResponse),
    )

    assert.equal(chain.ok, true)
    assert.deepEqual(
      chain.issues.map((i) => [i.code, i.severity]),
      [['ungated_execution', 'warning']],
    )
  })

  it('keeps two actions in one channel apart', async (t) => {
    const run = await deployed()
    t.after(() => run.finish())

    // An auditor is handed a channel, not a chain. Folding two actions together
    // would make every digest comparison in this file meaningless.
    const other = new Keyholder()
    const input = { scope: 'signing' }
    const proposed = await other.sign({
      kind: Kinds.Action,
      thread: threadRef(find(run.events, 'proposed'))!,
      created_at: find(run.events, 'proposed').created_at + 100,
      body: {
        name: 'rotate.keys',
        status: 'proposed',
        summary: 'rotate the signing keys',
        input,
        input_digest: digest(input),
      },
    })

    const chains = verifyActionChains([...run.events, proposed])
    assert.deepEqual(
      chains.map((c) => [c.name, c.status, c.approvals.length]),
      [
        ['deploy.production', 'succeeded', 1],
        ['rotate.keys', 'proposed', 0],
      ],
    )
    assert.equal(
      tagValue(proposed.tags, TagName.Action),
      undefined,
      'a proposal carries no `action` tag: it names the chain by being its first event',
    )
    assert.equal(chains[1]!.actionId, proposed.id)
  })
})
