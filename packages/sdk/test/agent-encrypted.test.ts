/**
 * An agent on a `nip44` channel.
 *
 * The claim M9 has to earn is that nothing above `ChannelCrypto` changes: a
 * handler written in M3 runs unmodified on an encrypted channel, `ctx.text` is
 * plaintext, `ctx.say` comes out sealed, and the packer still packs. So these
 * tests are mostly the M3 tests again with a rotation in front of them, which
 * is the point — if they had to be written differently, the abstraction would
 * have failed.
 *
 * The two that are new are about *not* having a key. An event sealed under an
 * epoch this agent was never given is neither an error nor silence, and the
 * difference matters because the two fixes are opposite: a missing key is an
 * admin publishing one 8110, a dropped event is a relay problem. Both paths
 * therefore say which, out loud, and both are asserted on here.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { Kinds, isSealed, refTo, type NostrEvent } from '@quorum/protocol'
import { FakeRelay, settle, waitFor, waitForCount } from '@quorum/test-kit'
import {
  ChannelCrypto,
  Counters,
  LocalSigner,
  MemoryStore,
  Publisher,
  RelayClient,
  approvalResponse,
  createAgent,
  renderContext,
  rotateChannelKey,
  verifyActionChains,
  wrapChannelKey,
  type PublishOptions,
  type Rotation,
} from '../src/index.ts'
import type { ContextPackResultBody } from '@quorum/protocol'

const group = 'payments'
const silent = { warn() {}, error() {} }

/** A human in the channel, holding whichever epochs they have been wrapped. */
class Human {
  readonly signer: LocalSigner
  readonly pubkey: string
  readonly client: RelayClient
  readonly crypto: ChannelCrypto
  readonly publisher: Publisher

  private constructor(
    signer: LocalSigner,
    client: RelayClient,
    crypto: ChannelCrypto,
    publisher: Publisher,
  ) {
    this.signer = signer
    this.pubkey = signer.publicKey
    this.client = client
    this.crypto = crypto
    this.publisher = publisher
  }

  static async create(url: string): Promise<Human> {
    const signer = LocalSigner.generate()
    const client = new RelayClient({ url, signer, reconnect: false, log: silent })
    await client.connect()
    const crypto = new ChannelCrypto({ client, signer, pubkey: signer.publicKey, group, log: silent })
    const publisher = new Publisher({
      client,
      signer,
      pubkey: signer.publicKey,
      group,
      counters: await Counters.load(new MemoryStore(), signer.publicKey),
      channel: crypto,
    })
    return new Human(signer, client, crypto, publisher)
  }

  rotate(members: string[], reason?: string): Promise<Rotation> {
    return rotateChannelKey({
      publisher: this.publisher,
      client: this.client,
      signer: this.signer,
      group,
      members,
      ...(reason ? { reason } : {}),
    })
  }

  thread(title: string, text: string, to: string[] = []): Promise<NostrEvent> {
    return this.publisher.publish({ kind: Kinds.Thread, text, to, tags: [['title', title]] })
  }

  comment(thread: NostrEvent, text: string, to: string[] = []): Promise<NostrEvent> {
    return this.publisher.publish({
      kind: Kinds.Comment,
      text,
      thread: refTo(thread),
      parent: refTo(thread),
      to,
    })
  }

  /** Anything else — an approval response, a grant. Sealed like everything else. */
  publish(options: PublishOptions): Promise<NostrEvent> {
    return this.publisher.publish(options)
  }

  /** The `open` hook an auditor holding this identity's keys would pass. */
  opener(): (event: NostrEvent) => NostrEvent | undefined {
    return this.crypto.opener()
  }
}

/** Collects warnings so a test can assert on the sentence, not just the silence. */
function recorder(): { warn(m: string): void; error(m: string): void; lines: string[] } {
  const lines: string[] = []
  return { lines, warn: (m) => void lines.push(m), error: (m) => void lines.push(m) }
}

describe('an agent on an encrypted channel', () => {
  it('reads sealed input and seals everything it says back', async (t) => {
    const relay = await FakeRelay.start()
    const ada = await Human.create(relay.url)
    const signer = LocalSigner.generate()
    const agent = createAgent({
      relay: relay.url,
      signer,
      group,
      store: new MemoryStore(),
      leases: false,
      log: silent,
    })
    t.after(async () => {
      await agent.stop()
      ada.client.close()
      await relay.stop()
    })

    // The key has to exist before the agent starts, or it comes up holding
    // nothing and its own `load()` says so.
    await ada.rotate([ada.pubkey, signer.publicKey])
    await ada.crypto.load()

    const heard: string[] = []
    agent.on(async (event, ctx) => {
      heard.push(ctx.text)
      await ctx.say(`echo: ${ctx.text}`)
    })
    await agent.start()

    const root = await ada.thread('deploy', 'ship api 1.4.2')
    await ada.comment(root, 'what is the rollback plan', [signer.publicKey])

    await waitFor(() => heard.length === 1, { describe: 'the sealed message to arrive' })
    assert.deepEqual(heard, ['what is the rollback plan'], 'the handler sees plaintext')

    const [reply] = await waitForCount(
      () => relay.received.filter((e) => e.pubkey === signer.publicKey && e.kind === Kinds.Comment),
      1,
      { describe: 'a reply' },
    )
    assert.ok(reply)
    // The three things that make it an encrypted channel rather than a channel
    // with encryption switched on somewhere: the bytes on the relay are not the
    // sentence, the tags still route it, and a member can read it.
    assert.ok(isSealed(reply))
    assert.notEqual(reply.content, 'echo: what is the rollback plan')
    assert.equal(ada.crypto.open(reply), 'echo: what is the rollback plan')
  })

  it('will not dispatch an event it has no key for, and says which epoch', async (t) => {
    // Skipping in silence would make an encrypted channel look empty to an
    // agent that had simply not been let in, and the operator would go looking
    // at the relay.
    const relay = await FakeRelay.start()
    const ada = await Human.create(relay.url)
    const signer = LocalSigner.generate()
    const log = recorder()
    const agent = createAgent({
      relay: relay.url,
      signer,
      group,
      store: new MemoryStore(),
      leases: false,
      log,
    })
    t.after(async () => {
      await agent.stop()
      ada.client.close()
      await relay.stop()
    })

    const first = await ada.rotate([ada.pubkey, signer.publicKey])
    await ada.crypto.load()

    const heard: string[] = []
    agent.on(async (event, ctx) => {
      heard.push(ctx.text)
      await ctx.say('ack')
    })
    await agent.start()

    const root = await ada.thread('deploy', 'ship api 1.4.2')
    await ada.comment(root, 'readable', [signer.publicKey])
    await waitFor(() => heard.length === 1, { describe: 'the readable message' })

    // Ada rotates the agent out. Everything after this is sealed under an
    // epoch it does not hold.
    await ada.rotate([ada.pubkey], 'the agent is being retired')
    await ada.crypto.load()
    await ada.comment(root, 'not for you', [signer.publicKey])
    await settle()

    assert.deepEqual(heard, ['readable'], 'the handler must not run on an unreadable event')
    assert.ok(
      log.lines.some((l) => /sealed under epoch 2 and this agent holds 1/.test(l)),
      `no line named the missing epoch: ${JSON.stringify(log.lines)}`,
    )
    // And nothing was published in response, which is the failure that would
    // otherwise look like the agent working.
    assert.equal(
      relay.received.filter((e) => e.pubkey === signer.publicKey && e.kind === Kinds.Comment).length,
      1,
    )
    assert.equal(first.epoch, 1)
  })

  it('packs a thread with holes in it rather than refusing to pack', async (t) => {
    // An agent that joined one epoch late must not lose *every* thread that
    // contains a single older message. Dropping is the smaller lie, but it is
    // still a lie by omission — the pack looks complete — so the count is
    // warned about.
    const relay = await FakeRelay.start()
    const ada = await Human.create(relay.url)
    const signer = LocalSigner.generate()
    const log = recorder()
    const agent = createAgent({
      relay: relay.url,
      signer,
      group,
      store: new MemoryStore(),
      leases: false,
      log,
    })
    t.after(async () => {
      await agent.stop()
      ada.client.close()
      await relay.stop()
    })

    // Epoch 1 is Ada's alone: she says something the agent will never read.
    const first = await ada.rotate([ada.pubkey])
    await ada.crypto.load()
    const root = await ada.thread('incident', 'the database is on fire')
    await ada.comment(root, 'and the backups are cold')

    // Then the agent is let in at epoch 2 — and *not* handed epoch 1, which is
    // the conservative half of the join decision.
    const second = await ada.rotate([ada.pubkey, signer.publicKey])
    await ada.crypto.load()

    let packed: ContextPackResultBody | undefined
    agent.on(async (event, ctx) => {
      packed = await ctx.context({ budget_tokens: 4000 })
    })
    await agent.start()

    await ada.comment(root, 'what do we tell the customer', [signer.publicKey])
    await waitFor(() => packed !== undefined, { describe: 'the pack' })

    // Rendered rather than read off the segments, because the rendering is what
    // reaches the model — and `{ preamble: '' }` because `PROMPT_PREAMBLE` is
    // prose about the fence, which a naive `doesNotMatch` could match on.
    assert.ok(packed)
    const prompt = renderContext(packed, { preamble: '' })
    assert.match(prompt, /what do we tell the customer/)
    assert.doesNotMatch(prompt, /backups are cold/, 'an unreadable event must not leak')
    assert.ok(
      log.lines.some((l) => /packing a thread without 2 event\(s\)/.test(l)),
      `no line counted the dropped events: ${JSON.stringify(log.lines)}`,
    )
    assert.equal(first.epoch, 1)
    assert.equal(second.epoch, 2)

    // The control: hand it epoch 1 after the fact and the same thread packs
    // whole. Without this the assertion above would also pass against an agent
    // that could not pack anything at all.
    await wrapChannelKey({
      publisher: ada.publisher,
      signer: ada.signer,
      group,
      member: signer.publicKey,
      epoch: first.epoch,
      key: first.key,
    })
    packed = undefined
    // No reload call. The agent watches for its own key wraps, which is the
    // only version of this that works for a process nobody is going to restart.
    await waitFor(() => agent.channel.epochs.includes(1), { describe: 'the backfilled key' })
    await ada.comment(root, 'and now', [signer.publicKey])
    await waitFor(() => packed !== undefined, { describe: 'the second pack' })
    assert.match(renderContext(packed!, { preamble: '' }), /backups are cold/)
  })

  it('runs the whole approval loop sealed, and the audit needs a key to read it', async (t) => {
    // The claim this project is built on is that consent is cryptographic and
    // checkable by anyone. Encrypting the channel changes who "anyone" is, and
    // pretending otherwise would be the dishonest version of this milestone —
    // so both halves are asserted here: the loop still works, and the audit
    // that made it worth doing now has a key as a prerequisite.
    const relay = await FakeRelay.start()
    const ada = await Human.create(relay.url)
    const signer = LocalSigner.generate()
    const agent = createAgent({
      relay: relay.url,
      signer,
      group,
      store: new MemoryStore(),
      leases: false,
      log: silent,
    })
    t.after(async () => {
      await agent.stop()
      ada.client.close()
      await relay.stop()
    })

    await ada.rotate([ada.pubkey, signer.publicKey])
    await ada.crypto.load()

    const input = { service: 'api', version: '1.4.2', replicas: 3 }
    const ran: string[] = []
    agent.on(async (event, ctx) => {
      const result = await ctx.act({
        name: 'deploy.production',
        summary: 'deploy api 1.4.2 to production',
        input,
        approvers: [ada.pubkey],
        risk: 'high',
        run: () => 'deployed',
      })
      if (result.status === 'succeeded') ran.push(result.output)
    })
    await agent.start()
    await ada.thread('deploy', 'please ship 1.4.2', [signer.publicKey])

    const [request] = await waitForCount(() => relay.storedOfKind(Kinds.ApprovalRequest), 1, {
      describe: 'the approval request',
    })
    assert.ok(isSealed(request!), 'even the request to a human is sealed')

    // Ada has to open it before she can answer it, and that is not a detail of
    // this test: `approvalResponse` reads the request's `input_digest` out of
    // its body, so a client that fed it the ciphertext would sign consent to
    // nothing. The digest travels in the sealed body, not in a tag.
    await ada.publish(approvalResponse({ request: ada.crypto.opened(request!), decision: 'approved' }))
    await waitFor(() => ran.length === 1, { describe: 'the action to run' })

    const events = [...relay.stored]

    // Without a key: the signatures still verify — they are over the sealed
    // bytes, which is what the relay holds and what anyone can check — and
    // nothing above that can be read. Reported as sealed rather than as broken.
    const [blind] = verifyActionChains(events)
    assert.ok(blind)
    assert.equal(blind.ok, false)
    assert.ok(
      blind.issues.some((i) => i.code === 'sealed'),
      `no issue said the chain was sealed: ${JSON.stringify(blind.issues.map((i) => i.code))}`,
    )
    assert.ok(
      !blind.issues.some((i) => i.code === 'bad_signature'),
      'a sealed chain must not look like a forged one',
    )

    // With one: the same events, the same function, the whole answer.
    const [chain] = verifyActionChains(events, { open: ada.opener() })
    assert.ok(chain)
    assert.deepEqual(chain.issues, [], 'the chain verifies once it can be read')
    assert.equal(chain.ok, true)
    assert.equal(chain.status, 'succeeded')
    assert.deepEqual(chain.input, input)
    assert.deepEqual(
      chain.approvals.map((a) => [a.pubkey, a.decision, a.counted]),
      [[ada.pubkey, 'approved', true]],
    )
  })
})
