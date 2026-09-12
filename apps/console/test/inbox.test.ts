/**
 * What the console decides is waiting on you.
 *
 * These are permission rules wearing a list's clothing. Getting any of them
 * wrong produces the same outcome from opposite directions: a queue that shows
 * requests nobody asked you to answer is a queue you learn to clear without
 * reading, which is precisely the habit this project exists to avoid.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { Kinds, build, digest, type NostrEvent } from '@quorum/protocol'
import { LocalSigner } from '@quorum/sdk'
import { addressees, findByPrefix, inbox } from '../src/inbox.ts'

const GROUP = 'payments'
const NOW = 1_800_000_000

const ada = LocalSigner.generate()
const bob = LocalSigner.generate()
const bot = LocalSigner.generate()

const input = { service: 'api', version: '1.4.2', env: 'production', replicas: 3 }

/**
 * The thread everything hangs off.
 *
 * Built once and shared, because a request outside a thread is not a thing the
 * protocol allows: `approvalResponse()` refuses to answer one, and `build()`
 * refuses to emit a parent link without the NIP-22 root scope beside it.
 */
const thread = await ada.sign(
  build({
    kind: Kinds.Thread,
    pubkey: ada.publicKey,
    group: GROUP,
    text: 'deploy api 1.4.2',
    to: [bot.publicKey],
    created_at: NOW - 120,
    tags: [['title', 'deploy']],
  }),
)
const threadRef = { id: thread.id, kind: thread.kind, pubkey: thread.pubkey }

async function request(options: {
  to: string[]
  expiresAt?: number
  required?: number
  createdAt?: number
}): Promise<NostrEvent> {
  return bot.sign(
    build({
      kind: Kinds.ApprovalRequest,
      pubkey: bot.publicKey,
      group: GROUP,
      thread: threadRef,
      to: options.to,
      created_at: options.createdAt ?? NOW - 60,
      body: {
        title: 'Deploy api 1.4.2',
        summary: 'deploy api 1.4.2 to production on 3 replicas',
        risk: 'high',
        input_digest: digest(input),
        required: options.required ?? 1,
        ...(options.expiresAt ? { expires_at: options.expiresAt } : {}),
      },
    }),
  )
}

async function response(to: NostrEvent, signer: LocalSigner): Promise<NostrEvent> {
  return signer.sign(
    build({
      kind: Kinds.ApprovalResponse,
      pubkey: signer.publicKey,
      group: GROUP,
      thread: threadRef,
      parent: { id: to.id, kind: to.kind, pubkey: to.pubkey },
      created_at: NOW - 30,
      body: { decision: 'approved', input_digest: digest(input) },
    }),
  )
}

describe('inbox', () => {
  it('lists a request addressed to me', async () => {
    const asked = await request({ to: [ada.publicKey] })
    const items = inbox([asked], { me: ada.publicKey, now: NOW })
    assert.equal(items.length, 1)
    assert.equal(items[0]!.body.title, 'Deploy api 1.4.2')
  })

  it('ignores a request addressed to somebody else', async () => {
    const asked = await request({ to: [bob.publicKey] })
    assert.deepEqual(inbox([asked], { me: ada.publicKey, now: NOW }), [])
  })

  it('ignores a request that merely mentions me', async () => {
    // A `p` tag without the `to` marker is a mention, and a mention is not a
    // question. This is the one addressing rule the whole system rests on, so
    // the console must not quietly widen it.
    const mentioned = await bot.sign(
      build({
        kind: Kinds.ApprovalRequest,
        pubkey: bot.publicKey,
        group: GROUP,
        mention: [ada.publicKey],
        created_at: NOW - 60,
        body: { title: 'FYI', summary: 'nothing for you to do', risk: 'low', required: 1 },
      }),
    )
    assert.deepEqual(inbox([mentioned], { me: ada.publicKey, now: NOW }), [])
  })

  it('drops one I have already answered, and keeps it under --all', async () => {
    const asked = await request({ to: [ada.publicKey] })
    const events = [asked, await response(asked, ada)]

    assert.deepEqual(inbox(events, { me: ada.publicKey, now: NOW }), [])

    const all = inbox(events, { me: ada.publicKey, now: NOW, all: true })
    assert.equal(all.length, 1)
    assert.equal(all[0]!.answered, true)
  })

  it('does not count somebody else\'s answer as mine', async () => {
    // Bob answering is not Ada answering, even on a request that named them
    // both. n-of-m is counted by distinct signer, so this must stay open.
    const asked = await request({ to: [ada.publicKey, bob.publicKey], required: 2 })
    const items = inbox([asked, await response(asked, bob)], { me: ada.publicKey, now: NOW })
    assert.equal(items.length, 1)
    assert.equal(items[0]!.answered, false)
  })

  it('hides an expired request unless asked for it', async () => {
    const asked = await request({ to: [ada.publicKey], expiresAt: NOW - 1 })
    assert.deepEqual(inbox([asked], { me: ada.publicKey, now: NOW }), [])
    assert.equal(inbox([asked], { me: ada.publicKey, now: NOW, all: true })[0]!.expired, true)
  })

  it('skips an event whose body is not an approval request', async () => {
    const junk = await bot.sign({
      kind: Kinds.ApprovalRequest,
      pubkey: bot.publicKey,
      created_at: NOW - 60,
      tags: [
        ['h', GROUP],
        ['p', ada.publicKey, '', 'to'],
        ['alt', 'malformed'],
      ],
      content: 'not json at all',
    })
    assert.deepEqual(inbox([junk], { me: ada.publicKey, now: NOW }), [])
  })

  it('puts the longest-waiting request first', async () => {
    const older = await request({ to: [ada.publicKey], createdAt: NOW - 500 })
    const newer = await request({ to: [ada.publicKey], createdAt: NOW - 10 })
    const items = inbox([newer, older], { me: ada.publicKey, now: NOW })
    assert.deepEqual(
      items.map((i) => i.request.id),
      [older.id, newer.id],
    )
  })

  it('reports the approvers a request names', async () => {
    const asked = await request({ to: [ada.publicKey, bob.publicKey], required: 2 })
    assert.deepEqual(addressees(asked), [ada.publicKey, bob.publicKey])
  })
})

describe('findByPrefix', () => {
  it('finds one by the start of its id', async () => {
    const asked = await request({ to: [ada.publicKey] })
    const items = inbox([asked], { me: ada.publicKey, now: NOW })
    assert.equal(findByPrefix(items, asked.id.slice(0, 6)).request.id, asked.id)
  })

  it('refuses an ambiguous prefix rather than guessing', async () => {
    // Approving the wrong action because two ids shared four characters is not
    // something a signature can be taken back from.
    const one = await request({ to: [ada.publicKey], createdAt: NOW - 100 })
    const two = await request({ to: [ada.publicKey], createdAt: NOW - 90 })
    const items = inbox([one, two], { me: ada.publicKey, now: NOW })
    const shared = commonPrefix(one.id, two.id)
    assert.throws(() => findByPrefix(items, shared), /matches 2 requests|Use more characters/)
  })

  it('says so when nothing matches', async () => {
    assert.throws(() => findByPrefix([], 'ffff'), /nothing pending/)
  })
})

/** The prefix both ids share — empty for two random ids, which still matches both. */
function commonPrefix(a: string, b: string): string {
  let i = 0
  while (i < a.length && a[i] === b[i]) i++
  return a.slice(0, i)
}
