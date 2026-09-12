/**
 * Typing part of an id and getting the request you meant.
 *
 * The queue rules themselves are the SDK's, and tested there. What is tested
 * here is the one thing only a terminal needs: turning `a91f` into exactly one
 * pending request, or refusing.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { Kinds, build, digest, type NostrEvent } from '@quorum/protocol'
import { LocalSigner, inbox } from '@quorum/sdk'
import { findByPrefix } from '../src/inbox.ts'

const GROUP = 'payments'
const NOW = 1_800_000_000

const ada = LocalSigner.generate()
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
