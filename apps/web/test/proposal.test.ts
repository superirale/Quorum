/**
 * Finding the payload behind an approval request.
 *
 * The case that matters is the negative one: when the proposal is not on the
 * relay, this must say so rather than return an empty object. A card rendering
 * `{}` tells an approver the action takes no arguments, which is a different
 * claim from "I could not find out what the arguments are".
 */

import assert from 'node:assert/strict'
import { describe, it } from 'vitest'
import { Kinds, build, refTo, type NostrEvent } from '@quorum/protocol'
import { LocalSigner } from '@quorum/sdk'
import { proposedInput } from '../src/proposal.ts'

const GROUP = 'ops'
const bot = LocalSigner.generate()

const input = { service: 'api', version: '1.4.2', replicas: 2 }

async function transcript(): Promise<{ proposal: NostrEvent; request: NostrEvent }> {
  const thread = await bot.sign(
    build({ kind: Kinds.Thread, pubkey: bot.publicKey, group: GROUP, text: 'deploy please', tags: [['title', 'deploy']] }),
  )
  const proposal = await bot.sign(
    build({
      kind: Kinds.Action,
      pubkey: bot.publicKey,
      group: GROUP,
      thread: refTo(thread),
      body: { name: 'deploy', status: 'proposed', summary: 'ship api', input },
    }),
  )
  const request = await bot.sign(
    build({
      kind: Kinds.ApprovalRequest,
      pubkey: bot.publicKey,
      group: GROUP,
      thread: refTo(thread),
      parent: refTo(proposal),
      action: proposal.id,
      to: [bot.publicKey],
      body: { title: 'deploy', summary: 'ship api', risk: 'high', required: 1 },
    }),
  )
  return { proposal, request }
}

describe('proposedInput', () => {
  it('finds the proposal by the action id, which is its own event id', async () => {
    const { proposal, request } = await transcript()
    assert.deepEqual(proposedInput([proposal, request], request), { found: true, input })
  })

  it('reports not-found rather than an empty payload when the proposal is absent', async () => {
    const { request } = await transcript()
    assert.deepEqual(proposedInput([request], request), { found: false })
  })

  it('will not accept some other event that happens to carry the id', async () => {
    // The id is a content hash, so this cannot really happen on the wire — but
    // the kind check is what makes that a fact about the data rather than a
    // hope, and it costs one comparison.
    const { proposal, request } = await transcript()
    const impostor = { ...proposal, kind: Kinds.Summary }
    assert.deepEqual(proposedInput([impostor, request], request), { found: false })
  })
})
