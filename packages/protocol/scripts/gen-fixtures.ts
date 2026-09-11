/**
 * Generate the golden transcript in `fixtures/`.
 *
 * This is the M0 deploy scenario — human asks, agent proposes, human approves,
 * agent executes — expressed as real, signed Nostr events. It exists so that:
 *
 *   - other-language implementations have something concrete to validate
 *     against, rather than reading prose and guessing;
 *   - the conformance suite has a fixed input whose packed-context output two
 *     independent packers must agree on byte for byte;
 *   - a generic NIP-29/NIP-7D client can be pointed at it to check that our
 *     interop claim is true rather than aspirational.
 *
 * Everything is deterministic: fixed keys, fixed timestamps, fixed signing
 * nonce. A diff in `fixtures/` therefore means the protocol changed, which is
 * exactly the signal we want in review.
 *
 * Run: pnpm --filter @quorum/protocol fixtures
 */

import { schnorr } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { build, buildComment, buildThread } from '../src/build.ts'
import { digest } from '../src/digest.ts'
import { computeId, type NostrEvent, type UnsignedEvent } from '../src/event.ts'
import { Kinds } from '../src/kinds.ts'

const here = dirname(fileURLToPath(import.meta.url))
const outDir = join(here, '..', 'fixtures')
mkdirSync(outDir, { recursive: true })

// --- deterministic actors ---------------------------------------------------

/** Keys derived from a label so the fixtures are reproducible and obviously fake. */
function actor(label: string) {
  const secret = sha256(new TextEncoder().encode(`quorum-fixture/${label}`))
  return {
    label,
    secret,
    pubkey: bytesToHex(schnorr.getPublicKey(secret)),
  }
}

const ada = actor('ada')
const deployBot = actor('deploy-bot')
const relay = actor('relay')

/** A fixed aux nonce: schnorr signing is randomised by default, fixtures must not be. */
const AUX = hexToBytes('00'.repeat(32))

function sign(event: UnsignedEvent, secret: Uint8Array): NostrEvent {
  const id = computeId(event)
  return { ...event, id, sig: bytesToHex(schnorr.sign(id, secret, AUX)) }
}

const GROUP = 'payments'
const T0 = 1_757_000_000

// --- the transcript ---------------------------------------------------------

const events: NostrEvent[] = []
const push = (e: NostrEvent) => (events.push(e), e)

const thread = push(
  sign(
    buildThread({
      pubkey: ada.pubkey,
      group: GROUP,
      title: 'Ship the payments hotfix',
      text: 'Charge capture is double-billing on retry. Please get a1b2c3d out.',
      to: [deployBot.pubkey],
      counter: 1,
      created_at: T0,
    }),
    ada.secret,
  ),
)

const threadRef = { id: thread.id, kind: thread.kind, pubkey: thread.pubkey }

push(
  sign(
    buildComment({
      pubkey: deployBot.pubkey,
      group: GROUP,
      text: 'Looking at this now.',
      thread: threadRef,
      counter: 1,
      created_at: T0 + 4,
    }),
    deployBot.secret,
  ),
)

const deployInput = {
  service: 'payments-api',
  ref: 'a1b2c3d',
  env: 'production',
}
const inputDigest = digest(deployInput)

const proposed = push(
  sign(
    build({
      kind: Kinds.Action,
      pubkey: deployBot.pubkey,
      group: GROUP,
      thread: threadRef,
      counter: 2,
      created_at: T0 + 5,
      body: {
        name: 'deploy.production',
        status: 'proposed',
        summary: 'Deploy payments-api@a1b2c3d to production',
        input: deployInput,
        input_digest: inputDigest,
      },
    }),
    deployBot.secret,
  ),
)

push(
  sign(
    build({
      kind: Kinds.Action,
      pubkey: deployBot.pubkey,
      group: GROUP,
      thread: threadRef,
      action: proposed.id,
      counter: 3,
      created_at: T0 + 6,
      body: {
        name: 'deploy.production',
        status: 'awaiting_approval',
        summary: 'Deploy payments-api@a1b2c3d to production',
      },
    }),
    deployBot.secret,
  ),
)

const request = push(
  sign(
    build({
      kind: Kinds.ApprovalRequest,
      pubkey: deployBot.pubkey,
      group: GROUP,
      thread: threadRef,
      action: proposed.id,
      to: [ada.pubkey],
      counter: 4,
      created_at: T0 + 6,
      body: {
        title: 'Deploy payments-api to production',
        summary:
          'Deploys a1b2c3d (hotfix: retry idempotency on charge capture). Affects 3 pods, rolling. Roughly 90s of mixed-version traffic.',
        risk: 'high',
        input_digest: inputDigest,
        requested_grant: {
          resource: 'action:deploy.production',
          actions: ['invoke'],
          scope: { env: 'production' },
          expires_at: T0 + 606,
        },
        expires_at: T0 + 606,
      },
    }),
    deployBot.secret,
  ),
)

push(
  sign(
    build({
      kind: Kinds.ApprovalResponse,
      pubkey: ada.pubkey,
      group: GROUP,
      thread: threadRef,
      parent: { id: request.id, kind: request.kind, pubkey: request.pubkey },
      action: proposed.id,
      to: [deployBot.pubkey],
      counter: 2,
      created_at: T0 + 41,
      body: {
        decision: 'approved',
        input_digest: inputDigest,
        reason: 'Freeze window does not apply to sev-2 hotfixes.',
      },
    }),
    ada.secret,
  ),
)

push(
  sign(
    build({
      kind: Kinds.Action,
      pubkey: deployBot.pubkey,
      group: GROUP,
      thread: threadRef,
      action: proposed.id,
      counter: 5,
      created_at: T0 + 42,
      body: {
        name: 'deploy.production',
        status: 'running',
        summary: 'Deploy payments-api@a1b2c3d to production',
      },
    }),
    deployBot.secret,
  ),
)

push(
  sign(
    build({
      kind: Kinds.Action,
      pubkey: deployBot.pubkey,
      group: GROUP,
      thread: threadRef,
      action: proposed.id,
      counter: 6,
      created_at: T0 + 133,
      body: {
        name: 'deploy.production',
        status: 'succeeded',
        summary: 'Deploy payments-api@a1b2c3d to production',
        output_summary: 'Rolled out to 3/3 pods. Health checks green. 0 errors in 60s.',
        cost: { tokens_in: 4210, tokens_out: 380, usd: 0.06 },
      },
    }),
    deployBot.secret,
  ),
)

push(
  sign(
    buildComment({
      pubkey: deployBot.pubkey,
      group: GROUP,
      text: 'Deployed and healthy. Rolling back is one word away if you need it.',
      thread: threadRef,
      to: [ada.pubkey],
      counter: 7,
      created_at: T0 + 134,
    }),
    deployBot.secret,
  ),
)

// The relay's projection of the task, signed by the relay — NIP-29 precedent.
push(
  sign(
    build({
      kind: Kinds.ThreadState,
      pubkey: relay.pubkey,
      group: GROUP,
      d: thread.id,
      counter: 1,
      created_at: T0 + 135,
      body: {
        status: 'done',
        title: 'Ship the payments hotfix',
        assignee: deployBot.pubkey,
        spent: { tokens_in: 4210, tokens_out: 380, usd: 0.06 },
        folded_from: [],
        updated_at: T0 + 135,
      },
    }),
    relay.secret,
  ),
)

writeFileSync(
  join(outDir, 'deploy-approval.json'),
  `${JSON.stringify(
    {
      description:
        'The M0 deploy loop as signed Nostr events: request, proposal, approval, execution.',
      group: GROUP,
      thread: thread.id,
      action: proposed.id,
      input_digest: inputDigest,
      actors: {
        [ada.pubkey]: { name: 'Ada', kind: 'human' },
        [deployBot.pubkey]: { name: 'Deploy Bot', kind: 'agent' },
        [relay.pubkey]: { name: 'reference relay', kind: 'relay' },
      },
      events,
    },
    null,
    2,
  )}\n`,
)

console.log(`wrote fixtures/deploy-approval.json — ${events.length} events`)
console.log(`  thread ${thread.id}`)
console.log(`  action ${proposed.id}`)
console.log(`  input_digest ${inputDigest}`)
