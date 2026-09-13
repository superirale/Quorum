/**
 * The reader agent, long-running, against a real relay.
 *
 * `demo.ts` runs the same handler over an in-process relay and is the faster
 * way to see it work; `live.ts` is the one that proves the two packers agree.
 * This is the one you leave running.
 *
 *   pnpm --filter @quorum/protocol schemas
 *   cd apps/relay && make run                       # :3334
 *
 *   export QUORUM_AGENT_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
 *   export ANTHROPIC_API_KEY=sk-ant-…               # optional; see below
 *   pnpm --filter @quorum/claude-agent start
 *
 * Then invite it — `quorum workspace invite <its npub>` from the console, since
 * the relay refuses a join request nobody granted — and ask it something inside
 * a thread, with a `["p", "<its pubkey>", "", "to"]` tag. `quorum say --to` and
 * the web client both do that; a generic Nostr client writes an unmarked `p`
 * and the agent will correctly ignore it.
 *
 * Three knobs:
 *
 *   QUORUM_PACKER    a context DVM's pubkey. Unset means pack locally from this
 *                    agent's own backfill, which is the only option on an
 *                    encrypted channel and so is the default here. Set it to the
 *                    relay's pubkey — the `pubkey` field of its NIP-11 document
 *                    — to have the relay do the arithmetic instead. The answers
 *                    are the same bytes; `live.ts` is the test that says so.
 *   QUORUM_BUDGET    token budget per turn. Advisory: the mandatory-keep set can
 *                    exceed it, and `used_tokens` in the log is what it cost.
 *   QUORUM_STATE_DIR the `once()` ledger and counters. Durable on purpose — an
 *                    agent that forgets it already paid for an answer buys it
 *                    again on the next restart.
 *
 * Without `ANTHROPIC_API_KEY` it still runs, and still answers, with the grep
 * stand-in from `model.ts` rather than a model. Everything this example is
 * actually demonstrating — the pack, the fence, the memory — happens either way.
 */

import { LocalSigner } from '@quorum/sdk'
import { FileStore } from '@quorum/sdk/node'
import { DEFAULT_BUDGET, announce, createClaudeAgent } from './agent.ts'
import { createModel } from './model.ts'

const relay = process.env.QUORUM_RELAY ?? 'ws://localhost:3334'
const group = process.env.QUORUM_GROUP ?? 'payments'
const stateDir = process.env.QUORUM_STATE_DIR ?? './state'
const budgetTokens = Number(process.env.QUORUM_BUDGET ?? DEFAULT_BUDGET)

const signer = LocalSigner.fromEnv('QUORUM_AGENT_KEY')
const model = createModel()
const packer = process.env.QUORUM_PACKER

const agent = createClaudeAgent({
  relay,
  signer,
  group,
  model,
  budgetTokens,
  ...(packer ? { packer } : {}),
  // Durable, and for a different reason than the deploy agent's. Nothing here
  // waits on a human, so nothing outlives the process by design — but the
  // handler is replayed on restart, the model call inside it is the expensive
  // line, and `once()` is only as durable as what it writes to.
  store: FileStore.in(stateDir, `reader-${signer.publicKey.slice(0, 8)}`),
  log: console,
})

await agent.start()

// After `start()`, because `publish` allocates a counter and the agent recovers
// its counter from the relay on start. Before the first question, because a
// thread packed while this is missing labels every agent in it `human` — see
// the note on `announce`.
await announce(agent, {
  name: process.env.QUORUM_AGENT_NAME ?? 'reader',
  description: 'answers questions about a thread from its packed history',
  model: model.name,
  ...(process.env.QUORUM_OPERATOR ? { operator: process.env.QUORUM_OPERATOR } : {}),
})

console.log(`reader ${signer.npub} listening on ${relay} in #${group}`)
console.log(`model   ${model.name}${model.live ? '' : '   — set ANTHROPIC_API_KEY for the real thing'}`)
console.log(`packing ${packer ? `via the DVM at ${packer.slice(0, 16)}…` : 'locally, from its own backfill'}`)
console.log(`budget  ${budgetTokens} tokens per turn (advisory)`)
if (!process.env.QUORUM_OPERATOR) {
  // Not fatal, and worth a line anyway: `operator` is what makes one human's
  // messages `operator` rather than `member` in every pack this agent reads, so
  // leaving it unset quietly flattens the trust ordering the packer exists to
  // express.
  console.log('⚠ QUORUM_OPERATOR unset — no human is named as this agent’s operator')
}

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.once(signal, () => {
    void agent.stop().then(() => process.exit(0))
  })
}
