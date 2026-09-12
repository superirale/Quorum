/**
 * The echo agent — the smallest complete Quorum agent.
 *
 * It repeats back whatever it is told, which is deliberately the least
 * interesting thing an agent can do: everything worth looking at here is the
 * machinery around the handler, and a handler that did real work would hide it.
 *
 * What it demonstrates, in order of how much trouble each one saves:
 *
 *   1. it answers only when `p`-tagged, and ignores prose that names it
 *   2. it survives a restart mid-handler without repeating what it already said
 *   3. two replicas of it do not both answer
 *
 * Run it against the reference relay:
 *
 *   pnpm --filter @quorum/protocol schemas
 *   cd apps/relay && make run                       # :3334
 *
 *   export QUORUM_AGENT_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
 *   pnpm --filter @quorum/echo-agent start
 *
 * Then talk to it from any Nostr client that can post a NIP-29 kind 11 with a
 * `["p", "<the agent's pubkey>", "", "to"]` tag. `pnpm --filter @quorum/echo-agent demo`
 * does that for you, and is the faster way to see it work.
 */

import { Kinds } from '@quorum/protocol'
import { LocalSigner, createAgent } from '@quorum/sdk'
import { FileStore } from '@quorum/sdk/node'

const relay = process.env.QUORUM_RELAY ?? 'ws://localhost:3334'
const group = process.env.QUORUM_GROUP ?? 'payments'
const stateDir = process.env.QUORUM_STATE_DIR ?? './state'

/**
 * The key is the identity. Not a bot token some server can reissue — lose it
 * and the agent is a different agent; leak it and someone else is this one.
 */
const signer = LocalSigner.fromEnv('QUORUM_AGENT_KEY')

const agent = createAgent({
  relay,
  signer,
  group,
  // Durable, because none of the restart guarantees mean anything without it.
  // A memory store here would re-run every effect on every start.
  store: FileStore.in(stateDir, `echo-${signer.publicKey.slice(0, 8)}`),
  // Naming the replica keeps two processes' cursors apart when they share a
  // state directory. They still share one key, which is what makes them
  // replicas of the same agent rather than two agents.
  name: process.env.QUORUM_INSTANCE ?? 'echo',
  kinds: [Kinds.ChatMessage, Kinds.Thread, Kinds.Comment],
})

// `on` — not `onAny`. The handler is never handed an event that was not
// addressed to this pubkey with a `to`-marked `p` tag, so "should I answer
// this?" is not a judgement the agent has to make. That judgement is what the
// M0 spike got wrong, and it deployed to production over it.
agent.on(async (event, ctx) => {
  // One replica answers. Losing is the expected outcome half the time, so it
  // resolves rather than throwing.
  const lease = ctx.thread ? await ctx.lease('echo') : undefined
  if (lease && !lease.held) return

  console.log(`← ${event.pubkey.slice(0, 8)}: ${event.content}`)

  // Every side effect goes through the ledger. `say` labels itself with a
  // digest of the text, so a replay after a crash rebuilds the same event, with
  // the same id, and the relay recognises it as one it already holds.
  await ctx.say(`echo: ${event.content}`)

  const gaps = ctx.gaps()
  if (gaps.length) {
    // Provable, because counters are signed by their author: no relay can
    // fabricate a sequence it does not have.
    console.warn(`⚠ missed events from ${gaps.length} author(s):`, gaps)
  }
})

await agent.start()
console.log(`echo agent ${signer.npub} listening on ${relay} in #${group}`)

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.once(signal, () => {
    // Stopping cleanly matters: a handler interrupted here stays *in flight* in
    // the cursor, so the next process replays it rather than losing the work.
    void agent.stop().then(() => process.exit(0))
  })
}
