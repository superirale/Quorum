/**
 * The M3 demo, narrated, against an in-process relay.
 *
 * `pnpm --filter @quorum/echo-agent demo` — no infrastructure, no keys, no
 * config. It runs the three claims the milestone rests on and prints what
 * happened, including the negative control for each: the mechanism removed, so
 * you can see the failure it prevents.
 *
 *   1. addressing    prose that names the agent gets no answer; a `to`-marked
 *                    `p` tag does
 *   2. restart       a process killed mid-handler replays it, and the message it
 *                    had already sent is *not* sent twice — first in the easy
 *                    case, then in the one the design actually exists for
 *   3. replicas      two processes, one key — one answer
 *
 * Each act gets its own relay and its own workspace. That is not tidiness: an
 * agent starting up backfills the channel, so a shared relay would have act two
 * answering act one's messages and every count below would be a sum of things
 * that have nothing to do with each other.
 *
 * `packages/sdk/test/agent.test.ts` asserts all of this. This file exists
 * because a passing test and a thing you can watch are not the same artifact.
 */

import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Kinds, digest, refTo, type NostrEvent } from '@quorum/protocol'
import {
  Counters,
  LocalSigner,
  MemoryStore,
  Publisher,
  RelayClient,
  createAgent,
  type Agent,
  type Store,
} from '@quorum/sdk'
import { FileStore } from '@quorum/sdk/node'
import { FakeRelay, settle } from '@quorum/test-kit'

const GROUP = 'payments'
const quiet = { debug() {}, warn() {}, error() {} }

const workdir = await mkdtemp(join(tmpdir(), 'quorum-echo-'))
const agentKey = LocalSigner.generate()
console.log(`agent ${agentKey.npub}`)

/** A relay, a human, and a way to make echo agents against them. */
async function world() {
  const relay = await FakeRelay.start()
  const adaKey = LocalSigner.generate()
  const client = new RelayClient({ url: relay.url, signer: adaKey, reconnect: false, log: quiet })
  await client.connect()
  const ada = new Publisher({
    client,
    signer: adaKey,
    pubkey: adaKey.publicKey,
    group: GROUP,
    counters: await Counters.load(new MemoryStore(), adaKey.publicKey),
  })

  const agents: Agent[] = []
  return {
    relay,
    ada,
    /** An echo agent. `stall` never resolving is how a handler is "killed". */
    echo(options: { name: string; store: Store; stall?: () => Promise<void>; lease?: boolean }): Agent {
      const agent = createAgent({
        relay: relay.url,
        signer: agentKey,
        group: GROUP,
        name: options.name,
        store: options.store,
        leases: { settleMs: 120, ttlSeconds: 5 },
        log: quiet,
      })
      agent.on(async (event, ctx) => {
        if (options.lease) {
          const lease = await ctx.lease('echo')
          if (!lease.held) {
            say(options.name, 'saw it, deferred — a sibling holds the thread')
            return
          }
        }
        say(options.name, `handling "${event.content}"`)
        await ctx.say(`echo: ${event.content}`)
        if (options.stall) await options.stall()
        await ctx.say('and done')
      })
      agents.push(agent)
      return agent
    },
    /** Everything the agent published, as a reader of the channel would see it. */
    said(): string[] {
      return relay.stored
        .filter((e) => e.pubkey === agentKey.publicKey && e.kind === Kinds.Comment)
        .map((e) => e.content)
    },
    /** Everything the relay was *sent*, duplicates included. */
    arrivals(): NostrEvent[] {
      return relay.received.filter(
        (e) => e.pubkey === agentKey.publicKey && e.kind === Kinds.Comment,
      )
    },
    /** How many of those arrivals were distinct events rather than re-sends. */
    distinct(): number {
      return new Set(this.arrivals().map((e) => e.id)).size
    },
    async close() {
      for (const agent of agents) await agent.stop()
      client.close()
      await relay.stop()
    },
  }
}

// --- 1. addressing ----------------------------------------------------------

{
  act('1. addressing — the agent answers what it is sent, not what mentions it')
  const w = await world()
  await w.echo({ name: 'echo', store: new MemoryStore() }).start()

  const thread = await w.ada.publish({
    kind: Kinds.Thread,
    text: `we should get the bot on this — p-tag ${agentKey.publicKey} to reach it`,
    tags: [['title', 'deploy']],
  })
  say('ada', 'posts a thread naming the agent in prose, every way a human might')
  await settle(300)
  report('replies', w.said(), 'prose is not addressing — this is the M0 bug')

  await w.ada.publish({
    kind: Kinds.Comment,
    text: 'echo this please',
    thread: refTo(thread),
    to: [agentKey.publicKey],
  })
  say('ada', 'posts the same words with a `to`-marked p tag')
  await settle(400)
  report('replies', w.said(), 'the tag is the only signal that counts')
  await w.close()
}

// --- 2. restart -------------------------------------------------------------

const never = new Promise<void>(() => {})

{
  act('2. restart — an interrupted handler is replayed, and the ledger absorbs the part already done')
  const w = await world()
  const stateDir = join(workdir, 'restart')

  const life1 = w.echo({ name: 'life-1', store: FileStore.in(stateDir), stall: () => never })
  await life1.start()
  await w.ada.publish({
    kind: Kinds.Thread,
    text: 'ship it',
    tags: [['title', 'ship']],
    to: [agentKey.publicKey],
  })
  say('ada', 'asks for something')
  await settle(400)
  report('said so far', w.said(), 'the handler is stuck between its two messages')

  say('life-1', 'is killed here, mid-handler')
  await life1.stop()

  const life2 = w.echo({ name: 'life-2', store: FileStore.in(stateDir) })
  await life2.start()
  say('life-2', 'starts with the same key and the same state directory')
  await settle(500)

  report('what a reader sees', w.said(), 'both messages, each once — the work finished')
  report(
    'what the relay was sent',
    w.arrivals().length,
    'the first message was never re-sent: the ledger had already recorded it',
  )
  await w.close()
}

// --- 2b. the same thing, killed in the window the design is for --------------

{
  act('2b. the harder case — killed after the send, before the ledger recorded it')
  const w = await world()
  const stateDir = join(workdir, 'crash')

  /**
   * A store that loses its very last write, which is the failure the two-phase
   * reservation exists for.
   *
   * Above, the crash landed in a place `once()` could see: the effect was
   * recorded, so the replay skipped it. The genuinely dangerous window is the
   * one between the effect happening and the record of it reaching disk — the
   * ledger says "not done", the world says otherwise, and the replay does it
   * again. Dropping the completion write reproduces that exactly.
   *
   * `endsWith`, not `includes`: `say` nests a second reservation at
   * `<label>/counter` so that a retry reuses the counter it already spent. Lose
   * that one too and the rebuilt event carries a fresh counter, hashes to a new
   * id, and this demo prints two messages instead of proving there is one.
   */
  function losesCompletionOf(label: string, inner: Store): Store {
    return {
      get: (key) => inner.get(key),
      delete: (key) => inner.delete(key),
      keys: (prefix) => inner.keys(prefix),
      async set(key, value) {
        const completing = key.endsWith(`:${label}`) && (value as { done?: boolean }).done === true
        if (completing) {
          say('life-1', 'dies here — the message is out, the ledger never learned it')
          return
        }
        await inner.set(key, value)
      },
    }
  }

  const label = `say:${digest('echo: land it').slice(0, 16)}`
  const life1 = w.echo({
    name: 'life-1',
    store: losesCompletionOf(label, FileStore.in(stateDir)),
    stall: () => never,
  })
  await life1.start()
  await w.ada.publish({
    kind: Kinds.Thread,
    text: 'land it',
    tags: [['title', 'land']],
    to: [agentKey.publicKey],
  })
  say('ada', 'asks for something')
  await settle(400)
  await life1.stop()

  const life2 = w.echo({ name: 'life-2', store: FileStore.in(stateDir) })
  await life2.start()
  say('life-2', 'replays the handler from the top, with no record of the send')
  await settle(500)

  report('what the relay was sent', w.arrivals().length, 'the message really was sent twice…')
  report('distinct event ids', w.distinct(), '…as one event: same reserved created_at, same id')
  report('what a reader sees', w.said(), 'so the channel is unharmed')
  await w.close()
}

// --- 3. replicas ------------------------------------------------------------

for (const useLease of [true, false]) {
  act(
    useLease
      ? '3. replicas — two processes, one key, one answer'
      : '3b. the control — the same thing with the lease taken out',
  )
  const w = await world()
  const replicas = ['a', 'b'].map((name) =>
    w.echo({ name: `replica-${name}`, store: new MemoryStore(), lease: useLease }),
  )
  await Promise.all(replicas.map((r) => r.start()))

  await w.ada.publish({
    kind: Kinds.Thread,
    text: 'who is taking this?',
    tags: [['title', 'who']],
    to: [agentKey.publicKey],
  })
  say('ada', 'asks the agent — which is running twice — for one thing')
  await settle(900)

  // Counted as arrivals, not as what a reader sees. Two replicas of a
  // *deterministic* agent produce byte-identical events, which the relay
  // dedupes — so the reader's view is the same either way and the control would
  // look like a success. That dedup is luck, not a guarantee: the moment the
  // handler says anything that varies (a timestamp, a model's output) the two
  // replicas produce two different events and the channel gets both.
  report(
    'sent to the relay',
    w.arrivals().length,
    useLease
      ? 'one replica answered; the other saw the lease and stood down'
      : 'both answered — the lease is the only thing that was stopping this',
  )
  report('what a reader sees', w.said(), 'identical here only because echoing is deterministic')
  await w.close()
}

await rm(workdir, { recursive: true, force: true })
console.log('\ndone.')

// --- narration --------------------------------------------------------------

function act(title: string): void {
  console.log(`\n\x1b[1m${title}\x1b[0m`)
}

function say(who: string, what: string): void {
  console.log(`  ${who.padEnd(10)} ${what}`)
}

function report(label: string, value: unknown, note: string): void {
  console.log(`  \x1b[2m→ ${label}:\x1b[0m ${JSON.stringify(value)}\n  \x1b[2m  ${note}\x1b[0m`)
}
