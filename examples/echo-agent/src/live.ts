/**
 * The same claims as `demo.ts`, against the real Go relay.
 *
 *   cd apps/relay && make run          # :3334, in another terminal
 *   pnpm --filter @quorum/echo-agent live
 *
 * The fake relay in `@quorum/test-kit` is deliberately permissive — it does no
 * NIP-29 membership check and no Quorum validation, because a test double that
 * has opinions about what is legal becomes a second, unversioned specification.
 * That is the right trade for unit tests and it means the fake cannot tell you
 * whether the SDK's filters and events are acceptable to a relay that *does*
 * check. This file is where that gets found out.
 *
 * Two things in particular are only testable here:
 *
 *   - **The M2 trap.** relay29 refuses a `{"#p": [...]}` filter that carries no
 *     `h` tag, by CLOSED rather than by an empty result. The SDK's
 *     `addressedFilter` includes `h`; if that ever regresses the agent goes
 *     permanently deaf and every unit test still passes.
 *   - **Validation.** The relay validates Quorum kinds against the committed
 *     JSON Schema, so this is the first place an event the SDK builds meets the
 *     spec as an independent implementation reads it.
 *
 * Exits non-zero on the first failed expectation.
 */

import { Kinds, refTo, type NostrEvent, type UnsignedEvent } from '@quorum/protocol'
import {
  Counters,
  LocalSigner,
  MemoryStore,
  Publisher,
  RelayClient,
  createAgent,
} from '@quorum/sdk'

const url = process.env.QUORUM_RELAY ?? 'ws://localhost:3334'
// A fresh group per run. Reusing one would leave the previous run's messages in
// the channel, and the agent backfills on start — so run two and the second one
// answers the first one's questions.
const group = process.env.QUORUM_GROUP ?? `live-${Date.now().toString(36)}`

const NIP29 = { createGroup: 9007, joinRequest: 9021 } as const

const ada = LocalSigner.generate()
const bot = LocalSigner.generate()

let failures = 0

console.log(`relay ${url}`)
console.log(`group #${group}`)
console.log(`ada   ${ada.npub.slice(0, 20)}…`)
console.log(`bot   ${bot.npub.slice(0, 20)}…\n`)

const adaClient = new RelayClient({ url, signer: ada })
const botClient = new RelayClient({ url, signer: bot })
await adaClient.connect()
await botClient.connect()

// Ada creates the workspace, which makes her its admin. The bot asks to join;
// the relay's auto-admit is open until M4 wires capability grants into
// membership, and that gap is why this is two lines rather than an approval.
await publishRaw(adaClient, ada, { kind: NIP29.createGroup, tags: [['h', group]], content: '' })
await publishRaw(botClient, bot, { kind: NIP29.joinRequest, tags: [['h', group]], content: '' })
await waitFor('the bot to be admitted', async () => {
  const admitted = await adaClient.query([
    // put-user, written by the relay when it admits someone
    { kinds: [9000], '#h': [group], '#p': [bot.publicKey] },
  ])
  return admitted.length > 0
})
ok('the relay admitted the bot to the group')

const agent = createAgent({
  relay: url,
  signer: bot,
  group,
  store: new MemoryStore(),
  name: 'live',
  kinds: [Kinds.ChatMessage, Kinds.Thread, Kinds.Comment],
})
agent.on(async (event, ctx) => {
  await ctx.say(`echo: ${event.content}`)
})
await agent.start()
ok('the agent subscribed — its `#p` filter was not refused')

const publisher = new Publisher({
  client: adaClient,
  signer: ada,
  pubkey: ada.publicKey,
  group,
  counters: await Counters.load(new MemoryStore(), ada.publicKey),
})

// 1. addressing.
const thread = await publisher.publish({
  kind: Kinds.Thread,
  text: `someone should get ${bot.publicKey} to look at this`,
  tags: [['title', 'live check']],
})
ok('the relay accepted a Quorum kind 11 built by the SDK')

await settle(1500)
expect((await replies()).length === 0, 'prose that names the bot gets no reply')

// 2. the reply, addressed.
await publisher.publish({
  kind: Kinds.Comment,
  text: 'ping',
  thread: refTo(thread),
  to: [bot.publicKey],
})
await waitFor('the echo', async () => (await replies()).length > 0)
const got = await replies()
expect(got[0]?.content === 'echo: ping', `the bot replied: ${JSON.stringify(got[0]?.content)}`)
expect(
  got[0]?.tags.some((t) => t[0] === 'counter'),
  'the reply carries a counter tag, so gaps in it are detectable',
)

await agent.stop()
adaClient.close()
botClient.close()

console.log(failures === 0 ? '\nall good.' : `\n${failures} failed.`)
process.exit(failures === 0 ? 0 : 1)

// --- helpers ----------------------------------------------------------------

/**
 * Publish something the protocol package will not build.
 *
 * NIP-29 management events are not Quorum kinds — no `alt`, no `quorum`, no
 * counter — and `build()` is right to refuse them. Group administration is the
 * relay's protocol, not ours.
 */
async function publishRaw(
  client: RelayClient,
  signer: LocalSigner,
  event: Omit<UnsignedEvent, 'pubkey' | 'created_at'>,
): Promise<void> {
  await client.publish(
    await signer.sign({
      ...event,
      pubkey: signer.publicKey,
      created_at: Math.floor(Date.now() / 1000),
    }),
  )
}

async function replies(): Promise<NostrEvent[]> {
  const events = await adaClient.query([
    { kinds: [Kinds.Comment, Kinds.ChatMessage], authors: [bot.publicKey], '#h': [group] },
  ])
  return events.sort((a, b) => a.created_at - b.created_at)
}

async function waitFor(what: string, done: () => Promise<boolean>): Promise<void> {
  const deadline = Date.now() + 10_000
  while (Date.now() < deadline) {
    if (await done()) return
    await settle(250)
  }
  fail(`timed out waiting for ${what}`)
}

function settle(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function expect(condition: unknown, what: string): void {
  if (condition) ok(what)
  else fail(what)
}

function ok(what: string): void {
  console.log(`  \x1b[32m✔\x1b[0m ${what}`)
}

function fail(what: string): void {
  failures += 1
  console.log(`  \x1b[31m✘\x1b[0m ${what}`)
}
