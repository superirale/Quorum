/**
 * A connected identity: a key, a socket, and a publisher that knows the group.
 *
 * Every command that touches the relay opens one of these and closes it. There
 * is no daemon and no cached connection, which costs a websocket handshake per
 * command and buys the property that matters for a tool you are using to test
 * a protocol: what you see is what the relay would serve anyone.
 */

import {
  Kinds,
  TagName,
  tagValue,
  type NostrEvent,
  type UnsignedEvent,
} from '@quorum/protocol'
import { Counters, LocalSigner, Publisher, RelayClient } from '@quorum/sdk'
import { FileStore } from '@quorum/sdk/node'
import { home, loadConfig, loadKey, type Config } from './config.ts'

/** NIP-29 management kinds. Not Quorum kinds, so they are signed raw. */
export const NIP29 = { createGroup: 9007, putUser: 9000, joinRequest: 9021 } as const

export interface Session {
  config: Config
  name: string
  signer: LocalSigner
  me: string
  client: RelayClient
  publisher: Publisher
  close(): void
}

export async function open(identity: string | undefined): Promise<Session> {
  const config = await loadConfig()
  const name = identity ?? config.identity
  if (!name) {
    throw new Error(
      'no identity selected — run `quorum keygen ada` then `quorum use ada`, or pass `--as ada`',
    )
  }

  const signer = LocalSigner.fromHex(await loadKey(name))
  const client = new RelayClient({
    url: config.relay,
    signer,
    // Quiet by default: a reconnect notice interleaved with command output
    // reads like part of the answer.
    log: { warn: () => {}, error: (m) => console.error(m) },
  })
  await client.connect()

  const publisher = new Publisher({
    client,
    signer,
    pubkey: signer.publicKey,
    group: config.group,
    // Durable, and per identity. The `counter` tag must be monotonic per
    // author; a fresh counter each command would make every message look like
    // a gap to anyone watching for one.
    counters: await Counters.load(
      FileStore.in(home(), `counters-${signer.publicKey.slice(0, 8)}`),
      signer.publicKey,
    ),
  })

  return {
    config,
    name,
    signer,
    me: signer.publicKey,
    client,
    publisher,
    close: () => client.close(),
  }
}

/**
 * Publish an event that `build()` will not make.
 *
 * NIP-29's management kinds have no Quorum envelope — no `alt`, no `quorum`
 * version tag — and `build()` is right to refuse them. Group administration is
 * borrowed, not ours.
 */
export async function publishRaw(
  session: Session,
  event: Omit<UnsignedEvent, 'pubkey' | 'created_at'>,
): Promise<NostrEvent> {
  const signed = await session.signer.sign({
    ...event,
    pubkey: session.me,
    created_at: Math.floor(Date.now() / 1000),
  })
  await session.client.publish(signed)
  return signed
}

/**
 * Resolve a saved identity name, or accept a hex pubkey as itself.
 *
 * Names are a convenience of this console and mean nothing on the wire. The
 * relay, the agent and the auditor all see only the key — which is the point,
 * and why `whoami` prints the hex next to the name every time.
 */
export async function resolvePubkey(who: string): Promise<string> {
  if (/^[0-9a-f]{64}$/i.test(who)) return who.toLowerCase()
  try {
    return LocalSigner.fromHex(await loadKey(who)).publicKey
  } catch {
    throw new Error(
      `"${who}" is neither a 64-character hex pubkey nor a saved identity. ` +
        'Run `quorum whoami --all` to see what is saved.',
    )
  }
}

/** Every event in the group, which is what an auditor would be handed. */
export async function groupEvents(session: Session): Promise<NostrEvent[]> {
  return session.client.query([{ '#h': [session.config.group], limit: 2000 }])
}

/**
 * The action id an approval request refers to.
 *
 * `action` is a multi-character tag and therefore not indexed by relays, so it
 * cannot be filtered on — which is fine, because the action id *is* the id of
 * the proposal event. Looking the proposal up is `{ids: [actionId]}`, an exact
 * lookup rather than a scan.
 */
export function actionOf(event: NostrEvent): string | undefined {
  return tagValue(event.tags, TagName.Action)
}

export async function proposalOf(session: Session, actionId: string): Promise<NostrEvent | undefined> {
  const found = await session.client.query([{ ids: [actionId] }])
  return found.find((e) => e.kind === Kinds.Action)
}
