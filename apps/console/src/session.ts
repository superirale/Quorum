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
import {
  ChannelCrypto,
  Counters,
  LocalSigner,
  Nip46Signer,
  Publisher,
  RelayClient,
  openReadable,
  type Signer,
} from '@quorum/sdk'
import { FileStore } from '@quorum/sdk/node'
import { home, loadBunker, loadConfig, loadKey, type Config } from './config.ts'
import { dim, yellow } from './format.ts'

/** NIP-29 management kinds. Not Quorum kinds, so they are signed raw. */
export const NIP29 = { createGroup: 9007, putUser: 9000, removeUser: 9001, joinRequest: 9021 } as const

export interface Session {
  config: Config
  name: string
  signer: Signer
  me: string
  client: RelayClient
  publisher: Publisher
  /** The channel's encryption state, already loaded. See the note in `open()`. */
  channel: ChannelCrypto
  /** `local` or `bunker` — which kind of identity this is, for commands that say so. */
  backing: 'local' | 'bunker'
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

  const { signer, me, backing, closeSigner } = await signerFor(name)
  const client = new RelayClient({
    url: config.relay,
    signer,
    // Quiet by default: a reconnect notice interleaved with command output
    // reads like part of the answer.
    log: { warn: () => {}, error: (m) => console.error(m) },
  })
  await client.connect()

  // Loaded here, for every command, rather than by the commands that need it.
  //
  // It costs two queries per invocation and buys the property that the console
  // cannot publish plaintext into an encrypted channel by forgetting a step.
  // That failure has no symptom: the relay takes the event, every reader shows
  // it normally, and the channel is simply less private than its own policy
  // says. Paying a round trip on `quorum whoami` is the cheaper side of that
  // trade by a wide margin.
  const channel = new ChannelCrypto({
    client,
    signer,
    pubkey: me,
    group: config.group,
    log: { warn: (m) => console.error(yellow(String(m))) },
  })
  await channel.load()

  const publisher = new Publisher({
    client,
    signer,
    pubkey: me,
    group: config.group,
    channel,
    // Durable, and per identity. The `counter` tag must be monotonic per
    // author; a fresh counter each command would make every message look like
    // a gap to anyone watching for one.
    counters: await Counters.load(FileStore.in(home(), `counters-${me.slice(0, 8)}`), me),
  })

  return {
    config,
    name,
    signer,
    me,
    client,
    publisher,
    channel,
    backing,
    close: () => {
      client.close()
      closeSigner()
    },
  }
}

/**
 * The signer behind a name: a key file, or a bunker session.
 *
 * A bunker identity is tried first. The two file kinds can both exist for one
 * name — `keygen ada` and then `bunker connect ada …` — and preferring the
 * bunker is the safe order: it is the one whose secret is not on this disk, and
 * silently signing with a leftover local key that happens to share a name would
 * produce events attributed to an entirely different pubkey.
 */
async function signerFor(name: string): Promise<{
  signer: Signer
  me: string
  backing: 'local' | 'bunker'
  closeSigner: () => void
}> {
  const saved = await loadBunker(name)
  if (!saved) {
    const signer = LocalSigner.fromHex(await loadKey(name))
    return { signer, me: signer.publicKey, backing: 'local', closeSigner: () => {} }
  }

  const signer = await Nip46Signer.open({
    uri: saved.uri,
    clientSecretKey: saved.clientSecretKey,
    // The URL goes to stderr so it survives `quorum export > file`, and it is
    // printed rather than opened: this console has no business launching a
    // browser, and on a remote shell there is none to launch.
    onAuth: (url) => {
      console.error(`${yellow('!')} ${saved.uri.slice(9, 17)}… wants a human to approve this:`)
      console.error(`  ${url}`)
      console.error(dim('  waiting…'))
    },
    log: { warn: () => {}, error: (m) => console.error(m) },
  })

  const me = await signer.pubkey()
  if (me !== saved.pubkey) {
    signer.close()
    throw new Error(
      `the bunker for "${name}" now reports ${me}, but this session was connected to ` +
        `${saved.pubkey}. Every grant, approval and membership saved under this name belongs ` +
        'to the old key, so nothing here will work as expected. Run ' +
        `\`quorum bunker forget ${name}\` and connect again if the change was intended.`,
    )
  }
  return { signer, me, backing: 'bunker', closeSigner: () => signer.close() }
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
  // A bunker identity's pubkey is the one the bunker reported at connect time.
  // Taking it from the file rather than re-asking is deliberate: resolving a
  // name is something `grant` and `workspace add` do about *other* people, and
  // it must not open a socket to someone else's signer to answer.
  const saved = await loadBunker(who)
  if (saved) return saved.pubkey
  try {
    return LocalSigner.fromHex(await loadKey(who)).publicKey
  } catch {
    throw new Error(
      `"${who}" is neither a 64-character hex pubkey nor a saved identity. ` +
        'Run `quorum whoami --all` to see what is saved.',
    )
  }
}

/**
 * Every event in the group, exactly as the relay served it.
 *
 * Sealed events come back sealed. This is what an auditor would be handed and
 * what `quorum export` must write, because an opened event's id commits to the
 * ciphertext — writing plaintext copies to a file called a transcript would
 * produce a transcript in which every signature fails.
 */
export async function groupEvents(session: Session): Promise<NostrEvent[]> {
  return session.client.query([{ '#h': [session.config.group], limit: 2000 }])
}

/**
 * The same events, with everything this identity can read opened.
 *
 * What every *display* command wants. The events it returns are not
 * re-verifiable — see `ChannelCrypto.opened` — which is why the two functions
 * are separate and named for what they are for rather than for a flag.
 */
export async function readableEvents(session: Session): Promise<NostrEvent[]> {
  return openReadable(session.channel, await groupEvents(session), (missing, held) =>
    console.error(
      yellow(`! ${missing} event(s) are sealed under an epoch ${session.name} does not hold`) +
        dim(` (it holds ${held.join(', ') || 'nothing'})`),
    ),
  )
}

/**
 * The `open` hook for {@link verifyActionChains}, or nothing on a plaintext channel.
 *
 * Returns `undefined` per event we have no key for rather than throwing, so one
 * missing epoch costs that event and not the whole audit.
 */
export function opener(session: Session): (event: NostrEvent) => NostrEvent | undefined {
  return session.channel.opener()
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
