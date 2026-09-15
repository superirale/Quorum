/**
 * A connected identity: a key, a socket, and a publisher that knows the group.
 *
 * Every command that touches the relay opens one of these and closes it. There
 * is no daemon and no cached connection, which costs a websocket handshake per
 * command and buys the property that matters for a tool you are using to test
 * a protocol: what you see is what the relay would serve anyone.
 */

import {
  EncMode,
  Kinds,
  TagName,
  tagValue,
  type NostrEvent,
  type UnsignedEvent,
} from '@quorum/protocol'
import {
  Archive,
  ChannelCrypto,
  Counters,
  LocalSigner,
  MlsCrypto,
  Nip46Signer,
  Publisher,
  RelayClient,
  SealedEnvelopes,
  channelPolicy,
  mlsCiphersuite,
  mlsIdentity,
  openReadable,
  openReadableMls,
  type ChannelPolicy,
  type ChannelSealer,
  type MlsIdentity,
  type Signer,
} from '@quorum/sdk'
import { FileStore } from '@quorum/sdk/node'
import { home, loadBunker, loadConfig, loadKey, type Config } from './config.ts'
import { dim, short, yellow } from './format.ts'

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
  channel: ChannelView
  /** `local` or `bunker` — which kind of identity this is, for commands that say so. */
  backing: 'local' | 'bunker'
  close(): void
}

/**
 * One way to ask "what can I read and write here", over two mechanisms that the
 * SDK deliberately refuses to unify.
 *
 * `MlsCrypto` is not a `ChannelCrypto` and the reason is in its own header: one
 * holds a map of epoch keys that opens any message any number of times, the
 * other holds a single evolving state that opens each message once, and an
 * interface over both is how a caller replays a decryption and loses a message.
 * That argument is about the *ratchet*. It is not an argument for every console
 * command growing a `switch`, which is a different way to lose a message —
 * `quorum tasks` silently showing base64 on an `mls` channel because nobody
 * added an arm to it.
 *
 * So the seam is here, in the application, and it is narrow on purpose: the
 * union is discriminated by `enc`, the `nip44` and `mls` handles are exposed
 * under their own names for the commands that are genuinely about one mode, and
 * everything shared is async because the ratchet half has to be. The one rule
 * this file enforces is that reading goes through {@link ChannelView.readable},
 * which on `mls` goes through `MlsCrypto.open` and therefore through the
 * archive — so a command that reads the channel twice still spends each
 * generation once.
 */
export interface ChannelView {
  enc: EncMode
  encrypted: boolean
  /** What the 38107 says, verbatim, including who signed it. */
  policy: ChannelPolicy
  /** What the `Publisher` was given. */
  sealer: ChannelSealer
  /** Present on `plaintext` and `nip44`; `undefined` on `mls`. */
  nip44: ChannelCrypto | undefined
  /** Present on `mls`; `undefined` otherwise. */
  mls: MlsCrypto | undefined
  /** The epoch this identity would write under, or `undefined`. */
  epoch: number | undefined
  /** Sealed and this identity cannot open it. */
  unreadable(event: NostrEvent): boolean
  /** Every event, with what this identity can read opened. Warns about the rest. */
  readable(events: readonly NostrEvent[]): Promise<NostrEvent[]>
  /**
   * One event's body, for the live path that has no set to hand.
   *
   * Async on both modes even though `nip44` answers immediately, because the
   * caller must not be able to tell them apart — a `watch` that awaited on one
   * channel and not the other would print its lines in a different order
   * depending on the encryption mode, which is the sort of difference nobody
   * discovers until the two feeds disagree about what was said first.
   */
  open(event: NostrEvent): Promise<string>
  /**
   * The sync opener the audit path wants, over what has already been read.
   *
   * On `mls` it answers only for events {@link ChannelView.readable} has
   * already been through — the ratchet cannot be re-entered per event on
   * demand, which is the whole point of the archive. Callers that need it warm
   * call `readable()` first; {@link opener} does that for them.
   */
  opener(): (event: NostrEvent) => NostrEvent | undefined
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
  const channel = await channelView({ client, signer, me, group: config.group })

  const publisher = new Publisher({
    client,
    signer,
    pubkey: me,
    group: config.group,
    channel: channel.sealer,
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
 * Read the policy, then build the machinery that policy implies.
 *
 * The order matters and it is the reverse of `ChannelCrypto`'s, which reads the
 * policy itself as part of `load()`. It cannot be that way here, because what
 * gets constructed *is* the question the policy answers — and getting it wrong
 * is not a degraded session but a silently plaintext one.
 */
async function channelView(deps: {
  client: RelayClient
  signer: Signer
  me: string
  group: string
}): Promise<ChannelView> {
  const { client, me, group } = deps
  const policy = await channelPolicy(client, group)
  if (policy.enc !== EncMode.Mls) return nip44View(deps)

  const mls = await openMlsCrypto(me, group)

  return {
    enc: EncMode.Mls,
    encrypted: true,
    policy,
    sealer: mls,
    nip44: undefined,
    mls,
    get epoch() {
      return mls.joined ? mls.epoch : undefined
    },
    unreadable: (event) => mls.unreadable(event),
    readable: (events) =>
      openReadableMls(mls, events, (missing) => {
        console.error(
          yellow(`! ${missing} event(s) cannot be read by ${short(me)}`) +
            dim(
              mls.joined
                ? ' — said before this identity joined, or under keys the ratchet has deleted'
                : ' — this identity is not in the group; `quorum mls join`',
            ),
        )
      }),
    open: (event) => mls.open(event),
    opener: () => mls.opener(),
  }
}

function nip44View(deps: {
  client: RelayClient
  signer: Signer
  me: string
  group: string
}): Promise<ChannelView> {
  const { client, signer, me, group } = deps
  const crypto = new ChannelCrypto({
    client,
    signer,
    pubkey: me,
    group,
    log: { warn: (m) => console.error(yellow(String(m))) },
  })
  // `load()` re-reads the policy, which is one query more than strictly needed.
  // Left alone rather than plumbed around: the alternative is a second way for
  // `ChannelCrypto` to learn what mode it is in, and this console already
  // pays a round trip per command by design.
  return crypto.load().then(() => ({
    enc: crypto.policy.enc,
    encrypted: crypto.encrypted,
    policy: crypto.policy,
    sealer: crypto,
    nip44: crypto,
    mls: undefined,
    epoch: crypto.policy.epoch,
    unreadable: (event: NostrEvent) => crypto.unreadable(event),
    readable: async (events: readonly NostrEvent[]) =>
      openReadable(crypto, events, (missing, held) =>
        console.error(
          yellow(`! ${missing} event(s) are sealed under an epoch this identity does not hold`) +
            dim(` (it holds ${held.join(', ') || 'nothing'})`),
        ),
      ),
    open: async (event: NostrEvent) => crypto.open(event),
    opener: () => crypto.opener(),
  }))
}

/** A group id is operator-chosen and lands in a filename here. */
function safeName(group: string): string {
  return group.replace(/[^a-zA-Z0-9._-]/g, '_')
}

/**
 * The one file this identity keeps for this channel.
 *
 * Ratchet state, sealed envelopes, the archive and the KeyPackage private half,
 * all in it — which is why `FileStore` writes 0600. Exported because
 * `renewMlsIdentity` and `forgetMlsIdentity` take the store rather than a
 * session, and because "it is all one file" is the fact an operator needs when
 * they are deciding whether to delete it.
 */
export function mlsStore(me: string, group: string): FileStore {
  return FileStore.in(home(), `mls-${me.slice(0, 8)}-${safeName(group)}`)
}

/**
 * The ratchet for one identity in one channel, whatever the policy currently says.
 *
 * Keyed per identity *and* per channel. A ratchet is a single evolving secret:
 * two channels sharing one file would each overwrite the other's state on every
 * message, and the symptom is a channel that stops opening its own messages
 * with an error from inside `ts-mls`. The `nip44` epoch map has no equivalent
 * hazard, which is why only this one is split out.
 */
async function openMlsCrypto(me: string, group: string): Promise<MlsCrypto> {
  const store = mlsStore(me, group)
  return MlsCrypto.open({
    store,
    pubkey: me,
    group,
    ciphersuite: await mlsCiphersuite(),
    // The archive is the record. On an `mls` channel the relay's copy is
    // unreadable to everyone including its author the moment the epoch turns
    // over, so this file — not the relay — is what `quorum export`, `audit` and
    // every display command are reading a month from now.
    archive: new Archive(store),
    envelopes: new SealedEnvelopes(store),
    log: { warn: (m) => console.error(yellow(String(m))) },
  })
}

/**
 * This session's ratchet, built on demand if the policy did not call for one.
 *
 * The one caller that needs the second half is `channel encrypt --mls`, which
 * runs against a channel that is still plaintext and therefore has a
 * `ChannelCrypto` in the session. Making it re-open the session after
 * publishing the policy would work and would be worse: the group has to exist
 * before the policy announcing it does, or the channel spends the gap refusing
 * plaintext with no ratchet to write to instead.
 *
 * Same store either way, so the `MlsCrypto` this returns is the one the next
 * command will load.
 */
export async function mlsFor(session: Session): Promise<MlsCrypto> {
  return session.channel.mls ?? openMlsCrypto(session.me, session.config.group)
}

/**
 * The KeyPackage this identity holds for this channel, minted on first use.
 *
 * Deliberately the same store as the ratchet, and deliberately not regenerated:
 * see `mls-identity.ts` in the SDK. The console is where the failure it
 * prevents actually happens — a command that generates a package, publishes it
 * and exits has nowhere else to keep the private half, and the member it
 * invites can never be added.
 */
export async function mlsIdentityFor(session: Session): Promise<MlsIdentity> {
  const group = session.config.group
  return mlsIdentity({
    store: mlsStore(session.me, group),
    group,
    pubkey: session.me,
    ciphersuite: await mlsCiphersuite(),
  })
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
  return session.channel.readable(await groupEvents(session))
}

/**
 * The `open` hook for {@link verifyActionChains}, or nothing on a plaintext channel.
 *
 * Returns `undefined` per event we have no key for rather than throwing, so one
 * missing epoch costs that event and not the whole audit.
 *
 * Async because of `mls`, where an opener is only as good as what has already
 * been through the ratchet: this reads the channel once to warm the archive and
 * then hands back the sync lookup. A synchronous version would have compiled,
 * returned an opener that answered `undefined` to everything, and reported an
 * encrypted channel's honest chains as unverifiable.
 */
export async function opener(
  session: Session,
): Promise<(event: NostrEvent) => NostrEvent | undefined> {
  if (session.channel.mls) await readableEvents(session)
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
