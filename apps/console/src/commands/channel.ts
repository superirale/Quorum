/**
 * Turning a channel's encryption on, rotating it, and seeing who can read it.
 *
 * Four commands, and the interesting thing about them is how little they do.
 * Encrypting a channel is `rotateChannelKey` — mint an epoch, wrap it for every
 * member, publish the policy — and everything downstream follows from the
 * policy event without being told. The console does not seal anything here; the
 * session's `ChannelCrypto` does that for every command equally.
 *
 * The one thing this file insists on is that an operator cannot be vague. Three
 * of these four commands change who can read a channel, and each refuses the
 * case where the operator plainly meant the other one:
 *
 *   - `encrypt` refuses an already-encrypted channel, because the person typing
 *     it believes the channel is in the clear, and they are wrong about
 *     something.
 *   - `rotate` refuses a plaintext one, because a rotation that silently
 *     *enabled* encryption would be a much bigger change than the word implies.
 *   - `plaintext` takes `--confirm`, because it is the only command in this
 *     console that makes a private channel public, and it does so silently:
 *     nothing fails afterwards, no ciphertext breaks, messages simply start
 *     arriving readable.
 *
 * `keys` changes nothing and is the one to run first. On an encrypted channel
 * the question "can this agent actually read us" has no other answer — a locked
 * out member looks exactly like a quiet one.
 */

import {
  AddressableKinds,
  ChannelKeyBody,
  RegularKinds,
  addressees,
  type NostrEvent,
} from '@quorum/protocol'
import { channelMembers, rotateChannelKey, wrapChannelKey } from '@quorum/sdk'
import { bool, flag, flagAll, int, type ParsedArgs } from '../args.ts'
import { bold, cyan, dim, green, red, short, when, yellow } from '../format.ts'
import { open, resolvePubkey, type Session } from '../session.ts'

export async function channel(args: ParsedArgs): Promise<void> {
  const sub = args.words[1] ?? 'status'
  switch (sub) {
    case 'status':
      return withSession(args, status)
    case 'keys':
      return withSession(args, keys)
    case 'encrypt':
      return withSession(args, encrypt)
    case 'rotate':
      return withSession(args, rotate)
    case 'key':
      return withSession(args, handKey)
    case 'plaintext':
      return withSession(args, declassify)
    default:
      throw new Error(
        'usage: quorum channel [status] | keys | encrypt | rotate | key <who> | plaintext --confirm',
      )
  }
}

async function withSession(
  args: ParsedArgs,
  run: (session: Session, args: ParsedArgs) => Promise<void>,
): Promise<void> {
  const session = await open(flag(args, 'as'))
  try {
    await run(session, args)
  } finally {
    session.close()
  }
}

async function status(session: Session): Promise<void> {
  const { policy, epochs } = session.channel
  console.log(`${bold(`#${session.config.group}`)} ${dim(`on ${session.config.relay}`)}`)
  console.log(`  mode    ${policy.enc === 'plaintext' ? yellow('plaintext') : green(policy.enc)}`)
  if (policy.epoch !== undefined) console.log(`  writing epoch ${cyan(String(policy.epoch))}`)
  if (policy.reason) console.log(`  reason  ${policy.reason}`)
  if (policy.author) console.log(`  set by  ${dim(short(policy.author))}`)

  if (policy.enc === 'plaintext') {
    console.log(
      dim('\n  The relay can read every message in this channel, and so can anyone it serves.'),
    )
    console.log(dim('  `quorum channel encrypt` changes that.'))
    return
  }

  console.log(`  ${bold(session.name)} holds ${epochs.length ? cyan(epochs.join(', ')) : red('nothing')}`)
  if (policy.epoch !== undefined && !epochs.includes(policy.epoch)) {
    // The failure this line exists for: the console can still read history and
    // still publish an unsealed kind, so the first symptom of being locked out
    // is usually a message that never appears.
    console.log(red(`  cannot write — nobody has wrapped epoch ${policy.epoch} for this identity`))
  }
}

/**
 * Who has been handed which epoch, read off the relay's own 8110s.
 *
 * This is the membership list that matters on an encrypted channel, and it is
 * not the same list as the relay's. A member with no wrap is in the group,
 * counted by `workspace members`, indexed by every filter — and cannot read a
 * word. The gap opens by itself: somebody is added between two rotations and
 * nobody notices until they say so.
 *
 * The wraps are public by design (see `ChannelKeyBody`), so this needs no key
 * and anyone can run it. "Who can read this channel" being answerable is worth
 * more than hiding it, especially to whoever is responsible for the workspace.
 */
async function keys(session: Session): Promise<void> {
  const group = session.config.group
  const wraps = await session.client.query([
    { kinds: [RegularKinds.ChannelKey], '#h': [group], limit: 1000 },
  ])

  if (!wraps.length) {
    console.log(`no channel keys have ever been issued in ${bold(`#${group}`)}`)
    return
  }

  const byEpoch = new Map<number, Map<string, NostrEvent>>()
  for (const wrap of wraps) {
    const body = ChannelKeyBody.safeParse(JSON.parse(wrap.content))
    if (!body.success) continue
    const holders = byEpoch.get(body.data.epoch) ?? new Map<string, NostrEvent>()
    // The `to` tag is the routing one and `recipient` is the body's copy; they
    // are required to agree, so a disagreement is worth showing rather than
    // resolving silently.
    for (const to of addressees(wrap.tags)) holders.set(to, wrap)
    byEpoch.set(body.data.epoch, holders)
  }

  const members = new Set(await channelMembers(session.client, group))
  const current = session.channel.policy.epoch

  for (const epoch of [...byEpoch.keys()].sort((a, b) => a - b)) {
    const holders = byEpoch.get(epoch)!
    const mark = epoch === current ? green('→') : ' '
    console.log(`${mark} epoch ${bold(String(epoch))} ${dim(`${holders.size} holder(s)`)}`)
    for (const [holder, wrap] of holders) {
      const note = members.has(holder) ? '' : yellow('no longer a member')
      console.log(`    ${short(holder)} ${dim(`by ${short(wrap.pubkey)} ${when(wrap.created_at)}`)} ${note}`)
    }
  }

  if (current !== undefined) {
    const holders = byEpoch.get(current) ?? new Map()
    const missing = [...members].filter((m) => !holders.has(m))
    if (missing.length) {
      console.log(
        `\n${yellow('!')} in the group and unable to read it: ${missing.map(short).join(', ')}`,
      )
      console.log(dim('  `quorum channel key <who>` hands them the current epoch.'))
    }
  }
}

async function encrypt(session: Session, args: ParsedArgs): Promise<void> {
  if (session.channel.encrypted) {
    throw new Error(
      `#${session.config.group} is already encrypted, writing under epoch ${session.channel.policy.epoch}. ` +
        'Use `quorum channel rotate` to mint a new epoch.',
    )
  }
  await mint(session, args, 'encrypted')
}

async function rotate(session: Session, args: ParsedArgs): Promise<void> {
  if (!session.channel.encrypted) {
    throw new Error(
      `#${session.config.group} is not encrypted, so there is nothing to rotate. ` +
        'Use `quorum channel encrypt` to turn encryption on.',
    )
  }
  await mint(session, args, 'rotated')
}

/**
 * Mint an epoch and hand it out. Both `encrypt` and `rotate` are this.
 *
 * They are the same operation on the wire — a fresh key, one wrap per member, a
 * policy naming the new epoch — and the difference is entirely in what the
 * operator believes is true beforehand. Keeping one implementation means the
 * first rotation of a channel's life is not a separate code path that gets
 * exercised once.
 */
async function mint(session: Session, args: ParsedArgs, verb: string): Promise<void> {
  const group = session.config.group
  const listed = await channelMembers(session.client, group)
  // `--to` repeated overrides the relay's member list, which is how a removal
  // is completed: take them out with `workspace remove`, then rotate. Passing
  // it explicitly also covers the case the relay has not caught up with.
  const named = flagAll(args, 'to')
  const only = named.length ? await Promise.all(named.map(resolvePubkey)) : undefined
  const members = only ?? listed

  const rotation = await rotateChannelKey({
    publisher: session.publisher,
    client: session.client,
    signer: session.signer,
    group,
    members,
    ...(flag(args, 'reason') ? { reason: flag(args, 'reason')! } : {}),
  })

  console.log(`${green('✓')} ${bold(`#${group}`)} ${verb} — epoch ${bold(String(rotation.epoch))}`)
  console.log(`  wrapped for ${rotation.wraps.length}: ${members.map(short).join(', ')}`)
  console.log(`  policy  ${dim(short(rotation.policy.id))}`)

  if (only) {
    const dropped = listed.filter((m) => !only.includes(m))
    if (dropped.length) {
      console.log(yellow(`  not wrapped for ${dropped.map(short).join(', ')} — still in the group`))
    }
  }

  // Said on every rotation, because it is the thing people assume and it is not
  // true. Rotation controls the future; nothing controls the past.
  console.log(
    dim(
      '\n  Anyone who held an earlier epoch can still read everything written under it,\n' +
        '  forever. A rotation decides who reads what is said next, and nothing else.',
    ),
  )
}

/** The join path: hand a member an epoch that already exists. */
async function handKey(session: Session, args: ParsedArgs): Promise<void> {
  const who = args.words[2]
  if (!who) throw new Error('usage: quorum channel key <name|pubkey> [--epoch n] [--all]')
  if (!session.channel.encrypted) throw new Error(`#${session.config.group} is not encrypted`)

  const member = await resolvePubkey(who)
  const current = session.channel.policy.epoch
  const chosen = int(args, 'epoch')

  // Which epochs a joiner may read is a judgement nobody else can make, so the
  // console asks rather than guessing: the current one by default, all of them
  // with `--all`, one named epoch with `--epoch`.
  const epochs = bool(args, 'all')
    ? session.channel.epochs
    : chosen !== undefined
      ? [chosen]
      : current !== undefined
        ? [current]
        : []
  if (!epochs.length) throw new Error('nothing to hand over: this channel has no epoch')

  for (const epoch of epochs) {
    const key = session.channel.keyFor(epoch)
    if (!key) {
      throw new Error(
        `${bold(session.name)} does not hold epoch ${epoch}, so it cannot hand it to anyone. ` +
          `Held: ${session.channel.epochs.join(', ') || 'nothing'}.`,
      )
    }
    await wrapChannelKey({
      publisher: session.publisher,
      signer: session.signer,
      group: session.config.group,
      member,
      epoch,
      key,
    })
    console.log(`${green('✓')} ${short(member)} can now read epoch ${bold(String(epoch))}`)
  }

  if (!bool(args, 'all') && session.channel.epochs.length > epochs.length) {
    console.log(
      dim(`  earlier epochs were not handed over — \`--all\` gives them the channel's history.`),
    )
  }
}

/**
 * Turn encryption off.
 *
 * Here because a policy an operator can only ever set one way is half a policy,
 * and because the alternative — hand-crafting a 38107 — is worse than a command
 * that at least prints what it is about to do.
 *
 * It does not decrypt anything. Every message already on the relay keeps its
 * `enc` tag and stays sealed under the epoch that sealed it; members holding
 * those keys go on reading them. What changes is that everything said *next* is
 * written in the clear, and the relay stops refusing plaintext — which is
 * exactly the silent part, and why this one asks twice.
 */
async function declassify(session: Session, args: ParsedArgs): Promise<void> {
  const group = session.config.group
  if (!session.channel.encrypted) throw new Error(`#${group} is already plaintext`)

  if (!bool(args, 'confirm')) {
    console.log(`${red('!')} this makes ${bold(`#${group}`)} readable by the relay from now on.`)
    console.log('  Everything written after it lands in the clear, and nothing fails to warn you:')
    console.log('  no ciphertext breaks, no reader errors, messages simply stop being private.')
    console.log(dim('\n  Add --confirm if that is what you want.'))
    return
  }

  const event = await session.publisher.publish({
    kind: AddressableKinds.ChannelPolicy,
    group,
    d: group,
    body: {
      enc: 'plaintext',
      ...(flag(args, 'reason') ? { reason: flag(args, 'reason')! } : {}),
      changed_at: Math.floor(Date.now() / 1000),
    },
  })

  console.log(`${green('✓')} ${bold(`#${group}`)} is plaintext ${dim(short(event.id))}`)
  console.log(dim('  History stays sealed. Only new messages are affected.'))
}
