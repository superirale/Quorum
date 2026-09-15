/**
 * Getting into an `mls` channel, and getting other people in.
 *
 * Five commands for what `nip44` does in one. Under `nip44` an admin wraps the
 * channel key for a member and that member can read; the whole exchange is one
 * event and one decision. MLS is a ratchet, so joining is a handshake with three
 * parties to it — the joiner, an existing member, and the delivery service that
 * decides whose commit is the next epoch — and each step can be the last one
 * that happened:
 *
 *   quorum mls keypackage   the joiner offers a way in                 (30443)
 *   quorum mls invite <who> a member takes the offer and commits  (8112 + 8111)
 *   quorum mls join         the joiner opens the Welcome and is in
 *   quorum mls catchup      every *other* member follows the commit
 *   quorum mls members      what the ratchet tree says, next to what the relay says
 *
 * `catchup` looks like plumbing and is the command this file exists for. A
 * member who misses one commit cannot read anything published after it, ever —
 * MLS has no mechanism for catching up across a commit you never held — and the
 * symptom is `CryptoError: OperationError` from inside `ts-mls`, which names no
 * epoch, no group and no member. Every command here runs it first for that
 * reason, and it is exposed separately so an operator can run it on its own.
 *
 * What none of them do is make the ratchet tree and the relay's member list
 * agree. They answer different questions — "who can read this" and "who may
 * publish here" — and both directions of disagreement are real states somebody
 * has to be told about, which is what `members` is for.
 */

import { BorrowedKinds, type NostrEvent } from '@quorum/protocol'
import {
  acceptMlsInvite,
  catchUpMls,
  channelMembers,
  fetchKeyPackages,
  fetchMlsWelcomes,
  inviteToMls,
  mlsCiphersuite,
  publishKeyPackage,
  renewMlsIdentity,
  type MlsCrypto,
  type PublishedKeyPackage,
} from '@quorum/sdk'
import { flag, type ParsedArgs } from '../args.ts'
import { bold, cyan, dim, green, red, short, yellow } from '../format.ts'
import { mlsFor, mlsIdentityFor, mlsStore, open, resolvePubkey, type Session } from '../session.ts'

export async function mls(args: ParsedArgs): Promise<void> {
  const sub = args.words[1] ?? 'members'
  switch (sub) {
    case 'keypackage':
      return withSession(args, keypackage)
    case 'invite':
      return withSession(args, invite)
    case 'join':
      return withSession(args, join)
    case 'catchup':
      return withSession(args, catchup)
    case 'members':
      return withSession(args, members)
    default:
      throw new Error('usage: quorum mls [members] | keypackage | invite <who> | join | catchup')
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

/**
 * Publish this identity's way in.
 *
 * Idempotent on purpose, and that is not a convenience. The private half is
 * stored on first use and never regenerated, so running this twice republishes
 * the same offer rather than making a second one — which matters because the
 * window between publishing and being invited is exactly when a joiner restarts,
 * and a regenerated package would silently invalidate a Welcome already in
 * flight. `quorum mls join` is what replaces it, after the join has worked.
 */
async function keypackage(session: Session): Promise<void> {
  const group = session.config.group
  const identity = await mlsIdentityFor(session)
  const event = await publishKeyPackage({
    publisher: session.publisher,
    group,
    identity,
    ciphersuite: await mlsCiphersuite(),
  })

  console.log(`${green('✓')} ${bold(session.name)} offered a KeyPackage for #${group} ${dim(short(event.id))}`)
  console.log(dim('  A member now runs `quorum mls invite ' + session.name + '`.'))
  console.log(
    dim('  Nothing happens until they do, and nothing tells you when they have —\n') +
      dim('  run `quorum mls join` to check for a Welcome.'),
  )
}

/**
 * Add members, which is a commit and therefore is about everybody.
 *
 * The named members are resolved to pubkeys and matched against the 30443s in
 * the channel, rather than the reverse, because "invite everyone who published a
 * package" is the command nobody should have. A KeyPackage is an offer from
 * whoever signed it; taking every offer in a channel is how an operator adds a
 * member they never meant to and cannot see they have added.
 */
async function invite(session: Session, args: ParsedArgs): Promise<void> {
  const group = session.config.group
  const names = args.words.slice(2)
  if (!names.length) throw new Error('usage: quorum mls invite <name|pubkey> [<name|pubkey>...]')

  const crypto = await mlsFor(session)
  if (!crypto.joined) {
    throw new Error(
      `${session.name} is not in the mls group for #${group}, so it cannot add anyone. ` +
        'A member has to invite it first — `quorum mls keypackage` offers the way in.',
    )
  }
  await follow(session, crypto)

  const wanted = new Set(await Promise.all(names.map(resolvePubkey)))
  const already = new Set(crypto.members)
  const offered = await fetchKeyPackages(session.client, group, {
    ciphersuite: await mlsCiphersuite(),
    // Reported, never silently dropped: a member missing from the commit is a
    // member who will wait for a Welcome that is not coming.
    onProblem: (event, reason) =>
      console.error(yellow(`! unusable KeyPackage from ${short(event.pubkey)}: ${reason}`)),
  })

  const chosen: PublishedKeyPackage[] = []
  for (const pubkey of wanted) {
    if (already.has(pubkey)) {
      console.log(dim(`  ${short(pubkey)} is already in the group — skipped`))
      continue
    }
    const found = offered.find((p) => p.pubkey === pubkey)
    if (!found) {
      console.log(
        `${red('!')} ${short(pubkey)} has published no usable KeyPackage for #${group}` +
          dim(' — they run `quorum mls keypackage` first'),
      )
      continue
    }
    chosen.push(found)
  }

  if (!chosen.length) {
    console.log(dim('nothing to do — nobody named here is invitable right now'))
    return
  }

  const result = await inviteToMls({
    publisher: session.publisher,
    signer: session.signer,
    crypto,
    group,
    packages: chosen,
  })
  if (!result) throw new Error('mls: the invitation produced no commit')

  console.log(
    `${green('✓')} added ${chosen.map((p) => short(p.pubkey)).join(', ')} — ` +
      `#${group} is at epoch ${cyan(String(result.epoch))}`,
  )
  console.log(dim(`  commit ${short(result.commit.id)}, ${result.welcomes.length} welcome(s)`))
  console.log(
    dim('\n  Every other member must run `quorum mls catchup` before they can read again.\n') +
      dim('  They get nothing from this channel until they do, and no error saying why.'),
  )
  console.log(
    dim('  The new members can read from this epoch forward and nothing before it.\n') +
      dim('  That is what forward secrecy is; there is no way to hand them the history.'),
  )
}

/**
 * Open a Welcome and become a member.
 *
 * Newest Welcome first, because a member who was added, removed and re-added has
 * more than one and only the newest matches the package they hold —
 * `acceptMlsInvite` returns `false` rather than throwing for exactly that, so
 * this walks the list instead of insisting on the first.
 *
 * The renewal afterwards is not tidying. The accepted Welcome consumed the init
 * key it was sealed to, so the 30443 still sitting in the relay's addressable
 * slot is an offer nobody can honour: an inviter who takes it commits an Add
 * against a private half that no longer exists, and the member they add reads
 * nothing and is told nothing. It happens in this order — join, then renew, then
 * republish — because a renewal before a successful join destroys the only key
 * that can open the Welcome that is arriving.
 */
async function join(session: Session): Promise<void> {
  const group = session.config.group
  const crypto = await mlsFor(session)
  if (crypto.joined) {
    console.log(`${bold(session.name)} is already in the mls group for #${group}`)
    return catchup(session)
  }

  const identity = await mlsIdentityFor(session)
  const welcomes = await fetchMlsWelcomes(session.client, session.me, group)
  if (!welcomes.length) {
    console.log(`no Welcome for ${bold(session.name)} in #${group}`)
    console.log(
      dim('  Either nobody has invited this identity yet, or it never offered a way in:\n') +
        dim('  `quorum mls keypackage` publishes one. There is no notification either way.'),
    )
    return
  }

  let joined = false
  for (const event of welcomes) {
    if (
      await acceptMlsInvite({
        signer: session.signer,
        crypto,
        identity,
        event,
        ciphersuite: await mlsCiphersuite(),
      })
    ) {
      joined = true
      console.log(`${green('✓')} joined #${group} at epoch ${cyan(String(crypto.epoch))} ${dim(short(event.id))}`)
      break
    }
  }

  if (!joined) {
    console.log(
      `${red('!')} ${welcomes.length} Welcome(s) for ${bold(session.name)}, none for the KeyPackage it holds`,
    )
    console.log(
      dim('  The package this identity offers was replaced after the invitation was built.\n') +
        dim('  Ask a member to `quorum mls invite` again; the current offer is still published.'),
    )
    return
  }

  await follow(session, crypto)

  const fresh = await renewMlsIdentity({
    store: mlsStore(session.me, group),
    group,
    pubkey: session.me,
    ciphersuite: await mlsCiphersuite(),
  })
  const offer = await publishKeyPackage({
    publisher: session.publisher,
    group,
    identity: fresh,
    ciphersuite: await mlsCiphersuite(),
  })
  console.log(dim(`  spent KeyPackage replaced ${short(offer.id)}`))
  console.log(
    dim('\n  Everything said in this channel before now is unreadable to this identity,\n') +
      dim('  permanently. The keys are deleted; there is nobody who can hand them over.'),
  )
}

/** Apply every commit this member has not seen. */
async function catchup(session: Session): Promise<void> {
  const crypto = await mlsFor(session)
  if (!crypto.joined) {
    throw new Error(
      `${session.name} is not in the mls group for #${session.config.group} — ` +
        'there is nothing to catch up on. Run `quorum mls join`.',
    )
  }
  const applied = await catchUpMls(session.client, crypto, session.config.group)
  console.log(
    applied
      ? `${green('✓')} applied ${applied} commit(s) — now at epoch ${cyan(String(crypto.epoch))}`
      : `${bold(session.name)} is up to date at epoch ${cyan(String(crypto.epoch))}`,
  )
}

/** The same, quietly, as a precondition of something else. */
async function follow(session: Session, crypto: MlsCrypto): Promise<void> {
  await catchUpMls(session.client, crypto, session.config.group)
}

/**
 * Two membership lists, side by side, because neither is the answer.
 *
 * The ratchet tree says who can read the channel. The relay's NIP-29 list says
 * who may publish into it. They are maintained by different acts and can
 * disagree in both directions, and each disagreement is a different problem:
 *
 *   in the tree, not at the relay — reads everything, cannot say anything, and
 *     the relay refuses their events with "unknown member". Looks to them like
 *     a channel that has gone quiet.
 *   at the relay, not in the tree — publishes ciphertext nobody can open and
 *     receives ciphertext they cannot read. Looks like a member who has stopped
 *     participating.
 *
 * A removal has to be performed in both places and neither is sufficient alone:
 * `workspace remove` stops them publishing here and leaves them reading the
 * channel from any other relay that carries it, and only an MLS Remove commit
 * ends that.
 */
async function members(session: Session): Promise<void> {
  const group = session.config.group
  if (!session.channel.mls) {
    throw new Error(
      `#${group} is ${session.channel.enc}, not mls — it has no ratchet tree. ` +
        'Use `quorum channel keys` to see who holds which epoch.',
    )
  }

  const crypto = session.channel.mls
  if (!crypto.joined) {
    console.log(`${bold(session.name)} ${red('is not in the mls group')} for #${group}`)
    console.log(dim('  The ratchet tree is only legible to members, so there is nothing to show.'))
    console.log(dim('  `quorum mls keypackage` offers a way in; a member then invites you.'))
    return
  }

  await follow(session, crypto)

  const offers = await session.client.query([
    { kinds: [BorrowedKinds.MlsKeyPackage], '#h': [group], limit: 500 },
  ])
  const rows = membership({
    tree: crypto.members,
    relay: await channelMembers(session.client, group),
    offering: offers.map((e: NostrEvent) => e.pubkey),
  })

  console.log(`${bold(`#${group}`)} ${dim('mls')} epoch ${cyan(String(crypto.epoch))}`)
  for (const row of rows.members) {
    const me = row.pubkey === session.me ? ` ${dim('(you)')}` : ''
    const mark = row.standing === 'both' ? green('✓') : yellow('!')
    console.log(`  ${mark} ${short(row.pubkey)}${me}  ${colour(row.standing)(STANDING[row.standing])}`)
  }

  if (rows.waiting.length) {
    console.log(
      `\n${yellow('!')} offering a KeyPackage and not in the group: ${rows.waiting.map(short).join(', ')}`,
    )
    console.log(dim('  `quorum mls invite <who>` adds them. Nothing else will.'))
  }
}

/** Which of the two lists a pubkey is on. */
export type Standing = 'both' | 'ratchet-only' | 'relay-only'

export interface MembershipRow {
  pubkey: string
  standing: Standing
}

/**
 * The sentence each standing gets, kept next to the type rather than inline.
 *
 * Separated out because the two disagreements are opposites and the wrong one is
 * a plausible-looking line. "Can read, cannot publish" and "publishes what
 * nobody can open" describe the same person seen from the two lists, and an
 * operator reading the wrong sentence goes and fixes the list that was already
 * correct — adding to the relay somebody who needed adding to the ratchet, which
 * changes nothing and looks like it did.
 */
export const STANDING: Record<Standing, string> = {
  both: 'reads and writes',
  'ratchet-only': 'in the ratchet, not a relay member — can read, cannot publish here',
  'relay-only': 'a relay member, not in the ratchet — publishes what nobody can open',
}

function colour(standing: Standing): (s: string) => string {
  return standing === 'both' ? dim : standing === 'ratchet-only' ? yellow : red
}

/**
 * Fold the two lists and the outstanding offers into rows, sorted.
 *
 * Pure, and exported for the tests, because this is the layer where a correct
 * value becomes a false sentence: every input here is a set of hex strings that
 * some other component got right, and the only thing that can be wrong is what
 * this says about them.
 *
 * `waiting` is deliberately measured against the *ratchet* and not against the
 * relay's list. A member of the workspace who has published a KeyPackage and is
 * not in the tree is precisely the person who needs inviting; dropping them
 * because the relay already counts them as a member is how somebody sits in a
 * channel reading nothing while both lists look plausible.
 */
export function membership(lists: {
  tree: readonly string[]
  relay: readonly string[]
  offering: readonly string[]
}): { members: MembershipRow[]; waiting: string[] } {
  const tree = new Set(lists.tree)
  const relay = new Set(lists.relay)
  const members = [...new Set([...tree, ...relay])].sort().map((pubkey) => ({
    pubkey,
    standing: (tree.has(pubkey)
      ? relay.has(pubkey)
        ? 'both'
        : 'ratchet-only'
      : 'relay-only') as Standing,
  }))
  const waiting = [...new Set(lists.offering)].filter((p) => !tree.has(p)).sort()
  return { members, waiting }
}
