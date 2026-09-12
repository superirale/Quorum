/**
 * The workspace: a NIP-29 group on the relay.
 *
 * Borrowed wholesale, which is why `add` and `members` are the only commands
 * here that publish or read events with no Quorum envelope. Membership is the
 * relay's business; what a member may *do* is the capability system's, and the
 * two are kept apart deliberately — a member with no grant can talk and can do
 * nothing.
 *
 * Getting *in*, though, is now a capability like any other. There are two ways
 * and only two: an admin says so directly (`add`, a NIP-29 put-user), or an
 * admin signs an invitation the holder presents themselves (`invite`, a
 * `group:join` grant). They differ in who has to be there: `add` needs the
 * pubkey in hand now, `invite` can be issued to a key that has not been
 * generated yet and handed over with it.
 */

import { Resource, TagName, tagValue, type NostrEvent } from '@quorum/protocol'
import { Grants } from '@quorum/sdk'
import { flag, int, type ParsedArgs } from '../args.ts'
import { loadConfig, saveConfig } from '../config.ts'
import { bold, dim, green, short, yellow } from '../format.ts'
import { NIP29, open, publishRaw, resolvePubkey } from '../session.ts'

export async function workspace(args: ParsedArgs): Promise<void> {
  const sub = args.words[1]
  if (sub === 'create') return create(args)
  if (sub === 'add') return add(args)
  if (sub === 'invite') return invite(args)
  if (sub === 'join') return join(args)
  if (sub === 'remove') return remove(args)
  if (sub === 'members') return members(args)
  if (sub === 'use') return useGroup(args)
  throw new Error('usage: quorum workspace <create|add|invite|join|remove|members|use>')
}

async function create(args: ParsedArgs): Promise<void> {
  const group = args.words[2]
  if (!group) throw new Error('usage: quorum workspace create <group>')

  // The group name is set here rather than read from config, because creating
  // a workspace you did not name is a way to create the wrong one.
  process.env.QUORUM_GROUP = group
  const session = await open(flag(args, 'as'))
  try {
    await publishRaw(session, { kind: NIP29.createGroup, tags: [['h', group]], content: '' })
    // Made the default immediately. The alternative is every subsequent command
    // needing `--group`, and the first one you forget goes to whatever group was
    // configured before — which is a quiet way to grant a capability in the
    // wrong workspace.
    await saveConfig({ ...(await loadConfig()), group })
    console.log(`${green('✓')} created ${bold(`#${group}`)}, with ${bold(session.name)} as admin`)
    console.log(dim(`  nobody else is in it yet: ${bold('workspace add')} to admit a key you have,`))
    console.log(dim(`  ${bold('workspace invite')} to sign an invitation somebody presents later.`))
  } finally {
    session.close()
  }
}

async function add(args: ParsedArgs): Promise<void> {
  const who = args.words[2]
  if (!who) throw new Error('usage: quorum workspace add <name|pubkey>')

  const session = await open(flag(args, 'as'))
  try {
    const pubkey = await resolvePubkey(who)
    await publishRaw(session, {
      kind: NIP29.putUser,
      tags: [
        ['h', session.config.group],
        ['p', pubkey],
      ],
      content: '',
    })
    console.log(`${green('✓')} admitted ${bold(who)} ${dim(short(pubkey))} to #${session.config.group}`)
  } finally {
    session.close()
  }
}

/**
 * Sign an invitation: a `group:join` grant scoped to this workspace.
 *
 * The grantee publishes a NIP-29 join request whenever they like and the relay
 * checks this signature before admitting them. Three things follow from it
 * being a grant rather than a row:
 *
 * - It can be issued to a key that does not exist yet, then handed over with
 *   the key — which is the ordinary case for an agent someone else will run.
 * - It can be revoked, and `quorum revoke <who> group:join` does that.
 * - The grantee can be shown exactly what they were given, and a third party
 *   can check who gave it, without asking the relay to be believed.
 *
 * Always scoped to the current group, and `--expires` is encouraged rather than
 * required: the relay refuses to honour `--max-uses` on a `group:join`, because
 * it has no caller to ask how many times it has been used, so an invitation
 * that should not stand forever has to bound itself by time.
 */
async function invite(args: ParsedArgs): Promise<void> {
  const who = args.words[2]
  if (!who) throw new Error('usage: quorum workspace invite <name|pubkey> [--expires <seconds>]')

  const session = await open(flag(args, 'as'))
  try {
    const grantee = await resolvePubkey(who)
    const expiresIn = int(args, 'expires')
    const grants = new Grants({
      client: session.client,
      group: session.config.group,
      publisher: session.publisher,
    })
    const event = await grants.issue({
      grantee,
      resource: Resource.Join,
      actions: ['invoke'],
      scope: { group: session.config.group },
      ...(expiresIn !== undefined
        ? { expiresAt: Math.floor(Date.now() / 1000) + expiresIn }
        : {}),
    })

    console.log(
      `${green('✓')} ${bold(session.name)} invited ${bold(who)} ${dim(short(grantee))} to #${session.config.group}`,
    )
    console.log(`  event   ${dim(short(event.id))}`)
    if (expiresIn === undefined) {
      console.log(dim('  no expiry — it stands until revoked. --expires <seconds> bounds it.'))
    }
    console.log(dim('  they are not a member yet; they become one when they present it.'))
  } finally {
    session.close()
  }
}

/**
 * Put somebody out: a NIP-29 remove-user.
 *
 * This exists because `revoke <who> group:join` does not do it, and an operator
 * would reasonably expect it to. Withdrawing an invitation stops it being
 * redeemed again; it does not undo a membership already granted, any more than
 * cancelling a keycard un-enters the building. The two questions are asked at
 * different moments, so they need different commands — and the one that ends an
 * existing membership is this one.
 *
 * Revoke as well, though, or the removed key walks back in with the invitation
 * it still holds.
 */
async function remove(args: ParsedArgs): Promise<void> {
  const who = args.words[2]
  if (!who) throw new Error('usage: quorum workspace remove <name|pubkey>')

  const session = await open(flag(args, 'as'))
  try {
    const pubkey = await resolvePubkey(who)
    await publishRaw(session, {
      kind: NIP29.removeUser,
      tags: [
        ['h', session.config.group],
        ['p', pubkey],
      ],
      content: '',
    })
    console.log(`${green('✓')} removed ${bold(who)} ${dim(short(pubkey))} from #${session.config.group}`)
    console.log(dim(`  any ${Resource.Join} they hold still stands — ${bold('quorum revoke')} it too.`))
  } finally {
    session.close()
  }
}

/**
 * Present an invitation: publish the NIP-29 join request and wait to be let in.
 *
 * The other half of `invite`, and the reason it is here rather than left to the
 * SDK: an invitation nobody using this tool can redeem is a feature with one
 * end. The relay does the deciding — it reads the grant, checks the issuer is
 * an admin of this group, and signs the put-user itself — so there is nothing
 * to pass in. Either somebody invited you or they did not.
 */
async function join(args: ParsedArgs): Promise<void> {
  const session = await open(flag(args, 'as'))
  try {
    await publishRaw(session, {
      kind: NIP29.joinRequest,
      tags: [['h', session.config.group]],
      content: '',
    })

    // The relay admits on a post-save hook, so the request being accepted is not
    // yet the membership being real. 39002 is the relay's own signed member
    // list, which is the one answer that cannot be ahead of the thing it states.
    const deadline = Date.now() + 5_000
    while (Date.now() < deadline) {
      const [list] = await session.client.query([
        { kinds: [39002], '#d': [session.config.group], limit: 1 },
      ])
      if (list && pubkeys(list).includes(session.signer.publicKey)) {
        console.log(`${green('✓')} ${bold(session.name)} is now a member of #${session.config.group}`)
        return
      }
      await new Promise((resolve) => setTimeout(resolve, 200))
    }
    console.log(yellow(`the relay accepted the request but has not admitted ${session.name} yet`))
  } finally {
    session.close()
  }
}

async function members(args: ParsedArgs): Promise<void> {
  const session = await open(flag(args, 'as'))
  try {
    // relay29 maintains kind 39002 as the group's member list and signs it, so
    // this is the relay's own statement of who is in — not a scan of who has
    // published, which would miss a silent member and count a stranger whose
    // event was rejected.
    const [list] = await session.client.query([
      { kinds: [39002], '#d': [session.config.group], limit: 1 },
    ])
    if (!list) {
      console.log(yellow(`no member list for #${session.config.group} — does the group exist?`))
      return
    }
    console.log(`${bold(`#${session.config.group}`)} ${dim(`as of ${new Date(list.created_at * 1000).toLocaleTimeString()}`)}`)
    for (const pubkey of pubkeys(list)) {
      console.log(`  ${pubkey}`)
    }
  } finally {
    session.close()
  }
}

async function useGroup(args: ParsedArgs): Promise<void> {
  const group = args.words[2]
  if (!group) throw new Error('usage: quorum workspace use <group>')
  await saveConfig({ ...(await loadConfig()), group })
  console.log(`${green('✓')} now working in ${bold(`#${group}`)}`)
}

function pubkeys(list: NostrEvent): string[] {
  return list.tags.filter((t) => t[0] === TagName.Pubkey && t[1]).map((t) => t[1]!)
}

/** Exported for the tests: what the relay's signed member list claims. */
export function memberList(events: readonly NostrEvent[], group: string): string[] {
  const list = events
    .filter((e) => e.kind === 39002 && tagValue(e.tags, TagName.Identifier) === group)
    .sort((a, b) => b.created_at - a.created_at)[0]
  return list ? pubkeys(list) : []
}
