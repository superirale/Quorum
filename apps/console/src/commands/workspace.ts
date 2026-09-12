/**
 * The workspace: a NIP-29 group on the relay.
 *
 * Borrowed wholesale, which is why these are the only commands here that
 * publish events with no Quorum envelope. Membership is the relay's business;
 * what a member may *do* is the capability system's, and the two are kept
 * apart deliberately — a member with no grant can talk and can do nothing.
 */

import { TagName, tagValue, type NostrEvent } from '@quorum/protocol'
import { flag, type ParsedArgs } from '../args.ts'
import { loadConfig, saveConfig } from '../config.ts'
import { bold, dim, green, short, yellow } from '../format.ts'
import { NIP29, open, publishRaw, resolvePubkey } from '../session.ts'

export async function workspace(args: ParsedArgs): Promise<void> {
  const sub = args.words[1]
  if (sub === 'create') return create(args)
  if (sub === 'add') return add(args)
  if (sub === 'members') return members(args)
  if (sub === 'use') return useGroup(args)
  throw new Error('usage: quorum workspace <create|add|members|use>')
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
    console.log(
      dim(
        '  the relay will admit anyone who asks to join — a known gap, still open.\n' +
          '  Until it closes, treat group membership as a convenience and the grant as the control.',
      ),
    )
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
