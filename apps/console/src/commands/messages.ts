/** Talking to an agent, and watching what comes back. */

import { Kinds, TagName, tagValue, type NostrEvent } from '@quorum/protocol'
import { channelFilter, controlFilter } from '@quorum/sdk'
import { flag, type ParsedArgs } from '../args.ts'
import { bold, cyan, describe, dim, green, short, when, yellow } from '../format.ts'
import { open, resolvePubkey } from '../session.ts'

export async function say(args: ParsedArgs): Promise<void> {
  const text = args.words.slice(1).join(' ')
  if (!text) throw new Error('usage: quorum say "<text>" --to <name|pubkey>')

  const to = flag(args, 'to')
  const session = await open(flag(args, 'as'))
  try {
    const addressees = to ? [await resolvePubkey(to)] : []
    const event = await session.publisher.publish({
      kind: Kinds.Thread,
      text,
      to: addressees,
      tags: [['title', flag(args, 'title') ?? text.slice(0, 60)]],
    })

    console.log(`${green('✓')} posted ${dim(short(event.id))} to #${session.config.group}`)
    if (!addressees.length) {
      // Worth saying every time. The agent is not being rude; `to` is the only
      // addressing signal there is, and an agent that answered prose naming it
      // would be the bug this project exists to avoid.
      console.log(
        yellow('  addressed to nobody — no agent will act on this.') +
          dim(' Use --to <who> to address it.'),
      )
    }
  } finally {
    session.close()
  }
}

export async function watch(args: ParsedArgs): Promise<void> {
  const session = await open(flag(args, 'as'))
  const group = session.config.group

  console.log(`${bold(`#${group}`)} ${dim(`on ${session.config.relay} — ctrl-c to stop`)}\n`)

  const show = (event: NostrEvent) => {
    const alt = tagValue(event.tags, TagName.Alt)
    const mine = event.pubkey === session.me
    const who = mine ? bold(session.name) : short(event.pubkey)
    // The `alt` tag is doing the work here, and this is exactly the case the
    // spec requires it for: a reader that has never heard of kind 8102 still
    // gets a usable line out of it.
    console.log(
      `${dim(when(event.created_at))} ${cyan(String(event.kind).padStart(5))} ${who.padEnd(10)} ${describe(event.kind, alt, event.content)}`,
    )
  }

  session.client.subscribe(
    [channelFilter({ group, limit: 20 }), controlFilter({ group })],
    { onEvent: show },
  )

  await new Promise<void>((resolve) => {
    for (const signal of ['SIGINT', 'SIGTERM'] as const) {
      process.once(signal, () => {
        session.close()
        resolve()
      })
    }
  })
}
