/** Talking to an agent, and watching what comes back. */

import { Kinds, TagName, isMlsSealed, tagValue, type NostrEvent } from '@quorum/protocol'
import { channelFilter, controlFilter } from '@quorum/sdk'
import { flag, type ParsedArgs } from '../args.ts'
import { bold, cyan, describe, dim, green, red, short, when, yellow } from '../format.ts'
import { open, resolvePubkey, type ChannelView } from '../session.ts'

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

    const how = session.channel.encrypted ? green(`sealed under ${sealing(session.channel)}`) : dim('in the clear')
    console.log(`${green('✓')} posted ${dim(short(event.id))} to #${session.config.group} ${how}`)
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

/**
 * Which epoch, and which kind of epoch.
 *
 * Both modes have a number called `epoch` and they are read from different
 * places, which is the whole reason this is a function. Under `nip44` the
 * channel policy states it, so it is the same number for everyone and a client
 * that has never held a key can still print it. Under `mls` no policy may carry
 * one — the ratchet is the only thing that knows, and this identity's ratchet
 * may be behind the group's. Naming the mode is what stops "epoch 3" being read
 * as a fact about the channel when it is a fact about this console.
 */
export function sealing(channel: ChannelView): string {
  if (!channel.mls) return `epoch ${channel.policy.epoch}`
  return channel.epoch === undefined
    ? 'MLS, not in the group'
    : `MLS epoch ${channel.epoch} ${dim('(this identity’s)')}`
}

/**
 * The line for an event this identity cannot open, and the two different
 * sentences behind it.
 *
 * Under `nip44` this is a missing wrap and it has a cure somebody can perform:
 * a member who holds the epoch runs `quorum channel key <who>` and the history
 * opens. Under `mls` the keys are deleted by design, so there is nobody to ask.
 * Printing the `nip44` wording on an `mls` channel would send an operator
 * looking for a member to chase.
 */
export function noKey(event: NostrEvent): string {
  const epoch = tagValue(event.tags, TagName.Epoch) ?? '?'
  return isMlsSealed(event)
    ? red(`sealed to MLS epoch ${epoch} — unreadable to this identity, permanently`)
    : red(`sealed under epoch ${epoch} — no key`)
}

export async function watch(args: ParsedArgs): Promise<void> {
  const session = await open(flag(args, 'as'))
  const group = session.config.group

  const mode = session.channel.encrypted ? green(`sealed, ${sealing(session.channel)}`) : yellow('plaintext')
  console.log(`${bold(`#${group}`)} ${dim(`on ${session.config.relay}`)} ${mode} ${dim('— ctrl-c to stop')}\n`)

  const line = async (event: NostrEvent): Promise<void> => {
    const alt = tagValue(event.tags, TagName.Alt)
    const mine = event.pubkey === session.me
    const who = mine ? bold(session.name) : short(event.pubkey)
    // Opened for display only. An event we have no key for is shown as a line
    // saying so rather than skipped: "there is traffic here I cannot read" is a
    // different fact from "the channel is quiet", and on an encrypted channel
    // it is the one an operator needs.
    //
    // `open()` can still throw on `mls` after `unreadable()` said no — the
    // ratchet only finds out by trying, and an event from a generation it has
    // already spent is the ordinary case on a channel two clients are reading.
    // That is the same line, not a crashed `watch`.
    let content: string
    if (session.channel.unreadable(event)) content = noKey(event)
    else {
      try {
        content = describe(event.kind, alt, await session.channel.open(event))
      } catch {
        content = noKey(event)
      }
    }
    // The `alt` tag is doing the work here, and this is exactly the case the
    // spec requires it for: a reader that has never heard of kind 8102 still
    // gets a usable line out of it. It is also never sealed, so it keeps
    // working for the line above.
    console.log(
      `${dim(when(event.created_at))} ${cyan(String(event.kind).padStart(5))} ${who.padEnd(10)} ${content}`,
    )
  }

  // Printed in arrival order rather than in the order the opens finish.
  // On `mls` an archived event answers immediately and one needing the ratchet
  // does not, so unchained these lines would interleave by decryption cost —
  // a feed that reorders a conversation according to what the reader happened
  // to have cached.
  let printing: Promise<void> = Promise.resolve()
  const show = (event: NostrEvent) => {
    printing = printing.then(() => line(event)).catch((e: unknown) => console.error(red(String(e))))
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
