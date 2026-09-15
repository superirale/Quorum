/**
 * What the console says about an `mls` channel.
 *
 * The ratchet is the SDK's and tested there; what is tested here is the layer
 * above it, where a correct value becomes a false sentence. Every input in this
 * file is a value some other component already got right — a set of pubkeys, an
 * epoch number, an `enc` tag — and the only thing that can be wrong is the
 * English composed from it. That is the shape of the console's audit-verdict bug
 * from M4 and the web suite's rules from M10, and it is the one failure mode a
 * suite over the SDK cannot reach.
 *
 * Two claims dominate:
 *
 *   - an `mls` epoch is a fact about *this* client and a `nip44` epoch is a fact
 *     about the channel, so they must not be printed the same way;
 *   - "cannot read this" has a cure under `nip44` and none under `mls`, so the
 *     two must not share a sentence.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { EncMode, Kinds, TagName, build, type NostrEvent } from '@quorum/protocol'
import { STANDING, membership } from '../src/commands/mls.ts'
import { noKey, sealing } from '../src/commands/messages.ts'
import type { ChannelView } from '../src/session.ts'

const GROUP = 'payments'
const NOW = 1_800_000_000
const ADA = 'a'.repeat(64)
const BOB = 'b'.repeat(64)
const CAT = 'c'.repeat(64)

/**
 * Enough of a `ChannelView` for the two sentences under test.
 *
 * Cast rather than constructed, because building a real one needs a socket, a
 * signer and a ratchet — and none of the three participate in deciding what the
 * line says, which is the point of having split these functions out.
 */
function view(fields: Partial<ChannelView>): ChannelView {
  return {
    enc: EncMode.Plaintext,
    encrypted: false,
    policy: { enc: EncMode.Plaintext },
    nip44: undefined,
    mls: undefined,
    epoch: undefined,
    ...fields,
  } as ChannelView
}

const sealed = (enc: EncMode, epoch?: number): NostrEvent =>
  ({
    ...build({
      kind: Kinds.ChatMessage,
      pubkey: BOB,
      group: GROUP,
      text: 'ciphertext',
      created_at: NOW,
      ...(epoch === undefined ? {} : { epoch }),
      enc,
    }),
    id: 'd'.repeat(64),
    sig: 'e'.repeat(128),
  }) as NostrEvent

describe('how the console names an epoch', () => {
  it('states a nip44 epoch plainly, because it is the same number for everyone', () => {
    assert.equal(sealing(view({ enc: EncMode.Nip44, encrypted: true, policy: { enc: EncMode.Nip44, epoch: 3 } })), 'epoch 3')
  })

  it('says which mechanism on mls, because the number is this client’s and not the channel’s', () => {
    // The failure this pins: printing `epoch 2` on an mls channel invites the
    // reader to compare it with another member's and conclude somebody is
    // behind — when the policy carries no epoch at all and the ratchet is the
    // only thing that knows. Under nip44 that comparison is meaningful.
    const line = sealing(view({ enc: EncMode.Mls, encrypted: true, mls: {} as never, epoch: 2 }))
    assert.match(line, /MLS/)
    assert.match(line, /2/)
    assert.match(line, /this identity/)
  })

  it('does not print an epoch for an identity that has not joined', () => {
    // `epoch 0` would be the wrong answer twice over: MLS groups genuinely start
    // at 0, so it is indistinguishable from a founder who has committed nothing,
    // and it tells someone who can read nothing that they are in the group.
    const line = sealing(view({ enc: EncMode.Mls, encrypted: true, mls: {} as never, epoch: undefined }))
    assert.match(line, /not in the group/)
    assert.doesNotMatch(line, /\d/)
  })
})

describe('the line for an event that cannot be opened', () => {
  it('offers the nip44 cure, because there is one', () => {
    const line = noKey(sealed(EncMode.Nip44, 2))
    assert.match(line, /no key/)
    assert.doesNotMatch(line, /permanent/)
  })

  it('refuses to offer it on mls, because there is nobody to ask', () => {
    // The whole reason these are two sentences. `no key` sends an operator to
    // find a member holding the epoch; on mls that member does not exist and
    // never will, and the time they spend looking is time not spent doing the
    // one thing that works — being re-invited, from this epoch forward.
    const line = noKey(sealed(EncMode.Mls, 4))
    assert.match(line, /permanently/)
    assert.doesNotMatch(line, /no key/)
  })

  it('still names the epoch it could not open, on both', () => {
    // The epoch tag is the difference between "I cannot read this channel" and
    // "I am missing epoch 4", which is the whole reason the tag is required of
    // a sender. A reader that drops it collapses them back into one sentence.
    assert.match(noKey(sealed(EncMode.Mls, 4)), /4/)
    assert.match(noKey(sealed(EncMode.Nip44, 7)), /7/)
  })

  it('says so rather than inventing a number when the sender omitted the tag', () => {
    const bare = sealed(EncMode.Mls, 4)
    assert.match(
      noKey({ ...bare, tags: bare.tags.filter((t) => t[0] !== TagName.Epoch) }),
      /epoch \?/,
    )
  })
})

describe('two membership lists that disagree', () => {
  it('marks somebody on both lists as needing nothing', () => {
    const { members } = membership({ tree: [ADA], relay: [ADA], offering: [] })
    assert.deepEqual(members, [{ pubkey: ADA, standing: 'both' }])
  })

  it('tells the two disagreements apart, and they are opposites', () => {
    // Swap these two and the advice inverts: the reader is told to add to the
    // relay somebody who is already there and needs adding to the ratchet. The
    // command still prints a plausible line and the member still reads nothing.
    const { members } = membership({ tree: [ADA, BOB], relay: [ADA, CAT], offering: [] })
    assert.deepEqual(members, [
      { pubkey: ADA, standing: 'both' },
      { pubkey: BOB, standing: 'ratchet-only' },
      { pubkey: CAT, standing: 'relay-only' },
    ])
  })

  it('lists everyone from either list, because a union is the only honest answer', () => {
    // Intersecting would hide exactly the people the command exists to find, and
    // it would hide them behind a list that looks complete.
    const { members } = membership({ tree: [BOB], relay: [CAT], offering: [] })
    assert.equal(members.length, 2)
  })

  it('reports an outstanding offer from somebody the relay already counts as a member', () => {
    // The trap: Cat is a workspace member, so a `waiting` computed against the
    // relay's list drops them — and Cat sits in the channel reading nothing
    // while both lists look plausible. It is measured against the ratchet.
    const { waiting } = membership({ tree: [ADA], relay: [ADA, CAT], offering: [CAT] })
    assert.deepEqual(waiting, [CAT])
  })

  it('says the right thing about each disagreement, not just the right thing about which it is', () => {
    // Written because the assertions above do not cover this. They check the
    // tag, and the tag is computed correctly by a mutation that swaps the two
    // sentences — which is the M4 audit-verdict bug exactly: every field right,
    // and the English composed from them describing the other case.
    assert.match(STANDING['ratchet-only'], /can read/)
    assert.match(STANDING['ratchet-only'], /cannot publish/)
    assert.match(STANDING['relay-only'], /nobody can open/)
    assert.doesNotMatch(STANDING['relay-only'], /can read/)
  })

  it('does not report an offer from somebody already in the ratchet', () => {
    // A joined member republishes its package after every join — that is the
    // spent-package renewal — so treating a live offer as "waiting" would name
    // every member of the channel every time.
    const { waiting } = membership({ tree: [ADA, CAT], relay: [ADA], offering: [CAT] })
    assert.deepEqual(waiting, [])
  })
})
