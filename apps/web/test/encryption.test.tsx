/**
 * What the browser says about an `mls` channel, which is mostly "no".
 *
 * This client holds no MLS ratchet and is not going to: a Nostr key has one
 * KeyPackage slot per channel, so a tab cannot join as a second device of the
 * identity the console already joined as, and MLS state is single-writer, so
 * two clients sharing one ratchet spend each other's generations and lose
 * messages outright rather than duplicating them. The surface is therefore a
 * refusal, and the whole risk is in how it is worded.
 *
 * Every assertion below is about a sentence, because that is where a correct
 * value turns into a false statement — the layer the SDK suites cannot reach.
 * Two failures in particular:
 *
 *   - offering the `nip44` cure on an mls channel ("ask an admin to wrap the
 *     current epoch") sends an operator to ask for something no admin has and
 *     no member can produce, because the keys are deleted by design;
 *   - a chip reading "sealed · epoch 3" invites a reader to compare a number
 *     the policy is forbidden to carry with a member's ratchet.
 */

import assert from 'node:assert/strict'
import { render, screen } from '@testing-library/react'
import { describe, it } from 'vitest'
import { EncMode, type NostrEvent } from '@quorum/protocol'
import { PLAINTEXT_POLICY, type ChannelPolicy } from '@quorum/sdk'
import { Composer } from '../src/components/Composer.tsx'
import { ModeBadge, Unreadable } from '../src/components/Encryption.tsx'
import { Feed } from '../src/components/Feed.tsx'
import { MLS_NO_KEY } from '../src/useWorkspace.ts'
import { ADA, absent, event, workspace } from './fixtures.ts'

const MLS: ChannelPolicy = { enc: EncMode.Mls, epoch: undefined }
const NIP44: ChannelPolicy = { enc: EncMode.Nip44, epoch: 3 }

/** A message as it arrives on an encrypted channel: base64, plus an `alt`. */
function sealed(enc: EncMode, epoch: number): NostrEvent {
  return event({
    kind: 9,
    content: 'qqqqqqqqqqqqqqqqqqqqqq==',
    tags: [
      ['enc', enc],
      ['epoch', String(epoch)],
      ['alt', 'a chat message'],
    ],
  })
}

describe('the chip that names the mode', () => {
  it('names the nip44 epoch, which is the same number for every member', () => {
    render(<ModeBadge policy={NIP44} />)
    screen.getByText(/epoch 3/)
  })

  it('says plaintext when the channel has no policy', () => {
    render(<ModeBadge policy={PLAINTEXT_POLICY} />)
    screen.getByText('plaintext')
  })

  it('names mls without a number, because the policy is forbidden to carry one', () => {
    const { container } = render(<ModeBadge policy={MLS} />)
    const text = container.textContent ?? ''
    assert.match(text, /MLS/)
    assert.doesNotMatch(text, /\d/, 'an epoch here would be a fact about somebody else’s ratchet')
  })

  it('does not present mls as a channel this client is reading normally', () => {
    // The chip is the only thing on the header saying so, and an operator who
    // reads "sealed" walks away believing the screen below it is the channel.
    const { container } = render(<ModeBadge policy={MLS} />)
    assert.equal(container.querySelector('.sealed'), null)
    assert.match(container.textContent ?? '', /no ratchet/i)
  })
})

describe('the banner for events this client cannot read', () => {
  it('says nothing when there is nothing it could not read', () => {
    const { container } = render(<Unreadable count={0} policy={MLS} me={ADA} />)
    assert.equal(container.textContent, '')
  })

  it('offers the nip44 cure, because there is one and somebody can perform it', () => {
    const { container } = render(<Unreadable count={2} policy={NIP44} me={ADA} />)
    const text = container.textContent ?? ''
    assert.match(text, /wrap the current epoch/)
    assert.match(text, /aaaaaaaa/, 'the admin needs the key to wrap it for')
  })

  it('refuses to offer it on mls, because there is nobody to ask', () => {
    // The failure this pins. Every field is right — a count, a mode, a pubkey —
    // and the sentence composed from them sends an operator to chase an admin
    // who cannot help, while the one thing that works (read it from the
    // console) goes unsaid.
    const text = render(<Unreadable count={2} policy={MLS} me={ADA} />).container.textContent ?? ''
    assert.doesNotMatch(text, /wrap/i)
    assert.match(text, /quorum/)
  })

  it('says the history stays shut even to a member added a moment from now', () => {
    // Forward secrecy is the reason, and leaving it out makes "join the group"
    // look like the fix for the events already on the screen. It is the fix for
    // the next ones only.
    const text = render(<Unreadable count={2} policy={MLS} me={ADA} />).container.textContent ?? ''
    assert.match(text, /even a member added a moment from now gets none of this history/)
  })

  it('says why this tab cannot simply join, rather than leaving it to be tried', () => {
    // One KeyPackage slot per (key, channel). Without this the obvious next
    // move is to publish one from the browser, which retires the console's
    // offer and takes the identity out of reach of the group it is in.
    const text = render(<Unreadable count={2} policy={MLS} me={ADA} />).container.textContent ?? ''
    assert.match(text, /one KeyPackage slot per channel/)
    assert.match(text, /second device/)
  })
})

describe('the composer on a channel it cannot seal for', () => {
  it('offers no box to type in, and names the console instead', () => {
    render(<Composer workspace={workspace({ policy: MLS })} />)
    absent(screen.queryByPlaceholderText('start a task'), 'composer input')
    screen.getByText(/quorum say/)
  })

  it('refuses for the same stated reason the publish path refuses', () => {
    // Two copies of "why can't I" drift, and the one that drifts is the one
    // nobody reads until it is wrong. `useWorkspace` throws this string; the
    // composer renders it.
    const { container } = render(<Composer workspace={workspace({ policy: MLS })} />)
    assert.match(container.textContent ?? '', new RegExp(MLS_NO_KEY.slice(0, 60)))
  })

  it('still composes on a plaintext channel', () => {
    // The control. A refusal keyed on the wrong condition would pass every
    // assertion above by refusing everywhere.
    render(<Composer workspace={workspace()} />)
    screen.getByPlaceholderText('start a task')
  })
})

describe('the lock beside a line in the feed', () => {
  const locked = (event: NostrEvent): string =>
    render(<Feed events={[event]} me={ADA} sealed={() => true} />)
      .container.querySelector('[title]')
      ?.getAttribute('title') ?? ''

  it('says an mls message will not become readable here', () => {
    assert.match(locked(sealed(EncMode.Mls, 3)), /will not become readable/)
  })

  it('does not say that about a nip44 message, which is waiting for a wrap', () => {
    assert.doesNotMatch(locked(sealed(EncMode.Nip44, 3)), /will not become readable/)
  })

  it('renders the alt tag either way, rather than the ciphertext', () => {
    // `alt` is never sealed, which is the strongest demonstration in this app
    // of why the spec requires it: a reader with no key still gets a sentence.
    render(<Feed events={[sealed(EncMode.Mls, 3)]} me={ADA} sealed={() => true} />)
    screen.getByText('a chat message')
  })
})
