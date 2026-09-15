/**
 * The hook, against a relay, and the one branch that decides everything else.
 *
 * Every other test in this directory hands a component a `Workspace` built by
 * hand, which is right for a rendering claim and useless for this one: what is
 * under test here is the *wiring* — that reading the channel policy happens
 * before anything is built on top of it, and that an `mls` policy stops a
 * `ChannelCrypto` and a `Publisher` from being constructed at all.
 *
 * Why that matters more than it looks. A `ChannelCrypto` over an mls channel is
 * not inert. Its `encrypted` getter asks whether the mode is `nip44`, so on mls
 * it says no, `buildOptions` returns nothing, and the composer publishes *in
 * the clear* into a channel whose policy says otherwise — a leak this relay
 * happens to refuse and a generic one would store. Its `unreadable()` mean-
 * while answers true for every message in the channel, which this app renders
 * as "ask an admin to wrap the current epoch": the nip44 cure, offered for a
 * condition no admin can fix.
 *
 * So the assertions are mostly absences, and each one has a plaintext control
 * in the same file for the reason M9 wrote down — a negative claim that would
 * hold against a hook that did nothing is not a test.
 */

import assert from 'node:assert/strict'
import { renderHook, waitFor } from '@testing-library/react'
import { afterEach, describe, it } from 'vitest'
import { WebSocket as NodeWebSocket } from 'ws'
import { AddressableKinds, EncMode, Kinds, TagName } from '@quorum/protocol'
import { LocalSigner, RelayClient } from '@quorum/sdk'
import { FakeRelay } from '@quorum/test-kit'
import type { Identity } from '../src/identity.ts'
import { MLS_NO_KEY, useWorkspace } from '../src/useWorkspace.ts'

// jsdom's own WebSocket cannot be used here, and the reason is a collision
// between two globals rather than anything about this code: jsdom implements it
// over undici, undici builds its events with the ambient `Event` — which jsdom
// has replaced — and Node's EventTarget then refuses them with "the event
// argument must be an instance of Event. Received an instance of Event". The
// connection never opens and every test in this file times out. `ws` is the
// same implementation the fake relay is serving with, and the client only ever
// uses `addEventListener`, `send` and `close`.
globalThis.WebSocket = NodeWebSocket as unknown as typeof WebSocket

const GROUP = 'payments'

/** Quiet: the client logs a reconnect notice on close and it is not the subject. */
const silent = { debug() {}, info() {}, warn() {}, error() {} }

let relay: FakeRelay | undefined
/** Kept open past `channel()`, so a test can change the policy under the hook. */
let writer: { client: RelayClient; signer: LocalSigner } | undefined
afterEach(async () => {
  writer?.client.close()
  writer = undefined
  await relay?.stop()
  relay = undefined
})

function asIdentity(signer: LocalSigner): Identity {
  return {
    signer,
    pubkey: signer.publicKey,
    name: 'ada',
    backing: 'local',
    close() {},
  }
}

/**
 * Start a relay with the channel already in the given mode.
 *
 * The policy is planted as a signed 38107 rather than published through the
 * console's code path, because what this file tests is a reader: the writer has
 * its own suite, and going through it would make a failure here ambiguous.
 */
async function channel(enc: EncMode): Promise<Identity> {
  relay = await FakeRelay.start()
  const signer = LocalSigner.generate()
  const client = new RelayClient({ url: relay.url, signer, reconnect: false, log: silent })
  await client.connect()
  writer = { client, signer }
  const at = Math.floor(Date.now() / 1000)
  if (enc !== EncMode.Plaintext) await policy(enc, at)
  // One message, so the counts below have something to count. This identity
  // cannot read it in either encrypted mode — it holds no nip44 wrap and no
  // ratchet — which is what makes the two modes comparable here.
  await client.publish(
    await signer.sign({
      pubkey: signer.publicKey,
      created_at: at,
      kind: Kinds.ChatMessage,
      tags: [
        [TagName.Group, GROUP],
        [TagName.Alt, 'a chat message'],
        ...(enc === EncMode.Plaintext
          ? []
          : [
              [TagName.Enc, enc],
              [TagName.Epoch, enc === EncMode.Mls ? '0' : '1'],
            ]),
      ],
      content: enc === EncMode.Plaintext ? 'in the clear' : 'cXFxcXFxcXE=',
    }),
  )
  return asIdentity(signer)
}

/** Publish a 38107 into the open channel. Addressable, so this replaces it. */
async function policy(enc: EncMode, at = Math.floor(Date.now() / 1000)): Promise<void> {
  const { client, signer } = writer!
  await client.publish(
    await signer.sign({
      pubkey: signer.publicKey,
      created_at: at,
      kind: AddressableKinds.ChannelPolicy,
      tags: [
        [TagName.Identifier, GROUP],
        [TagName.Group, GROUP],
        [TagName.Alt, `this channel is encrypted with ${enc}`],
      ],
      // No `epoch` on mls, which the spec forbids: the ratchet is the only
      // thing that knows it.
      content: JSON.stringify(enc === EncMode.Mls ? { enc } : { enc, epoch: 1 }),
    }),
  )
}

/** The hook, run until it has finished talking to the relay. */
async function connected(identity: Identity) {
  const url = relay?.url ?? ''
  const hook = renderHook(() => useWorkspace(identity, url, GROUP))
  await waitFor(() => assert.equal(hook.result.current.status, 'live'))
  return hook
}

describe('a channel whose policy says mls', () => {
  it('reports the mode, so every screen downstream can refuse for the right reason', async () => {
    const { result } = await connected(await channel(EncMode.Mls))
    assert.equal(result.current.policy.enc, EncMode.Mls)
  })

  it('builds no channel crypto, because the one it would build answers wrongly', async () => {
    const { result } = await connected(await channel(EncMode.Mls))
    assert.equal(result.current.channel, undefined)
  })

  it('refuses to publish, and says which of the two reasons it is', async () => {
    // Not "not connected to the relay yet". The client is connected, the relay
    // is answering, and the thing missing is a ratchet that is never going to
    // arrive — an operator told to wait would wait forever.
    const { result } = await connected(await channel(EncMode.Mls))
    await assert.rejects(
      () => result.current.publish({ kind: 9, text: 'hello' }),
      (error: Error) => {
        assert.equal(error.message, MLS_NO_KEY)
        return true
      },
    )
  })

  it('counts what it cannot read, rather than showing a channel that looks quiet', async () => {
    // With no `ChannelCrypto` there is nothing to ask, so the test falls back
    // to the event's own `enc` tag. Getting this wrong is the quiet failure:
    // the banner never renders, the feed shows no locks, and a channel full of
    // traffic this client cannot read presents as a channel nobody is using.
    const { result } = await connected(await channel(EncMode.Mls))
    await waitFor(() => assert.equal(result.current.raw.length, 1))
    assert.equal(result.current.unreadable, 1)
    assert.equal(result.current.sealed(result.current.raw[0]!), true)
  })

  it('notices the channel leaving mls, and says a reload is what picks the keys up', async () => {
    // The one thing that can change here, and the client cannot act on it by
    // itself: the ChannelCrypto it skipped is what fetches keys, and building
    // one now would mean re-running a connect from inside a state update. A tab
    // that went on refusing a channel reopened an hour ago is the worse answer.
    const { result } = await connected(await channel(EncMode.Mls))
    await policy(EncMode.Plaintext, Math.floor(Date.now() / 1000) + 5)
    await waitFor(() => assert.notEqual(result.current.problem, undefined))
    assert.match(result.current.problem!, /reload/)
  })

  it('still connects and still subscribes, rather than presenting as broken', async () => {
    // The channel is readable in the sense that matters for everything outside
    // the ciphertext: membership, capabilities, who is beating. Reporting
    // `error` would hide all of it behind a failure that is not one.
    const { result } = await connected(await channel(EncMode.Mls))
    assert.equal(result.current.status, 'live')
    assert.equal(result.current.problem, undefined)
  })
})

describe('the same hook on a channel it can read', () => {
  it('builds the crypto and will publish, on plaintext', async () => {
    const { result } = await connected(await channel(EncMode.Plaintext))
    assert.notEqual(result.current.channel, undefined)
    assert.equal(result.current.policy.enc, EncMode.Plaintext)
  })

  it('counts an unreadable nip44 message the same way, which is the control', async () => {
    // The count is not an mls affordance. This identity holds no key for epoch
    // 1 either, and the difference between the two is the sentence offered
    // next to the number, not the number.
    const { result } = await connected(await channel(EncMode.Nip44))
    await waitFor(() => assert.equal(result.current.raw.length, 1))
    assert.equal(result.current.unreadable, 1)
  })

  it('counts nothing on a plaintext channel', async () => {
    const { result } = await connected(await channel(EncMode.Plaintext))
    await waitFor(() => assert.equal(result.current.raw.length, 1))
    assert.equal(result.current.unreadable, 0)
  })

  it('follows a channel that turns mls while the tab is open', async () => {
    // The other half of the publish guard's reason for existing. A composer
    // that rendered a second ago is still on the screen, and the policy it was
    // built under is no longer the channel's.
    const { result } = await connected(await channel(EncMode.Plaintext))
    await policy(EncMode.Mls, Math.floor(Date.now() / 1000) + 5)
    await waitFor(() => assert.equal(result.current.policy.enc, EncMode.Mls))
    await assert.rejects(() => result.current.publish({ kind: 9, text: 'hello' }), /no ratchet/)
  })

  it('builds it on nip44 too, where a key genuinely can arrive later', async () => {
    // The control that stops the mls branch from being "skip it whenever the
    // channel is encrypted". This identity holds no key for epoch 1 either, and
    // the difference is that somebody can send it one.
    const { result } = await connected(await channel(EncMode.Nip44))
    assert.notEqual(result.current.channel, undefined)
    assert.equal(result.current.policy.enc, EncMode.Nip44)
    assert.equal(result.current.policy.epoch, 1)
  })
})
