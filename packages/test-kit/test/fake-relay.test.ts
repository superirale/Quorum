/**
 * Tests for the fake relay.
 *
 * Test infrastructure that is subtly wrong produces test suites that are subtly
 * wrong, and this one is asked to *misbehave* on purpose — so the thing worth
 * pinning is that it misbehaves only when told to, and behaves like NIP-01
 * otherwise. The storage rules in particular are load-bearing: an agent's replay
 * logic is built on ephemeral events not coming back, and a relay that stored
 * them would make a broken SDK look correct.
 *
 * Written against the raw wire rather than `@quorum/sdk`, deliberately. The SDK
 * is the thing these tests exist to support; using it here would mean a bug in
 * either one could hide a bug in the other.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { schnorr } from '@noble/curves/secp256k1.js'
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js'
import { computeId, type NostrEvent, type UnsignedEvent } from '@quorum/protocol'
import WebSocket from 'ws'
import { FakeRelay, waitFor } from '../src/index.ts'

const GROUP = 'payments'

// A minimal signer, so the test-kit does not depend on the SDK. See the header.
const secret = randomBytes(32)
const PUBKEY = bytesToHex(schnorr.getPublicKey(secret))

let clock = 1_700_000_000
function sign(overrides: Partial<UnsignedEvent> = {}): NostrEvent {
  const unsigned: UnsignedEvent = {
    pubkey: PUBKEY,
    created_at: clock++,
    kind: 9,
    tags: [['h', GROUP]],
    content: 'hello',
    ...overrides,
  }
  const id = computeId(unsigned)
  return { ...unsigned, id, sig: bytesToHex(schnorr.sign(id, secret)) }
}

/** A raw client that records everything the relay says to it. */
class Peer {
  readonly messages: unknown[][] = []
  private readonly socket: WebSocket

  private constructor(socket: WebSocket) {
    this.socket = socket
    socket.on('message', (raw) => this.messages.push(JSON.parse(raw.toString()) as unknown[]))
  }

  static async connect(url: string): Promise<Peer> {
    const socket = new WebSocket(url)
    // Listening before the handshake completes, not after: with `requireAuth`
    // the relay sends its challenge the instant the connection is accepted, and
    // a listener attached once `open` has resolved has already missed it.
    const peer = new Peer(socket)
    await new Promise((resolve, reject) => {
      socket.once('open', resolve)
      socket.once('error', reject)
    })
    return peer
  }

  send(message: unknown[]): void {
    this.socket.send(JSON.stringify(message))
  }

  of(type: string): unknown[][] {
    return this.messages.filter((m) => m[0] === type)
  }

  /** Wait for a message of this type, then return every one seen so far. */
  async expect(type: string, count = 1): Promise<unknown[][]> {
    await waitFor(() => this.of(type).length >= count, { describe: `${count}× ${type}` })
    return this.of(type)
  }

  close(): void {
    this.socket.close()
  }
}

async function relayAndPeer(
  t: { after: (fn: () => void | Promise<void>) => void },
  options: Parameters<typeof FakeRelay.start>[0] = {},
) {
  const relay = await FakeRelay.start(options)
  const peer = await Peer.connect(relay.url)
  t.after(async () => {
    peer.close()
    await relay.stop()
  })
  return { relay, peer }
}

describe('NIP-01', () => {
  it('OKs an event and serves it back', async (t) => {
    const { relay, peer } = await relayAndPeer(t)
    const event = sign()

    peer.send(['EVENT', event])
    assert.deepEqual((await peer.expect('OK'))[0], ['OK', event.id, true, ''])

    peer.send(['REQ', 'a', { '#h': [GROUP] }])
    await peer.expect('EOSE')
    assert.deepEqual(peer.of('EVENT')[0], ['EVENT', 'a', event])
    assert.deepEqual(relay.stored, [event])
  })

  it('refuses an event whose id or signature is wrong', async (t) => {
    const { relay, peer } = await relayAndPeer(t)

    peer.send(['EVENT', { ...sign(), content: 'tampered' }])
    const [ok] = await peer.expect('OK')
    assert.equal(ok![2], false)
    assert.match(String(ok![3]), /bad id or signature/)
    assert.deepEqual(relay.received, [])
  })

  it('delivers live events only to subscriptions that match', async (t) => {
    const { peer } = await relayAndPeer(t)
    peer.send(['REQ', 'chat', { '#h': [GROUP], kinds: [9] }])
    peer.send(['REQ', 'threads', { '#h': [GROUP], kinds: [11] }])
    await peer.expect('EOSE', 2)

    peer.send(['EVENT', sign({ kind: 9 })])
    await peer.expect('EVENT')
    assert.deepEqual(
      peer.of('EVENT').map((m) => m[1]),
      ['chat'],
    )
  })

  it('applies limit as a tail, newest events kept', async (t) => {
    const { peer } = await relayAndPeer(t)
    for (const content of ['one', 'two', 'three']) peer.send(['EVENT', sign({ content })])
    await peer.expect('OK', 3)

    peer.send(['REQ', 'a', { '#h': [GROUP], limit: 2 }])
    await peer.expect('EOSE')
    assert.deepEqual(
      peer.of('EVENT').map((m) => (m[2] as NostrEvent).content),
      ['two', 'three'],
    )
  })

  it('closes a subscription on CLOSE', async (t) => {
    const { peer } = await relayAndPeer(t)
    peer.send(['REQ', 'a', { '#h': [GROUP] }])
    await peer.expect('EOSE')
    peer.send(['CLOSE', 'a'])
    peer.send(['EVENT', sign()])
    await peer.expect('OK')
    assert.deepEqual(peer.of('EVENT'), [])
  })
})

describe('storage rules', () => {
  it('broadcasts an ephemeral event and forgets it', async (t) => {
    const { relay, peer } = await relayAndPeer(t)
    peer.send(['REQ', 'a', { '#h': [GROUP] }])
    await peer.expect('EOSE')

    const lease = sign({ kind: 28102, content: '{}' })
    peer.send(['EVENT', lease])
    await peer.expect('EVENT')

    // Not an optimisation. Storing these would replay last week's interrupt to
    // an agent resuming from history, and the SDK's control plane assumes it
    // cannot happen.
    assert.deepEqual(relay.stored, [])
    assert.deepEqual(relay.received, [lease])
  })

  it('replaces an addressable event by (pubkey, kind, d)', async (t) => {
    const { relay, peer } = await relayAndPeer(t)
    const first = sign({ kind: 38101, tags: [['h', GROUP], ['d', 'thread-1']], content: 'open' })
    const second = sign({ kind: 38101, tags: [['h', GROUP], ['d', 'thread-1']], content: 'done' })
    const other = sign({ kind: 38101, tags: [['h', GROUP], ['d', 'thread-2']], content: 'open' })
    for (const e of [first, second, other]) peer.send(['EVENT', e])
    await peer.expect('OK', 3)

    assert.deepEqual(relay.stored.map((e) => e.content).sort(), ['done', 'open'])
  })

  it('deduplicates a regular event republished byte-for-byte', async (t) => {
    // The property the SDK's `once()` reservation depends on: a replayed handler
    // rebuilds the same event, and the relay absorbs it.
    const { relay, peer } = await relayAndPeer(t)
    const event = sign()
    peer.send(['EVENT', event])
    peer.send(['EVENT', event])
    await peer.expect('OK', 2)

    assert.equal(relay.received.length, 2, 'received is the arrival log; it should show both')
    assert.deepEqual(relay.stored, [event])
  })
})

describe('relay29 filter scoping', () => {
  it('refuses an unscoped filter with a CLOSED, as the real relay does', async (t) => {
    const { peer } = await relayAndPeer(t)
    peer.send(['REQ', 'a', { '#p': [PUBKEY] }])
    const [closed] = await peer.expect('CLOSED')
    assert.equal(closed![1], 'a')
    assert.match(String(closed![2]), /must contain an h/)
  })

  it('can be turned off, for tests that are not about the group rule', async (t) => {
    const { peer } = await relayAndPeer(t, { requireScopedFilters: false })
    peer.send(['REQ', 'a', { kinds: [9] }])
    await peer.expect('EOSE')
    assert.deepEqual(peer.of('CLOSED'), [])
  })
})

describe('NIP-42', () => {
  it('challenges on connect and refuses reads and writes until answered', async (t) => {
    const { peer } = await relayAndPeer(t, { requireAuth: true })
    const [auth] = await peer.expect('AUTH')
    const challenge = String(auth![1])

    peer.send(['EVENT', sign()])
    assert.match(String((await peer.expect('OK'))[0]![3]), /auth-required/)
    peer.send(['REQ', 'a', { '#h': [GROUP] }])
    assert.match(String((await peer.expect('CLOSED'))[0]![2]), /auth-required/)

    peer.send([
      'AUTH',
      sign({ kind: 22242, tags: [['relay', 'ws://x'], ['challenge', challenge]], content: '' }),
    ])
    await peer.expect('OK', 2)

    const event = sign({ content: 'now allowed' })
    peer.send(['EVENT', event])
    const oks = await peer.expect('OK', 3)
    assert.equal(oks[2]![2], true)
  })

  it('rejects an AUTH event answering a different challenge', async (t) => {
    const { peer } = await relayAndPeer(t, { requireAuth: true })
    await peer.expect('AUTH')
    peer.send([
      'AUTH',
      sign({ kind: 22242, tags: [['challenge', 'not-the-one-we-sent']], content: '' }),
    ])
    const [ok] = await peer.expect('OK')
    assert.equal(ok![2], false)
  })
})

describe('chaos', () => {
  it('withholds a matching event from everyone while keeping the OK', async (t) => {
    const { relay, peer } = await relayAndPeer(t)
    peer.send(['REQ', 'a', { '#h': [GROUP] }])
    await peer.expect('EOSE')

    relay.withholdMatching((e) => e.content === 'secret')
    const hidden = sign({ content: 'secret' })
    peer.send(['EVENT', hidden])
    const [ok] = await peer.expect('OK')
    assert.equal(ok![1], hidden.id)
    assert.equal(ok![2], true, 'the author must be told it was accepted')

    relay.withholdMatching(() => false)
    peer.send(['EVENT', sign({ content: 'visible' })])
    await peer.expect('EVENT')

    // Accepted, acknowledged, and invisible to every reader. Nothing in Nostr
    // forbids this, which is the entire argument for the counter tags.
    assert.deepEqual(
      peer.of('EVENT').map((m) => (m[2] as NostrEvent).content),
      ['visible'],
    )
    const second = await Peer.connect(relay.url)
    t.after(() => second.close())
    second.send(['REQ', 'b', { '#h': [GROUP] }])
    await second.expect('EOSE')
    assert.deepEqual(
      second.of('EVENT').map((m) => (m[2] as NostrEvent).content),
      ['visible'],
    )
  })

  it('keeps its events across a dropped connection', async (t) => {
    const { relay, peer } = await relayAndPeer(t)
    const event = sign()
    peer.send(['EVENT', event])
    await peer.expect('OK')

    relay.dropConnections()
    await waitFor(() => relay.connectionCount === 0, { describe: 'the drop' })

    const reconnected = await Peer.connect(relay.url)
    t.after(() => reconnected.close())
    reconnected.send(['REQ', 'a', { '#h': [GROUP] }])
    await reconnected.expect('EOSE')
    assert.deepEqual(reconnected.of('EVENT')[0]![2], event)
  })

  it('injects a message no honest path could produce', async (t) => {
    const { relay, peer } = await relayAndPeer(t)
    peer.send(['REQ', 'a', { '#h': [GROUP] }])
    await peer.expect('EOSE')

    relay.injectRaw(['EVENT', 'a', { ...sign(), content: 'forged' }])
    await peer.expect('EVENT')
    assert.equal((peer.of('EVENT')[0]![2] as NostrEvent).content, 'forged')
    assert.deepEqual(relay.received, [], 'an injection must not look like an accepted event')
  })

  it('rejects on demand, with the relay’s own words', async (t) => {
    const { peer } = await relayAndPeer(t, {
      reject: (e) => (e.kind === 9 ? 'restricted: not a member of this group' : undefined),
    })
    peer.send(['EVENT', sign({ kind: 9 })])
    const [ok] = await peer.expect('OK')
    assert.equal(ok![2], false)
    assert.match(String(ok![3]), /restricted: not a member/)
  })
})

describe('malformed input', () => {
  it('answers with a NOTICE rather than dying', async (t) => {
    const { relay, peer } = await relayAndPeer(t)
    peer.send(['not', 'a', 'real', 'verb'])
    await peer.expect('NOTICE')

    // Still alive and still serving.
    peer.send(['EVENT', sign()])
    const oks = await peer.expect('OK')
    assert.equal(oks[0]![2], true)
    assert.equal(relay.received.length, 1)
  })
})
