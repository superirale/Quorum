/**
 * The relay connection.
 *
 * Almost everything here is a failure mode. The connection is the layer where
 * "nothing happened" and "nothing could happen" look identical, and every test
 * below is a case where the obvious client reports the first while the second
 * is true.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { Kinds, type NostrEvent, type UnsignedEvent } from '@quorum/protocol'
import { FakeRelay, settle, waitFor } from '@quorum/test-kit'
import { LocalSigner, PublishError, RelayClient, SubscriptionClosed } from '../src/index.ts'

const GROUP = 'payments'

async function chat(signer: LocalSigner, content: string, createdAt = 1_700_000_000) {
  const unsigned: UnsignedEvent = {
    pubkey: signer.publicKey,
    created_at: createdAt,
    kind: Kinds.ChatMessage,
    tags: [
      ['h', GROUP],
      ['alt', 'a chat message'],
    ],
    content,
  }
  return signer.sign(unsigned)
}

/** A relay and a client, both torn down when the test ends. */
async function connected(
  t: { after: (fn: () => void | Promise<void>) => void },
  relayOptions: Parameters<typeof FakeRelay.start>[0] = {},
  clientOptions: Partial<ConstructorParameters<typeof RelayClient>[0]> = {},
) {
  const relay = await FakeRelay.start(relayOptions)
  const signer = LocalSigner.generate()
  const client = new RelayClient({
    url: relay.url,
    signer,
    reconnect: false,
    log: silent,
    ...clientOptions,
  })
  t.after(async () => {
    client.close()
    await relay.stop()
  })
  await client.connect()
  return { relay, client, signer }
}

const silent = { warn() {}, error() {} }

describe('publish', () => {
  it('resolves on OK and rejects with the relay’s own words', async (t) => {
    const { relay, client, signer } = await connected(t, {
      reject: (e) => (e.content === 'no' ? 'restricted: you are not a member of this group' : undefined),
    })

    await client.publish(await chat(signer, 'yes'))
    assert.equal(relay.received.length, 1)

    const bad = await chat(signer, 'no')
    const error = await client.publish(bad).catch((e: unknown) => e)
    assert.ok(error instanceof PublishError)
    assert.equal(error.prefix, 'restricted')
    assert.equal(error.eventId, bad.id)
    assert.match(error.message, /not a member/)
  })

  it('does not report success for an event the relay never accepted', async (t) => {
    // The whole reason `publish` waits for OK. An agent that resolves when the
    // bytes leave the socket is an agent that believes it answered.
    const { client, signer } = await connected(t, { reject: () => 'invalid: nope' })
    const event = await chat(signer, 'hi')
    await assert.rejects(() => client.publish(event), PublishError)
  })
})

describe('NIP-42', () => {
  it('authenticates on demand and retries the publish', async (t) => {
    const { relay, client, signer } = await connected(t, { requireAuth: true })

    // The first attempt is refused with `auth-required:`, which is a request
    // rather than a refusal — the client answers it and tries again.
    await client.publish(await chat(signer, 'hello'))
    assert.equal(client.authenticatedAs, signer.publicKey)
    assert.equal(relay.eventsOfKind(Kinds.ChatMessage).length, 1)
  })

  it('re-authenticates on a new socket, because the challenge is per-connection', async (t) => {
    const relay = await FakeRelay.start({ requireAuth: true })
    const signer = LocalSigner.generate()
    const client = new RelayClient({
      url: relay.url,
      signer,
      reconnect: { minDelayMs: 20, maxDelayMs: 40 },
      log: silent,
    })
    t.after(async () => {
      client.close()
      await relay.stop()
    })

    await client.connect()
    await client.publish(await chat(signer, 'one'))
    assert.equal(client.authenticatedAs, signer.publicKey)

    relay.dropConnections()
    await waitFor(() => client.connected === false, { describe: 'the drop' })
    await waitFor(() => client.connected, { describe: 'the reconnect' })
    assert.equal(client.authenticatedAs, undefined, 'auth must not be assumed across sockets')

    await client.publish(await chat(signer, 'two', 1_700_000_001))
    assert.equal(client.authenticatedAs, signer.publicKey)
  })

  it('refuses to authenticate without a signer', async (t) => {
    const { client } = await connected(t, { requireAuth: true }, { signer: undefined })
    await assert.rejects(() => client.authenticate(), /no signer/)
  })
})

describe('query', () => {
  it('surfaces a refused filter as an error, not as an empty result', async (t) => {
    const { client } = await connected(t)

    // This is the M2 trap, verbatim: go-nostr's QuerySync returns a nil error
    // whether the subscription ended in EOSE or in CLOSED, so a relay refusing
    // the filter is indistinguishable from a channel with nothing in it.
    const error = await client.query([{ '#p': ['a'.repeat(64)] }]).catch((e: unknown) => e)
    assert.ok(error instanceof SubscriptionClosed)
    assert.match(error.reason, /must contain an h/)
  })

  it('returns stored events and stops at EOSE', async (t) => {
    const { client, signer } = await connected(t)
    await client.publish(await chat(signer, 'one', 1_700_000_000))
    await client.publish(await chat(signer, 'two', 1_700_000_001))

    const events = await client.query([{ '#h': [GROUP], kinds: [Kinds.ChatMessage] }])
    assert.deepEqual(events.map((e) => e.content), ['one', 'two'])
  })
})

describe('subscribe', () => {
  it('sends exactly one REQ when subscribing during connect', async (t) => {
    const relay = await FakeRelay.start()
    const client = new RelayClient({ url: relay.url, reconnect: false, log: silent })
    t.after(async () => {
      client.close()
      await relay.stop()
    })

    // Deliberately not awaiting `connect()` first: `subscribe` has to cope with
    // a socket that is still opening, and the version that did this by hand
    // sent the REQ twice — once from `onOpen`, once from its own `.then`.
    const seen: NostrEvent[] = []
    client.subscribe([{ '#h': [GROUP] }], { onEvent: (e) => seen.push(e) })
    await client.connect()
    await settle(100)

    assert.equal(relay.requests.length, 1, 'the same subscription was sent twice')
  })

  it('re-subscribes after a reconnect, with the filters re-evaluated', async (t) => {
    const relay = await FakeRelay.start()
    const signer = LocalSigner.generate()
    const client = new RelayClient({
      url: relay.url,
      signer,
      reconnect: { minDelayMs: 20, maxDelayMs: 40 },
      log: silent,
    })
    t.after(async () => {
      client.close()
      await relay.stop()
    })
    await client.connect()

    let since = 1_700_000_000
    const seen: NostrEvent[] = []
    client.subscribe(() => [{ '#h': [GROUP], since }], { onEvent: (e) => seen.push(e) })
    await settle(60)

    since = 1_700_000_100
    relay.dropConnections()
    await waitFor(() => relay.requests.length === 2, { describe: 'the re-subscribe' })

    // Re-evaluated, not replayed: a subscription driven by a cursor must resume
    // from where the cursor now is, or every reconnect refetches the channel.
    assert.equal(relay.requests[1]!.filters[0]!.since, 1_700_000_100)

    await client.publish(await chat(signer, 'after', 1_700_000_200))
    await waitFor(() => seen.length === 1, { describe: 'a live event on the new socket' })
  })

  it('reports a closed subscription instead of going quiet', async (t) => {
    const { client } = await connected(t)
    const reasons: string[] = []
    client.subscribe([{ kinds: [Kinds.ChatMessage] }], {
      onEvent: () => {},
      onClosed: (reason) => reasons.push(reason),
    })
    await waitFor(() => reasons.length === 1, { describe: 'the CLOSED' })
    assert.match(reasons[0]!, /must contain an h/)
  })

  it('stops delivering after close()', async (t) => {
    const { client, signer } = await connected(t)
    const seen: NostrEvent[] = []
    const sub = client.subscribe([{ '#h': [GROUP] }], { onEvent: (e) => seen.push(e) })
    await settle(50)
    sub.close()

    await client.publish(await chat(signer, 'after close'))
    await settle(80)
    assert.deepEqual(seen, [])
  })
})

describe('trusting the relay', () => {
  it('drops an event whose signature does not check out', async (t) => {
    const { relay, client, signer } = await connected(t)
    const seen: NostrEvent[] = []
    client.subscribe([{ '#h': [GROUP] }], { onEvent: (e) => seen.push(e) })
    await settle(50)

    const real = await chat(signer, 'the real one')
    // Straight down the socket, bypassing the relay's own validation — the
    // relay is the one party with both the position and the motive to
    // substitute an event, and from M4 that event could be an approval.
    const forged = { ...real, content: 'deploy to production' }
    relay.injectRaw(['EVENT', relay.requests[0]!.subId, forged])
    await settle(80)

    assert.deepEqual(seen, [])
  })

  it('drops an event that matches no filter it asked for', async (t) => {
    const { relay, client, signer } = await connected(t)
    const seen: NostrEvent[] = []
    client.subscribe([{ '#h': [GROUP], kinds: [Kinds.Thread] }], { onEvent: (e) => seen.push(e) })
    await settle(50)

    // Valid, signed, and not what was asked for. Matching locally means a relay
    // can narrow what an agent reacts to but never widen it.
    relay.injectRaw(['EVENT', relay.requests[0]!.subId, await chat(signer, 'unasked-for')])
    await settle(80)

    assert.deepEqual(seen, [])
  })
})
