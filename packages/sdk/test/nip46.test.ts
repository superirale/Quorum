/**
 * NIP-46 tests — both halves, over a real socket.
 *
 * Every method on `Nip46Signer` is a round trip, so there is no unit of it that
 * can be tested alone: a test with no bunker on the other end can only assert
 * that requests time out. `FakeBunker` from `@quorum/test-kit` is the other end,
 * and it can misbehave on purpose, which is the only way the three checks in
 * `sign()` are anything more than a comment.
 *
 * The relay here runs with `requireScopedFilters: false`, and that is not a
 * convenience. A bunker relay is a generic public relay chosen by whoever runs
 * the bunker — it is deliberately *not* the Quorum workspace relay, which is why
 * `Nip46Signer` builds its own `RelayClient` rather than borrowing the agent's,
 * and why a `{kinds, #p}` filter with no `h` tag is the correct filter to send
 * it.
 */

import assert from 'node:assert/strict'
import { describe, it, type TestContext } from 'node:test'
import { FakeBunker, FakeRelay } from '@quorum/test-kit'
import { type NostrEvent, type UnsignedEvent } from '@quorum/protocol'
import { LocalSigner, Nip46Signer, bunkerUri, generateSecretKey, parseBunkerUri } from '../src/index.ts'

const silent = { warn() {}, error() {} }

const draft = (pubkey: string, overrides: Partial<UnsignedEvent> = {}): UnsignedEvent => ({
  pubkey,
  created_at: 1_700_000_000,
  kind: 9,
  tags: [['h', 'payments']],
  content: 'ship it',
  ...overrides,
})

interface Session {
  relay: FakeRelay
  bunker: FakeBunker
  signer: Nip46Signer
}

/**
 * Start a relay, a bunker on it, and a signer connected to that bunker.
 *
 * `t.after` rather than a shared fixture: each test gets its own relay for the
 * same reason the demos do — a bunker remembers which clients it has connected,
 * and a shared one would let a later test pass on an earlier test's handshake.
 */
async function session(
  t: TestContext,
  bunkerOptions: Partial<Parameters<typeof FakeBunker.start>[0]> = {},
  signerOptions: Partial<Parameters<typeof Nip46Signer.open>[0]> = {},
): Promise<Session> {
  const relay = await FakeRelay.start({ requireScopedFilters: false })
  const bunker = await FakeBunker.start({ relay: relay.url, ...bunkerOptions })
  const signer = await Nip46Signer.open({
    uri: bunker.uri,
    requestTimeoutMs: 5_000,
    log: silent,
    ...signerOptions,
  })
  t.after(async () => {
    signer.close()
    bunker.close()
    await relay.stop()
  })
  return { relay, bunker, signer }
}

describe('parseBunkerUri', () => {
  it('reads a remote pubkey, every relay, and the secret', () => {
    const remote = LocalSigner.generate().publicKey
    const parsed = parseBunkerUri(
      bunkerUri(remote, ['wss://a.example', 'wss://b.example'], 'handshake'),
    )

    assert.equal(parsed.remote, remote)
    assert.deepEqual(parsed.relays, ['wss://a.example', 'wss://b.example'])
    assert.equal(parsed.secret, 'handshake')
  })

  it('refuses a URI with no relay rather than guessing one', () => {
    // The symptom of a guess is a NIP-44 payload sent to a relay the bunker is
    // not watching, which surfaces sixty seconds later as an unexplained
    // timeout. Refusing here names the actual fault.
    const remote = LocalSigner.generate().publicKey

    assert.throws(() => parseBunkerUri(`bunker://${remote}`), /at least one \?relay=/)
    assert.throws(() => parseBunkerUri(`nostrconnect://${remote}?relay=wss://a`), /not a bunker URI/)
    assert.throws(() => parseBunkerUri('bunker://not-a-pubkey?relay=wss://a'), /64-hex remote/)
  })
})

describe('Nip46Signer', () => {
  it('connects, then asks who it is speaking for', async (t) => {
    const { bunker, signer } = await session(t)

    assert.deepEqual(
      bunker.requests.map((r) => r.method),
      ['connect', 'get_public_key'],
      'connect must come first: a bunker may refuse everything until it has one',
    )
    assert.equal(await signer.pubkey(), bunker.pubkey)
    assert.equal(await signer.ping(), 'pong')
  })

  it('keeps the client key separate from the identity it signs as', async (t) => {
    // The distinction the whole transport rests on. The client key addresses and
    // encrypts the RPC and is not an identity; losing it costs a reconnect,
    // whereas the user key is the thing a production approval is attributed to.
    const { bunker, signer } = await session(t)

    assert.notEqual(signer.clientPubkey, bunker.pubkey)
    assert.equal(bunker.requests[0]?.from, signer.clientPubkey)

    // And it is reusable, which is what lets a bunker's approval of this
    // session survive a console restart.
    const again = await Nip46Signer.open({
      uri: bunker.uri,
      clientSecretKey: signer.clientSecretKey,
      requestTimeoutMs: 5_000,
      log: silent,
    })
    t.after(() => again.close())
    assert.equal(again.clientPubkey, signer.clientPubkey)
  })

  it('signs an event that verifies, as the user key', async (t) => {
    const { bunker, signer } = await session(t)
    const event = await signer.sign(draft(bunker.pubkey))

    assert.equal(event.pubkey, bunker.pubkey)
    assert.equal(event.content, 'ship it')
    assert.deepEqual(bunker.requests.at(-1)?.method, 'sign_event')
  })

  it('stamps the user pubkey onto the draft rather than trusting the caller', async (t) => {
    // A caller that has not yet learned the user pubkey — or has a stale one
    // from a previous session — would otherwise hand the bunker a draft naming
    // the wrong author, and the id would commit to it.
    const { bunker, signer } = await session(t)
    const event = await signer.sign(draft(LocalSigner.generate().publicKey))

    assert.equal(event.pubkey, bunker.pubkey)
  })

  it('refuses an event the bunker signed as a different key', async (t) => {
    // The attack this stops is quiet: a bunker that signs a production approval
    // as a key the human never agreed to use. It still reports the real pubkey
    // from `get_public_key`, so nothing before this check notices.
    const { bunker, signer } = await session(t, { signAs: generateSecretKey() })

    await assert.rejects(() => signer.sign(draft(bunker.pubkey)), /signed as .*, expected/)
  })

  it('refuses an event the bunker edited on the way past', async (t) => {
    const { bunker, signer } = await session(t, {
      tamper: (event: NostrEvent) => ({ ...event, content: 'ship it to production' }),
    })

    await assert.rejects(() => signer.sign(draft(bunker.pubkey)), /altered the event/)
  })

  it('refuses an event whose signature does not cover what came back', async (t) => {
    // Backdating, specifically — it passes both earlier checks, because the
    // pubkey, the kind and the content are all untouched. Only recomputing the
    // id catches it, and an approval whose timestamp can be moved is an
    // approval that can be made to predate the thing it approved.
    const { bunker, signer } = await session(t, {
      tamper: (event: NostrEvent) => ({ ...event, created_at: event.created_at - 86_400 }),
    })

    await assert.rejects(() => signer.sign(draft(bunker.pubkey)), /invalid id or signature/)
  })

  it('encrypts and decrypts with the key it does not hold', async (t) => {
    // This is what makes a bunker usable on a `nip44` channel at all: the
    // channel key is wrapped to the user pubkey, so unwrapping it needs the
    // user secret, which is the one thing this process never sees.
    const { bunker, signer } = await session(t)
    const peer = LocalSigner.generate()

    const payload = await signer.nip44Encrypt(peer.publicKey, 'epoch 3')
    assert.equal(await peer.nip44Decrypt(bunker.pubkey, payload), 'epoch 3')

    const back = await peer.nip44Encrypt(bunker.pubkey, 'epoch 4')
    assert.equal(await signer.nip44Decrypt(peer.publicKey, back), 'epoch 4')
  })

  it('refuses a client the connect secret does not match', async (t) => {
    const relay = await FakeRelay.start({ requireScopedFilters: false })
    const bunker = await FakeBunker.start({ relay: relay.url, secret: 'the-right-one' })
    t.after(async () => {
      bunker.close()
      await relay.stop()
    })

    await assert.rejects(
      () =>
        Nip46Signer.open({
          uri: bunkerUri(bunker.pubkey, [relay.url], 'the-wrong-one'),
          requestTimeoutMs: 5_000,
          log: silent,
        }),
      /connect failed: .*secret did not match/,
    )
  })
})

describe('the auth challenge', () => {
  it('hands the URL to onAuth and finishes once a human approves', async (t) => {
    // `auth_url` arrives *instead of* the answer and resolves nothing, so the
    // request is still pending when the human clicks. A client that treated the
    // challenge as a failure would have given up before the bunker replied.
    const relay = await FakeRelay.start({ requireScopedFilters: false })
    const bunker = await FakeBunker.start({
      relay: relay.url,
      authUrl: { method: 'connect', url: 'https://bunker.example/approve/abc' },
    })
    const seen: string[] = []

    const signer = await Nip46Signer.open({
      uri: bunker.uri,
      requestTimeoutMs: 5_000,
      log: silent,
      onAuth: (url) => {
        seen.push(url)
        bunker.approve()
      },
    })
    t.after(async () => {
      signer.close()
      bunker.close()
      await relay.stop()
    })

    assert.deepEqual(seen, ['https://bunker.example/approve/abc'])
    assert.equal(await signer.pubkey(), bunker.pubkey)
  })

  it('fails loudly when the caller handed it nowhere to send a human', async (t) => {
    // The alternative is a thirty-second hang ending in a timeout that blames
    // the bunker, which is the single most confusing failure this transport can
    // produce. The message names what the *caller* did not handle.
    const relay = await FakeRelay.start({ requireScopedFilters: false })
    const bunker = await FakeBunker.start({
      relay: relay.url,
      authUrl: { method: 'connect', url: 'https://bunker.example/approve/abc' },
    })
    t.after(async () => {
      bunker.close()
      await relay.stop()
    })

    await assert.rejects(
      () => Nip46Signer.open({ uri: bunker.uri, requestTimeoutMs: 5_000, log: silent }),
      /needs a human to approve this at https:\/\/bunker\.example\/approve\/abc.*no onAuth/s,
    )
  })

  it('challenges once per method, so a later signature is not gated again', async (t) => {
    const relay = await FakeRelay.start({ requireScopedFilters: false })
    const bunker = await FakeBunker.start({
      relay: relay.url,
      authUrl: { method: 'sign_event', url: 'https://bunker.example/approve/xyz' },
    })
    let challenges = 0

    const signer = await Nip46Signer.open({
      uri: bunker.uri,
      requestTimeoutMs: 5_000,
      log: silent,
      onAuth: () => {
        challenges += 1
        bunker.approve()
      },
    })
    t.after(async () => {
      signer.close()
      bunker.close()
      await relay.stop()
    })

    await signer.sign(draft(bunker.pubkey))
    await signer.sign(draft(bunker.pubkey, { content: 'and again' }))

    assert.equal(challenges, 1)
  })
})

describe('when the bunker is not there', () => {
  it('times out with a message naming the two likely causes', async (t) => {
    // "The bunker is broken" is the conclusion people jump to and almost never
    // the right one. It is usually watching a different relay, or waiting for
    // someone to click something.
    const relay = await FakeRelay.start({ requireScopedFilters: false })
    const bunker = await FakeBunker.start({ relay: relay.url })
    const signer = await Nip46Signer.open({
      uri: bunker.uri,
      requestTimeoutMs: 250,
      log: silent,
    })
    t.after(async () => {
      signer.close()
      await relay.stop()
    })

    bunker.close()

    await assert.rejects(
      () => signer.ping(),
      new RegExp(`did not answer \`ping\` within 250ms.*${relay.url}`, 's'),
    )
  })
})
