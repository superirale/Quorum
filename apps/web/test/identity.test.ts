/**
 * What this page remembers about who you are.
 *
 * Storage, not signing — the interesting claims here are about what is written
 * and what is refused, and every one of them is a thing that goes wrong on a
 * *reload* rather than on the screen where it was set up. That is why they are
 * worth tests at all: a mistake in this file is invisible until the second
 * visit, by which point the page is already signing as somebody.
 *
 * `connectBunker` and `resumeBunker` are absent. Both are a websocket handshake
 * with a remote signer, and a fake bunker here would test this file's use of a
 * mock rather than its use of NIP-46. The part of `resumeBunker` that is pure
 * policy — refusing a session whose user pubkey changed — is asserted through
 * the session `savedBunker` hands back, which is the input it reads.
 */

import assert from 'node:assert/strict'
import { beforeAll as before, beforeEach, test } from 'vitest'

// Installed before the module under test is imported, because `identity.ts`
// reaches for the global. A `Map` rather than a real store: these tests care
// about which keys are written, and the cheapest way to see that is to look.
//
// `defineProperty` rather than assignment because jsdom's `localStorage` is a
// getter on `Window` with no setter, so `globalThis.localStorage = …` throws
// where it worked under bare Node.
const store = new Map<string, string>()
Object.defineProperty(globalThis, 'localStorage', {
  configurable: true,
  value: {
    getItem: (k: string) => store.get(k) ?? null,
    setItem: (k: string, v: string) => void store.set(k, v),
    removeItem: (k: string) => void store.delete(k),
    clear: () => store.clear(),
  },
})

type Identity = typeof import('../src/identity.ts')
let identity: Identity

before(async () => {
  identity = await import('../src/identity.ts')
})

beforeEach(() => store.clear())

const SECRET = 'd1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2'

test('a saved dev key comes back as the same pubkey', () => {
  const saved = identity.save(SECRET, 'ada')
  const loaded = identity.loadLocal()
  assert.equal(loaded?.pubkey, saved.pubkey)
  assert.equal(loaded?.name, 'ada')
  assert.equal(loaded?.backing, 'local')
})

test('a nameless identity gets a placeholder rather than an empty header', () => {
  assert.equal(identity.save(SECRET, '   ').name, 'me')
})

test('a key that is not a key is refused at the form, not on the next load', () => {
  assert.throws(() => identity.save('not-a-key', 'ada'))
  assert.equal(identity.loadLocal(), undefined)
})

test('a corrupt saved key loads as nobody rather than as a new pubkey', () => {
  // Silently generating a fresh key would change who you are mid-session, and
  // every grant issued to the old pubkey would stop working with nothing on
  // screen connecting the two facts.
  store.set('quorum.secret', 'truncated')
  const quiet = console.error
  console.error = () => {}
  try {
    assert.equal(identity.loadLocal(), undefined)
  } finally {
    console.error = quiet
  }
})

test('generate() produces a key that save() accepts', () => {
  assert.doesNotThrow(() => identity.save(identity.generate(), 'ada'))
})

test('savedBunker refuses a half-written session', () => {
  // Each of these would otherwise reach `Nip46Signer.open` and fail there, on a
  // restore screen, with a message about a URI rather than about storage.
  assert.equal(identity.savedBunker(), undefined)

  store.set('quorum.bunker', 'not json')
  assert.equal(identity.savedBunker(), undefined)

  store.set('quorum.bunker', JSON.stringify({ uri: 'bunker://x', connectedAt: 1 }))
  assert.equal(identity.savedBunker(), undefined, 'no client key: nothing to reconnect with')

  store.set(
    'quorum.bunker',
    JSON.stringify({ uri: 'bunker://x', clientSecretKey: SECRET, connectedAt: 1 }),
  )
  assert.equal(identity.savedBunker(), undefined, 'no pubkey: the swap check has nothing to compare')

  const whole = { uri: 'bunker://x', clientSecretKey: SECRET, pubkey: 'abc', connectedAt: 1 }
  store.set('quorum.bunker', JSON.stringify(whole))
  assert.deepEqual(identity.savedBunker(), whole)
})

test('saving a dev key drops a bunker session, and there is no second identity to race', () => {
  // The failure this prevents: both are in storage, the first paint takes the
  // local key, the restore replaces it with whoever the bunker says you are,
  // and the page changes pubkey a second after it loads.
  store.set(
    'quorum.bunker',
    JSON.stringify({ uri: 'bunker://x', clientSecretKey: SECRET, pubkey: 'abc', connectedAt: 1 }),
  )
  identity.save(SECRET, 'ada')
  assert.equal(identity.savedBunker(), undefined)
})

test('signing out forgets both backings', () => {
  // A half-signed-out page lies: it shows the setup screen and then restores a
  // session the human believes they ended.
  identity.save(SECRET, 'ada')
  store.set(
    'quorum.bunker',
    JSON.stringify({ uri: 'bunker://x', clientSecretKey: SECRET, pubkey: 'abc', connectedAt: 1 }),
  )
  identity.forget()
  assert.equal(identity.loadLocal(), undefined)
  assert.equal(identity.savedBunker(), undefined)
  assert.deepEqual([...store.keys()], [])
})
