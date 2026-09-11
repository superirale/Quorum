/**
 * Signer tests.
 *
 * Two of these are not about cryptography at all. `sign()` refusing a foreign
 * pubkey and `LocalSigner` redacting itself are both guards against ordinary
 * mistakes with consequences that cannot be undone — an event attributed to a
 * key you do not hold, and a secret key in a log file.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { inspect } from 'node:util'
import { computeId, verifyEvent, type UnsignedEvent } from '@quorum/protocol'
import { bech32 } from '@scure/base'
import { LocalSigner, Nip07Signer, generateSecretKey } from '../src/index.ts'

const unsigned = (pubkey: string, overrides: Partial<UnsignedEvent> = {}): UnsignedEvent => ({
  pubkey,
  created_at: 1_700_000_000,
  kind: 9,
  tags: [['h', 'payments']],
  content: 'hello',
  ...overrides,
})

describe('LocalSigner', () => {
  it('signs an event that verifies', async () => {
    const signer = LocalSigner.generate()
    const event = await signer.sign(unsigned(signer.publicKey))

    assert.equal(event.pubkey, signer.publicKey)
    assert.equal(event.id, computeId(unsigned(signer.publicKey)))
    assert.ok(verifyEvent(event))
  })

  it('round-trips through hex and nsec to the same key', () => {
    const secret = generateSecretKey()
    const fromHex = LocalSigner.fromHex(secret)
    const fromNsec = LocalSigner.fromNsec(nsecOf(secret))

    assert.equal(fromNsec.publicKey, fromHex.publicKey)
    assert.match(fromHex.npub, /^npub1[02-9ac-hj-np-z]+$/)
  })

  it('reads either encoding out of the environment', () => {
    const secret = generateSecretKey()
    const expected = LocalSigner.fromHex(secret).publicKey

    assert.equal(LocalSigner.fromEnv('K', { K: secret }).publicKey, expected)
    assert.equal(LocalSigner.fromEnv('K', { K: ` ${nsecOf(secret)} ` }).publicKey, expected)
    assert.throws(() => LocalSigner.fromEnv('K', {}), /needs a key to have an identity/)
  })

  it('refuses to sign for someone else', async () => {
    const mine = LocalSigner.generate()
    const theirs = LocalSigner.generate()

    // Not pedantry: `build()` takes a pubkey, and a config mix-up that swaps two
    // agents' keys would otherwise produce events signed by one agent claiming
    // to be the other. Nothing downstream can tell that from an impersonation.
    await assert.rejects(() => mine.sign(unsigned(theirs.publicKey)), /refusing to sign/)
    await assert.rejects(() => mine.sign(unsigned('')), /refusing to sign/)
  })

  it('cannot be stringified into a log line', () => {
    const signer = LocalSigner.fromHex('11'.repeat(32))
    const expected = `LocalSigner(${signer.publicKey})`

    assert.equal(String(signer), expected)
    assert.equal(`${signer}`, expected)
    assert.equal(JSON.stringify({ signer }), JSON.stringify({ signer: expected }))
    assert.equal(JSON.stringify({ config: { signer } }).includes('1111'), false)

    // `util.inspect` is what `console.log(obj)` uses, which is the likeliest
    // path a key takes into a logfile.
    assert.equal(inspect(signer), expected)
  })

  it('rejects a key of the wrong length or encoding', () => {
    assert.throws(() => LocalSigner.fromHex('abc'), /64 hex characters/)
    assert.throws(() => LocalSigner.fromHex('z'.repeat(64)), /64 hex characters/)
    assert.throws(
      () => LocalSigner.fromNsec(LocalSigner.generate().npub),
      /expected an nsec, got a npub/,
    )
  })
})

describe('Nip07Signer', () => {
  const key = LocalSigner.fromHex('22'.repeat(32))

  it('passes an event through a well-behaved extension', async () => {
    const signer = new Nip07Signer({
      getPublicKey: async () => key.publicKey,
      signEvent: (event) => key.sign(event),
    })
    const event = await signer.sign(unsigned(key.publicKey))
    assert.ok(verifyEvent(event))
  })

  it('catches an extension that signs as someone else', async () => {
    const other = LocalSigner.generate()
    const signer = new Nip07Signer({
      getPublicKey: async () => key.publicKey,
      signEvent: (event) => other.sign({ ...event, pubkey: other.publicKey }),
    })
    await assert.rejects(() => signer.sign(unsigned(key.publicKey)), /signed as/)
  })

  it('catches an extension that edits the event on the way past', async () => {
    // The reason this check exists. An extension that can rewrite `content`
    // between the human reading it and the key signing it can turn an approval
    // for one thing into an approval for another, and the signature will be
    // perfectly valid.
    const signer = new Nip07Signer({
      getPublicKey: async () => key.publicKey,
      signEvent: (event) => key.sign({ ...event, content: 'something else entirely' }),
    })
    await assert.rejects(() => signer.sign(unsigned(key.publicKey)), /altered the event/)
  })

  it('catches an extension that returns a bad signature', async () => {
    const signer = new Nip07Signer({
      getPublicKey: async () => key.publicKey,
      signEvent: async (event) => ({ ...(await key.sign(event)), sig: '00'.repeat(64) }),
    })
    await assert.rejects(() => signer.sign(unsigned(key.publicKey)), /invalid id or signature/)
  })
})

/**
 * Encoded here rather than exported from the SDK. Nothing in Quorum should turn
 * a secret key back into a string a human can copy — a test needs one, an agent
 * never does.
 */
function nsecOf(hex: string): string {
  const bytes = Uint8Array.from(hex.match(/../g)!.map((b) => parseInt(b, 16)))
  return bech32.encode('nsec', bech32.toWords(bytes), 1000)
}
