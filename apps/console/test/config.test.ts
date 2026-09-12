/**
 * The keystore.
 *
 * Two of these are security assertions rather than behaviour checks: a secret
 * key must land on disk `0600`, and an identity name must never be able to
 * write outside the console's own directory. Both are the kind of thing that
 * works by accident until the day it does not.
 */

import assert from 'node:assert/strict'
import { mkdtemp, rm, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, it } from 'node:test'
import { keyPath, listIdentities, loadConfig, loadKey, saveConfig, saveKey } from '../src/config.ts'

let dir: string
const env = { ...process.env }

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'quorum-console-'))
  process.env.QUORUM_HOME = dir
  delete process.env.QUORUM_RELAY
  delete process.env.QUORUM_GROUP
  delete process.env.QUORUM_IDENTITY
})

afterEach(async () => {
  await rm(dir, { recursive: true, force: true })
  process.env = { ...env }
})

describe('keys', () => {
  const secret = 'a'.repeat(64)

  it('round-trips a saved key', async () => {
    await saveKey('ada', secret)
    assert.equal(await loadKey('ada'), secret)
  })

  it('writes it 0600 and nothing wider', async () => {
    // `writeFile`'s mode is masked by the umask, so the explicit chmod in
    // saveKey is what actually guarantees this. Remove it and this fails.
    await saveKey('ada', secret)
    const mode = (await stat(keyPath('ada'))).mode & 0o777
    assert.equal(mode, 0o600, `expected 0600, got ${mode.toString(8)}`)
  })

  it('refuses a name that would escape the directory', async () => {
    for (const bad of ['../outside', 'a/b', '..', '.hidden', '']) {
      await assert.rejects(async () => saveKey(bad, secret), /not a usable identity name/)
    }
  })

  it('says what to do when an identity is missing', async () => {
    await assert.rejects(async () => loadKey('nobody'), /quorum keygen nobody/)
  })

  it('lists what is saved', async () => {
    await saveKey('ada', secret)
    await saveKey('bot', secret)
    assert.deepEqual((await listIdentities()).sort(), ['ada', 'bot'])
  })

  it('has no identities before anything is saved', async () => {
    assert.deepEqual(await listIdentities(), [])
  })
})

describe('config', () => {
  it('falls back to the local relay and #payments', async () => {
    const config = await loadConfig()
    assert.equal(config.relay, 'ws://localhost:3334')
    assert.equal(config.group, 'payments')
    assert.equal(config.identity, undefined)
  })

  it('round-trips what was saved', async () => {
    await saveConfig({ relay: 'ws://elsewhere:7777', group: 'ops', identity: 'ada' })
    assert.deepEqual(await loadConfig(), {
      relay: 'ws://elsewhere:7777',
      group: 'ops',
      identity: 'ada',
    })
  })

  it('lets the environment win, without writing it down', async () => {
    // So `QUORUM_GROUP=other quorum inbox` is a one-off that leaves no trace —
    // which matters when the alternative is forgetting you switched groups.
    await saveConfig({ relay: 'ws://saved:1', group: 'saved', identity: 'ada' })
    process.env.QUORUM_GROUP = 'temporary'
    assert.equal((await loadConfig()).group, 'temporary')

    delete process.env.QUORUM_GROUP
    assert.equal((await loadConfig()).group, 'saved')
  })
})
