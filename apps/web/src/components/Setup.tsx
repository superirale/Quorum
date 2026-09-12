/**
 * The first screen: a key, a relay, a group.
 *
 * The warning at the top is not boilerplate and is not collapsible. This page
 * puts a secret key in `localStorage` in the clear, and the failure mode of a
 * development tool is that it stops being one — somebody points it at a relay
 * that matters because it looked finished. Saying so on the screen where the
 * key is created is the only placement that reaches the person deciding.
 */

import { useState } from 'react'
import { generate, save, type Identity } from '../identity.ts'
import { saveSettings, type Settings } from '../settings.ts'

export function Setup({
  identity,
  settings,
  onReady,
}: {
  identity: Identity | undefined
  settings: Settings
  onReady: (identity: Identity, settings: Settings) => void
}) {
  const [secret, setSecret] = useState('')
  const [name, setName] = useState(identity?.name ?? '')
  const [relay, setRelay] = useState(settings.relay)
  const [group, setGroup] = useState(settings.group)
  const [problem, setProblem] = useState<string | undefined>()

  const submit = (event: React.FormEvent) => {
    event.preventDefault()
    setProblem(undefined)
    if (!group.trim()) return setProblem('a group id is required — it is the NIP-29 `h` tag')
    try {
      // The identity is only re-derived when a key was typed. Changing the relay
      // must not silently mint a new pubkey: every grant already issued names
      // the old one, and they would all stop working for no visible reason.
      const next = secret.trim() ? save(secret, name) : identity
      if (!next) return setProblem('paste or generate a secret key')
      onReady(next, saveSettings({ relay, group }))
    } catch (error) {
      setProblem((error as Error).message)
    }
  }

  return (
    <div className="setup">
      <h1>Quorum</h1>

      <div className="banner warn">
        <strong>This page keeps your secret key in localStorage, unencrypted.</strong>
        <p>
          Any script that runs on this origin can read it, and so can anyone with a minute at
          your unlocked machine. That is worse than the console, which at least writes a mode
          0600 file. Use a throwaway key and a local relay. The real answer is NIP-46 — a
          remote signer that holds the key and signs on request — and it is a later milestone.
        </p>
      </div>

      <form onSubmit={submit}>
        <label>
          Secret key
          <div className="row">
            <input
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              placeholder={identity ? `keeping ${identity.pubkey.slice(0, 16)}…` : 'hex or nsec1…'}
              spellCheck={false}
            />
            <button type="button" onClick={() => setSecret(generate())}>
              generate
            </button>
          </div>
        </label>

        <label>
          Display name
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="ada"
            spellCheck={false}
          />
          <span className="hint">
            Local only. Nothing on the wire carries it — the relay, the agents and the auditor
            all see the key.
          </span>
        </label>

        <label>
          Relay
          <input value={relay} onChange={(e) => setRelay(e.target.value)} spellCheck={false} />
        </label>

        <label>
          Group
          <input
            value={group}
            onChange={(e) => setGroup(e.target.value)}
            placeholder="demo"
            spellCheck={false}
          />
          <span className="hint">
            The NIP-29 group id. It must already exist, and this key must be a member: run{' '}
            <code>q workspace add &lt;pubkey&gt;</code> from the console as the owner.
          </span>
        </label>

        {problem && <div className="banner error">{problem}</div>}
        <button type="submit" className="primary">
          connect
        </button>
      </form>
    </div>
  )
}
