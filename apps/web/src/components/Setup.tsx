/**
 * The first screen: a signer, a relay, a group.
 *
 * Two ways in, in the order they deserve. A **bunker** (NIP-46) keeps the key
 * out of this page entirely and is the default tab. A **dev key** puts a secret
 * key in `localStorage` in the clear, which is fine for a throwaway identity on
 * a local relay and is not fine for anything else.
 *
 * The warning on the dev-key tab is not boilerplate and is not collapsible. The
 * failure mode of a development tool is that it stops being one — somebody
 * points it at a relay that matters because it looked finished — and the screen
 * where the key is created is the only placement that reaches the person
 * deciding.
 */

import { useState } from 'react'
import { connectBunker, generate, save, type Identity } from '../identity.ts'
import { saveSettings, type Settings } from '../settings.ts'
import { AuthPrompt } from './AuthPrompt.tsx'

type How = 'bunker' | 'key'

export function Setup({
  identity,
  settings,
  problem: reported,
  onReady,
}: {
  identity: Identity | undefined
  settings: Settings
  /** Something that went wrong before this screen — a failed session restore. */
  problem?: string
  onReady: (identity: Identity, settings: Settings) => void
}) {
  const [how, setHow] = useState<How>(identity ? 'key' : 'bunker')
  const [uri, setUri] = useState('')
  const [secret, setSecret] = useState('')
  const [name, setName] = useState(identity?.name ?? '')
  const [relay, setRelay] = useState(settings.relay)
  const [group, setGroup] = useState(settings.group)
  const [problem, setProblem] = useState<string | undefined>(reported)
  const [authUrl, setAuthUrl] = useState<string | undefined>()
  const [connecting, setConnecting] = useState(false)

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    setProblem(undefined)
    if (!group.trim()) return setProblem('a group id is required — it is the NIP-29 `h` tag')

    try {
      if (how === 'bunker') {
        if (!uri.trim()) return setProblem('paste a bunker:// URI from your signer')
        setConnecting(true)
        const next = await connectBunker(uri, name, setAuthUrl)
        onReady(next, saveSettings({ relay, group }))
        return
      }
      // The identity is only re-derived when a key was typed. Changing the relay
      // must not silently mint a new pubkey: every grant already issued names
      // the old one, and they would all stop working for no visible reason.
      const next = secret.trim() ? save(secret, name) : identity
      if (!next) return setProblem('paste or generate a secret key')
      onReady(next, saveSettings({ relay, group }))
    } catch (error) {
      setProblem((error as Error).message)
    } finally {
      setConnecting(false)
      setAuthUrl(undefined)
    }
  }

  return (
    <div className="setup">
      <h1>Quorum</h1>

      <nav className="tabs">
        <button className={how === 'bunker' ? 'tab on' : 'tab'} onClick={() => setHow('bunker')}>
          Remote signer
        </button>
        <button className={how === 'key' ? 'tab on' : 'tab'} onClick={() => setHow('key')}>
          Dev key
        </button>
      </nav>

      {how === 'key' && (
        <div className="banner warn">
          <strong>This page keeps your secret key in localStorage, unencrypted.</strong>
          <p>
            Any script that runs on this origin can read it, and so can anyone with a minute at
            your unlocked machine. That is worse than the console, which at least writes a mode
            0600 file. Use a throwaway key and a local relay — or use a remote signer, which is
            the tab next to this one and does not hand this page a key at all.
          </p>
        </div>
      )}

      {authUrl && <AuthPrompt url={authUrl} />}

      <form onSubmit={submit}>
        {how === 'bunker' ? (
          <label>
            Bunker URI
            <input
              value={uri}
              onChange={(e) => setUri(e.target.value)}
              placeholder="bunker://<pubkey>?relay=wss://…&secret=…"
              spellCheck={false}
            />
            <span className="hint">
              From your signer — nsecbunker, Amber, or any NIP-46 bunker. This page generates a
              throwaway client key to talk to it and stores that, never your identity key. The
              signer may ask you to approve the connection.
            </span>
          </label>
        ) : (
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
        )}

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
          <span className="hint">
            The workspace relay. A bunker is reached on the relays named in its own URI, which
            need not be this one.
          </span>
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
            <code>q workspace add &lt;pubkey&gt;</code> from the console as the owner. If the
            channel is encrypted, somebody also has to wrap its key for you —{' '}
            <code>q channel key &lt;pubkey&gt;</code>.
          </span>
        </label>

        {problem && <div className="banner error">{problem}</div>}
        <button type="submit" className="primary" disabled={connecting}>
          {connecting ? 'waiting for your signer…' : 'connect'}
        </button>
      </form>
    </div>
  )
}
