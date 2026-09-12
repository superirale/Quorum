/**
 * The whole client, in two states: set up, or connected.
 *
 * There is no router and no server session. Everything this app knows is the
 * key in `localStorage` and the events the relay hands it, which is the same
 * position the console is in and the same position an auditor is in. A reload
 * is a full rebuild of every view from signed events.
 */

import { useCallback, useState } from 'react'
import { Approvals } from './components/Approvals.tsx'
import { Chains } from './components/Chains.tsx'
import { Composer } from './components/Composer.tsx'
import { Feed } from './components/Feed.tsx'
import { Setup } from './components/Setup.tsx'
import { forget, load, type Identity } from './identity.ts'
import { loadSettings, type Settings } from './settings.ts'
import { short } from './format.ts'
import { useWorkspace } from './useWorkspace.ts'

export function App() {
  const [identity, setIdentity] = useState<Identity | undefined>(load)
  const [settings, setSettings] = useState<Settings>(loadSettings)

  if (!identity || !settings.group) {
    return (
      <Setup
        identity={identity}
        settings={settings}
        onReady={(next, where) => {
          setIdentity(next)
          setSettings(where)
        }}
      />
    )
  }

  return (
    <Connected
      identity={identity}
      settings={settings}
      onForget={() => {
        forget()
        setIdentity(undefined)
      }}
    />
  )
}

function Connected({
  identity,
  settings,
  onForget,
}: {
  identity: Identity
  settings: Settings
  onForget: () => void
}) {
  const workspace = useWorkspace(identity, settings.relay, settings.group)
  const [copied, setCopied] = useState(false)

  const copy = useCallback(() => {
    void navigator.clipboard?.writeText(identity.pubkey).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    })
  }, [identity.pubkey])

  return (
    <div className="app">
      <header>
        <div>
          <strong>#{settings.group}</strong>{' '}
          <span className={`status ${workspace.status}`}>{workspace.status}</span>
          <span className="dim"> · {settings.relay}</span>
        </div>
        <div>
          <span className="dim">{identity.name} </span>
          <button className="link" onClick={copy} title="copy this pubkey">
            {copied ? 'copied' : short(identity.pubkey)}
          </button>{' '}
          <button className="link danger" onClick={onForget}>
            forget key
          </button>
        </div>
      </header>

      {workspace.problem && (
        <div className="banner error">
          {workspace.problem}
          <div className="dim">
            If this says you are not a member: the relay has to admit this key first. Run{' '}
            <code>q workspace add {identity.pubkey}</code> from the console as the workspace
            owner.
          </div>
        </div>
      )}

      <main>
        <section className="left">
          <h2>
            Waiting on you{' '}
            {workspace.pending.length > 0 && <span className="count">{workspace.pending.length}</span>}
          </h2>
          <Approvals workspace={workspace} me={identity.pubkey} />

          <h2>Actions</h2>
          <Chains chains={workspace.chains} />
        </section>

        <section className="right">
          <h2>Channel</h2>
          <Feed events={workspace.feed} me={identity.pubkey} />
          <Composer workspace={workspace} />
        </section>
      </main>
    </div>
  )
}
