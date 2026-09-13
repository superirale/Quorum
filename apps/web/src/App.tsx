/**
 * The whole client, in two states: set up, or connected.
 *
 * There is no router and no server session. Everything this app knows is the
 * key in `localStorage` and the events the relay hands it, which is the same
 * position the console is in and the same position an auditor is in. A reload
 * is a full rebuild of every view from signed events.
 */

import { useCallback, useState } from 'react'
import { Agents } from './components/Agents.tsx'
import { Approvals } from './components/Approvals.tsx'
import { Chains } from './components/Chains.tsx'
import { Composer } from './components/Composer.tsx'
import { Feed } from './components/Feed.tsx'
import { Grants } from './components/Grants.tsx'
import { Setup } from './components/Setup.tsx'
import { Tasks } from './components/Tasks.tsx'
import { ThreadView } from './components/ThreadView.tsx'
import { forget, load, type Identity } from './identity.ts'
import { loadSettings, type Settings } from './settings.ts'
import { short } from './format.ts'
import { useWorkspace } from './useWorkspace.ts'

/** Which pane is on the right. Selecting a task switches to `thread`. */
type View = 'channel' | 'thread' | 'actions' | 'grants'

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

function Tab({
  now,
  is,
  go,
  children,
}: {
  now: View
  is: View
  go: (view: View) => void
  children: React.ReactNode
}) {
  return (
    <button className={now === is ? 'tab on' : 'tab'} onClick={() => go(is)}>
      {children}
    </button>
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
  const [view, setView] = useState<View>('channel')
  const [selected, setSelected] = useState<string | undefined>()

  // Looked up on every render rather than held in state. A thread is derived
  // from events that keep arriving, so a copy stored on selection would go
  // stale the moment the agent it is about does anything.
  const thread = workspace.threads.find((t) => t.id === selected)

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
        <Agents agents={workspace.agents} now={workspace.now} />
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

          <h2>Tasks</h2>
          <Tasks
            threads={workspace.threads}
            now={workspace.now}
            selected={view === 'thread' ? selected : undefined}
            onSelect={(id) => {
              setSelected(id)
              setView('thread')
            }}
          />
        </section>

        <section className="right">
          <nav className="tabs">
            <Tab now={view} is="channel" go={setView}>
              Channel
            </Tab>
            {thread && (
              <Tab now={view} is="thread" go={setView}>
                {thread.title}
              </Tab>
            )}
            <Tab now={view} is="actions" go={setView}>
              Actions
            </Tab>
            <Tab now={view} is="grants" go={setView}>
              Capabilities
            </Tab>
          </nav>

          {view === 'channel' && (
            <>
              <Feed events={workspace.feed} me={identity.pubkey} />
              <Composer workspace={workspace} />
            </>
          )}

          {view === 'thread' &&
            (thread ? (
              <>
                <ThreadView
                  workspace={workspace}
                  thread={thread}
                  me={identity.pubkey}
                  onBack={() => setView('channel')}
                />
                <Composer workspace={workspace} thread={thread} />
              </>
            ) : (
              // The root has not been served yet, or was never served: a
              // comment can name a thread this client does not hold, and
              // `threads()` refuses to invent one from it.
              <p className="dim empty">that task's root is not in anything this client was served</p>
            ))}

          {view === 'actions' && <Chains chains={workspace.chains} />}
          {view === 'grants' && <Grants grants={workspace.grants} now={workspace.now} />}
        </section>
      </main>
    </div>
  )
}
