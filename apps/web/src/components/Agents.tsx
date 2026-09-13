/**
 * Who is up, and — the part that needs saying out loud — who has merely not said.
 *
 * Presence is kind 28103, which is ephemeral: relays do not store it, so a
 * client that connected thirty seconds ago knows only about agents that have
 * beaten since. An empty row here means *nobody has said anything yet*. It
 * never means nobody is running, and an agent absent from this list may be
 * midway through a production deploy.
 *
 * That caveat is in the UI and not only in this comment, because the mistake it
 * prevents is the expensive one: starting a second replica of an agent that
 * looked idle. The lease (28102) is what actually stops two agents working one
 * thread; this is a status light.
 *
 * A beat expires at its own `created_at + ttl_seconds` — the author's clock, so
 * every reader agrees on the moment, and a skewed agent looks stale to
 * everybody rather than fresh to some. Nothing is ever authorised on a
 * heartbeat, which is the only reason that is an acceptable trade.
 */

import type { Presence } from '@quorum/sdk'
import { ago, hue, short } from '../format.ts'

export function Agents({ agents, now }: { agents: Presence[]; now: number }) {
  if (!agents.length) {
    return (
      <p className="dim empty" title="kind 28103 is ephemeral: relays store nothing, so this only ever shows agents that have beaten since you connected">
        nobody has said
      </p>
    )
  }

  return (
    <ul className="agents">
      {agents.map((agent) => (
        <li key={agent.pubkey} className={agent.live ? undefined : 'stale'}>
          <span className={`dot ${agent.live ? agent.status : 'gone'}`} aria-hidden />
          <span className="who" style={{ color: `hsl(${hue(agent.pubkey)} 60% 70%)` }}>
            {short(agent.pubkey)}
          </span>
          <span className="dim">{caption(agent, now)}</span>
        </li>
      ))}
    </ul>
  )
}

/**
 * What to say beside the dot.
 *
 * A stale beat is reported as "last seen", not as "offline". The agent did not
 * tell us it stopped — we stopped hearing from it, which is also what a dropped
 * websocket looks like from here.
 */
function caption(agent: Presence, now: number): string {
  if (!agent.live) return `last seen ${ago(agent.at, now)}`
  if (agent.status === 'offline') return 'signed off'
  return agent.activity ? `${agent.status} · ${agent.activity}` : agent.status
}
