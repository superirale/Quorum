/**
 * Every event in the channel, rendered through its `alt` tag.
 *
 * Deliberately one renderer for all kinds, including the ones this client
 * understands perfectly well. NIP-31 `alt` is required on every Quorum kind so
 * that a reader which has never heard of kind 8106 still produces a usable
 * line, and the way to know that holds is to depend on it here rather than to
 * keep a special case per kind and a fallback nobody exercises.
 *
 * The kind number stays visible next to it. When a new kind lands, this feed
 * will render it on the day it is invented, and you will be able to see that it
 * did so without knowing what it was.
 */

import type { NostrEvent } from '@quorum/protocol'
import { describe, hue, short, when } from '../format.ts'

export function Feed({ events, me }: { events: NostrEvent[]; me: string }) {
  if (!events.length) return <p className="dim empty">nothing here yet</p>

  return (
    <ol className="feed">
      {events.map((event) => (
        <li key={event.id} className={event.pubkey === me ? 'mine' : undefined}>
          <span className="kind">{event.kind}</span>
          <span className="who" style={{ color: `hsl(${hue(event.pubkey)} 60% 70%)` }}>
            {short(event.pubkey)}
          </span>
          <span className="text">{describe(event)}</span>
          <span className="at dim">{when(event.created_at)}</span>
        </li>
      ))}
    </ol>
  )
}
