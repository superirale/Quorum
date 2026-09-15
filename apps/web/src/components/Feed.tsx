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

import { isMlsSealed, type NostrEvent } from '@quorum/protocol'
import { describe, hue, short, when } from '../format.ts'

export function Feed({
  events,
  me,
  sealed,
}: {
  events: NostrEvent[]
  me: string
  /** True for an event sealed under an epoch this key does not hold. */
  sealed?: (event: NostrEvent) => boolean
}) {
  if (!events.length) return <p className="dim empty">nothing here yet</p>

  return (
    <ol className="feed">
      {events.map((event) => {
        // Shown, not skipped. "There is traffic here I cannot read" and "the
        // channel is quiet" are different facts, and on an encrypted channel
        // the first one is what being locked out of an epoch looks like.
        //
        // The line is still readable, because `alt` is never sealed — which is
        // the strongest demonstration this app has of why the spec requires it
        // on every kind: a reader with no key at all still gets a sentence.
        const locked = sealed?.(event) ?? false
        // Two locks, and the difference is whether anything can be done. A
        // nip44 event is waiting for a wrap somebody can still send; an mls one
        // is waiting for nothing, because the epoch secrets that opened it were
        // deleted by every member as the group moved on.
        const why = isMlsSealed(event)
          ? 'sealed to an MLS epoch — this client holds no ratchet, and this message will not become readable here'
          : 'sealed under a key you do not hold'
        return (
          <li key={event.id} className={event.pubkey === me ? 'mine' : undefined}>
            <span className="kind">{event.kind}</span>
            <span className="who" style={{ color: `hsl(${hue(event.pubkey)} 60% 70%)` }}>
              {short(event.pubkey)}
            </span>
            <span className={locked ? 'text locked' : 'text'}>
              {locked && <span title={why}>🔒 </span>}
              {describe(event)}
            </span>
            <span className="at dim">{when(event.created_at)}</span>
          </li>
        )
      })}
    </ol>
  )
}
