/**
 * Turning events into text a human can read.
 *
 * `describe` is the browser's copy of the console's, and it is the one function
 * in this client that proves a spec claim rather than merely using it: the
 * `alt` tag is required on every Quorum kind so that a reader which has never
 * heard of kind 8102 still renders a usable line. This client knows several
 * kinds and deliberately renders all of them through `alt` anyway, because a
 * fallback nothing exercises is a fallback that does not work.
 */

import { TagName, tagValue, type NostrEvent } from '@quorum/protocol'

/** Enough of a hex id to recognise, short enough to scan a column of them. */
export function short(hex: string): string {
  return hex.length > 12 ? `${hex.slice(0, 8)}…` : hex
}

export function when(seconds: number): string {
  return new Date(seconds * 1000).toLocaleTimeString()
}

/**
 * How long ago, in the coarsest unit that is still true.
 *
 * Both arguments are seconds from the events themselves, so this says the same
 * thing in every client reading the same channel — and it can go negative, when
 * an author's clock is ahead of ours. "just now" rather than "in 4 seconds":
 * a clock skew is not a fact about the work.
 */
export function ago(seconds: number, now: number): string {
  const d = Math.max(0, now - seconds)
  return d < 45 ? 'just now' : `${span(d)} ago`
}

/**
 * The same thing, in whichever direction the moment lies.
 *
 * Deadlines need both: a grant's `expires_at` is in the future until the second
 * it is not, and the row must go on saying something true across that boundary
 * without the caller checking which side it is on.
 */
export function until(seconds: number, now: number): string {
  return seconds <= now ? ago(seconds, now) : `in ${span(seconds - now)}`
}

function span(d: number): string {
  if (d < 90) return `${Math.max(1, Math.round(d))}s`
  if (d < 3600) return `${Math.round(d / 60)}m`
  if (d < 86_400) return `${Math.round(d / 3600)}h`
  return `${Math.round(d / 86_400)}d`
}

export function describe(event: NostrEvent): string {
  const alt = tagValue(event.tags, TagName.Alt)
  if (alt) return alt
  if (event.content && event.content.length < 200) return event.content
  return `kind ${event.kind}`
}

/**
 * A stable colour per pubkey, so two agents are distinguishable at a glance.
 *
 * Derived from the key itself rather than assigned on arrival: the same agent
 * must look the same after a reload, and there is no server to ask.
 */
export function hue(pubkey: string): number {
  let h = 0
  for (const c of pubkey.slice(0, 16)) h = (h * 31 + c.charCodeAt(0)) % 360
  return h
}
