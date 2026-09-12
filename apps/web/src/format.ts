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
