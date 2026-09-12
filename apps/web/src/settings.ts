/**
 * Which relay, which group. Two strings, in `localStorage`.
 *
 * Deliberately not part of `Identity`: a key is a thing you must not lose and a
 * relay URL is a thing you will change six times in an afternoon while testing.
 */

const RELAY = 'quorum.relay'
const GROUP = 'quorum.group'

export interface Settings {
  relay: string
  group: string
}

export const DEFAULTS: Settings = { relay: 'ws://localhost:3334', group: '' }

export function loadSettings(): Settings {
  return {
    relay: localStorage.getItem(RELAY) ?? DEFAULTS.relay,
    group: localStorage.getItem(GROUP) ?? DEFAULTS.group,
  }
}

export function saveSettings(settings: Settings): Settings {
  const clean = { relay: settings.relay.trim(), group: settings.group.trim() }
  localStorage.setItem(RELAY, clean.relay)
  localStorage.setItem(GROUP, clean.group)
  return clean
}
