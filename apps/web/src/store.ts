/**
 * A `Store` over `localStorage`.
 *
 * The SDK's durable store writes a JSON file, which a browser cannot do; this
 * is the same four methods over the only durable thing a page has. It matters
 * for exactly one reason here: the `counter` tag must be monotonic per author,
 * and a counter that resets to zero when you reload the tab makes every message
 * you send afterwards look, to anyone watching for gaps, like a replay of
 * messages they have already seen.
 *
 * Keys are namespaced by pubkey by the caller, because two identities in one
 * browser profile sharing a counter sequence would produce the same symptom
 * from the other direction — visible gaps in both.
 */

import type { Store } from '@quorum/sdk'

export class LocalStore implements Store {
  private readonly prefix: string

  constructor(prefix: string) {
    this.prefix = prefix
  }

  async get<T>(key: string): Promise<T | undefined> {
    const raw = localStorage.getItem(this.prefix + key)
    if (raw === null) return undefined
    try {
      return JSON.parse(raw) as T
    } catch {
      return undefined
    }
  }

  async set(key: string, value: unknown): Promise<void> {
    localStorage.setItem(this.prefix + key, JSON.stringify(value))
  }

  async delete(key: string): Promise<void> {
    localStorage.removeItem(this.prefix + key)
  }

  async keys(prefix = ''): Promise<string[]> {
    const want = this.prefix + prefix
    const out: string[] = []
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i)
      if (key?.startsWith(want)) out.push(key.slice(this.prefix.length))
    }
    return out
  }
}
