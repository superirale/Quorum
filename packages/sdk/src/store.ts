/**
 * Local durable state: the `once()` ledger, the cursor, counters, lease epochs.
 *
 * An agent needs somewhere to remember what it has already done, and that place
 * must outlive the process or none of the restart guarantees mean anything. It
 * is deliberately local rather than relay-hosted. Publishing your own dedup
 * ledger to a relay means every effect costs a round trip and a relay outage
 * turns "do this once" into "do this never" — and on Nostr you cannot unpublish
 * an ops log you did not mean to make public.
 *
 * The interface is four methods so that a real deployment can back it with
 * whatever it already runs. The durable file-backed implementation lives in
 * `store-file.ts` and is exported from `@quorum/sdk/node`, not from the root:
 * the SDK is also what the reference client is built on, and a browser bundle
 * cannot contain an import of `node:fs`. Keeping the split at the module
 * boundary means the bundler enforces it rather than a comment asking nicely.
 */

export interface Store {
  get<T>(key: string): Promise<T | undefined>
  set(key: string, value: unknown): Promise<void>
  delete(key: string): Promise<void>
  /** Keys beginning with `prefix`, or all of them. Order is unspecified. */
  keys(prefix?: string): Promise<string[]>
}

/** Non-durable. Correct for tests that are not about restarts; wrong for agents. */
export class MemoryStore implements Store {
  private readonly data = new Map<string, string>()

  async get<T>(key: string): Promise<T | undefined> {
    const raw = this.data.get(key)
    return raw === undefined ? undefined : (JSON.parse(raw) as T)
  }

  async set(key: string, value: unknown): Promise<void> {
    // Serialised on write so that a caller mutating the object afterwards
    // cannot retroactively change what was recorded — the same guarantee a
    // file-backed store gives for free, and the difference is the kind of thing
    // that makes a test pass here and fail in production.
    this.data.set(key, JSON.stringify(value))
  }

  async delete(key: string): Promise<void> {
    this.data.delete(key)
  }

  async keys(prefix = ''): Promise<string[]> {
    return [...this.data.keys()].filter((k) => k.startsWith(prefix))
  }

  get size(): number {
    return this.data.size
  }
}

/** A `Store` view under a key prefix, so two concerns cannot collide. */
export function namespaced(store: Store, namespace: string): Store {
  const full = (key: string) => `${namespace}:${key}`
  return {
    get: (key) => store.get(full(key)),
    set: (key, value) => store.set(full(key), value),
    delete: (key) => store.delete(full(key)),
    keys: async (prefix = '') =>
      (await store.keys(full(prefix))).map((k) => k.slice(namespace.length + 1)),
  }
}
