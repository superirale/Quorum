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
 * whatever it already runs. `FileStore` is here so the answer to "what do I
 * need to run an agent" stays "node".
 */

import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'

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

/**
 * A single JSON file, rewritten atomically.
 *
 * Whole-file rewrites are the wrong shape above a few thousand keys and the
 * right shape below that, which is where an agent's ledger sits. When it stops
 * being true, implement `Store` over SQLite; nothing above this file changes.
 *
 * Writes go to a temporary file and are then renamed over the target, because
 * `rename` within a directory is atomic on POSIX: a crash mid-write leaves the
 * previous ledger intact rather than a truncated one. A truncated ledger is the
 * worst case here — it reads as "none of that happened" and re-runs every
 * effect the agent had already committed to.
 */
export class FileStore implements Store {
  private readonly path: string
  private data: Record<string, unknown> = {}
  /**
   * The one in-flight load, shared.
   *
   * `set()` loads before it writes, and nothing stops fifty of them from being
   * in flight at once — a handler publishing while the cursor saves is the
   * ordinary case. Without sharing, each of those reads the file, finds it
   * absent, and assigns a fresh `{}` over whatever the ones that finished first
   * had already put there. The symptom is a state file with one key in it, and
   * an agent that repeats every effect but the last.
   */
  private loading: Promise<void> | undefined
  /** Writes are chained rather than concurrent; two renames can interleave. */
  private writing: Promise<void> = Promise.resolve()

  constructor(path: string) {
    this.path = path
  }

  /** `<dir>/<name>.json`, creating the directory when first written. */
  static in(dir: string, name = 'agent-state'): FileStore {
    return new FileStore(join(dir, `${name}.json`))
  }

  private load(): Promise<void> {
    this.loading ??= (async () => {
      try {
        this.data = JSON.parse(await readFile(this.path, 'utf8')) as Record<string, unknown>
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
          // Do not cache the failure: an unreadable file may be a transient
          // permission or mount problem, and refusing forever is worse than
          // trying again on the next call.
          this.loading = undefined
          throw error
        }
        this.data = {}
      }
    })()
    return this.loading
  }

  private flush(): Promise<void> {
    this.writing = this.writing.then(async () => {
      const body = JSON.stringify(this.data)
      await mkdir(dirname(this.path), { recursive: true })
      const tmp = `${this.path}.${process.pid}.tmp`
      await writeFile(tmp, body, 'utf8')
      await rename(tmp, this.path)
    })
    return this.writing
  }

  async get<T>(key: string): Promise<T | undefined> {
    await this.load()
    const value = this.data[key]
    return value === undefined ? undefined : (JSON.parse(JSON.stringify(value)) as T)
  }

  async set(key: string, value: unknown): Promise<void> {
    await this.load()
    this.data[key] = value
    await this.flush()
  }

  async delete(key: string): Promise<void> {
    await this.load()
    delete this.data[key]
    await this.flush()
  }

  async keys(prefix = ''): Promise<string[]> {
    await this.load()
    return Object.keys(this.data).filter((k) => k.startsWith(prefix))
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
