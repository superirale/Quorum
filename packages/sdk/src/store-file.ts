/**
 * The durable `Store`: one JSON file, rewritten atomically.
 *
 * Separate from `store.ts` because this is the only part of the SDK that
 * cannot run in a browser, and `@quorum/sdk` is what the reference client is
 * built on as well as the agents. The root entry point stays isomorphic; this
 * one is reachable as `@quorum/sdk/node` and a bundler will refuse it, which is
 * the intended outcome — a web client reaching for a file-backed ledger has
 * made a mistake that should surface at build time, not as a blank page.
 */

import { chmod, mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import type { Store } from './store.ts'

/**
 * Owner-only, because this file stopped being a ledger of ids.
 *
 * Through M8 a `Store` held dedup keys, cursors, counters and lease epochs —
 * nothing whose disclosure costs anything. `mls` changed that twice over: the
 * ratchet's `GroupState` is written here and contains `signaturePrivateKey` and
 * the whole key schedule, and the {@link Archive} beside it holds the plaintext
 * of every message this client could read. Between them, this one file is enough
 * to read the channel and to impersonate its owner in the group.
 *
 * The default was 0644 masked by umask, so on an ordinary multi-user box every
 * account could read both. Narrowed here rather than left to the caller because
 * the caller cannot know: the SDK decides what goes in the file.
 */
const OWNER_ONLY = 0o600

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
      // The mode goes on the *temporary* file, because `rename` replaces the
      // target inode and a mode applied to an existing ledger is discarded by
      // the next flush.
      //
      // Both calls are here and each covers what the other cannot.
      // `writeFile`'s `mode` applies only when it *creates* the file, so it is
      // the one that stops the ledger existing at 0644 for the instant before
      // the `chmod` — a window an unprivileged reader only has to open an fd
      // inside, since the access check happens once at open. And it does
      // nothing at all when the path already exists, which happens here
      // whenever a process died between the write and the rename: the
      // temporary is named by pid, and a containerised agent is pid 1 on every
      // restart, so `<path>.1.tmp` from the crash is exactly the file the next
      // boot writes into. Only the second of those is reachable by a test —
      // deleting `mode:` leaves the suite green, and the comment is the record
      // of why it stays.
      await writeFile(tmp, body, { encoding: 'utf8', mode: OWNER_ONLY })
      await chmod(tmp, OWNER_ONLY)
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

