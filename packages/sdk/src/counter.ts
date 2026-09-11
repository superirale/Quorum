/**
 * Per-author counters — ordering layer 1.
 *
 * Every event an agent publishes carries a `counter` tag, monotonic for that
 * pubkey. It is the cheapest of the three ordering mechanisms and the only one
 * that works everywhere: it needs no cooperation from the relay, it is signed
 * along with the rest of the event so nobody else can fabricate a sequence, and
 * it makes "did I miss something from this author" a local check.
 *
 * The number is persisted *before* it is used. A crash between publishing and
 * recording would otherwise hand the same counter to two different events,
 * which reads to everyone else as a forked sequence — a much worse signal than
 * the harmless gap that skipping a number produces. Gaps in your own sequence
 * mean "this agent crashed"; duplicates mean "this key is being used twice",
 * and that is a security question rather than an operational one.
 */

import type { Store } from './store.ts'

export class Counters {
  private readonly store: Store
  private readonly key: string
  private value: number
  /** Allocations are chained; two concurrent `next()` calls must not tie. */
  private chain: Promise<number> = Promise.resolve(0)

  private constructor(store: Store, pubkey: string, value: number) {
    this.store = store
    this.key = `counter:${pubkey}`
    this.value = value
  }

  static async load(store: Store, pubkey: string): Promise<Counters> {
    return new Counters(store, pubkey, (await store.get<number>(`counter:${pubkey}`)) ?? 0)
  }

  /** The last number handed out. */
  get current(): number {
    return this.value
  }

  async next(): Promise<number> {
    this.chain = this.chain.then(async () => {
      const n = this.value + 1
      await this.store.set(this.key, n)
      this.value = n
      return n
    })
    return this.chain
  }

  /**
   * Catch up to a counter already published under this key.
   *
   * Needed when an agent's state file is lost but its history is not: restarting
   * from 1 would republish counters the channel has already seen. The SDK calls
   * this with the highest counter it finds in its own backfill.
   */
  async observeOwn(counter: number): Promise<void> {
    if (counter <= this.value) return
    this.value = counter
    await this.store.set(this.key, counter)
  }
}
