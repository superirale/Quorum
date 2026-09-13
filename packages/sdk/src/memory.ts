/**
 * Scoped agent memory: kind 38104, one addressable event per key.
 *
 * ## Why this is not `Store`
 *
 * `store.ts` is the agent's private notebook — the `once()` ledger, counters,
 * the cursor — and it is local because a relay round trip per effect would be
 * absurd and because you cannot unpublish an ops log you did not mean to
 * publish. Memory is the opposite thing on purpose. What an agent *learned* is
 * published, addressable and readable by every member of the workspace.
 *
 * That is a position, not a convenience. A workspace whose agents remember
 * things nobody can read is one where "why did it do that" is answered by
 * somebody with shell access; here the answer is an event a human can fetch,
 * quote and argue with. It also means an agent that loses its disk has lost
 * nothing that mattered, and that two replicas of one key share a memory
 * without a database between them.
 *
 * The cost is real and is the reason `set()` takes plain JSON and nothing else:
 * on a plaintext channel the relay and every member can read this, Nostr has no
 * unpublish, and a secret written here is a secret published forever. Under
 * `nip44` the body is encrypted like any other and this file does not change.
 *
 * ## Scoping
 *
 * Addressable events are keyed by `(pubkey, kind, d)`, so an agent's memory is
 * namespaced by the key that wrote it and no agent can overwrite another's.
 * There is nothing to coordinate and no lock to hold. Two *replicas* of one key
 * do share a namespace — that is what makes them the same agent — so a write
 * from a replica is last-writer-wins, and anything needing more than that wants
 * a lease (`lease.ts`), not a memory entry.
 */

import { AgentMemoryBody, Kinds, TagName, tagValue, type NostrEvent } from '@quorum/protocol'
import type { RelayClient } from './client.ts'
import type { PublishOptions } from './publish.ts'

/** What an agent remembers, one key at a time. */
export interface Memory {
  /** The value stored under `key`, or `undefined` if nothing is. */
  get<T = unknown>(key: string): Promise<T | undefined>
  /** Write `value` under `key`. Replaces whatever was there. */
  set(key: string, value: unknown): Promise<void>
  /** Every key this agent currently holds, with its value. */
  all(): Promise<Record<string, unknown>>
  /**
   * Forget `key`.
   *
   * Writes `null`, and the doc comment is the honest part: this is a tombstone,
   * not an erasure. The old event may sit in any relay that mirrored it and in
   * anyone's cache, so "forgotten" here means "no reader following the rules
   * will use it again". Nostr cannot offer more than that and a method that
   * implied otherwise would be a lie in an API shape.
   */
  forget(key: string): Promise<void>
}

export interface MemoryDeps {
  client: RelayClient
  publish(options: PublishOptions): Promise<NostrEvent>
  /** Whose memory this is. Reads are scoped to this author. */
  pubkey: string
  group: string
}

/** A {@link Memory} backed by the relay. */
export function createMemory(deps: MemoryDeps): Memory {
  const read = async (key?: string): Promise<NostrEvent[]> =>
    deps.client.query([
      {
        kinds: [Kinds.AgentMemory],
        authors: [deps.pubkey],
        [`#${TagName.Group}`]: [deps.group],
        ...(key ? { [`#${TagName.Identifier}`]: [key] } : {}),
      },
    ])

  return {
    async get<T>(key: string): Promise<T | undefined> {
      const value = valueOf(newest(await read(key)))
      return value === null ? undefined : (value as T)
    },

    async set(key, value) {
      await deps.publish(memoryEntry(key, value))
    },

    async all() {
      const out: Record<string, unknown> = {}
      // Newest per `d`, because a relay serving from more than one addressable
      // copy is allowed to and because a client may hold both after a
      // reconnect. Sorting here rather than trusting arrival order is the
      // difference between "what I last wrote" and "whichever one came back
      // first".
      const byKey = new Map<string, NostrEvent[]>()
      for (const event of await read()) {
        const key = tagValue(event.tags, TagName.Identifier)
        if (!key) continue
        byKey.set(key, [...(byKey.get(key) ?? []), event])
      }
      for (const [key, events] of byKey) {
        const value = valueOf(newest(events))
        if (value !== null && value !== undefined) out[key] = value
      }
      return out
    },

    async forget(key) {
      await deps.publish(memoryEntry(key, null))
    },
  }
}

/**
 * The 38104 for one key.
 *
 * `updated_at` is deliberately left out. It would be the author's own clock
 * repeating what `created_at` already says, and two replicas writing the same
 * value would produce different bytes, different ids, and a second stored copy
 * of an entry the relay could otherwise have deduplicated.
 */
export function memoryEntry(key: string, value: unknown): PublishOptions {
  return { kind: Kinds.AgentMemory, d: key, body: { value } }
}

function newest(events: readonly NostrEvent[]): NostrEvent | undefined {
  return [...events].sort(
    (a, b) => b.created_at - a.created_at || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0),
  )[0]
}

function valueOf(event: NostrEvent | undefined): unknown {
  if (!event) return undefined
  try {
    const body = AgentMemoryBody.safeParse(JSON.parse(event.content))
    return body.success ? body.data.value : undefined
  } catch {
    return undefined
  }
}
