/**
 * Shared scaffolding for the SDK tests.
 *
 * Not a `.test.ts`, so the runner's `test/*.test.ts` glob leaves it alone.
 */

import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Kinds, refTo, validateEvent, type EventRef, type NostrEvent } from '@quorum/protocol'
import { FakeRelay } from '@quorum/test-kit'
import { Counters, LocalSigner, MemoryStore, Publisher, RelayClient } from '../src/index.ts'

/** A human, or another agent: something that publishes into the channel. */
export class Actor {
  readonly pubkey: string
  readonly client: RelayClient
  private readonly publisher: Publisher

  private constructor(pubkey: string, client: RelayClient, publisher: Publisher) {
    this.pubkey = pubkey
    this.client = client
    this.publisher = publisher
  }

  static async create(url: string, group: string): Promise<Actor> {
    const signer = LocalSigner.generate()
    const client = new RelayClient({ url, signer, reconnect: false })
    await client.connect()
    const counters = await Counters.load(new MemoryStore(), signer.publicKey)
    const publisher = new Publisher({ client, signer, pubkey: signer.publicKey, group, counters })
    return new Actor(signer.publicKey, client, publisher)
  }

  /** Channel-level chat, NIP-C7. */
  chat(text: string, to: string[] = []): Promise<NostrEvent> {
    return this.publisher.publish({ kind: Kinds.ChatMessage, text, to })
  }

  /** A NIP-7D thread root. Its id is the thread id. */
  thread(title: string, text: string, to: string[] = []): Promise<NostrEvent> {
    return this.publisher.publish({ kind: Kinds.Thread, text, to, tags: [['title', title]] })
  }

  /** A NIP-22 comment inside a thread. */
  comment(thread: EventRef, text: string, to: string[] = [], parent?: NostrEvent): Promise<NostrEvent> {
    return this.publisher.publish({
      kind: Kinds.Comment,
      text,
      thread,
      parent: parent ? refTo(parent) : undefined,
      to,
    })
  }

  close(): void {
    this.client.close()
  }
}

export interface Harness {
  relay: FakeRelay
  group: string
  /** Register something to be torn down; called in reverse order. */
  cleanup(fn: () => void | Promise<void>): void
  finish(): Promise<void>
}

export async function harness(group = 'payments'): Promise<Harness> {
  const relay = await FakeRelay.start()
  const teardown: (() => void | Promise<void>)[] = []
  return {
    relay,
    group,
    cleanup: (fn) => teardown.push(fn),
    finish: async () => {
      for (const fn of teardown.reverse()) await fn()
      await relay.stop()
    },
  }
}

/** A temporary directory that removes itself, for `FileStore` tests. */
export async function tempDir(): Promise<{ path: string; remove: () => Promise<void> }> {
  const path = await mkdtemp(join(tmpdir(), 'quorum-sdk-'))
  return { path, remove: () => rm(path, { recursive: true, force: true }) }
}

/**
 * Every event the SDK published must be a valid Quorum event.
 *
 * The fake relay does not validate — deliberately, so that it cannot become a
 * second opinion about what is legal. This is what stands in for that, and it
 * is the reason the SDK's output can be trusted to survive `apps/relay`.
 */
export function assertAllValid(events: readonly NostrEvent[]): void {
  for (const event of events) {
    const result = validateEvent(event)
    const errors = result.issues.filter((i) => i.severity === 'error')
    assert.deepEqual(
      errors,
      [],
      `kind ${event.kind} event ${event.id.slice(0, 8)} is not a valid Quorum event`,
    )
  }
}

export function text(events: readonly NostrEvent[], kind: number, author?: string): string[] {
  return events
    .filter((e) => e.kind === kind && (author === undefined || e.pubkey === author))
    .map((e) => e.content)
}

export function deferred<T = void>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((r) => {
    resolve = r
  })
  return { promise, resolve }
}
