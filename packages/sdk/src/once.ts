/**
 * `once()` — exactly-once effects on top of at-least-once delivery.
 *
 * This is not an optimisation and it is not optional. Nostr gives at-least-once
 * delivery, the SDK deliberately *replays* a handler rather than resuming it
 * (see `replay.ts`), and a handler that runs twice must not deploy twice. Every
 * side effect an agent performs goes through here.
 *
 * ## The key
 *
 * `${triggering event id}:${semantic label}`.
 *
 * The label must describe *what the effect is*, never *which step it is*. A
 * counter — `step:1`, `step:2` — looks equivalent and is not: insert a branch
 * above it and every subsequent key shifts by one, so a replay silently matches
 * the wrong record and returns the wrong cached value. M0 lost an afternoon to
 * that. There is no way to detect it from in here, which is why it is stated
 * this loudly.
 *
 * ## The two-phase record, and why publishes are genuinely idempotent
 *
 * A naive `once()` runs the effect and then records it, which leaves a window:
 * crash in between and the effect happened but the ledger says it did not, so
 * the replay does it again. That window cannot be closed against an arbitrary
 * side effect — but it can be closed against the one that matters here.
 *
 * A Nostr event id is the hash of its contents, so republishing byte-identical
 * bytes is a no-op: the relay dedupes. The only field that would differ on a
 * re-run is `created_at`. So `once()` writes a *reservation* before running the
 * effect, containing the timestamp the effect must use, and hands it back on
 * every attempt. A re-run after a crash therefore rebuilds the same event, with
 * the same id, and the relay throws it away.
 *
 * Non-publish effects — an HTTP POST to something outside Nostr — remain
 * at-least-once, and honestly so. The reservation still tells you an attempt was
 * in progress, which is the input a caller needs to decide whether to retry.
 */

import type { Store } from './store.ts'

/** Passed to the effect. Everything here is stable across retries. */
export interface OnceAttempt {
  /** The full ledger key, for logging. */
  readonly key: string
  /**
   * The timestamp this effect reserved. Use it as `created_at` on anything you
   * publish; that is what makes a retry produce the same event id.
   */
  readonly createdAt: number
  /** 1 on the first run. Greater means a previous attempt did not complete. */
  readonly attempt: number
}

export type Effect<T> = (attempt: OnceAttempt) => T | Promise<T>

interface Reservation {
  at: number
  attempts: number
  done?: boolean
  value?: unknown
}

const PREFIX = 'once'

/** Bound to one triggering event. Handed to handlers as `ctx.once`. */
export interface Once {
  <T>(label: string, effect: Effect<T>): Promise<T>
}

export interface OnceOptions {
  /** Overridable so tests are not at the mercy of the wall clock. */
  now?: () => number
}

/**
 * Build the `once` bound to one triggering event.
 *
 * In-flight calls are shared through a promise map: two concurrent calls with
 * the same label must not both run the effect, and the ledger alone cannot stop
 * them because neither has written to it yet.
 */
export function createOnce(
  store: Store,
  eventId: string,
  inFlight: Map<string, Promise<unknown>>,
  options: OnceOptions = {},
): Once {
  const now = options.now ?? (() => Math.floor(Date.now() / 1000))

  return async function once<T>(label: string, effect: Effect<T>): Promise<T> {
    if (!label) throw new Error('once() needs a label describing the effect')
    const key = `${PREFIX}:${eventId}:${label}`

    const running = inFlight.get(key)
    if (running) return running as Promise<T>

    const promise = (async (): Promise<T> => {
      const existing = await store.get<Reservation>(key)
      if (existing?.done) return existing.value as T

      const reservation: Reservation = {
        at: existing?.at ?? now(),
        attempts: (existing?.attempts ?? 0) + 1,
      }
      await store.set(key, reservation)

      const value = await effect({ key, createdAt: reservation.at, attempt: reservation.attempts })

      await store.set(key, { ...reservation, done: true, value })
      return value
    })().finally(() => inFlight.delete(key))

    inFlight.set(key, promise)
    return promise
  }
}

/** True if this effect has already completed. Rarely needed; useful in tests. */
export async function hasRun(store: Store, eventId: string, label: string): Promise<boolean> {
  const record = await store.get<Reservation>(`${PREFIX}:${eventId}:${label}`)
  return record?.done === true
}

/**
 * Effects that were reserved but never completed.
 *
 * An agent that crashed mid-effect leaves these behind, and they are the only
 * evidence that something may have half-happened. Worth logging at startup:
 * "I was in the middle of `deploy:production` when I died" is the sentence an
 * operator needs, and no relay can tell them.
 */
export async function incompleteEffects(store: Store): Promise<string[]> {
  const keys = await store.keys(`${PREFIX}:`)
  const out: string[] = []
  for (const key of keys) {
    const record = await store.get<Reservation>(key)
    if (record && !record.done) out.push(key.slice(PREFIX.length + 1))
  }
  return out
}
