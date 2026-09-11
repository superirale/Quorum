/**
 * Waiting helpers.
 *
 * Every assertion about an agent is an assertion about something that has not
 * happened yet, and a test that sleeps for a fixed 200ms is either slow or
 * flaky and usually manages both. These poll instead, and fail with the
 * condition's own description rather than "timeout".
 */

export interface WaitOptions {
  /** Give up after this long. */
  timeoutMs?: number
  /** How often to re-check. */
  intervalMs?: number
  /** Included in the failure message. Say what you were waiting *for*. */
  describe?: string
}

export async function waitFor(
  condition: () => boolean | Promise<boolean>,
  options: WaitOptions = {},
): Promise<void> {
  const { timeoutMs = 2000, intervalMs = 5, describe = 'condition' } = options
  const deadline = Date.now() + timeoutMs
  for (;;) {
    if (await condition()) return
    if (Date.now() >= deadline) throw new Error(`timed out after ${timeoutMs}ms waiting for ${describe}`)
    await sleep(intervalMs)
  }
}

/** Wait until `read()` has at least `count` entries, then return them. */
export async function waitForCount<T>(
  read: () => readonly T[],
  count: number,
  options: WaitOptions = {},
): Promise<T[]> {
  await waitFor(() => read().length >= count, {
    describe: `${count} of ${options.describe ?? 'item'} (saw ${read().length})`,
    ...options,
  })
  return [...read()]
}

/**
 * Give the system a chance to do the wrong thing.
 *
 * "The agent did not reply" is only worth asserting after enough time that it
 * would have. Named so the wait is visibly deliberate rather than a stray
 * sleep someone will delete.
 */
export function settle(ms = 150): Promise<void> {
  return sleep(ms)
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}
