/**
 * @quorum/test-kit — an in-process relay and the helpers for making it misbehave.
 *
 * The goal is that testing an agent needs no Docker, no ports you have to pick,
 * and no sleeps. Start a relay, point a signer at it, and drop the connection
 * whenever the test wants to know what happens next.
 */

export * from './fake-bunker.ts'
export * from './fake-relay.ts'
export * from './wait.ts'
