/**
 * @quorum/protocol — the Quorum NIP, as code.
 *
 * Quorum is an agent-first messaging protocol on Nostr: humans and agents are
 * peers in the same signed event log, agents hold their own keys, and consent
 * to consequential work is a signed event rather than a row in someone's
 * database.
 *
 * This package is the normative artefact. `spec/nip-quorum.md` is the prose
 * version and `schemas/` is the language-neutral one; where they disagree, the
 * NIP text wins and the disagreement is a bug in here.
 */

export * from './alt.ts'
export * from './bodies/index.ts'
export * from './build.ts'
export * from './digest.ts'
export * from './event.ts'
export * from './kinds.ts'
export * from './tags.ts'
export * from './validate.ts'
export * from './version.ts'
