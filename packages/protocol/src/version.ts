/**
 * Protocol version, carried in the optional `quorum` tag.
 *
 * Versioning policy, in full:
 *
 * - Adding a kind, or an optional field to a body, is a MINOR bump. Readers
 *   must ignore unknown kinds (rendering their `alt` text) and unknown body
 *   fields. Validators are non-strict for exactly this reason.
 * - Removing or repurposing a kind, adding a required field, or changing the
 *   meaning of a tag is a MAJOR bump and needs a migration note in
 *   `spec/CHANGELOG.md`.
 * - Kind numbers are provisional until the NIP PR merges. If the registry
 *   forces a reallocation, that is a MAJOR bump even though nothing else moved.
 */
export const PROTOCOL_VERSION = '0.1'

export const PROTOCOL_NAME = 'quorum'
