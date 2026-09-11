/**
 * Canonical JSON and `input_digest`.
 *
 * An approval binds a human to an exact payload via a sha256 of that payload.
 * That only works if every implementation — TypeScript SDK, Go relay, someone
 * else's Rust agent — hashes the same bytes for the same value. "sha256 of the
 * JSON" is not a specification; JSON has key order, whitespace and number
 * formatting freedom, and each of those turns into a digest mismatch that
 * looks, from the outside, exactly like an attempted tamper.
 *
 * So Quorum specifies a canonical form: **RFC 8785 (JCS)**, with two
 * deliberate restrictions.
 *
 * 1. Numbers MUST be finite. NaN and Infinity are not JSON, and their
 *    serialisation differs across languages.
 * 2. Object keys are sorted by UTF-16 code unit, which is what
 *    `Array.prototype.sort` does natively and what RFC 8785 specifies.
 *
 * Non-integer numbers are permitted but discouraged in action inputs: JCS
 * mandates the ECMAScript number-to-string algorithm, and while that is
 * well-defined, not every language's default float formatter matches it. If
 * you can express a quantity as an integer or a string, do.
 */

import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex } from '@noble/hashes/utils.js'

/** RFC 8785 canonical JSON serialisation. Throws on values JSON cannot hold. */
export function canonicalJson(value: unknown): string {
  return write(value, [])
}

function write(value: unknown, path: string[]): string {
  if (value === null) return 'null'

  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false'

    case 'number':
      if (!Number.isFinite(value)) {
        throw new TypeError(`non-finite number at ${pathOf(path)}: ${value}`)
      }
      // Object.is distinguishes -0, which JSON.stringify renders as "0" — the
      // right answer here, since -0 and 0 are the same JSON value.
      return JSON.stringify(Object.is(value, -0) ? 0 : value)

    case 'string':
      return JSON.stringify(value)

    case 'object': {
      if (Array.isArray(value)) {
        return `[${value.map((v, i) => write(v, [...path, String(i)])).join(',')}]`
      }
      const entries = Object.entries(value as Record<string, unknown>)
        // `undefined` members are dropped, matching JSON.stringify. A caller
        // relying on their presence has a bug the digest would only hide.
        .filter(([, v]) => v !== undefined)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      return `{${entries
        .map(([k, v]) => `${JSON.stringify(k)}:${write(v, [...path, k])}`)
        .join(',')}}`
    }

    default:
      throw new TypeError(`value of type ${typeof value} is not JSON at ${pathOf(path)}`)
  }
}

function pathOf(path: string[]): string {
  return path.length ? `$.${path.join('.')}` : '$'
}

/** sha256 of the canonical JSON of `value`, lowercase hex. */
export function digest(value: unknown): string {
  return bytesToHex(sha256(new TextEncoder().encode(canonicalJson(value))))
}

/** Constant-time-ish digest comparison. Both sides are public, so this is hygiene. */
export function digestEquals(a: string | undefined, b: string | undefined): boolean {
  if (!a || !b || a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return diff === 0
}
