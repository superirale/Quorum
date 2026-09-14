/**
 * Build the contents of `schemas/` in memory.
 *
 * Separated from the writer so the test suite can regenerate and compare
 * against what is committed. Without that check, `schemas/` would drift from
 * the Zod definitions the moment someone edited a body and forgot to re-run the
 * generator — and the drift would only surface in whichever other-language
 * implementation hit it first.
 */

import { z } from 'zod'

import { ALT_MAX_LENGTH } from '../src/alt.ts'
import { BODY_SCHEMAS } from '../src/bodies/index.ts'
import { NostrEventSchema } from '../src/event.ts'
import { QUORUM_KINDS, SUPPORTED_KINDS, kindName } from '../src/kinds.ts'
import { INVOKE, Resource, SCOPE_GROUP } from '../src/resources.ts'
import { UNSEALED_KINDS, UNSEALED_KIND_RANGES } from '../src/seal.ts'
import { ADDRESS_MARKER, ENC_MODES } from '../src/tags.ts'
import { REQUIREMENTS } from '../src/validate.ts'
import { PROTOCOL_VERSION } from '../src/version.ts'

const BASE_URI = 'https://quorum.chat/schemas'

/**
 * `io: 'input'` matters. Several bodies use `.default()`, and the input view —
 * field optional, default applied on parse — is what a publisher must satisfy.
 * The output view marks defaulted fields as required, which would reject valid
 * events from any implementation that sensibly omitted them.
 */
function toSchema(schema: z.ZodType): Record<string, unknown> {
  return z.toJSONSchema(schema, {
    target: 'draft-2020-12',
    io: 'input',
    unrepresentable: 'any',
  }) as Record<string, unknown>
}

export function slugFor(name: string): string {
  return name.replace(/([a-z0-9])([A-Z])/g, '$1-$2').toLowerCase()
}

export function bodyFileName(kind: number): string {
  const name = kindName(kind)
  if (!name) throw new Error(`kind ${kind} has a body schema but no name in kinds.ts`)
  return `body-${kind}-${slugFor(name)}.json`
}

/** Filename → contents, exactly as they should appear on disk. */
export function generate(): Record<string, unknown> {
  const files: Record<string, unknown> = {}

  files['nostr-event.json'] = {
    $id: `${BASE_URI}/nostr-event.json`,
    ...toSchema(NostrEventSchema),
    title: 'Nostr event (NIP-01)',
  }

  const bodyFiles: Record<number, string> = {}

  for (const [kindString, schema] of Object.entries(BODY_SCHEMAS)) {
    const kind = Number(kindString)
    const file = bodyFileName(kind)
    bodyFiles[kind] = file
    files[file] = {
      $id: `${BASE_URI}/${file}`,
      ...toSchema(schema as z.ZodType),
      title: `${kindName(kind)} body (kind ${kind})`,
    }
  }

  files['index.json'] = {
    $id: `${BASE_URI}/index.json`,
    protocol: 'quorum',
    version: PROTOCOL_VERSION,
    generated_by: '@quorum/protocol scripts/gen-schemas.ts',
    note: 'Kind numbers are provisional until the Quorum NIP PR merges.',
    kinds: Object.fromEntries(
      QUORUM_KINDS.map((kind) => [
        kind,
        {
          name: kindName(kind),
          body: bodyFiles[kind] ?? null,
          // Envelope rules as data, so a non-TypeScript validator enforces the
          // same table this package does instead of a copy of it.
          requires: REQUIREMENTS[kind] ?? {},
        },
      ]),
    ),
    supported_kinds: SUPPORTED_KINDS.map(String),
    // The two capabilities a relay must check itself, because they have no
    // resource anywhere else. Published as data for the same reason the envelope
    // table is: a resource name is matched exactly, so the Go relay and this
    // package disagreeing by one character is a grant that authorises nothing
    // and reports no error.
    relay_enforced: {
      action: INVOKE,
      scope_key: SCOPE_GROUP,
      resources: {
        [Resource.Join]: 'admits the grantee to the workspace named in the scope',
        [Resource.ThreadBudget]: "sets a thread's spending ceiling",
        [Resource.ChannelEncrypt]: "sets a channel's encryption policy and key epoch",
      },
    },
    envelope: {
      required_tags: ['h', 'alt'],
      alt_max_length: ALT_MAX_LENGTH,
      enc_modes: ENC_MODES,
      address_marker: ADDRESS_MARKER,
      // On a channel whose policy says `nip44`, every kind except these must
      // carry sealed content. Published as data and written as exceptions so
      // that a kind added later is sealed by default in every implementation
      // at once — the Go relay enforces this list and cannot read the Zod.
      unsealed_kinds: UNSEALED_KINDS.map(String),
      unsealed_kind_ranges: UNSEALED_KIND_RANGES.map((range) => ({
        from: String(range.from),
        to: String(range.to),
        why: range.why,
      })),
      content:
        'canonical JSON (RFC 8785) of the body schema, or plain text for kinds 9, 11 and 1111',
    },
  }

  return files
}

export function serialize(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`
}
