/**
 * Validation.
 *
 * Three layers, deliberately separable because different callers need different
 * amounts of it:
 *
 *   parseNostrEvent   NIP-01 shape only
 *   validateEnvelope  the Quorum tag rules — works on encrypted events
 *   validateBody      the JSON body — impossible on encrypted events
 *
 * The split is forced by the encryption policy. On a `nip44` or `mls` channel a
 * relay can still check the envelope (there is a group, an alt, a counter, a
 * thread) but cannot see the body at all. A validator that fused the two would
 * be unusable in exactly the deployment mode the project promises.
 *
 * Every rule below returns a structured issue rather than throwing, because the
 * relay reports rejections back over the wire as NIP-01 `OK` messages and needs
 * a reason string, not a stack trace.
 */

import { z } from 'zod'
import { defaultAlt, isValidAlt, ALT_MAX_LENGTH } from './alt.ts'
import { bodySchema } from './bodies/index.ts'
import { NostrEventSchema, verifyEvent, type NostrEvent } from './event.ts'
import {
  AddressableKinds,
  EphemeralKinds,
  Kinds,
  RegularKinds,
  isAddressable,
  isQuorumKind,
} from './kinds.ts'
import {
  ENC_MODES,
  TagName,
  addressees,
  allTagValues,
  tagValue,
} from './tags.ts'

export type Severity = 'error' | 'warning'

export interface Issue {
  /** Stable machine-readable code, so relays and tests can assert on it. */
  code: string
  message: string
  severity: Severity
  /** Tag name or body path the issue concerns. */
  at?: string
}

export interface ValidationResult {
  valid: boolean
  issues: Issue[]
}

const ok = (issues: Issue[] = []): ValidationResult => ({
  valid: !issues.some((i) => i.severity === 'error'),
  issues,
})

function err(code: string, message: string, at?: string): Issue {
  return { code, message, severity: 'error', ...(at ? { at } : {}) }
}

function warn(code: string, message: string, at?: string): Issue {
  return { code, message, severity: 'warning', ...(at ? { at } : {}) }
}

// --- layer 1: NIP-01 --------------------------------------------------------

export function parseNostrEvent(input: unknown): NostrEvent {
  return NostrEventSchema.parse(input)
}

export function safeParseNostrEvent(input: unknown) {
  return NostrEventSchema.safeParse(input)
}

// --- kind requirement table -------------------------------------------------

export interface Requirements {
  /** Must sit inside a thread: carries NIP-22 `E`/`K` root-scope tags. */
  threaded?: boolean
  /** Must address at least one pubkey with a `to`-marked `p` tag. */
  addressed?: boolean
  /**
   * Must carry an `e` tag pointing at an event of this kind.
   *
   * Checking only that *some* `e` tag exists is not enough. Because a
   * top-level NIP-22 comment sets its parent to the thread root, every threaded
   * event already has an `e` tag — so "has a parent" is trivially true and
   * says nothing. An approval response whose parent is the thread rather than
   * a request is an approval of nothing, and it has to be caught here or the
   * agent will happily match it against a request by action id alone.
   */
  parentKind?: number
}

/**
 * Per-kind tag requirements.
 *
 * Written as a table rather than a switch so that adding a kind means adding a
 * row — and so that the NIP text and this file can be diffed against each other
 * by eye.
 *
 * Exported because it is published into `schemas/index.json`. A Go relay or a
 * Python harness that hand-copied these rules would drift from them silently;
 * reading them as data means a new row here reaches every implementation with
 * the next schema regeneration.
 */
export const REQUIREMENTS: Readonly<Record<number, Requirements>> = Object.freeze({
  [RegularKinds.Action]: { threaded: true },
  [RegularKinds.ApprovalRequest]: { threaded: true, addressed: true },
  [RegularKinds.ApprovalResponse]: {
    threaded: true,
    parentKind: RegularKinds.ApprovalRequest,
  },
  [RegularKinds.Summary]: { threaded: true },
  [RegularKinds.Error]: { threaded: true },
  [RegularKinds.Artifact]: { threaded: true },
  [RegularKinds.Handoff]: { threaded: true, addressed: true },
  [RegularKinds.ThreadOp]: { threaded: true },
  [RegularKinds.Checkpoint]: {},
  [EphemeralKinds.Interrupt]: { threaded: true },
  [EphemeralKinds.Lease]: { threaded: true },
  [EphemeralKinds.Presence]: {},
})

// --- layer 2: the Quorum envelope -------------------------------------------

/**
 * Validate everything that lives in tags. Safe to run on encrypted events, and
 * therefore the only validation a relay can do on a `nip44` channel.
 */
export function validateEnvelope(event: NostrEvent): ValidationResult {
  const issues: Issue[] = []
  const { kind, tags } = event

  if (!isQuorumKind(kind)) {
    return ok([
      warn('not_quorum_kind', `kind ${kind} is not defined by this NIP`, 'kind'),
    ])
  }

  // `h` — a Quorum event always belongs to a channel. Without it the relay
  // cannot apply group policy and the event is unroutable.
  if (!tagValue(tags, TagName.Group)) {
    issues.push(err('missing_group', 'a `h` tag naming the NIP-29 group is required', 'h'))
  }

  // `alt` — see alt.ts for why this is required despite NIP-31's status.
  const alt = tagValue(tags, TagName.Alt)
  if (alt === undefined) {
    issues.push(err('missing_alt', 'an `alt` tag is required on every Quorum kind', 'alt'))
  } else if (!isValidAlt(alt)) {
    issues.push(
      err(
        'invalid_alt',
        `alt must be 1–${ALT_MAX_LENGTH} characters of single-line plain text`,
        'alt',
      ),
    )
  }

  const encValue = tagValue(tags, TagName.Enc)
  if (encValue !== undefined && !(ENC_MODES as readonly string[]).includes(encValue)) {
    issues.push(
      err('invalid_enc', `enc must be one of: ${ENC_MODES.join(', ')}`, 'enc'),
    )
  }

  const counterValue = tagValue(tags, TagName.Counter)
  if (counterValue !== undefined && !/^(0|[1-9][0-9]*)$/.test(counterValue)) {
    issues.push(err('invalid_counter', 'counter must be a non-negative integer', 'counter'))
  } else if (counterValue === undefined) {
    // A warning, not an error: without it this author's readers lose gap
    // detection, but the event is still perfectly valid on any relay and
    // rejecting it would break generic clients that know nothing of Quorum.
    issues.push(
      warn('missing_counter', 'no `counter` tag: readers cannot detect gaps from this author', 'counter'),
    )
  }

  if (isAddressable(kind) && !tagValue(tags, TagName.Identifier)) {
    issues.push(err('missing_d', 'addressable kinds require a `d` tag', 'd'))
  }

  const req = REQUIREMENTS[kind] ?? {}

  if (req.threaded) {
    if (!tagValue(tags, TagName.RootEvent)) {
      issues.push(
        err('missing_thread', 'an `E` tag naming the kind:11 thread root is required', 'E'),
      )
    }
    const rootKind = tagValue(tags, TagName.RootKind)
    if (rootKind === undefined) {
      issues.push(err('missing_root_kind', 'NIP-22 requires a `K` tag alongside `E`', 'K'))
    } else if (rootKind !== String(Kinds.Thread)) {
      issues.push(
        err('bad_root_kind', `thread root must be kind ${Kinds.Thread}, got ${rootKind}`, 'K'),
      )
    }
  }

  if (req.addressed && addressees(tags).length === 0) {
    issues.push(
      err(
        'not_addressed',
        'requires at least one `p` tag marked "to"; an unaddressed approval request has nobody to answer it',
        'p',
      ),
    )
  }

  if (req.parentKind !== undefined) {
    if (!tagValue(tags, TagName.Event)) {
      issues.push(
        err('missing_parent', 'an `e` tag naming the event this answers is required', 'e'),
      )
    }
    const parentKind = tagValue(tags, TagName.ParentKind)
    if (parentKind === undefined) {
      issues.push(err('missing_parent_kind', 'NIP-22 requires a `k` tag alongside `e`', 'k'))
    } else if (parentKind !== String(req.parentKind)) {
      issues.push(
        err(
          'bad_parent_kind',
          `must answer a kind ${req.parentKind} event, but the k tag says ${parentKind}`,
          'k',
        ),
      )
    }
  }

  return ok(issues)
}

// --- layer 3: the body ------------------------------------------------------

export interface BodyResult<T = unknown> extends ValidationResult {
  body?: T
}

/**
 * Parse and validate `content` as this kind's JSON body.
 *
 * Callers must skip this when `enc` is not `plaintext`; there is no sensible
 * failure mode for validating ciphertext, so this reports it as an error rather
 * than guessing.
 */
export function validateBody(event: NostrEvent): BodyResult {
  const schema = bodySchema(event.kind)
  if (!schema) {
    return ok([warn('no_body_schema', `kind ${event.kind} has no JSON body`, 'content')])
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(event.content)
  } catch {
    return { valid: false, issues: [err('content_not_json', 'content is not valid JSON', 'content')] }
  }

  const result = schema.safeParse(parsed)
  if (!result.success) {
    return {
      valid: false,
      issues: result.error.issues.map((i) =>
        err('body_invalid', i.message, `content.${i.path.join('.') || '<root>'}`),
      ),
    }
  }

  return { ...ok(crossFieldIssues(event, result.data)), body: result.data }
}

/**
 * Rules that span fields, or span a field and a tag.
 *
 * These live here rather than in a `.refine()` on the schema because refinements
 * are invisible to `z.toJSONSchema()`. Expressed as a refinement, each of these
 * would be silently absent from the committed schema that other-language
 * implementations validate against — present in TypeScript, missing everywhere
 * else, with no error to notice. The duplication is the price of the schema
 * being honest about what it checks.
 */
function crossFieldIssues(event: NostrEvent, body: any): Issue[] {
  const issues: Issue[] = []
  const { kind, tags } = event

  if (kind === RegularKinds.Action) {
    if (body.status === 'proposed') {
      if (!body.input_digest) {
        issues.push(
          err(
            'missing_input_digest',
            'a proposed action must carry input_digest; an approval that cannot name its arguments authorises the action name forever',
            'content.input_digest',
          ),
        )
      }
    } else if (!tagValue(tags, TagName.Action)) {
      issues.push(
        err(
          'missing_action_tag',
          'only a `proposed` action opens a chain; every later status needs an `action` tag naming it',
          'action',
        ),
      )
    }
    if (body.status === 'failed' && !body.error) {
      issues.push(warn('failed_without_error', 'a failed action should carry `error`', 'content.error'))
    }
  }

  if (kind === RegularKinds.ApprovalRequest) {
    if (tagValue(tags, TagName.Action) && !body.input_digest) {
      issues.push(
        err(
          'missing_input_digest',
          'an approval request tied to an action must bind to its input_digest',
          'content.input_digest',
        ),
      )
    }
    const required = body.required ?? 1
    if (required > addressees(tags).length) {
      issues.push(
        err(
          'unreachable_quorum',
          `required is ${required} but only ${addressees(tags).length} approvers are addressed`,
          'content.required',
        ),
      )
    }
  }

  if (kind === RegularKinds.ApprovalResponse) {
    if (body.modified_input !== undefined && !body.modified_input_digest) {
      issues.push(
        err(
          'missing_modified_digest',
          'modified_input requires modified_input_digest, or the log records one thing and the agent runs another',
          'content.modified_input_digest',
        ),
      )
    }
  }

  if (kind === AddressableKinds.ThreadState) {
    const d = tagValue(tags, TagName.Identifier)
    if (d && !/^[0-9a-f]{64}$/.test(d)) {
      issues.push(
        err('bad_thread_d', 'thread_state `d` must be the 64-hex id of the kind:11 root', 'd'),
      )
    }
  }

  return issues
}

// --- the whole thing --------------------------------------------------------

export interface FullResult extends ValidationResult {
  body?: unknown
}

export interface ValidateOptions {
  /** Verify the id and schnorr signature. Off by default: it costs ~1ms. */
  verifySignature?: boolean
  /** Skip body validation. Set automatically for non-plaintext events. */
  envelopeOnly?: boolean
}

/**
 * Validate an event end to end.
 *
 * Body validation is skipped automatically when `enc` says the content is
 * encrypted, so a relay can call this on every inbound event regardless of
 * channel policy and get the strongest check available to it.
 */
export function validateEvent(input: unknown, options: ValidateOptions = {}): FullResult {
  const parsed = safeParseNostrEvent(input)
  if (!parsed.success) {
    return {
      valid: false,
      issues: parsed.error.issues.map((i) =>
        err('malformed_event', i.message, i.path.join('.') || '<root>'),
      ),
    }
  }

  const event = parsed.data
  const issues: Issue[] = []

  if (options.verifySignature && !verifyEvent(event)) {
    issues.push(err('bad_signature', 'event id or signature does not verify', 'sig'))
    // Everything downstream describes an event nobody actually signed.
    return { valid: false, issues }
  }

  const envelope = validateEnvelope(event)
  issues.push(...envelope.issues)

  const encrypted = (tagValue(event.tags, TagName.Enc) ?? 'plaintext') !== 'plaintext'
  if (options.envelopeOnly || encrypted || !isQuorumKind(event.kind)) {
    return { valid: !issues.some((i) => i.severity === 'error'), issues }
  }

  const body = validateBody(event)
  issues.push(...body.issues)

  return {
    valid: !issues.some((i) => i.severity === 'error'),
    issues,
    ...(body.body !== undefined ? { body: body.body } : {}),
  }
}

/** Throwing form, for tests and code paths where an invalid event is a bug. */
export function assertValid(input: unknown, options: ValidateOptions = {}): NostrEvent {
  const result = validateEvent(input, options)
  if (!result.valid) {
    const errors = result.issues.filter((i) => i.severity === 'error')
    throw new Error(
      `invalid Quorum event:\n${errors.map((i) => `  [${i.code}] ${i.at ?? ''} ${i.message}`).join('\n')}`,
    )
  }
  return parseNostrEvent(input)
}

// --- convenience ------------------------------------------------------------

/** Everything an event says about where it sits, without reading the body. */
export interface EventContext {
  group?: string
  thread?: string
  parent?: string
  action?: string
  addressees: string[]
  counter?: number
  alt?: string
}

export function eventContext(event: NostrEvent): EventContext {
  const t = event.tags
  const counterRaw = tagValue(t, TagName.Counter)
  return {
    group: tagValue(t, TagName.Group),
    thread: tagValue(t, TagName.RootEvent),
    parent: tagValue(t, TagName.Event),
    action: tagValue(t, TagName.Action),
    addressees: addressees(t),
    counter: counterRaw !== undefined ? Number(counterRaw) : undefined,
    alt: tagValue(t, TagName.Alt),
  }
}

/** Re-exported so callers can build a compliant `alt` without a second import. */
export { defaultAlt, allTagValues, z }
