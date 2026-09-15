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
  isEphemeral,
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
  // Channel-scoped, not thread-scoped: a key is handed to a member, not posted
  // into a conversation. `addressed` is what makes the recipient findable with
  // the same `#p` filter everything else uses.
  [RegularKinds.ChannelKey]: { addressed: true },
  // The `mls` twin of 8110, and it was missing this row for as long as it has
  // existed. An 8111 nobody is addressed by is a Welcome the recipient cannot
  // find: `inbox()` and every other reader locates one with `#p`, so an
  // unaddressed Welcome is stored, valid, and invisible to the one member who
  // needs it — which presents as an invitee waiting forever for a Welcome that
  // was published.
  [RegularKinds.MlsWelcome]: { addressed: true },
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
  } else if (counterValue === undefined && !isEphemeral(kind)) {
    // A warning, not an error: without it this author's readers lose gap
    // detection, but the event is still perfectly valid on any relay and
    // rejecting it would break generic clients that know nothing of Quorum.
    //
    // Ephemeral kinds are exempt, and should not carry a counter at all.
    // Relays do not store them, so a number spent on a heartbeat is a sequence
    // position no reader can ever backfill — gap detection would report a
    // permanent loss for every lease renewal the author has ever sent, which
    // is the same as having no gap detection.
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

/** One cross-field rule, as the other implementations are told about it. */
export interface CrossFieldRule {
  /** The `Issue.code` this rule raises. */
  code: string
  /** The kinds it applies to. */
  kinds: number[]
  /** What it requires, in one line, for a reader of the published table. */
  what: string
}

/**
 * Every cross-field rule, published so another implementation can be held to
 * the same list.
 *
 * This table exists because of a failure that has now happened four times: a
 * rule expressible only in TypeScript is a rule the Go relay does not have, and
 * nothing anywhere reports the difference. `ConfirmResourceNames`,
 * `UNSEALED_KINDS` and `RejectMlsPolicyEpoch` each closed one instance by
 * publishing the data behind it. The fifth was found by `@quorum/conformance`
 * asking both implementations the same question — a proposed action with no
 * `input_digest`, refused here and stored there — and a suite that finds one
 * instance of a recurring class should close the class.
 *
 * So the codes are data. The Go relay reads this table at boot and **refuses to
 * start** if it is published a rule it does not implement, which is the same
 * stance the resource names take and for the same reason: a check that silently
 * never fires is worse than an absent one, because the relay goes on saying it
 * enforces the rule.
 *
 * Warnings are deliberately not here. They change nothing about whether an
 * event is stored, so an implementation that omits one is not a relay with a
 * hole in it.
 */
export const CROSS_FIELD_RULES: readonly CrossFieldRule[] = Object.freeze([
  {
    code: 'missing_input_digest',
    kinds: [RegularKinds.Action, RegularKinds.ApprovalRequest],
    what: 'a proposed action, and an approval request tied to one, must carry `input_digest`',
  },
  {
    code: 'missing_action_tag',
    kinds: [RegularKinds.Action, EphemeralKinds.Interrupt],
    what: 'an action event after `proposed`, and an action-scoped interrupt, must name its action',
  },
  {
    code: 'unreachable_quorum',
    kinds: [RegularKinds.ApprovalRequest],
    what: 'an approval request may not require more approvals than it addresses approvers',
  },
  {
    code: 'missing_modified_digest',
    kinds: [RegularKinds.ApprovalResponse],
    what: 'an approval response carrying `modified_input` must carry its digest',
  },
  {
    code: 'many_recipients',
    kinds: [RegularKinds.ChannelKey, RegularKinds.MlsWelcome],
    what: 'a wrapped key and a Welcome are each addressed to exactly one member',
  },
  {
    code: 'recipient_mismatch',
    kinds: [RegularKinds.ChannelKey, RegularKinds.MlsWelcome],
    what: 'the addressed member and the body’s `recipient` must be the same member',
  },
  {
    code: 'mls_policy_epoch',
    kinds: [AddressableKinds.ChannelPolicy],
    what: 'an `mls` channel policy must not state an epoch',
  },
  {
    code: 'missing_epoch',
    kinds: [AddressableKinds.ChannelPolicy],
    what: 'a `nip44` channel policy must state the epoch writers seal under',
  },
  {
    code: 'bad_thread_d',
    kinds: [AddressableKinds.ThreadState],
    what: 'thread state is keyed by the 64-hex id of its kind 11 root',
  },
])

const CROSS_FIELD_CODES = new Set(CROSS_FIELD_RULES.map((rule) => rule.code))

/**
 * An error from a cross-field rule, refused unless the rule is published.
 *
 * The guard is the point of the table: a rule added here and not to
 * `CROSS_FIELD_RULES` would be enforced by this package and by nothing else,
 * which is the exact failure the table exists to end. Throwing rather than
 * warning because it is a programming error in this file, caught by the first
 * test that exercises the new rule, and never reachable from any input.
 */
function crossErr(code: string, message: string, at: string): Issue {
  if (!CROSS_FIELD_CODES.has(code)) {
    throw new Error(
      `cross-field rule "${code}" is not in CROSS_FIELD_RULES, so no other implementation ` +
        'is told it exists; add it to the table',
    )
  }
  return err(code, message, at)
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
 *
 * Each error below is raised through {@link crossErr}, which will not let a rule
 * exist here without also appearing in {@link CROSS_FIELD_RULES}.
 */
function crossFieldIssues(event: NostrEvent, body: any): Issue[] {
  const issues: Issue[] = []
  const { kind, tags } = event

  if (kind === RegularKinds.Action) {
    if (body.status === 'proposed') {
      if (!body.input_digest) {
        issues.push(
          crossErr(
            'missing_input_digest',
            'a proposed action must carry input_digest; an approval that cannot name its arguments authorises the action name forever',
            'content.input_digest',
          ),
        )
      }
    } else if (!tagValue(tags, TagName.Action)) {
      issues.push(
        crossErr(
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
        crossErr(
          'missing_input_digest',
          'an approval request tied to an action must bind to its input_digest',
          'content.input_digest',
        ),
      )
    }
    const required = body.required ?? 1
    if (required > addressees(tags).length) {
      issues.push(
        crossErr(
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
        crossErr(
          'missing_modified_digest',
          'modified_input requires modified_input_digest, or the log records one thing and the agent runs another',
          'content.modified_input_digest',
        ),
      )
    }
  }

  if (kind === EphemeralKinds.Interrupt) {
    // `scope` defaults to `action`, so an interrupt that names no action is the
    // easy one to publish by accident — and it is the dangerous shape, because
    // an agent reading it has to guess whether "stop" meant this action or
    // everything in the thread. Say which.
    if ((body.scope ?? 'action') === 'action' && !tagValue(tags, TagName.Action)) {
      issues.push(
        crossErr(
          'missing_action_tag',
          'an action-scoped interrupt must carry an `action` tag naming what to stop; use scope "thread" to stop everything',
          'action',
        ),
      )
    }
    if (body.mode === 'steer' && !body.instruction) {
      issues.push(
        warn(
          'steer_without_instruction',
          'a steer with no instruction tells an agent to change course without saying to what',
          'content.instruction',
        ),
      )
    }
  }

  // A wrapped key and a Welcome are each for exactly one member, and each says
  // so twice: once in a `to`-marked `p` tag, which is how a reader finds it, and
  // once in `recipient`, which is what the issuer signed. The two must agree.
  //
  // Disagreement is not a tidiness problem. The tag is the routing fact and the
  // body is the authorised one, so an 8110 addressed to Bob with
  // `recipient: cat` hands Bob a payload he cannot open and hands nobody the
  // one Cat was promised — and the failure surfaces as a NIP-44 MAC error,
  // which is the same thing tampering looks like. Two `to` tags are the same
  // bug wearing a different hat: both readers fetch it, one opens it, and the
  // other cannot tell "not mine" from "somebody altered this".
  if (kind === RegularKinds.ChannelKey || kind === RegularKinds.MlsWelcome) {
    const to = addressees(tags)
    if (to.length > 1) {
      issues.push(
        crossErr(
          'many_recipients',
          `a wrapped key is for one member; this one is addressed to ${to.length}. Publish one event per recipient`,
          'p',
        ),
      )
    } else if (to.length === 1 && body.recipient && to[0] !== body.recipient) {
      const addressed = to[0]!.slice(0, 8)
      const named = String(body.recipient).slice(0, 8)
      issues.push(
        crossErr(
          'recipient_mismatch',
          `addressed to ${addressed}… but the body says ${named}…; the reader who finds it is not the one who can open it`,
          'content.recipient',
        ),
      )
    }
  }

  if (kind === AddressableKinds.ChannelPolicy) {
    // `epoch` says which key a writer should be encrypting under *right now*,
    // and on an `mls` channel no policy event can answer that. The MLS epoch is
    // a property of the ratchet, advanced by every commit any member makes, and
    // the relay stores commits it cannot read — so a number written here is
    // stale the instant anybody adds a member, and it is stale in the direction
    // that matters: a client that believed it would seal at an epoch the group
    // has already left.
    //
    // Absent is therefore the only honest value, and it also sidesteps a
    // narrower defect: `Epoch` is positive because a `nip44` generation is
    // minted from 1, so an `mls` policy could not state epoch 0 — the first
    // epoch of every MLS group — even if it wanted to.
    if (body.enc === 'mls') {
      if (body.epoch !== undefined) {
        issues.push(
          crossErr(
            'mls_policy_epoch',
            'an mls channel policy must not state an epoch: the ratchet is the only thing that knows it, and a commit from any member makes this number wrong',
            'content.epoch',
          ),
        )
      }
    } else if (body.enc === 'nip44' && body.epoch === undefined) {
      issues.push(
        crossErr(
          'missing_epoch',
          'a nip44 channel policy must state the epoch writers should seal under, or nobody can tell a rotation from a missing key',
          'content.epoch',
        ),
      )
    }
  }

  if (kind === AddressableKinds.ThreadState) {
    const d = tagValue(tags, TagName.Identifier)
    if (d && !/^[0-9a-f]{64}$/.test(d)) {
      issues.push(
        crossErr('bad_thread_d', 'thread_state `d` must be the 64-hex id of the kind:11 root', 'd'),
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
