/**
 * Approvals — asking a human, and proving they answered.
 *
 * This is the file the project exists for. Everything else is plumbing that
 * makes it possible to say, months later and with no server running:
 *
 *   Ada approved *this* deploy, with *these* arguments, at this time, and here
 *   is her signature over a digest of the arguments that actually ran.
 *
 * ## The loop
 *
 *   action(proposed)         the full input, and a digest of it
 *   approval_request         binds to that digest, addressed to the approvers
 *   action(awaiting_approval)
 *     …a human signs an approval_response…
 *   action(running)          names the digest that is about to execute
 *   action(succeeded|failed|denied|cancelled)
 *
 * Every one of those is published through `once()`, so a process killed at any
 * point in the sequence resumes it rather than restarting it. That matters most
 * in the longest gap — between the request and the decision — where "the agent
 * was restarted while waiting" is not an edge case but the normal outcome of a
 * deploy, and where restarting the loop would mean asking a human to approve
 * the same thing twice and then doing it twice.
 *
 * ## Three rules that are not negotiable
 *
 * **The approver must have been asked.** A response is only counted if its
 * author appears in the request's `to`-marked `p` tags. Without this check any
 * pubkey on the relay can approve anything, and the signature proves only that
 * *somebody* said yes.
 *
 * **The response must echo the digest.** An approval that does not name what it
 * approved is an approval of the action's *name*, which would make one "yes" to
 * `deploy.production` a standing yes to every future deploy.
 *
 * **An edit re-opens the question.** If a human changes the parameters before
 * approving, the agent runs the edited input — but only after checking that
 * `modified_input_digest` really is the digest of `modified_input`, and only if
 * every counted approver approved the *same* edit. Two approvers who signed
 * different payloads have not agreed on anything.
 */

import {
  ApprovalRequestBody,
  ApprovalResponseBody,
  Kinds,
  TagName,
  addressees,
  digest,
  digestEquals,
  refTo,
  tagValue,
  threadRef,
  verifyEvent,
  type Cost,
  type ErrorDetail,
  type EventRef,
  type GrantSpec,
  type NostrEvent,
  type Risk,
} from '@quorum/protocol'
import type { Logger, RelayClient } from './client.ts'
import type { Once } from './once.ts'
import type { PublishOptions } from './publish.ts'

// --- verifying one response --------------------------------------------------

export interface ApprovalCheck {
  ok: boolean
  /** Present when `ok` is false. Written to be shown to a human. */
  reason?: string
}

/**
 * Is this response a valid answer to this request?
 *
 * Pure, and deliberately takes events rather than a relay: this is the same
 * function the offline auditor in `audit.ts` runs over a JSON dump, so the
 * check an agent performs before acting and the check an auditor performs
 * afterwards cannot drift apart.
 */
export function verifyApprovalResponse(request: NostrEvent, response: NostrEvent): ApprovalCheck {
  if (response.kind !== Kinds.ApprovalResponse) {
    return no(`kind ${response.kind} is not an approval response`)
  }
  // The relay client verifies everything it delivers, so this is belt and
  // braces there — but an auditor reading a file has no such guarantee, and
  // this is the function they will call.
  if (!verifyEvent(response)) return no('the id or signature does not verify')

  if (tagValue(response.tags, TagName.Event) !== request.id) {
    return no('answers a different request')
  }
  if (tagValue(response.tags, TagName.ParentKind) !== String(Kinds.ApprovalRequest)) {
    return no('its `k` tag does not say it is answering an approval request')
  }
  if (tagValue(response.tags, TagName.Group) !== tagValue(request.tags, TagName.Group)) {
    return no('was published in a different channel from the request')
  }

  // The rule that makes the signature mean something. Everything else here
  // could pass while a stranger approves their own agent's deploy.
  if (!addressees(request.tags).includes(response.pubkey)) {
    return no(`${short(response.pubkey)} was not one of the approvers this request asked`)
  }

  const asked = parseBody(ApprovalRequestBody, request)
  if (!asked) return no('the request body is not a valid approval request')
  const answer = parseBody(ApprovalResponseBody, response)
  if (!answer) return no('the response body is not a valid approval response')

  if (asked.input_digest && !digestEquals(answer.input_digest, asked.input_digest)) {
    return no('does not echo the input digest it was asked to approve')
  }

  if (answer.modified_input !== undefined) {
    if (!digestEquals(answer.modified_input_digest, digest(answer.modified_input))) {
      // The log would say one thing and the agent would run another. This is
      // the single most dangerous shape an approval can have.
      return no('modified_input does not hash to modified_input_digest')
    }
  }

  if (asked.expires_at !== undefined && response.created_at > asked.expires_at) {
    return no('arrived after the request expired')
  }

  return { ok: true }
}

// --- counting them -----------------------------------------------------------

export type TallyDecision = 'approved' | 'denied' | 'conflicted' | 'pending'

export interface RejectedResponse {
  event: NostrEvent
  reason: string
}

export interface Tally {
  decision: TallyDecision
  /** Responses that passed verification and count toward the outcome. */
  counted: NostrEvent[]
  /** Responses that did not count, each with why. Never silently dropped. */
  rejected: RejectedResponse[]
  /** The input to execute — the human's edit, if there was one. */
  input: unknown
  /** The digest of {@link input}. This is what `running` names. */
  inputDigest: string
  modified: boolean
  reason?: string
}

/**
 * Fold a set of responses into a decision.
 *
 * Deliberately not "the newest response wins". The rules, in order:
 *
 * - One vote per approver; the earliest response from a pubkey is the one that
 *   counts, and a second is reported as rejected rather than replacing it. An
 *   approver who wants to change their mind after the agent has acted needs an
 *   interrupt (28101), not a rewritten vote.
 * - A denial from anyone who was asked stops the action, whatever the count.
 *   `required: 2` means two people must say yes, not that one no can be
 *   outvoted.
 * - `expired` is a decision an approver can record explicitly; it counts as
 *   neither a yes nor a no.
 */
export function tallyApprovals(
  request: NostrEvent,
  responses: readonly NostrEvent[],
  context: { input: unknown; inputDigest: string },
): Tally {
  const asked = parseBody(ApprovalRequestBody, request)
  const base = {
    counted: [] as NostrEvent[],
    rejected: [] as RejectedResponse[],
    input: context.input,
    inputDigest: context.inputDigest,
    modified: false,
  }
  if (!asked) {
    return { ...base, decision: 'conflicted', reason: 'the request body is not valid' }
  }

  const rejected: RejectedResponse[] = []
  const votes = new Map<string, NostrEvent>()
  for (const response of [...responses].sort(byCreatedAt)) {
    const check = verifyApprovalResponse(request, response)
    if (!check.ok) {
      rejected.push({ event: response, reason: check.reason ?? 'rejected' })
      continue
    }
    if (votes.has(response.pubkey)) {
      rejected.push({ event: response, reason: 'this approver has already answered' })
      continue
    }
    votes.set(response.pubkey, response)
  }

  const answers = [...votes.values()].map((event) => ({
    event,
    body: parseBody(ApprovalResponseBody, event)!,
  }))

  const denial = answers.find((a) => a.body.decision === 'denied')
  if (denial) {
    return {
      ...base,
      rejected,
      decision: 'denied',
      counted: [denial.event],
      reason: denial.body.reason ?? `${short(denial.event.pubkey)} denied it`,
    }
  }

  const approvals = answers.filter((a) => a.body.decision === 'approved')
  if (approvals.length < asked.required) {
    return { ...base, rejected, decision: 'pending', counted: approvals.map((a) => a.event) }
  }

  const edits = approvals.filter((a) => a.body.modified_input !== undefined)
  if (edits.length) {
    // An edit invalidates everyone else's consent: they signed a digest of the
    // original. Requiring that every counted approver signed the *same* edit is
    // what stops "one of the three approvers quietly rewrote the payload" from
    // reading as a quorum.
    const distinct = new Set(edits.map((a) => a.body.modified_input_digest))
    if (distinct.size > 1 || edits.length !== approvals.length) {
      return {
        ...base,
        rejected,
        decision: 'conflicted',
        counted: approvals.map((a) => a.event),
        reason:
          distinct.size > 1
            ? 'approvers supplied different edits to the input'
            : 'one approver edited the input while others approved the original',
      }
    }
    const edit = edits[0]!.body
    return {
      ...base,
      rejected,
      decision: 'approved',
      counted: approvals.map((a) => a.event),
      input: edit.modified_input,
      inputDigest: edit.modified_input_digest!,
      modified: true,
    }
  }

  return { ...base, rejected, decision: 'approved', counted: approvals.map((a) => a.event) }
}

// --- the approver's side -----------------------------------------------------

export interface ApprovalResponseOptions {
  request: NostrEvent
  decision: 'approved' | 'denied' | 'expired'
  reason?: string
  /** Approve a changed payload. Its digest is computed here, never supplied. */
  modifiedInput?: unknown
  /** Addressable coordinate of a `capability_grant` issued alongside this yes. */
  grant?: string
}

/**
 * Build the response a human (or their client) publishes to answer a request.
 *
 * The digests are computed here rather than accepted from the caller, because
 * "pass in the digest of what you are approving" is an invitation to pass in
 * the wrong one, and the whole mechanism rests on that value being right.
 */
export function approvalResponse(options: ApprovalResponseOptions): PublishOptions {
  const { request } = options
  const thread = threadRef(request)
  if (!thread) throw new Error('an approval request must be inside a thread')

  const asked = parseBody(ApprovalRequestBody, request)
  if (!asked) throw new Error('that event is not a valid approval request')

  const actionId = tagValue(request.tags, TagName.Action)

  return {
    kind: Kinds.ApprovalResponse,
    thread,
    parent: refTo(request),
    ...(actionId ? { action: actionId } : {}),
    to: [request.pubkey],
    body: {
      decision: options.decision,
      ...(options.reason ? { reason: options.reason } : {}),
      ...(asked.input_digest ? { input_digest: asked.input_digest } : {}),
      ...(options.modifiedInput !== undefined
        ? {
            modified_input: options.modifiedInput,
            modified_input_digest: digest(options.modifiedInput),
          }
        : {}),
      ...(options.grant ? { grant: options.grant } : {}),
    },
  }
}

// --- the agent's side --------------------------------------------------------

/** Handed to the effect. `cost` is assignable; everything else is read-only. */
export interface ActRun {
  readonly actionId: string
  /** 1 on the first run. Greater means a previous attempt died mid-effect. */
  readonly attempt: number
  /** The digest the approvers signed over. Worth logging with the effect. */
  readonly inputDigest: string
  /** Set this and it lands on the terminal action event. */
  cost?: Cost
}

export interface ActOptions<I, T> {
  /** Stable dotted identifier. Also the capability resource: `action:<name>`. */
  name: string
  /** What this does, for the human deciding. */
  summary: string
  input: I
  /** The work. Receives the approved input, which may be a human's edit. */
  run: (input: I, run: ActRun) => T | Promise<T>

  /** Pubkeys who may approve. Omitted or empty means no gate. */
  approvers?: string[]
  /** How many distinct approvers must say yes. Defaults to 1 when asked at all. */
  required?: number
  risk?: Risk
  title?: string
  /** A capability to ask for as part of the yes. */
  requestedGrant?: GrantSpec
  /** Coordinate of the 38106 delegation this is performed under. */
  onBehalfOf?: string
  /**
   * How long the request stays answerable. Default one hour; `Infinity` waits
   * forever, which blocks this agent's queue until someone answers.
   */
  expiresInSeconds?: number
  /** One line describing the outcome, for the log and for `alt`. */
  describe?: (output: T) => string
  /** Override the `once()` label. See `once.ts` on naming. */
  label?: string
}

export type ActResult<T> =
  | { status: 'succeeded'; actionId: string; output: T; input: unknown; approvals: NostrEvent[] }
  | { status: 'denied'; actionId: string; reason: string; approvals: NostrEvent[] }
  | { status: 'cancelled'; actionId: string; reason: string; approvals: NostrEvent[] }
  | {
      status: 'failed'
      actionId: string
      error: ErrorDetail
      cause?: unknown
      approvals: NostrEvent[]
    }

export interface ActDeps {
  once: Once
  publish(label: string, options: PublishOptions): Promise<NostrEvent>
  client: RelayClient
  group: string
  me: string
  thread: EventRef
  /** What the action is a reply to — usually the event that triggered it. */
  parent?: EventRef
  log: Logger
  /** Overridable so tests do not wait on a wall clock. */
  now?: () => number
}

const DEFAULT_EXPIRY_SECONDS = 3600

/**
 * Propose an action, get it approved, run it, and record what happened.
 *
 * Returns rather than throws, including on failure: an action that failed is a
 * terminal state in the protocol with a signed event describing it, not an
 * exception in flight. The discriminated union is there so that ignoring the
 * outcome is a type error rather than a silent assumption of success.
 */
export async function runAction<I, T>(
  deps: ActDeps,
  options: ActOptions<I, T>,
): Promise<ActResult<T>> {
  const input = options.input
  const inputDigest = digest(input)
  const label = options.label ?? `act:${options.name}:${inputDigest.slice(0, 16)}`
  const approvers = dedupe(options.approvers ?? [])
  const required = options.required ?? (approvers.length ? 1 : 0)

  if (required > approvers.length) {
    throw new Error(
      `act('${options.name}') needs ${required} approvals but addresses ${approvers.length} ` +
        'approvers. A request nobody can satisfy would sit in the channel forever.',
    )
  }

  const proposed = await deps.publish(`${label}/proposed`, {
    kind: Kinds.Action,
    thread: deps.thread,
    ...(deps.parent ? { parent: deps.parent } : {}),
    body: {
      name: options.name,
      status: 'proposed',
      summary: options.summary,
      input,
      input_digest: inputDigest,
      ...(options.onBehalfOf ? { on_behalf_of: options.onBehalfOf } : {}),
    },
  })

  // The action id is the id of the `proposed` event, which is the hash of its
  // own contents. No allocator, no coordination — and stable across a restart,
  // because `once()` either returns the event it cached or rebuilds it from the
  // reserved `created_at` into the same bytes.
  const actionId = proposed.id

  const state: ActState<T> = { actionId, label, options, deps, approvals: [] }

  if (required === 0) {
    return execute(state, input, inputDigest, refTo(proposed))
  }

  const expiresAt =
    options.expiresInSeconds === Infinity
      ? undefined
      : proposed.created_at + (options.expiresInSeconds ?? DEFAULT_EXPIRY_SECONDS)

  const request = await deps.publish(`${label}/request`, {
    kind: Kinds.ApprovalRequest,
    thread: deps.thread,
    parent: refTo(proposed),
    action: actionId,
    to: approvers,
    body: {
      title: options.title ?? options.name,
      summary: options.summary,
      risk: options.risk ?? 'medium',
      input_digest: inputDigest,
      required,
      ...(expiresAt !== undefined ? { expires_at: expiresAt } : {}),
      ...(options.requestedGrant ? { requested_grant: options.requestedGrant } : {}),
    },
  })

  const awaiting = await deps.publish(`${label}/awaiting`, {
    kind: Kinds.Action,
    thread: deps.thread,
    parent: refTo(request),
    action: actionId,
    body: { name: options.name, status: 'awaiting_approval', summary: options.summary },
  })

  const tally = await awaitDecision(deps, request, { input, inputDigest }, expiresAt)
  state.approvals = tally.counted

  for (const { event, reason } of tally.rejected) {
    // Loud, because every one of these is either a bug in a client or an
    // attempt to approve something. Neither should be discovered by grep.
    deps.log.warn(
      `[approval] ignored a response to ${short(request.id)} from ${short(event.pubkey)}: ${reason}`,
    )
  }

  if (tally.decision === 'approved') {
    return execute(state, tally.input as I, tally.inputDigest, refTo(awaiting), tally.modified)
  }

  const reason =
    tally.reason ??
    (tally.decision === 'pending'
      ? 'nobody answered before the request expired'
      : 'the request was not approved')

  // There is no `expired` action status, on purpose: from the action's point of
  // view an unanswered request and a withdrawn one end the same way, and adding
  // a status for "nobody replied" would put a fact about the humans into the
  // state machine of the work.
  const status = tally.decision === 'denied' ? 'denied' : 'cancelled'
  await deps.publish(`${label}/${status}`, {
    kind: Kinds.Action,
    thread: deps.thread,
    parent: refTo(awaiting),
    action: actionId,
    body: {
      name: options.name,
      status,
      summary: options.summary,
      output_summary: reason,
    },
  })

  return { status, actionId, reason, approvals: tally.counted }
}

interface ActState<T> {
  actionId: string
  label: string
  options: ActOptions<any, T>
  deps: ActDeps
  approvals: NostrEvent[]
}

async function execute<I, T>(
  state: ActState<T>,
  input: I,
  inputDigest: string,
  parent: EventRef,
  modified = false,
): Promise<ActResult<T>> {
  const { deps, label, options, actionId } = state

  const running = await deps.publish(`${label}/running`, {
    kind: Kinds.Action,
    thread: deps.thread,
    parent,
    action: actionId,
    body: {
      name: options.name,
      status: 'running',
      summary: options.summary,
      // Names the digest that is actually about to execute. When a human edited
      // the payload this differs from the proposal's, and the pair of events is
      // what lets an auditor see the edit without trusting either party.
      input_digest: inputDigest,
    },
  })

  // The effect records *both* outcomes in the ledger, which is why this catches
  // rather than letting the throw escape. If a failure were left unrecorded, a
  // replay would re-run the effect, and a run that succeeded the second time
  // would publish `succeeded` after `failed` — an illegal transition, and a
  // chain that says two contradictory things about the same action. A failed
  // action is terminal: retrying means proposing a new one.
  const outcome = await deps.once(`${label}/run`, async ({ attempt }) => {
    const run: ActRun = { actionId, attempt, inputDigest }
    try {
      const output = await options.run(input, run)
      return { ok: true as const, output, cost: run.cost }
    } catch (error) {
      return { ok: false as const, error: toErrorDetail(error), cost: run.cost }
    }
  })

  if (!outcome.ok) {
    deps.log.error(`[action] ${options.name} failed: ${outcome.error.message}`)
    await deps.publish(`${label}/failed`, {
      kind: Kinds.Action,
      thread: deps.thread,
      parent: refTo(running),
      action: actionId,
      body: {
        name: options.name,
        status: 'failed',
        summary: options.summary,
        error: outcome.error,
        ...(outcome.cost ? { cost: outcome.cost } : {}),
      },
    })
    return { status: 'failed', actionId, error: outcome.error, approvals: state.approvals }
  }

  const output = outcome.output as T
  const summary = options.describe?.(output)
  await deps.publish(`${label}/succeeded`, {
    kind: Kinds.Action,
    thread: deps.thread,
    parent: refTo(running),
    action: actionId,
    body: {
      name: options.name,
      status: 'succeeded',
      summary: options.summary,
      ...(output !== undefined ? { output } : {}),
      ...(summary ? { output_summary: summary } : {}),
      ...(outcome.cost ? { cost: outcome.cost } : {}),
    },
  })

  if (modified) {
    deps.log.warn(
      `[action] ${options.name} ran the approver's edited input, not the proposal (${short(inputDigest)})`,
    )
  }

  return { status: 'succeeded', actionId, output, input, approvals: state.approvals }
}

/**
 * Wait for enough signed responses, or for the request to expire.
 *
 * Queries before subscribing, and that order is the whole point. An agent that
 * only subscribes hears nothing that happened while it was down — so the
 * ordinary case of "the agent was restarted between asking and being answered"
 * would hang forever, waiting for an event the relay already holds and will
 * never send again.
 */
async function awaitDecision(
  deps: ActDeps,
  request: NostrEvent,
  context: { input: unknown; inputDigest: string },
  expiresAt: number | undefined,
): Promise<Tally> {
  const filters = [
    {
      kinds: [Kinds.ApprovalResponse],
      [`#${TagName.Event}`]: [request.id],
      [`#${TagName.Group}`]: [deps.group],
    },
  ]

  const seen = new Map<string, NostrEvent>()
  const collect = (event: NostrEvent) => seen.set(event.id, event)

  for (const event of await deps.client.query(filters)) collect(event)
  let tally = tallyApprovals(request, [...seen.values()], context)
  if (tally.decision !== 'pending') return tally

  const now = deps.now ?? (() => Math.floor(Date.now() / 1000))
  if (expiresAt !== undefined && now() >= expiresAt) return tally

  return new Promise<Tally>((resolve, reject) => {
    let settled = false
    const finish = (fn: () => void) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      subscription.close()
      fn()
    }

    const timer =
      expiresAt === undefined
        ? undefined
        : setTimeout(
            () => finish(() => resolve(tallyApprovals(request, [...seen.values()], context))),
            Math.max(0, (expiresAt - now()) * 1000),
          )
    timer?.unref?.()

    const subscription = deps.client.subscribe(filters, {
      onEvent: (event) => {
        collect(event)
        tally = tallyApprovals(request, [...seen.values()], context)
        if (tally.decision !== 'pending') finish(() => resolve(tally))
      },
      onClosed: (reason) => {
        // Failing loudly beats waiting forever. An agent that silently stops
        // hearing approvals looks healthy and never finishes anything, and the
        // handler it is inside will be replayed — which is the right recovery.
        finish(() =>
          reject(new Error(`the relay closed the approval subscription: ${reason}`)),
        )
      },
    })
  })
}

// --- helpers -----------------------------------------------------------------

function no(reason: string): ApprovalCheck {
  return { ok: false, reason }
}

function parseBody<T>(schema: { safeParse(v: unknown): { success: boolean; data?: T } }, event: NostrEvent): T | undefined {
  try {
    const result = schema.safeParse(JSON.parse(event.content))
    return result.success ? result.data : undefined
  } catch {
    return undefined
  }
}

function byCreatedAt(a: NostrEvent, b: NostrEvent): number {
  return a.created_at - b.created_at || (a.id < b.id ? -1 : 1)
}

function dedupe(values: readonly string[]): string[] {
  return [...new Set(values)]
}

function short(hex: string): string {
  return hex.length > 12 ? `${hex.slice(0, 8)}…` : hex
}

function toErrorDetail(error: unknown): ErrorDetail {
  if (error instanceof Error) {
    return { code: 'action_failed', message: error.message, retryable: false }
  }
  return { code: 'action_failed', message: String(error), retryable: false }
}
