/**
 * The offline auditor.
 *
 * Hand it a pile of events — from a relay, a JSON file, a backup someone
 * emailed you — and it tells you what happened and whether the log is
 * self-consistent. No relay, no server, no database, no trust in whoever
 * handed you the events, because every claim it makes is backed by a signature
 * over content it re-hashes itself.
 *
 * This is the file that has to exist for the project's central claim to be
 * true. "The audit trail *is* the signatures" is a slogan until something can
 * read a chain and say: this deploy ran with these arguments, Ada approved
 * exactly those arguments, and here is the event where she said so.
 *
 * It deliberately shares {@link verifyApprovalResponse} and
 * {@link tallyApprovals} with the agent runtime. An auditor with its own
 * reimplementation of "does this approval count" would eventually disagree with
 * the agent, and the disagreement would be discovered by an auditor saying
 * everything is fine.
 */

import {
  ActionBody,
  ApprovalRequestBody,
  ApprovalResponseBody,
  Kinds,
  TagName,
  canTransition,
  digest,
  digestEquals,
  tagValue,
  verifyEvent,
  type ActionStatus,
  type Decision,
  type NostrEvent,
} from '@quorum/protocol'
import { tallyApprovals } from './approval.ts'

export interface ChainIssue {
  code: string
  message: string
  severity: 'error' | 'warning'
}

export interface ChainApproval {
  pubkey: string
  decision: Decision
  at: number
  event: NostrEvent
  counted: boolean
}

export interface ActionChain {
  actionId: string
  name: string
  /** The last status reached, by the transition graph rather than arrival order. */
  status: ActionStatus | 'unknown'
  /** No error-severity issues. The one field a script should branch on. */
  ok: boolean
  /** The input as proposed, verbatim. */
  input?: unknown
  /** The digest the action actually executed under — an edit changes it. */
  executedDigest?: string
  /** True when a human's edit replaced the proposed input. */
  modified: boolean
  approvals: ChainApproval[]
  events: NostrEvent[]
  issues: ChainIssue[]
}

export interface AuditOptions {
  /** For expiry checks. Defaults to now. */
  now?: number
}

/** Every action chain present in these events, oldest proposal first. */
export function verifyActionChains(
  events: readonly NostrEvent[],
  options: AuditOptions = {},
): ActionChain[] {
  const chains = new Map<string, NostrEvent[]>()
  for (const event of events) {
    const id = chainIdOf(event)
    if (!id) continue
    const list = chains.get(id) ?? []
    list.push(event)
    chains.set(id, list)
  }
  return [...chains.keys()]
    .map((id) => verifyActionChain(id, chains.get(id)!, options))
    .sort((a, b) => proposalTime(a) - proposalTime(b))
}

/**
 * Verify one action chain.
 *
 * The chain is every event carrying this action id, plus the `proposed` event
 * whose own id *is* that action id. Passing extra events is harmless; they are
 * ignored.
 */
export function verifyActionChain(
  actionId: string,
  events: readonly NostrEvent[],
  options: AuditOptions = {},
): ActionChain {
  const issues: ChainIssue[] = []
  const error = (code: string, message: string) => issues.push({ code, message, severity: 'error' })
  const warn = (code: string, message: string) =>
    issues.push({ code, message, severity: 'warning' })

  const mine = causalOrder(events.filter((e) => chainIdOf(e) === actionId))

  for (const event of mine) {
    // The first thing, always. Everything below reads content that only means
    // something if the author's key stands behind these exact bytes.
    if (!verifyEvent(event)) {
      error('bad_signature', `event ${short(event.id)} does not verify`)
    }
  }

  const actions = mine.filter((e) => e.kind === Kinds.Action)

  // The proposal is the event whose *id* is the action id. Definitional, and
  // load-bearing: "the first event in here whose status says proposed" would be
  // a different rule, and a worse one, because anyone may publish an 8101
  // carrying this chain's `action` tag. Let a stranger's event answer "who
  // proposed this" and they get to decide whose transitions count, which
  // inverts every authorship check below.
  const proposed = actions.find(
    (e) => e.id === actionId && bodyOf(ActionBody, e)?.status === 'proposed',
  )
  const chain: ActionChain = {
    actionId,
    name: proposed ? (bodyOf(ActionBody, proposed)?.name ?? '?') : '?',
    status: 'unknown',
    ok: false,
    modified: false,
    approvals: [],
    events: mine,
    issues,
  }

  if (!proposed) {
    const claimant = actions.find((e) => bodyOf(ActionBody, e)?.status === 'proposed')
    if (claimant) {
      error(
        'action_id_mismatch',
        `the action id is ${short(actionId)} but the only proposal here has id ${short(claimant.id)}`,
      )
    } else {
      error(
        'no_proposal',
        'the chain has no `proposed` event, so there is nothing it is anchored to',
      )
    }
    return finish(chain)
  }

  const proposal = bodyOf(ActionBody, proposed)!
  chain.input = proposal.input
  if (proposal.input !== undefined && !digestEquals(proposal.input_digest, digest(proposal.input))) {
    // The proposal says it is about one payload and carries another. Every
    // approval downstream binds to the digest, so this is the seam where a
    // tampered input would show.
    error('input_digest_mismatch', 'the proposal\'s input_digest is not the digest of its input')
  }

  // Only the proposer advances their own action. Everything here signed by
  // anyone else is set aside — recorded, reported, and given no say in what the
  // chain says happened.
  //
  // Both halves of that matter, and the second half is the one that is easy to
  // get wrong. Counting a stranger's transition would let any member publish a
  // `succeeded` for someone else's deploy and have the log read as if the work
  // happened. But treating it as an *error* — which this did until a mutation
  // test on the relay policies exposed it — is just as broken in the other
  // direction: one junk event from any workspace member would permanently
  // invalidate an honest chain, with no way for the proposer to clean it up,
  // and on a generic relay there is nothing to stop them publishing it. That is
  // a veto over every action in the workspace, handed out for free.
  //
  // So: a defect in a chain means *the party doing the work* did something
  // illegitimate. A stranger's event says nothing about the proposer's conduct.
  // This is the rule {@link tallyApprovals} already applies to responses from
  // people nobody asked, and the two should not disagree.
  const transitions: NostrEvent[] = []
  for (const event of actions) {
    if (event.pubkey === proposed.pubkey) transitions.push(event)
    else {
      warn(
        'foreign_transition',
        `${short(event.pubkey)} published a transition on an action proposed by ${short(proposed.pubkey)}; ignored`,
      )
    }
  }

  let status: ActionStatus = 'proposed'
  for (const event of transitions) {
    if (event === proposed) continue
    const body = bodyOf(ActionBody, event)
    if (!body) {
      error('bad_action_body', `event ${short(event.id)} is not a valid action`)
      continue
    }
    if (!canTransition(status, body.status)) {
      error('illegal_transition', `${status} → ${body.status} is not a legal transition`)
      continue
    }
    status = body.status
  }
  chain.status = status

  // --- the approval gate -----------------------------------------------------

  // Same rule, and here it is not merely a denial-of-service question. A
  // stranger's `approval_request` names its own approvers, so counting one
  // would let Mallory ask Mallory, answer herself, and produce a chain that
  // tallies as approved. It is not the request; it is somebody shouting.
  const requests = mine.filter((e) => e.kind === Kinds.ApprovalRequest)
  const request = requests.find((e) => e.pubkey === proposed.pubkey)
  for (const other of requests) {
    if (other.pubkey !== proposed.pubkey) {
      warn(
        'foreign_request',
        `${short(other.pubkey)} published an approval request on someone else's action; ignored`,
      )
    }
  }
  const responses = mine.filter((e) => e.kind === Kinds.ApprovalResponse)
  const running = transitions.find((e) => bodyOf(ActionBody, e)?.status === 'running')
  const executedDigest = running
    ? (bodyOf(ActionBody, running)?.input_digest ?? proposal.input_digest)
    : undefined
  chain.executedDigest = executedDigest
  chain.modified = Boolean(
    executedDigest && proposal.input_digest && executedDigest !== proposal.input_digest,
  )

  if (request) {
    const asked = bodyOf(ApprovalRequestBody, request)
    if (!asked) {
      error('bad_request_body', 'the approval request body is not valid')
    } else {
      if (!digestEquals(asked.input_digest, proposal.input_digest)) {
        // The agent asked about a different payload from the one it proposed.
        error(
          'request_digest_mismatch',
          'the approval request binds to a different digest from the proposal',
        )
      }
    }

    const tally = tallyApprovals(request, responses, {
      input: proposal.input,
      inputDigest: proposal.input_digest ?? '',
    })

    const counted = new Set(tally.counted.map((e) => e.id))
    for (const response of responses.sort(byCreatedAt)) {
      const body = bodyOf(ApprovalResponseBody, response)
      chain.approvals.push({
        pubkey: response.pubkey,
        decision: body?.decision ?? 'expired',
        at: response.created_at,
        event: response,
        counted: counted.has(response.id),
      })
    }
    for (const { event, reason } of tally.rejected) {
      warn('response_not_counted', `a response from ${short(event.pubkey)} did not count: ${reason}`)
    }

    if (running) {
      if (tally.decision !== 'approved') {
        error(
          'unapproved_execution',
          `the action ran, but the approvals do not reach a yes (${tally.decision}${
            tally.reason ? `: ${tally.reason}` : ''
          })`,
        )
      } else if (!digestEquals(tally.inputDigest, executedDigest)) {
        // The one every other check exists to make possible: approved one
        // payload, executed another.
        error(
          'executed_unapproved_input',
          `the approvals cover ${short(tally.inputDigest)} but the action ran ${short(executedDigest ?? '')}`,
        )
      }
    }
  } else if (running) {
    warn(
      'ungated_execution',
      'the action ran with no approval request; nothing in the log says a human agreed',
    )
  }

  if (options.now !== undefined && request) {
    const asked = bodyOf(ApprovalRequestBody, request)
    if (asked?.expires_at !== undefined && asked.expires_at < options.now && !running) {
      warn('request_expired', 'the approval request expired unanswered')
    }
  }

  return finish(chain)
}

// --- helpers -----------------------------------------------------------------

function finish(chain: ActionChain): ActionChain {
  chain.ok = !chain.issues.some((i) => i.severity === 'error')
  return chain
}

/** Which chain does this event belong to? */
function chainIdOf(event: NostrEvent): string | undefined {
  const tagged = tagValue(event.tags, TagName.Action)
  if (tagged) return tagged
  if (event.kind === Kinds.Action && bodyOf(ActionBody, event)?.status === 'proposed') {
    return event.id
  }
  return undefined
}

function proposalTime(chain: ActionChain): number {
  return chain.events[0]?.created_at ?? 0
}

function bodyOf<T>(
  schema: { safeParse(v: unknown): { success: boolean; data?: T } },
  event: NostrEvent,
): T | undefined {
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

/**
 * Order a chain by causality rather than by clock.
 *
 * This must not be `sort(byCreatedAt)`, and the reason is not subtle: an action
 * loop that needs no human — and even one that does, on either side of the wait
 * — publishes `proposed`, `awaiting_approval`, `running` and `succeeded` inside
 * the same second. `created_at` has one-second resolution, so ordering by it
 * falls through to the id tiebreak, which is a hash: the transitions come back
 * shuffled, and the state-machine check below rejects a perfectly honest chain
 * roughly as often as not.
 *
 * `created_at` could not fix this even at millisecond resolution. It is a
 * client-supplied wall clock — the author picks it, so an attacker picks theirs
 * — and the ordering that decides whether an execution was legal must not be a
 * field the executing party chooses. Every event in a chain names its parent by
 * id, and an id is a hash of content that already includes the parent, so the
 * causal order is the one thing here nobody can rewrite after the fact.
 *
 * Time still breaks ties between events that are genuinely unordered: two
 * approvers answering the same request are siblings, and so are a real
 * transition and a forged one claiming the same parent. A fork like that leaves
 * one of the two illegal whichever way it is read, which is the correct answer.
 */
function causalOrder(events: readonly NostrEvent[]): NostrEvent[] {
  const byId = new Map(events.map((e) => [e.id, e]))
  const depths = new Map<string, number>()

  const depthOf = (event: NostrEvent, seen: Set<string>): number => {
    const cached = depths.get(event.id)
    if (cached !== undefined) return cached
    // Only a forged chain can contain a cycle, and it must not cost us a stack.
    if (seen.has(event.id)) return 0
    seen.add(event.id)
    const parent = byId.get(tagValue(event.tags, TagName.Event) ?? '')
    const depth = parent && parent.id !== event.id ? depthOf(parent, seen) + 1 : 0
    depths.set(event.id, depth)
    return depth
  }

  for (const event of events) depthOf(event, new Set())
  return [...events].sort((a, b) => depths.get(a.id)! - depths.get(b.id)! || byCreatedAt(a, b))
}

function short(hex: string): string {
  return hex.length > 12 ? `${hex.slice(0, 8)}…` : hex
}
