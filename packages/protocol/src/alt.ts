/**
 * The `alt` tag: a required, human-readable one-line rendering of every Quorum
 * event.
 *
 * ## Why this is required even though NIP-31 is marked `unrecommended`
 *
 * The NIP registry flags NIP-31 as "unnecessarily bloated" and points at NIP-89
 * handler discovery instead. For its stated purpose — a kind:1 social client
 * stumbling across an unknown event — that is a fair call: resolving a handler
 * is better than shipping duplicate prose on every event.
 *
 * Quorum requires `alt` anyway, for a reason NIP-31 was not written to
 * anticipate. The primary consumer of an unknown Quorum event is not a client
 * with a UI; it is a **context packer feeding a language model**. NIP-89 cannot
 * help there. There is no handler to resolve, no iframe to open, and no user to
 * click through — there is a token budget and a model that must be told what
 * happened. An agent that meets kind 8199 from a newer peer needs a sentence,
 * synchronously, from the event it already holds.
 *
 * The same argument covers the second consumer: `UnknownKind` in our own
 * client, which renders `alt` and is built early precisely to prove that
 * forward compatibility works rather than assuming it.
 *
 * So the cost is real and accepted: every event carries a short redundant
 * string. In exchange, adding a kind never silently blanks a screen or a
 * prompt. This is the rule most likely to be skipped and the most expensive to
 * retrofit, which is why it is enforced by the validator rather than
 * recommended in prose.
 *
 * ## Rules
 *
 * 1. REQUIRED on every kind defined by this NIP.
 * 2. Plain text. No markup, no newlines — it may be rendered in a single line.
 * 3. Self-contained: understandable without fetching any other event.
 * 4. It MUST NOT be the only place a fact appears. `alt` is a rendering of the
 *    body, never a substitute for it. A reader that parses the body must never
 *    need to read `alt`, and vice versa.
 * 5. On encrypted channels `alt` is part of the ciphertext's *envelope*, so it
 *    leaks to the relay. Writers MUST keep it generic there — "Approval
 *    requested", not "Approval requested: wire $2M to Acme". See
 *    {@link redactedAlt}.
 */

import { Kinds, kindName } from './kinds.ts'

export const ALT_MAX_LENGTH = 280

export function isValidAlt(text: string): boolean {
  return text.length > 0 && text.length <= ALT_MAX_LENGTH && !/[\n\r]/.test(text)
}

function clamp(text: string): string {
  const flat = text.replace(/\s+/g, ' ').trim()
  return flat.length <= ALT_MAX_LENGTH ? flat : `${flat.slice(0, ALT_MAX_LENGTH - 1)}…`
}

/**
 * A generic `alt` carrying no body detail, for events on encrypted channels.
 *
 * Deliberately boring. The temptation on an encrypted channel is to write a
 * helpful `alt` and hand the relay exactly the summary the encryption was meant
 * to withhold.
 */
export function redactedAlt(kind: number): string {
  const name = kindName(kind)
  return name ? `Encrypted ${humanize(name)}` : `Encrypted Quorum event (kind ${kind})`
}

function humanize(name: string): string {
  return name.replace(/([a-z])([A-Z])/g, '$1 $2').toLowerCase()
}

/**
 * Default `alt` text for a known kind and body.
 *
 * Callers may write their own — a better sentence is always welcome — but
 * having a default means no code path can reach `publish()` with nothing to
 * put in the tag.
 */
export function defaultAlt(kind: number, body: unknown): string {
  const b = (body ?? {}) as Record<string, any>

  switch (kind) {
    case Kinds.Action: {
      const detail = b.output_summary ?? b.error?.message ?? b.summary ?? ''
      return clamp(`[${b.name}] ${b.status}${detail ? `: ${detail}` : ''}`)
    }
    case Kinds.ApprovalRequest:
      return clamp(`Approval requested (${b.risk} risk): ${b.title}`)
    case Kinds.ApprovalResponse:
      return clamp(`Approval ${b.decision}${b.reason ? `: ${b.reason}` : ''}`)
    case Kinds.Summary:
      return clamp(`Summary of ${b.covers} events (${b.method})`)
    case Kinds.Error:
      return clamp(`Error ${b.code}: ${b.message}`)
    case Kinds.Artifact:
      return clamp(`Artifact: ${b.name} (${b.mime})`)
    case Kinds.Handoff:
      return clamp(`Handed off to ${short(b.to)}: ${b.reason}`)
    case Kinds.Checkpoint:
      return clamp(`Relay checkpoint: ${b.count} events through ${iso(b.to)}`)
    case Kinds.ThreadOp:
      return clamp(threadOpAlt(b))
    case Kinds.Interrupt:
      return clamp(`Interrupt (${b.mode})${b.reason ? `: ${b.reason}` : ''}`)
    case Kinds.Lease:
      return clamp(`Lease claimed for ${b.ttl_seconds}s`)
    case Kinds.Presence:
      return clamp(`${b.status}${b.activity ? `: ${b.activity}` : ''}`)
    case Kinds.ThreadState:
      return clamp(`Task ${b.status}${b.assignee ? `, assigned to ${short(b.assignee)}` : ''}`)
    case Kinds.CapabilityGrant:
      return clamp(
        b.revoked
          ? `Revoked ${b.grant?.resource} for ${short(b.grantee)}`
          : `Granted ${b.grant?.resource} to ${short(b.grantee)}`,
      )
    case Kinds.AgentManifest:
      return clamp(`Agent ${b.name}: ${b.description}`)
    case Kinds.AgentMemory:
      return 'Agent memory entry'
    case Kinds.AgentCursor:
      return 'Agent cursor'
    case Kinds.Delegation:
      return clamp(
        b.revoked
          ? `Revoked delegation to ${short(b.delegate)}`
          : `Delegated authority to ${short(b.delegate)}`,
      )
    case Kinds.ContextPackRequest:
      return clamp(`Context requested: ${b.budget_tokens} tokens`)
    case Kinds.ContextPackResult:
      return clamp(`Context packed: ${b.segments?.length ?? 0} segments, ${b.used_tokens} tokens`)
    default: {
      const name = kindName(kind)
      return name ? `Quorum ${humanize(name)}` : `Quorum event (kind ${kind})`
    }
  }
}

function threadOpAlt(b: Record<string, any>): string {
  switch (b.op) {
    case 'set_status':
      return `Task set to ${b.status}${b.reason ? `: ${b.reason}` : ''}`
    case 'assign':
      return b.assignee ? `Assigned to ${short(b.assignee)}` : 'Unassigned'
    case 'set_title':
      return `Retitled: ${b.title}`
    case 'set_budget':
      return 'Budget updated'
    case 'add_spend':
      // No amount. `alt` is plaintext even where the body is not, and what a
      // task is costing is a number somebody would rather not broadcast.
      return 'Spend reported'
    default:
      return 'Thread updated'
  }
}

function short(pubkey: unknown): string {
  return typeof pubkey === 'string' && pubkey.length > 12 ? `${pubkey.slice(0, 8)}…` : String(pubkey)
}

function iso(seconds: unknown): string {
  return typeof seconds === 'number' ? new Date(seconds * 1000).toISOString() : String(seconds)
}
