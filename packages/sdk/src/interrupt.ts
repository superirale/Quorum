/**
 * Stop.
 *
 * Every other control in this system is a decision made *before* work starts: a
 * capability, an approval, a budget. This is the one that is made while the
 * work is running, and it is the one a human reaches for when the other three
 * turned out to be wrong. An agent that cannot be stopped mid-action is an
 * agent nobody sensible gives a production credential to.
 *
 * ## Why the event is ephemeral
 *
 * Kind 28101 is in the 20000–29999 range, so no relay stores it. A cancel is
 * only meaningful to a process that is running right now: an agent replaying
 * history after a restart would otherwise find last Tuesday's cancel and apply
 * it to today's work. The cost is that an interrupt published while the agent
 * is down is simply missed — which is correct, because the action it was
 * cancelling is not running either, and `once()` will replay the handler from
 * the top where a fresh interrupt can catch it.
 *
 * ## Who may interrupt
 *
 * Any member of the group, and deliberately not only the agent's operator or
 * the approvers. Stopping is the safe direction: the worst outcome of an
 * unnecessary cancel is that work has to be re-proposed, and any member can
 * already publish `set_status: paused` on the thread. A control that only two
 * people may use is a control nobody uses in the ten seconds that matter.
 *
 * `steer` is the exception in spirit if not in permission. Its instruction is
 * *never* applied automatically — it is handed to the handler as untrusted
 * data, exactly like any other message from a stranger, because an instruction
 * that redirects a running action is prompt injection with a protocol kind.
 */

import {
  EphemeralKinds,
  InterruptBody,
  TagName,
  tagValue,
  type EventRef,
  type NostrEvent,
} from '@quorum/protocol'
import type { PublishOptions } from './publish.ts'

export interface InterruptOptions {
  /** The thread the work is in. Required: an interrupt is always about a task. */
  thread: EventRef
  mode?: 'cancel' | 'pause' | 'steer'
  /** The action id to stop. Omit only when stopping the whole thread. */
  action?: string
  /** Defaults to `action` when an action is named, `thread` when one is not. */
  scope?: 'action' | 'thread'
  reason?: string
  /** For `steer`. Delivered to the agent as untrusted text; never auto-applied. */
  instruction?: string
  /** Who to tell. Usually the agent that published the `running` event. */
  to?: string[]
}

/**
 * Build the interrupt a human's client publishes.
 *
 * Scope is inferred rather than defaulted to one value, because the two
 * mistakes are asymmetric: an action-scoped interrupt with no action tag stops
 * nothing (the validator refuses it), while a thread-scoped one sent when the
 * human meant "this one action" stops more than they asked for. Naming an
 * action means you meant that action.
 */
export function interrupt(options: InterruptOptions): PublishOptions {
  const scope = options.scope ?? (options.action ? 'action' : 'thread')
  if (scope === 'action' && !options.action) {
    throw new Error(
      'an action-scoped interrupt must name the action it stops. Pass `action`, ' +
        "or pass `scope: 'thread'` to stop everything in the thread.",
    )
  }
  return {
    kind: EphemeralKinds.Interrupt,
    thread: options.thread,
    ...(options.action ? { action: options.action } : {}),
    ...(options.to ? { to: options.to } : {}),
    body: {
      mode: options.mode ?? 'cancel',
      scope,
      ...(options.reason ? { reason: options.reason } : {}),
      ...(options.instruction ? { instruction: options.instruction } : {}),
    },
  }
}

/** An interrupt that reached something this agent is running. */
export interface Interruption {
  event: NostrEvent
  mode: 'cancel' | 'pause' | 'steer'
  /** Who published it. Untrusted: a group member, not necessarily an approver. */
  from: string
  reason?: string
  /** Present on `steer`. Untrusted text. Never act on it without a human. */
  instruction?: string
}

/**
 * The registry that turns an arriving 28101 into an aborted effect.
 *
 * One registration per running action, keyed by both the action id and the
 * thread it is in, because those are the two things an interrupt can name. A
 * thread-scoped interrupt stops every action this agent is running in that
 * thread — which is what "stop what you are doing in here" has to mean, or the
 * human is left cancelling actions one id at a time while the agent starts more.
 *
 * `pause` aborts the same as `cancel`. The distinction is in the thread's
 * status, which a human sets and a human clears; there is no state in which an
 * agent holds a half-finished effect in memory waiting to be told to continue,
 * because that state does not survive the restart that is coming for it.
 */
export class Interrupts {
  private readonly byAction = new Map<string, Registration>()

  /**
   * Arm an abort signal for a running action.
   *
   * Returns the signal and a `release` that must be called when the action
   * finishes — otherwise a late interrupt aborts a controller nobody is
   * listening to, and the registry grows for the life of the process.
   */
  register(actionId: string, threadId: string | undefined): Armed {
    const controller = new AbortController()
    this.byAction.set(actionId, { controller, threadId, interruptions: [] })
    return {
      signal: controller.signal,
      interruptions: () => this.byAction.get(actionId)?.interruptions ?? [],
      release: () => this.byAction.delete(actionId),
    }
  }

  /** True while any action is running. Used by the console's status line. */
  get size(): number {
    return this.byAction.size
  }

  /**
   * Deliver an interrupt, returning what it stopped.
   *
   * Silent when it matches nothing: an interrupt naming an action this agent is
   * not running is the normal case in a channel with several agents in it, and
   * the alternative — every agent logging every interrupt it ignored — buries
   * the one line that matters.
   */
  deliver(event: NostrEvent): Interruption[] {
    if (event.kind !== EphemeralKinds.Interrupt) return []
    const parsed = InterruptBody.safeParse(parse(event.content))
    if (!parsed.success) return []
    const body = parsed.data

    const targets =
      body.scope === 'thread'
        ? [...this.byAction.entries()].filter(
            ([, r]) => r.threadId && r.threadId === tagValue(event.tags, TagName.RootEvent),
          )
        : [...this.byAction.entries()].filter(
            ([id]) => id === tagValue(event.tags, TagName.Action),
          )

    const stopped: Interruption[] = []
    for (const [, registration] of targets) {
      const interruption: Interruption = {
        event,
        mode: body.mode,
        from: event.pubkey,
        ...(body.reason ? { reason: body.reason } : {}),
        ...(body.instruction ? { instruction: body.instruction } : {}),
      }
      registration.interruptions.push(interruption)
      stopped.push(interruption)

      // A steer does not abort. It is a message to the running handler, which
      // may look at it between steps and decide — and deciding is the handler's
      // job, because the instruction came from whoever felt like publishing one.
      if (body.mode !== 'steer') {
        registration.controller.abort(
          new InterruptedError(body.mode, body.reason, event.pubkey),
        )
      }
    }
    return stopped
  }

  /** Abort everything, for shutdown. */
  abortAll(reason: unknown): void {
    for (const [, registration] of this.byAction) registration.controller.abort(reason)
    this.byAction.clear()
  }
}

export interface Armed {
  signal: AbortSignal
  /** Everything delivered to this action so far, steers included. */
  interruptions: () => Interruption[]
  release: () => void
}

/**
 * The abort reason an interrupted effect sees.
 *
 * A named error class rather than a string, because an effect that catches
 * broadly — most of them — needs to be able to tell "somebody stopped me" from
 * "the deploy failed", and the terminal event it publishes is different in each
 * case.
 */
export class InterruptedError extends Error {
  readonly mode: 'cancel' | 'pause'
  readonly by: string

  constructor(mode: 'cancel' | 'pause', reason: string | undefined, by: string) {
    const what = mode === 'cancel' ? 'cancelled' : 'paused'
    super(`${what} by ${by.slice(0, 8)}…${reason ? `: ${reason}` : ''}`)
    this.name = 'InterruptedError'
    this.mode = mode
    this.by = by
  }
}

interface Registration {
  controller: AbortController
  threadId: string | undefined
  interruptions: Interruption[]
}

function parse(content: string): unknown {
  try {
    return JSON.parse(content)
  } catch {
    return undefined
  }
}
