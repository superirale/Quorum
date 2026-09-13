/**
 * An agent that reads a thread and answers a question about it.
 *
 * The handler is a dozen lines and three of them are the example:
 *
 *   const pack = await ctx.context({ budget_tokens })   // the whole of M6
 *   const history = renderContext(pack)                 // fences what is not ours
 *   const answer = await ctx.once('ask-the-model', …)   // a call with a bill on it
 *
 * `ctx.context()` packs locally by default and asks a relay-hosted DVM when
 * given a `packer` pubkey. Those two paths run different code in different
 * languages and must return the same bytes; `live.ts` checks that they do. The
 * agent cannot tell which one answered, and that is the property — an operator
 * turning on encryption at M9 moves the packer into this process and changes
 * nothing an agent can observe.
 *
 * `once()` around the model call is not ceremony. Handlers are *replayed* after
 * a restart rather than resumed, so an unguarded `messages.create` is a second
 * invoice for an answer the agent already has, and — worse for the log — a
 * second, differently-worded reply to a question a colleague asked once.
 */

import { Kinds, type ContextPackResultBody, type NostrEvent } from '@quorum/protocol'
import {
  createAgent,
  renderContext,
  type Agent,
  type Logger,
  type RelayClient,
  type Signer,
  type Store,
} from '@quorum/sdk'
import { MODEL, type Answer, type Model } from './model.ts'

/**
 * What a run produced, for a caller that wants to show its work.
 *
 * The demo prints these; the long-running agent ignores them. Handing back the
 * prompt is the only way to assert on the thing that actually matters here —
 * a pack is a data structure, and what reaches the model is a string.
 */
export interface Turn {
  question: string
  pack: ContextPackResultBody
  history: string
  answer: Answer
  /** A real tokenizer's count of the prompt, when the model can provide one. */
  countedTokens: number | undefined
}

export interface ClaudeAgentOptions {
  relay: string | RelayClient
  signer: Signer
  group: string
  model: Model
  /**
   * Pubkey of a context DVM to ask, or unset to pack from a local backfill.
   *
   * On this relay it is the relay's own key, which NIP-11 publishes. On an
   * encrypted channel there is no such thing and the local path is the only
   * one — which is why it is the default rather than the fallback.
   */
  packer?: string | undefined
  /** Advisory. The mandatory-keep set can exceed it; read `used_tokens`. */
  budgetTokens?: number
  store?: Store
  log?: Logger
  onTurn?: (turn: Turn) => void
}

export const DEFAULT_BUDGET = 20_000

export function createClaudeAgent(options: ClaudeAgentOptions): Agent {
  const budget = options.budgetTokens ?? DEFAULT_BUDGET
  const agent = createAgent({
    relay: options.relay,
    signer: options.signer,
    group: options.group,
    leases: false,
    ...(options.store ? { store: options.store } : {}),
    ...(options.log ? { log: options.log } : {}),
  })

  agent.on(async (event, ctx) => {
    if (!ctx.threadId) {
      await ctx.say(
        'Ask me inside a thread. Context is packed per thread, and a channel is not one.',
      )
      return
    }

    const pack = await ctx.context({
      budget_tokens: budget,
      ...(options.packer ? { packer: options.packer } : {}),
    })
    const history = renderContext(pack)
    const question = event.content

    const answer = await ctx.once('ask-the-model', () => options.model.ask(history, question))

    // Published, addressable, and readable by every member — which is the whole
    // argument for kind 38104 over a local file. "Why did it answer that?" is
    // answerable by anyone in the workspace, with a query rather than with
    // shell access to the agent's host.
    //
    // No `once()` around it: the key is `(pubkey, 38104, d)`, so a replay
    // overwrites the entry it wrote last time instead of adding a second one.
    // The value is deliberately clock-free for the same reason — a timestamp
    // would make every replay a distinct event for an identical fact.
    await ctx.memory.set(`thread/${ctx.threadId}`, {
      question,
      segments: pack.segments.length,
      used_tokens: pack.used_tokens,
      dropped_events: pack.dropped_events,
      algorithm: pack.algorithm,
    })

    if (options.onTurn) {
      options.onTurn({
        question,
        pack,
        history,
        answer,
        countedTokens: await options.model.count(history, question).catch(() => undefined),
      })
    }

    await ctx.say(answer.text, { label: `answer:${event.id.slice(0, 16)}` })
  })

  return agent
}

export interface ManifestOptions {
  name: string
  description: string
  /** The human accountable for this agent. Also what makes their messages `operator`. */
  operator?: string | undefined
  model?: string
}

/**
 * Publish the agent's kind 38103. Call it once, after `start()`.
 *
 * Skip it and the packer has no way to know this pubkey is an agent: a manifest
 * is the only evidence in the event set, provenance is derived from the event
 * set and nothing else, and so *every* agent in the thread — this one included
 * — comes back labelled `human` and `member`. `renderContext` then fences
 * nothing, and another agent's output reaches the model as if a colleague had
 * typed it. One event, published once, and forgetting it removes the trust
 * boundary without breaking anything visible. Act 2 of the demo does exactly
 * that, on purpose.
 *
 * Through `agent.publish` rather than a `Publisher` of our own, because two
 * publishers over one key allocate `counter` from two copies of the same
 * ledger. See the note on {@link Agent.publish}.
 */
export function announce(agent: Agent, options: ManifestOptions): Promise<NostrEvent> {
  return agent.publish({
    kind: Kinds.AgentManifest,
    d: options.name,
    body: {
      name: options.name,
      description: options.description,
      model: options.model ?? MODEL,
      ...(options.operator ? { operator: options.operator } : {}),
    },
  })
}
