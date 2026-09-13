/**
 * @quorum/sdk — write an agent.
 *
 * ```ts
 * const agent = createAgent({
 *   relay: 'ws://localhost:3334',
 *   signer: LocalSigner.fromEnv('AGENT_SECRET_KEY'),
 *   group: 'payments',
 *   store: FileStore.in('./state'),
 * })
 *
 * agent.on(async (event, ctx) => {
 *   const lease = await ctx.lease('echo')
 *   if (!lease.held) return                 // a sibling replica has this thread
 *   await ctx.say(`you said: ${event.content}`)
 * })
 *
 * await agent.start()
 * ```
 *
 * Three things are worth knowing before writing the handler:
 *
 * - `on()` fires only for events addressed to this agent, with a `to`-marked
 *   `p` tag. That is the only addressing signal there is; nothing reads prose.
 * - The handler is **replayed** after a restart, not resumed. Every side effect
 *   must go through `ctx.once()` or `ctx.publish()`.
 * - Nothing here runs a language model. An agent is a process holding a key.
 */

export * from './addressing.ts'
export * from './agent.ts'
export * from './approval.ts'
export * from './audit.ts'
export * from './client.ts'
export * from './context.ts'
export * from './counter.ts'
export * from './delegation.ts'
export * from './edits.ts'
export * from './grants.ts'
export * from './inbox.ts'
export * from './lease.ts'
export * from './memory.ts'
export * from './once.ts'
export * from './presence.ts'
export * from './publish.ts'
export * from './replay.ts'
export * from './signer.ts'
export * from './store.ts'
export * from './threads.ts'
