/**
 * One relay connection, and everything it has served us, as React state.
 *
 * The shape is deliberately dumb: a flat list of every event in the group,
 * verified on arrival by the SDK client, with the interesting views derived
 * from it on each render. A workspace holds thousands of events, not millions,
 * and a derived view that cannot drift from its source is worth more here than
 * an index that can.
 *
 * Nothing in this file decides anything about approvals. `inbox()` in the SDK
 * does that, so this client and the console answer "is it waiting on me"
 * identically — a browser that quietly used a looser rule would be showing a
 * human requests nobody asked them to answer, which is how an approval queue
 * becomes something you clear without reading.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Kinds, type NostrEvent } from '@quorum/protocol'
import {
  Counters,
  Publisher,
  RelayClient,
  channelFilter,
  controlFilter,
  inbox,
  presence,
  summariseGrants,
  threads,
  verifyActionChains,
  type ActionChain,
  type GrantSummary,
  type Pending,
  type Presence,
  type PublishOptions,
  type Thread,
} from '@quorum/sdk'
import type { Identity } from './identity.ts'
import { LocalStore } from './store.ts'

export type Status = 'connecting' | 'live' | 'closed' | 'error'

export interface Workspace {
  status: Status
  problem?: string
  /** Every event served, in arrival order. `presence()` depends on that. */
  events: NostrEvent[]
  pending: Pending[]
  chains: ActionChain[]
  /** Threads as tasks: status, assignee, and the relay's projection checked. */
  threads: Thread[]
  /** Who is beating right now. Empty means "nobody has said", not "nobody is up". */
  agents: Presence[]
  /** Every current capability in the workspace. */
  grants: GrantSummary[]
  /** Everything, newest first, for the feed. */
  feed: NostrEvent[]
  publish(options: PublishOptions): Promise<NostrEvent>
  now: number
}

export function useWorkspace(identity: Identity, relay: string, group: string): Workspace {
  const [status, setStatus] = useState<Status>('connecting')
  const [problem, setProblem] = useState<string | undefined>()
  const [events, setEvents] = useState<NostrEvent[]>([])
  // Re-derives expiry once a second. An approval request whose deadline passes
  // while you are looking at it must stop offering you a button.
  const [now, setNow] = useState(() => Math.floor(Date.now() / 1000))
  const publisher = useRef<Publisher | undefined>(undefined)

  useEffect(() => {
    const id = setInterval(() => setNow(Math.floor(Date.now() / 1000)), 1000)
    return () => clearInterval(id)
  }, [])

  useEffect(() => {
    let live = true
    setStatus('connecting')
    setProblem(undefined)
    setEvents([])

    const client = new RelayClient({ url: relay, signer: identity.signer })

    const add = (event: NostrEvent) => {
      if (!live) return
      setEvents((current) => (current.some((e) => e.id === event.id) ? current : [...current, event]))
    }

    void (async () => {
      try {
        await client.connect()
        if (!live) return

        publisher.current = new Publisher({
          client,
          signer: identity.signer,
          pubkey: identity.pubkey,
          group,
          counters: await Counters.load(
            new LocalStore(`quorum.counters.${identity.pubkey.slice(0, 8)}.`),
            identity.pubkey,
          ),
        })

        client.subscribe([channelFilter({ group, limit: 500 }), controlFilter({ group })], {
          onEvent: add,
          // Mandatory to handle, and the reason is M2's trap: a relay that
          // refuses a filter and a relay with nothing to say look identical
          // unless you read CLOSED. An empty screen must be able to mean
          // "nothing here" and not "you are not subscribed to anything".
          onClosed: (reason) => {
            if (!live) return
            setStatus('error')
            setProblem(`the relay closed the subscription: ${reason}`)
          },
        })
        setStatus('live')
      } catch (error) {
        if (!live) return
        setStatus('error')
        setProblem((error as Error).message)
      }
    })()

    return () => {
      live = false
      publisher.current = undefined
      client.close()
    }
  }, [identity.signer, identity.pubkey, relay, group])

  const publish = useCallback(async (options: PublishOptions) => {
    if (!publisher.current) throw new Error('not connected to the relay yet')
    return publisher.current.publish(options)
  }, [])

  const pending = useMemo(
    () => inbox(events, { me: identity.pubkey, now }),
    [events, identity.pubkey, now],
  )

  // Verified here rather than trusted: the relay handed us these bytes and is
  // the one party with both motive and position to substitute an approval.
  const chains = useMemo(() => verifyActionChains(events), [events])

  // NIP-01's order, reversed: newest first, ties broken on the lowest id so
  // that every reader agrees. Ties are common — the whole propose/ask/approve
  // /run loop completes inside one second, and `created_at` has one-second
  // resolution.
  const feed = useMemo(
    () => [...events].sort((a, b) => b.created_at - a.created_at || (a.id < b.id ? -1 : 1)),
    [events],
  )

  // The relay signs a 38101 for every thread, and `threads()` replays the ops
  // it says it folded rather than believing the result. See `threads.ts`: this
  // is the first consumer `folded_from` has ever had.
  const tasks = useMemo(() => threads(events), [events])

  // `events` and not `feed`, deliberately. Two heartbeats can share a second —
  // an agent that finishes a job quickly publishes `busy` and `online` in one —
  // and only arrival order tells them apart.
  const agents = useMemo(() => presence(events, now), [events, now])

  const grants = useMemo(() => summariseGrants(events, now), [events, now])

  return { status, problem, events, pending, chains, threads: tasks, agents, grants, feed, publish, now }
}
