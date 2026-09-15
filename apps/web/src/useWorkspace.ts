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
import { EncMode, Kinds, isMlsSealed, type NostrEvent } from '@quorum/protocol'
import {
  ChannelCrypto,
  Counters,
  PLAINTEXT_POLICY,
  Publisher,
  RelayClient,
  channelFilter,
  channelPolicy,
  controlFilter,
  inbox,
  isKeyManagement,
  keyFilters,
  presence,
  summariseGrants,
  threads,
  verifyActionChains,
  type ActionChain,
  type ChannelPolicy,
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
  /**
   * Every event served, in arrival order, **opened where this key can open it**.
   * `presence()` depends on the order.
   *
   * On an encrypted channel these are the plaintext copies, whose ids commit to
   * the ciphertext — so `verifyEvent` on one is false and none of them may be
   * republished. Anything that checks a signature reads {@link raw} instead,
   * which is why both are here and named for what they are rather than for a
   * flag.
   */
  events: NostrEvent[]
  /** The bytes the relay served, sealed. What a signature is over. */
  raw: NostrEvent[]
  /**
   * The channel's encryption state. `undefined` until the relay answers — and
   * on an `mls` channel, for as long as the tab is open. See {@link MLS_NO_KEY}.
   */
  channel?: ChannelCrypto
  policy: ChannelPolicy
  /** True for an event sealed under an epoch this key does not hold. */
  sealed(event: NostrEvent): boolean
  /** How many served events this key cannot read. Shown, never hidden. */
  unreadable: number
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

/**
 * Why this client will not publish into an `mls` channel.
 *
 * Exported so the composer's refusal and the hook's are the same sentence, for
 * the reason the console's `noKey` exists: two copies of "why can't I" drift,
 * and the one that drifts is the one nobody reads until it is wrong.
 */
export const MLS_NO_KEY =
  'this channel is sealed with MLS and this client holds no ratchet for it, so there is nothing ' +
  'here to seal a message with'

export function useWorkspace(identity: Identity, relay: string, group: string): Workspace {
  const [status, setStatus] = useState<Status>('connecting')
  const [problem, setProblem] = useState<string | undefined>()
  const [raw, setEvents] = useState<NostrEvent[]>([])
  const [channel, setChannel] = useState<ChannelCrypto | undefined>()
  // Its own state rather than `channel.policy`, because on `mls` there is no
  // `channel` and the policy is the only thing this client has.
  const [policy, setPolicy] = useState<ChannelPolicy>(PLAINTEXT_POLICY)
  // Bumped whenever a key or a policy arrives. `ChannelCrypto` is mutable and
  // React cannot see into it, so without this a rotation would land, the events
  // would stay on screen as unreadable, and nothing would re-render to show
  // that the key had turned up.
  const [rekeys, setRekeys] = useState(0)
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
    setChannel(undefined)
    setPolicy(PLAINTEXT_POLICY)

    const client = new RelayClient({ url: relay, signer: identity.signer })
    // Built only once the policy has been read, and never on `mls`.
    //
    // A `ChannelCrypto` over an mls channel is not merely idle — it is wrong in
    // the expensive direction. `encrypted` is false there, so `buildOptions`
    // returns nothing and the composer publishes in the clear into a channel
    // whose policy says otherwise; and `unreadable()` answers true for every
    // message, which this app renders as "ask an admin to wrap the current
    // epoch". That is the nip44 cure, and on mls there is no admin who can
    // perform it: the keys are deleted by design.
    let crypto: ChannelCrypto | undefined

    // Re-read after any key management, on either path. On `nip44` this is a
    // wrap arriving or a rotation; on `mls` the only thing that can change is
    // the policy itself, and a client that missed the channel leaving mls would
    // go on refusing a channel that reopened.
    const reload = async () => {
      if (crypto) {
        await crypto.load()
        if (!live) return
        setPolicy(crypto.policy)
        setRekeys((n) => n + 1)
        return
      }
      const next = await channelPolicy(client, group)
      if (!live) return
      setPolicy(next)
      if (next.enc !== EncMode.Mls) {
        setProblem(`#${group} is no longer an mls channel — reload to pick up its keys`)
      }
    }

    const add = (event: NostrEvent) => {
      if (!live) return
      // A key wrap or a new policy is not content and never reaches the views;
      // it changes what the views can read. Reloading before the event is added
      // means one render, with the new key already in hand.
      if (isKeyManagement(event.kind)) {
        // Caught, and the reason is teardown rather than tidiness: closing the
        // client rejects every query in flight with "client closed", and a tab
        // being closed while a wrap arrives must not surface as an unhandled
        // rejection. If we are still live the re-read genuinely failed, and
        // this client is now reading the channel through a stale key set —
        // which is worth saying rather than swallowing.
        void reload().catch((error: Error) => {
          if (live) setProblem(`could not re-read the channel's keys: ${error.message}`)
        })
        return
      }
      setEvents((current) => (current.some((e) => e.id === event.id) ? current : [...current, event]))
    }

    void (async () => {
      try {
        await client.connect()
        if (!live) return

        // The policy first, because it decides whether there is anything to
        // build. Reading it costs one query that `ChannelCrypto.load()` would
        // have made anyway.
        const current = await channelPolicy(client, group)
        if (!live) return
        setPolicy(current)

        // Before the publisher, deliberately. A `Publisher` built without the
        // channel writes plaintext into an encrypted channel and nothing
        // complains: the relay stores it, every reader renders it, and the
        // channel is quietly less private than its own policy says.
        //
        // On `mls` there is no publisher at all, for the same reason stated the
        // other way round: there is nothing this client could seal *with*, so
        // the only event it could produce is the one the policy forbids.
        if (current.enc !== EncMode.Mls) {
          crypto = new ChannelCrypto({
            client,
            signer: identity.signer,
            pubkey: identity.pubkey,
            group,
          })
          await crypto.load()
          if (!live) return
          setChannel(crypto)
          setPolicy(crypto.policy)
          setRekeys((n) => n + 1)

          publisher.current = new Publisher({
            client,
            signer: identity.signer,
            pubkey: identity.pubkey,
            group,
            channel: crypto,
            counters: await Counters.load(
              new LocalStore(`quorum.counters.${identity.pubkey.slice(0, 8)}.`),
              identity.pubkey,
            ),
          })
        }

        client.subscribe(
          [
            channelFilter({ group, limit: 500 }),
            controlFilter({ group }),
            ...keyFilters({ group, pubkey: identity.pubkey }),
          ],
          {
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
          },
        )
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

  // The mls check is here as well as in the composer, and not only for tidiness:
  // a channel can turn mls while a form is already on the screen, and the send
  // button that was legitimate when it rendered must not publish in the clear.
  const publish = useCallback(
    async (options: PublishOptions) => {
      if (policy.enc === EncMode.Mls) throw new Error(MLS_NO_KEY)
      if (!publisher.current) throw new Error('not connected to the relay yet')
      return publisher.current.publish(options)
    },
    [policy.enc],
  )

  // Opened once, here, and read by everything below.
  //
  // An event with no key is *kept*, still sealed, rather than dropped. Every
  // derived view parses bodies through a schema and skips what will not parse,
  // so a sealed event is absent from the queue and the task list either way —
  // but the feed can still show a line saying there is traffic here this key
  // cannot read, which is the one thing a dropped event could never say.
  //
  // `rekeys` is in the dependency list because `channel` mutates in place: the
  // object identity does not change when a key wrap arrives.
  const events = useMemo(
    () => (channel ? raw.map((e) => (channel.unreadable(e) ? e : channel.opened(e))) : raw),
    [raw, channel, rekeys],
  )

  const pending = useMemo(
    () => inbox(events, { me: identity.pubkey, now }),
    [events, identity.pubkey, now],
  )

  // Verified here rather than trusted: the relay handed us these bytes and is
  // the one party with both motive and position to substitute an approval.
  //
  // The *sealed* events go in, with an opener alongside. A signature is over
  // the bytes as published, which on an encrypted channel are the ciphertext,
  // so verifying an opened copy would reject every honest chain in the
  // workspace and call the relay a forger for doing its job.
  const chains = useMemo(
    () => verifyActionChains(raw, channel ? { open: channel.opener() } : {}),
    [raw, channel, rekeys],
  )

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

  // "There is traffic here I cannot read" is a different fact from "the channel
  // is quiet", and on an encrypted channel it is the one that matters: it is
  // what being locked out of an epoch looks like from the inside.
  //
  // With no `channel` the test is the event's own `enc` tag, which is the only
  // thing left to ask. It is also the honest answer: an mls event is unreadable
  // here whatever the policy currently says, because this client never held a
  // ratchet for any epoch of it.
  const sealed = useCallback(
    (event: NostrEvent) => channel?.unreadable(event) ?? isMlsSealed(event),
    [channel, rekeys],
  )
  const unreadable = useMemo(() => raw.filter(sealed).length, [raw, sealed])

  return {
    status,
    problem,
    events,
    raw,
    channel,
    policy,
    sealed,
    unreadable,
    pending,
    chains,
    threads: tasks,
    agents,
    grants,
    feed,
    publish,
    now,
  }
}
