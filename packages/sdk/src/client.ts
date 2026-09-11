/**
 * The relay connection: one websocket, NIP-01 message handling, NIP-42 AUTH,
 * and reconnection.
 *
 * Two decisions here are worth stating up front, because both are places where
 * the obvious implementation is quietly wrong.
 *
 * **A rejected subscription is not an empty result.** go-nostr's `QuerySync`
 * returns success whether a subscription ended in EOSE or in CLOSED, which is
 * how M2's `#p`-without-`#h` rule went unnoticed for an afternoon: the relay was
 * refusing the filter and the client reported "no matching events". `query()`
 * here *rejects* on CLOSED and `subscribe()` has a mandatory-to-handle
 * `onClosed`. An agent that sees nothing must be able to tell "nobody has asked
 * me to do anything" from "I am not subscribed to anything".
 *
 * **Every incoming event is verified.** The relay is not trusted. It is the one
 * party with both the motive and the position to substitute an event — an
 * approval, say — and checking a signature costs a fraction of a millisecond.
 */

import {
  matchFilters,
  verifyEvent,
  type Filter,
  type NostrEvent,
  type UnsignedEvent,
} from '@quorum/protocol'
import type { Signer } from './signer.ts'

export interface Logger {
  debug?(message: string, ...rest: unknown[]): void
  warn(message: string, ...rest: unknown[]): void
  error(message: string, ...rest: unknown[]): void
}

export interface RelayClientOptions {
  url: string
  /** Needed for NIP-42. Without one the client cannot answer an auth challenge. */
  signer?: Signer
  /** Answer AUTH challenges as soon as they arrive, rather than on demand. */
  eagerAuth?: boolean
  publishTimeoutMs?: number
  queryTimeoutMs?: number
  /** `false` disables reconnection, which is only ever what a test wants. */
  reconnect?: false | { minDelayMs?: number; maxDelayMs?: number }
  log?: Logger
}

/** A publish the relay refused, carrying the relay's own words. */
export class PublishError extends Error {
  readonly eventId: string
  readonly reason: string

  constructor(eventId: string, reason: string) {
    super(`relay rejected ${eventId.slice(0, 8)}: ${reason}`)
    this.name = 'PublishError'
    this.eventId = eventId
    this.reason = reason
  }

  /** NIP-01 machine-readable prefixes: `invalid:`, `restricted:`, `duplicate:`… */
  get prefix(): string {
    return this.reason.split(':', 1)[0] ?? ''
  }
}

/** A subscription the relay closed, or refused to open. */
export class SubscriptionClosed extends Error {
  readonly reason: string

  constructor(reason: string) {
    super(`relay closed the subscription: ${reason}`)
    this.name = 'SubscriptionClosed'
    this.reason = reason
  }
}

export interface SubscribeHandlers {
  onEvent(event: NostrEvent): void
  /** Stored events are done; everything after this is live. Fires again after a reconnect. */
  onEose?(): void
  /** The relay refused the filter or terminated the subscription. Never silent. */
  onClosed?(reason: string): void
}

export interface Subscription {
  readonly id: string
  close(): void
}

/** Filters, or a function evaluated afresh on every (re)subscribe. */
export type FilterSource = Filter[] | (() => Filter[])

interface LiveSub {
  id: string
  filters: FilterSource
  handlers: SubscribeHandlers
  /** Which socket this REQ was last sent on. See `generation`. */
  sentOn: number
}

type ConnectionListener = (event: { url: string; error?: Error }) => void

const AUTH_KIND = 22242

export class RelayClient {
  readonly url: string

  private readonly options: RelayClientOptions
  private readonly log: Logger
  private readonly subs = new Map<string, LiveSub>()
  private readonly pendingOk = new Map<string, { ok: () => void; fail: (e: Error) => void; timer: ReturnType<typeof setTimeout> }>()
  private readonly onConnect = new Set<ConnectionListener>()
  private readonly onDisconnect = new Set<ConnectionListener>()

  private socket: WebSocket | undefined
  private opening: Promise<void> | undefined
  private challenge: string | undefined
  private authedAs: string | undefined
  private authing: Promise<void> | undefined
  private closed = false
  private attempt = 0
  private nextSubId = 0
  private retryTimer: ReturnType<typeof setTimeout> | undefined
  /**
   * Bumped on every successful open. A REQ belongs to one socket, so this is
   * how a subscription knows whether it has already been sent on *this* one —
   * without it, a subscription opened while the socket was connecting gets its
   * REQ sent twice and the agent sees every stored event in duplicate.
   */
  private generation = 0

  constructor(options: RelayClientOptions) {
    this.options = options
    this.url = options.url
    this.log = options.log ?? console
  }

  get connected(): boolean {
    return this.socket?.readyState === 1
  }

  /** The pubkey this connection has authenticated as, if any. */
  get authenticatedAs(): string | undefined {
    return this.authedAs
  }

  onConnected(listener: ConnectionListener): () => void {
    this.onConnect.add(listener)
    return () => this.onConnect.delete(listener)
  }

  onDisconnected(listener: ConnectionListener): () => void {
    this.onDisconnect.add(listener)
    return () => this.onDisconnect.delete(listener)
  }

  // --- lifecycle ------------------------------------------------------------

  async connect(): Promise<void> {
    this.closed = false
    if (this.connected) return
    this.opening ??= this.open().finally(() => {
      this.opening = undefined
    })
    return this.opening
  }

  private open(): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const socket = new WebSocket(this.url)
      this.socket = socket
      this.challenge = undefined
      this.authedAs = undefined

      const onOpen = () => {
        this.attempt = 0
        this.generation++
        this.log.debug?.(`[relay] connected to ${this.url}`)
        for (const listener of this.onConnect) listener({ url: this.url })
        // Re-send every live REQ. The filters are re-evaluated rather than
        // replayed verbatim, so a subscription driven by a cursor picks up
        // where the cursor now is instead of refetching from the beginning.
        for (const sub of this.subs.values()) this.sendReq(sub)
        resolve()
      }

      const onClose = () => {
        socket.removeEventListener('open', onOpen)
        if (this.socket !== socket) return
        this.socket = undefined
        this.authedAs = undefined
        for (const listener of this.onDisconnect) listener({ url: this.url })
        reject(new Error(`websocket to ${this.url} closed before it opened`))
        this.scheduleReconnect()
      }

      socket.addEventListener('open', onOpen, { once: true })
      socket.addEventListener('close', onClose, { once: true })
      socket.addEventListener('error', () => {
        // The `close` event follows, and carries the reconnect logic. Browsers
        // deliberately give no detail here, so there is nothing to report.
      })
      socket.addEventListener('message', (event) => this.receive(String(event.data)))
    })
  }

  private scheduleReconnect(): void {
    if (this.closed || this.options.reconnect === false) return
    const { minDelayMs = 100, maxDelayMs = 10_000 } = this.options.reconnect ?? {}
    const backoff = Math.min(maxDelayMs, minDelayMs * 2 ** this.attempt++)
    // Jitter, so a relay restarting does not get every agent back at once.
    const delay = backoff / 2 + Math.random() * (backoff / 2)
    this.retryTimer = setTimeout(() => {
      void this.connect().catch(() => {
        /* scheduleReconnect already queued the next attempt */
      })
    }, delay)
    this.retryTimer.unref?.()
  }

  close(): void {
    this.closed = true
    if (this.retryTimer) clearTimeout(this.retryTimer)
    for (const pending of this.pendingOk.values()) {
      clearTimeout(pending.timer)
      pending.fail(new Error('client closed'))
    }
    this.pendingOk.clear()
    this.subs.clear()
    this.socket?.close()
    this.socket = undefined
  }

  private send(message: unknown[]): void {
    if (!this.connected) throw new Error(`not connected to ${this.url}`)
    this.socket!.send(JSON.stringify(message))
  }

  // --- incoming -------------------------------------------------------------

  private receive(raw: string): void {
    let message: unknown
    try {
      message = JSON.parse(raw)
    } catch {
      this.log.warn(`[relay] ${this.url} sent something that is not JSON`)
      return
    }
    if (!Array.isArray(message)) return

    const [type] = message as [string, ...unknown[]]
    switch (type) {
      case 'EVENT': {
        const [, subId, event] = message as [string, string, NostrEvent]
        this.onIncomingEvent(subId, event)
        return
      }
      case 'OK': {
        const [, id, accepted, reason] = message as [string, string, boolean, string]
        const pending = this.pendingOk.get(id)
        if (!pending) return
        clearTimeout(pending.timer)
        this.pendingOk.delete(id)
        if (accepted) pending.ok()
        else pending.fail(new PublishError(id, reason ?? ''))
        return
      }
      case 'EOSE': {
        const [, subId] = message as [string, string]
        this.subs.get(subId)?.handlers.onEose?.()
        return
      }
      case 'CLOSED': {
        const [, subId, reason] = message as [string, string, string]
        this.onClosed(subId, reason ?? '')
        return
      }
      case 'AUTH': {
        const [, challenge] = message as [string, string]
        this.challenge = challenge
        if (this.options.eagerAuth && this.options.signer) void this.authenticate().catch(() => {})
        return
      }
      case 'NOTICE': {
        const [, text] = message as [string, string]
        this.log.warn(`[relay] notice from ${this.url}: ${text}`)
        return
      }
    }
  }

  private onIncomingEvent(subId: string, event: NostrEvent): void {
    const sub = this.subs.get(subId)
    if (!sub) return

    if (!event || typeof event !== 'object' || !verifyEvent(event)) {
      this.log.warn(`[relay] ${this.url} served an event with a bad id or signature; dropped`)
      return
    }
    // A relay can send anything it likes down an open subscription. Matching
    // locally means a relay cannot widen what an agent reacts to, only narrow
    // it — and narrowing is already detectable through the counter tags.
    if (!matchFilters(resolveFilters(sub.filters), event)) {
      this.log.warn(`[relay] ${this.url} served event ${event.id.slice(0, 8)} matching no filter; dropped`)
      return
    }
    sub.handlers.onEvent(event)
  }

  private onClosed(subId: string, reason: string): void {
    const sub = this.subs.get(subId)
    if (!sub) return

    // "auth-required" is a request, not a refusal. Answer it and ask again.
    if (reason.startsWith('auth-required:') && this.options.signer) {
      void this.authenticate()
        .then(() => this.sendReq(sub))
        .catch((error: unknown) => {
          sub.handlers.onClosed?.(`${reason} (authentication failed: ${String(error)})`)
        })
      return
    }

    this.subs.delete(subId)
    sub.handlers.onClosed?.(reason)
  }

  // --- NIP-42 ---------------------------------------------------------------

  /**
   * Prove control of the key to the relay.
   *
   * The challenge is per-connection, so this has to happen again after every
   * reconnect — which is why nothing caches the result across sockets.
   */
  async authenticate(): Promise<void> {
    const signer = this.options.signer
    if (!signer) throw new Error('cannot authenticate: no signer')
    if (!this.challenge) throw new Error(`${this.url} has not sent an AUTH challenge`)
    if (this.authedAs) return
    this.authing ??= this.doAuth(signer, this.challenge).finally(() => {
      this.authing = undefined
    })
    return this.authing
  }

  private async doAuth(signer: Signer, challenge: string): Promise<void> {
    const unsigned: UnsignedEvent = {
      pubkey: await signer.pubkey(),
      created_at: Math.floor(Date.now() / 1000),
      kind: AUTH_KIND,
      tags: [
        ['relay', this.url],
        ['challenge', challenge],
      ],
      content: '',
    }
    const event = await signer.sign(unsigned)
    const accepted = this.awaitOk(event.id, this.options.publishTimeoutMs ?? 10_000)
    this.send(['AUTH', event])
    await accepted
    this.authedAs = event.pubkey
  }

  // --- outgoing -------------------------------------------------------------

  /**
   * Publish, and wait for the relay to say what it did with the event.
   *
   * Resolving on OK rather than on "the bytes left the socket" is what makes a
   * rejected event an error the agent can act on. Publishing blind is how you
   * get an agent that thinks it answered.
   */
  async publish(event: NostrEvent): Promise<void> {
    await this.connect()
    try {
      await this.sendEvent(event)
    } catch (error) {
      if (error instanceof PublishError && error.prefix === 'auth-required' && this.options.signer) {
        await this.authenticate()
        await this.sendEvent(event)
        return
      }
      throw error
    }
  }

  private async sendEvent(event: NostrEvent): Promise<void> {
    const accepted = this.awaitOk(event.id, this.options.publishTimeoutMs ?? 10_000)
    this.send(['EVENT', event])
    return accepted
  }

  private awaitOk(id: string, timeoutMs: number): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingOk.delete(id)
        reject(new Error(`no OK for ${id.slice(0, 8)} from ${this.url} within ${timeoutMs}ms`))
      }, timeoutMs)
      timer.unref?.()
      this.pendingOk.set(id, { ok: resolve, fail: reject, timer })
    })
  }

  /**
   * Open a long-lived subscription. Survives reconnection: the REQ is re-sent
   * on every new socket, with the filters re-evaluated if they are a function.
   */
  subscribe(filters: FilterSource, handlers: SubscribeHandlers): Subscription {
    const id = `q${this.nextSubId++}`
    const sub: LiveSub = { id, filters, handlers, sentOn: -1 }
    this.subs.set(id, sub)

    void this.connect().then(
      () => {
        // If the socket was already up, `connect()` resolved without sending
        // anything; if it opened just now, `onOpen` already sent this REQ along
        // with the rest. The generation check distinguishes the two.
        if (this.connected && this.subs.has(id) && sub.sentOn !== this.generation) this.sendReq(sub)
      },
      (error: unknown) => handlers.onClosed?.(`could not connect: ${String(error)}`),
    )

    return {
      id,
      close: () => {
        if (!this.subs.delete(id)) return
        if (this.connected) this.send(['CLOSE', id])
      },
    }
  }

  private sendReq(sub: LiveSub): void {
    if (!this.connected) return
    sub.sentOn = this.generation
    this.send(['REQ', sub.id, ...resolveFilters(sub.filters)])
  }

  /**
   * Fetch stored events and stop at EOSE.
   *
   * Rejects with {@link SubscriptionClosed} if the relay refuses the filter,
   * which is the whole reason this is not three lines inline somewhere.
   */
  async query(filters: FilterSource, options: { timeoutMs?: number } = {}): Promise<NostrEvent[]> {
    const timeoutMs = options.timeoutMs ?? this.options.queryTimeoutMs ?? 10_000
    const events: NostrEvent[] = []

    return new Promise<NostrEvent[]>((resolve, reject) => {
      let settled = false
      const finish = (fn: () => void) => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        sub.close()
        fn()
      }
      const timer = setTimeout(
        () => finish(() => reject(new Error(`query on ${this.url} timed out after ${timeoutMs}ms`))),
        timeoutMs,
      )
      timer.unref?.()

      const sub = this.subscribe(filters, {
        onEvent: (event) => events.push(event),
        onEose: () => finish(() => resolve(events)),
        onClosed: (reason) => finish(() => reject(new SubscriptionClosed(reason))),
      })
    })
  }
}

function resolveFilters(source: FilterSource): Filter[] {
  return typeof source === 'function' ? source() : source
}
