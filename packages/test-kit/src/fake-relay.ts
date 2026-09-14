/**
 * An in-process Nostr relay, for testing agents without infrastructure.
 *
 * It is deliberately *not* a second reference relay. It implements NIP-01
 * message handling, NIP-42 AUTH and the storage rules for the four kind ranges,
 * and nothing else — no NIP-29 membership, no Quorum validation. `apps/relay`
 * is the thing that enforces policy, and duplicating that here would mean two
 * definitions of "accepted" that drift apart, with the tests trusting the wrong
 * one.
 *
 * What it adds instead is the ability to misbehave on demand. Every failure an
 * agent has to survive — a socket dying mid-stream, a publish refused, a filter
 * rejected, an event withheld — is a method call here, and the SDK's
 * restart/replay/lease guarantees are only claims until something can produce
 * those conditions on purpose.
 */

import { schnorr } from '@noble/curves/secp256k1.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import { randomBytes } from 'node:crypto'
import type { AddressInfo } from 'node:net'
import {
  Kinds,
  MERKLE_ALGORITHM,
  computeId,
  isAddressable,
  isEphemeral,
  isReplaceable,
  matchFilters,
  merkleRoot,
  tagValue,
  verifyEvent,
  type Filter,
  type NostrEvent,
  type UnsignedEvent,
} from '@quorum/protocol'
import { WebSocketServer, type WebSocket } from 'ws'

export interface FakeRelayOptions {
  /** Demand NIP-42 before accepting writes or serving reads. */
  requireAuth?: boolean
  /**
   * Reproduce relay29's `RequireKindAndSingleGroupIDOrSpecificEventReference`:
   * a filter must name an `h`, an `e`, an `a`, or explicit ids.
   *
   * On by default, because the M2 relay behaves this way and an SDK tested
   * against a permissive relay would ship a subscription the real one silently
   * closes. See `apps/relay/README.md`.
   */
  requireScopedFilters?: boolean
  /** Reject any event for which this returns a string; the string is the reason. */
  reject?: (event: NostrEvent) => string | undefined
  /**
   * The relay's own key, for signing checkpoints. Generated if absent.
   *
   * A relay needs an identity here for the same reason the real one does: a
   * kind 8108 is only worth anything because it is *signed*, and a test that
   * checked an unsigned commitment would be checking a suggestion.
   */
  secretKey?: string
}

interface Client {
  socket: WebSocket
  challenge: string
  authed: string | undefined
  subs: Map<string, Filter[]>
}

/** What a connected client asked for, so tests can assert on subscriptions. */
export interface SeenRequest {
  subId: string
  filters: Filter[]
}

export class FakeRelay {
  readonly url: string
  /** The relay's own pubkey — the author of the checkpoints it signs. */
  readonly pubkey: string
  readonly requests: SeenRequest[] = []
  /**
   * Every event the relay accepted, in arrival order — ephemeral ones included,
   * and duplicates too.
   *
   * A duplicate arrival is not a bug on either side: an agent replaying an
   * interrupted handler is *supposed* to rebuild a byte-identical event and send
   * it again, and the relay is supposed to recognise it. This log is the only
   * place that distinction is visible, so it deliberately does not collapse.
   * For "what a reader would see", use {@link stored}.
   */
  readonly received: NostrEvent[] = []

  private readonly server: WebSocketServer
  private readonly clients = new Set<Client>()
  private readonly options: FakeRelayOptions
  private storage: NostrEvent[] = []
  private withheld = new Set<string>()
  private swallow: ((event: NostrEvent) => boolean) | undefined
  private readonly secretKey: string
  /** The newest checkpoint per group, so `prev` chains without bookkeeping. */
  private readonly lastCheckpoint = new Map<string, NostrEvent>()

  private constructor(server: WebSocketServer, url: string, options: FakeRelayOptions) {
    this.server = server
    this.url = url
    this.options = options
    this.secretKey = options.secretKey ?? randomBytes(32).toString('hex')
    this.pubkey = bytesToHex(schnorr.getPublicKey(this.secretKey))
    server.on('connection', (socket) => this.accept(socket))
  }

  static async start(options: FakeRelayOptions = {}): Promise<FakeRelay> {
    const server = new WebSocketServer({ port: 0, host: '127.0.0.1' })
    await new Promise<void>((resolve, reject) => {
      server.once('listening', resolve)
      server.once('error', reject)
    })
    const { port } = server.address() as AddressInfo
    return new FakeRelay(server, `ws://127.0.0.1:${port}`, options)
  }

  async stop(): Promise<void> {
    for (const client of this.clients) client.socket.terminate()
    this.clients.clear()
    await new Promise<void>((resolve) => this.server.close(() => resolve()))
  }

  // --- chaos ----------------------------------------------------------------

  /**
   * Kill every socket without a close frame, the way a dropped network does.
   * The relay keeps its events, so a reconnecting client should find them.
   */
  dropConnections(): void {
    for (const client of this.clients) client.socket.terminate()
    this.clients.clear()
  }

  /**
   * Stop serving these event ids, while still holding them.
   *
   * A relay is *able* to do this and nothing in Nostr prevents it — which is the
   * whole argument for the counter tags and, from M7, the signed checkpoints.
   * Tests for gap detection need a relay willing to lie.
   */
  withhold(...ids: string[]): void {
    for (const id of ids) this.withheld.add(id)
  }

  /**
   * Withhold events as they arrive, before anyone is told about them.
   *
   * {@link withhold} can only hide an event from later queries; by the time a
   * test knows an event's id, the relay has already broadcast it. Silently
   * dropping an event the relay accepted — OK'd to its author, invisible to
   * everyone else — is the failure the ordering layers exist for, and it is not
   * reproducible after the fact.
   */
  withholdMatching(predicate: (event: NostrEvent) => boolean): void {
    this.swallow = predicate
  }

  /**
   * Send an arbitrary NIP-01 message to every connected client, bypassing every
   * check this relay would otherwise make.
   *
   * A hostile relay is the threat model the SDK's local verification exists for:
   * it is the one party with both the position and the motive to substitute an
   * event, and from M4 that event could be an approval. Nothing reachable
   * through the honest path can produce a forgery, so this is the door.
   */
  injectRaw(message: unknown[]): void {
    for (const client of this.clients) send(client, message)
  }

  /** Number of live connections. */
  get connectionCount(): number {
    return this.clients.size
  }

  // --- checkpoints ------------------------------------------------------------

  /**
   * Sign a kind 8108 over everything the relay *holds* for a group in a window.
   *
   * "Holds", not "serves" — withheld events are in the commitment. That is the
   * whole point and the only configuration in which this is worth testing: a
   * relay that excluded what it was hiding would be committing to the lie
   * rather than to the truth, and would never contradict itself. The real relay
   * has no such choice, because it commits before it decides to misbehave.
   *
   * Window defaults to everything up to now. Chains on the last checkpoint
   * issued for the same group.
   */
  checkpoint(group: string, window: { from?: number; to?: number } = {}): NostrEvent {
    const from = window.from ?? 0
    const to = window.to ?? Math.floor(Date.now() / 1000)

    const ids = this.storage
      .filter(
        (event) =>
          committed(event.kind) &&
          tagValue(event.tags, 'h') === group &&
          event.created_at >= from &&
          event.created_at <= to,
      )
      .map((event) => event.id)

    const previous = this.lastCheckpoint.get(group)
    const body = {
      algorithm: MERKLE_ALGORITHM,
      count: new Set(ids).size,
      from,
      merkle_root: merkleRoot(ids),
      ...(previous ? { prev: previous.id } : {}),
      to,
    }
    // Keys are written in RFC 8785 order above and every value is hex or an
    // integer, so JSON.stringify is already the canonical encoding.
    const event = this.sign({
      kind: Kinds.Checkpoint,
      // Signed now, for a window that has already closed — and never inside
      // its own window, which the real relay gets for free by closing windows
      // a lag behind `now`. It matters because 8108 is a committed kind
      // carrying an `h` tag: a checkpoint dated inside the window it describes
      // would be a member of the set it is describing. The `to + 1` floor is
      // for tests that name a window in the future.
      created_at: Math.max(to + 1, Math.floor(Date.now() / 1000)),
      content: JSON.stringify(body),
      tags: [
        ['h', group],
        ['alt', `checkpoint: ${body.count} events held up to ${to}`],
      ],
      pubkey: this.pubkey,
    })

    this.lastCheckpoint.set(group, event)
    this.received.push(event)
    this.store(event)
    this.broadcast(event)
    return event
  }

  private sign(draft: UnsignedEvent): NostrEvent {
    const id = computeId(draft)
    return { ...draft, id, sig: bytesToHex(schnorr.sign(id, this.secretKey)) }
  }

  // --- inspection -----------------------------------------------------------

  /**
   * What the relay would actually serve: deduplicated by id, replaced by
   * coordinate, ephemeral kinds absent. This is the reader's view of the
   * channel, as opposed to {@link received}, which is the writer's.
   */
  get stored(): NostrEvent[] {
    return [...this.storage]
  }

  eventsOfKind(kind: number): NostrEvent[] {
    return this.received.filter((e) => e.kind === kind)
  }

  /** {@link stored}, filtered — the counterpart to {@link eventsOfKind}. */
  storedOfKind(kind: number): NostrEvent[] {
    return this.storage.filter((e) => e.kind === kind)
  }

  // --- protocol -------------------------------------------------------------

  private accept(socket: WebSocket): void {
    const client: Client = {
      socket,
      challenge: randomBytes(16).toString('hex'),
      authed: undefined,
      subs: new Map(),
    }
    this.clients.add(client)
    socket.on('close', () => this.clients.delete(client))
    socket.on('error', () => this.clients.delete(client))
    socket.on('message', (raw) => this.handle(client, raw.toString()))

    if (this.options.requireAuth) send(client, ['AUTH', client.challenge])
  }

  private handle(client: Client, raw: string): void {
    let message: unknown
    try {
      message = JSON.parse(raw)
    } catch {
      send(client, ['NOTICE', 'invalid: not JSON'])
      return
    }
    if (!Array.isArray(message) || typeof message[0] !== 'string') {
      send(client, ['NOTICE', 'invalid: not a NIP-01 message'])
      return
    }

    switch (message[0]) {
      case 'EVENT':
        this.onEvent(client, message[1] as NostrEvent)
        return
      case 'REQ':
        this.onReq(client, message[1] as string, message.slice(2) as Filter[])
        return
      case 'CLOSE':
        client.subs.delete(message[1] as string)
        return
      case 'AUTH':
        this.onAuth(client, message[1] as NostrEvent)
        return
      default:
        send(client, ['NOTICE', `unsupported: ${message[0]}`])
    }
  }

  private onAuth(client: Client, event: NostrEvent): void {
    const ok =
      event?.kind === 22242 &&
      verifyEvent(event) &&
      tagValue(event.tags, 'challenge') === client.challenge
    if (ok) client.authed = event.pubkey
    send(client, ['OK', event?.id ?? '', ok, ok ? '' : 'auth-required: bad AUTH event'])
  }

  private onEvent(client: Client, event: NostrEvent): void {
    if (!event || typeof event !== 'object') {
      send(client, ['OK', '', false, 'invalid: not an event'])
      return
    }
    if (!verifyEvent(event)) {
      send(client, ['OK', event.id ?? '', false, 'invalid: bad id or signature'])
      return
    }
    if (this.options.requireAuth && !client.authed) {
      send(client, ['OK', event.id, false, 'auth-required: authenticate first'])
      return
    }
    const reason = this.options.reject?.(event)
    if (reason) {
      send(client, ['OK', event.id, false, reason])
      return
    }

    this.received.push(event)
    this.store(event)
    send(client, ['OK', event.id, true, ''])

    if (this.swallow?.(event)) {
      this.withheld.add(event.id)
      return
    }
    this.broadcast(event)
  }

  private store(event: NostrEvent): void {
    // Ephemeral events are broadcast and forgotten. This is load-bearing rather
    // than an optimisation: storing them would replay a cancel from last week to
    // an agent resuming from history.
    if (isEphemeral(event.kind)) return

    if (isReplaceable(event.kind)) {
      this.storage = this.storage.filter((e) => !(e.pubkey === event.pubkey && e.kind === event.kind))
    } else if (isAddressable(event.kind)) {
      const d = tagValue(event.tags, 'd') ?? ''
      this.storage = this.storage.filter(
        (e) => !(e.pubkey === event.pubkey && e.kind === event.kind && (tagValue(e.tags, 'd') ?? '') === d),
      )
    } else if (this.storage.some((e) => e.id === event.id)) {
      return
    }
    this.storage.push(event)
  }

  private onReq(client: Client, subId: string, filters: Filter[]): void {
    this.requests.push({ subId, filters })

    if (this.options.requireAuth && !client.authed) {
      send(client, ['CLOSED', subId, 'auth-required: authenticate first'])
      return
    }
    if (this.options.requireScopedFilters !== false) {
      const unscoped = filters.find((f) => !isScoped(f))
      if (unscoped) {
        send(client, [
          'CLOSED',
          subId,
          'invalid: filter must contain an h, an e, an a or a list of ids',
        ])
        return
      }
    }

    client.subs.set(subId, filters)

    const matches = this.storage
      .filter((e) => !this.withheld.has(e.id) && matchFilters(filters, e))
      .sort((a, b) => a.created_at - b.created_at || a.id.localeCompare(b.id))

    const limit = filters.reduce<number | undefined>(
      (acc, f) => (f.limit === undefined ? acc : Math.max(acc ?? 0, f.limit)),
      undefined,
    )
    const page = limit === undefined ? matches : matches.slice(-limit)

    for (const event of page) send(client, ['EVENT', subId, event])
    send(client, ['EOSE', subId])
  }

  private broadcast(event: NostrEvent): void {
    for (const client of this.clients) {
      for (const [subId, filters] of client.subs) {
        if (matchFilters(filters, event)) send(client, ['EVENT', subId, event])
      }
    }
  }
}

/**
 * The kinds a checkpoint commits to: everything that is not superseded.
 *
 * Duplicated from the SDK's `isCommittedKind` rather than imported, because
 * test-kit is a dependency *of* the SDK and cannot import back. Three lines and
 * a protocol rule; the SDK's checkpoint tests run against this relay, so a
 * divergence shows up there immediately.
 */
function committed(kind: number): boolean {
  return !isReplaceable(kind) && !isEphemeral(kind) && !isAddressable(kind)
}

function isScoped(filter: Filter): boolean {
  if (filter.ids?.length) return true
  for (const letter of ['h', 'e', 'a'] as const) {
    const values = filter[`#${letter}`]
    if (Array.isArray(values) && values.length) return true
  }
  return false
}

function send(client: Client, message: unknown[]): void {
  if (client.socket.readyState !== 1) return
  client.socket.send(JSON.stringify(message))
}
