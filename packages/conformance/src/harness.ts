/**
 * The machinery every check runs on: a relay connection, a workspace, three
 * keys, and two verbs — did it take this, and did it refuse that.
 *
 * Two rules here are load-bearing rather than tidy.
 *
 * **Every specimen is validated locally before it is published.** A suite that
 * sent a malformed event and recorded the relay's refusal would be reporting
 * its own bug as somebody else's non-conformance, and the operator on the other
 * end has no way to tell the difference. Nothing reaches the socket except
 * through {@link Session.craft} or {@link Session.vet}, which run
 * `validateEvent` and throw a {@link SuiteError} — recorded as `skip`, labelled
 * as this suite's fault — rather than letting the relay be blamed for it. This
 * is the one direction of mistake a conformance tool must never make, because
 * it is the one the relay's author cannot debug.
 *
 * **A refusal only counts against a relay that is otherwise accepting traffic.**
 * "The relay refused X" and "the relay is down" produce the same observation
 * from here. So the interop section runs first and unconditionally, and if it
 * cannot get a single honest event stored the run stops rather than reporting
 * forty refusals as forty passes. The pattern is the one M9 wrote down for the
 * demos: a negative claim is worth nothing without a positive control beside it
 * on the same relay in the same run.
 */

import {
  Kinds,
  TagName,
  build,
  validateEvent,
  type BuildOptions,
  type EventRef,
  type NostrEvent,
  type UnsignedEvent,
} from '@quorum/protocol'
import { LocalSigner, PublishError, RelayClient, SubscriptionClosed } from '@quorum/sdk'
import type { Filter } from '@quorum/protocol'
import type { Profile, RelayInfo } from './report.ts'

/** NIP-29 moderation kinds, which are the only way to make a workspace exist. */
export const NIP29 = { createGroup: 9007, putUser: 9000, removeUser: 9001, join: 9021 } as const

/** Thrown when the *suite* is wrong, never when the relay is. */
export class SuiteError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'SuiteError'
  }
}

export interface SessionOptions {
  url: string
  /** Override the group id, for a relay where `QUORUM_OWNER_PUBKEYS` is set. */
  group?: string
  /**
   * The owner's secret key, hex or `nsec1…`, instead of a fresh one.
   *
   * Both uses of {@link SessionOptions.group} need this and neither works
   * without it. A relay with `QUORUM_OWNER_PUBKEYS` set has to be told which
   * key may create the workspace *before* the run, and a run pointed at an
   * existing workspace has to be a member of it — so a suite that mints its
   * identity at startup can never satisfy either. The key is the one thing
   * about this run an operator has to be able to decide in advance.
   *
   * The member and the stranger stay generated: the member is added by the
   * owner, and the whole value of the stranger is that nobody has ever granted
   * it anything.
   */
  ownerKey?: string
  /** Seconds to wait for a relay-authored event before calling it absent. */
  patienceMs?: number
  log?: (line: string) => void
}

const quiet = { warn() {}, error() {} }

export class Session {
  readonly url: string
  /** The owner: creates the workspace, and is therefore an admin of it. */
  readonly owner: LocalSigner
  /** An ordinary member, put in the group by the owner. */
  readonly member: LocalSigner
  /**
   * Nobody. Never added to the group, never granted anything.
   *
   * Half the checks in this suite are about what a relay does to a key it has
   * no reason to trust, and they need a key that has never been trusted — a
   * demoted member is a different test with a different answer.
   */
  readonly stranger: LocalSigner

  readonly group: string
  readonly patienceMs: number

  private readonly clients = new Map<string, RelayClient>()
  private readonly signers = new Map<string, LocalSigner>()
  private readonly counters = new Map<string, number>()
  private readonly made = new Set<string>()
  private readonly note: (line: string) => void

  info: RelayInfo = {}

  private constructor(options: SessionOptions) {
    const stamp = Date.now().toString(36)
    this.url = options.url
    this.owner = options.ownerKey ? LocalSigner.from(options.ownerKey) : LocalSigner.generate()
    this.member = LocalSigner.generate()
    this.stranger = LocalSigner.generate()
    this.group = options.group ?? `conformance-${stamp}`
    this.patienceMs = options.patienceMs ?? 20_000
    this.note = options.log ?? (() => {})
    for (const who of [this.owner, this.member, this.stranger]) {
      this.signers.set(who.publicKey, who)
    }
  }

  /**
   * A key nobody has ever heard of, for a check that needs a fresh one.
   *
   * The positive control for every "the relay refuses an untrusted key" check
   * needs a key that then *becomes* trusted, and it cannot be
   * {@link Session.stranger} — granting the stranger anything would silently
   * turn every later refusal check into a test of a member, and they would all
   * go on passing while testing nothing.
   */
  newcomer(): LocalSigner {
    const who = LocalSigner.generate()
    this.signers.set(who.publicKey, who)
    return who
  }

  static async open(options: SessionOptions): Promise<Session> {
    const session = new Session(options)
    // Said out loud on every run, not only when `--key` was passed. An operator
    // whose relay refused this run has to know which key to allow-list, and a
    // run that generated its identity and never mentioned it leaves them with
    // no way to find out — which is how `--group` came to exist for a purpose
    // it could not serve.
    session.note(`owner ${session.owner.publicKey} · workspace ${session.group}`)
    session.info = await readNip11(options.url)
    await session.client(session.owner)
    return session
  }

  /** One connection per key, because a relay authenticates the socket. */
  async client(signer: LocalSigner): Promise<RelayClient> {
    const held = this.clients.get(signer.publicKey)
    if (held) return held
    // `eagerAuth`, because a relay with `QUORUM_REQUIRE_AUTH` set closes
    // subscriptions from an unauthenticated socket — and a CLOSED is
    // indistinguishable here from a relay that serves nothing, which is the
    // single worst thing this suite could get wrong about an honest relay.
    const client = new RelayClient({
      url: this.url,
      signer,
      eagerAuth: true,
      reconnect: false,
      log: quiet,
    })
    await client.connect()
    this.clients.set(signer.publicKey, client)
    return client
  }

  close(): void {
    for (const client of this.clients.values()) client.close()
    this.clients.clear()
  }

  /**
   * The next `counter` for one author.
   *
   * Per pubkey, because that is what the tag means. One shared sequence across
   * three keys would leave every author's stream full of holes, and a relay is
   * entitled to say something about that — which would be this suite creating
   * the anomaly it then reports.
   */
  next(who: LocalSigner = this.owner): number {
    const n = (this.counters.get(who.publicKey) ?? 0) + 1
    this.counters.set(who.publicKey, n)
    return n
  }

  /**
   * A workspace that exists, as far as this relay has the concept, with the
   * owner owning it and the member in it.
   *
   * A generic relay has never heard of kind 9007 and will either store it as an
   * ordinary event or refuse it; either is fine and neither is recorded,
   * because NIP-29 group creation is not a Quorum rule. What matters is only
   * whether `h`-tagged events are accepted afterwards, which the interop
   * section asks directly.
   *
   * Sections take their own workspace whenever they are about to change
   * something channel-wide — an encryption policy, most of all. A policy is
   * addressable on the group id, so a section that sealed the shared workspace
   * would silently invalidate every plaintext specimen published after it, and
   * the resulting refusals would be recorded against the relay.
   */
  async workspace(suffix = ''): Promise<string> {
    const id = suffix ? `${this.group}-${suffix}` : this.group
    if (this.made.has(id)) return id
    this.made.add(id)
    await this.quietly(this.owner, { kind: NIP29.createGroup, tags: [['h', id]], content: '' })
    // The member, and deliberately not the stranger. Every check that asks what
    // a relay does to an untrusted key depends on that key never having been
    // added here.
    await this.quietly(this.owner, {
      kind: NIP29.putUser,
      tags: [
        ['h', id],
        ['p', this.member.publicKey],
      ],
      content: '',
    })
    return id
  }

  /** Publish a raw event, swallowing a refusal. For setup, never for a check. */
  async quietly(
    who: LocalSigner,
    unsigned: Omit<UnsignedEvent, 'pubkey' | 'created_at'>,
  ): Promise<NostrEvent | undefined> {
    try {
      const event = await who.sign({ ...unsigned, pubkey: who.publicKey, created_at: now() })
      const client = await this.client(who)
      await client.publish(event)
      return event
    } catch (error) {
      this.note(`setup: ${describe(error)}`)
      return undefined
    }
  }

  /**
   * Build and sign a Quorum event, refusing to produce an invalid one.
   *
   * `build()` already guarantees a well-formed envelope, and `validateEvent`
   * then checks the body against the committed schema. Both, because they catch
   * different things and this is the boundary where a suite bug becomes an
   * accusation.
   */
  async craft(who: LocalSigner, options: Omit<BuildOptions, 'pubkey'>): Promise<NostrEvent> {
    return this.vet(await who.sign(build({ ...options, pubkey: who.publicKey })))
  }

  /** The same guarantee for an event assembled by hand rather than by `build`. */
  vet(event: NostrEvent): NostrEvent {
    const verdict = validateEvent(event)
    if (!verdict.valid) {
      throw new SuiteError(
        `the suite built an invalid kind ${event.kind}: ` +
          verdict.issues
            .filter((i) => i.severity === 'error')
            .map((i) => `${i.code}${i.at ? ` at ${i.at}` : ''}`)
            .join(', '),
      )
    }
    return event
  }

  /**
   * Did the relay take this event — and does it serve it back unchanged?
   *
   * Reading it back is the half that matters and the half a naive suite skips.
   * An OK means the relay accepted the bytes; it does not mean the relay kept
   * them. A relay that stores events with tags normalised, reordered or dropped
   * answers OK to everything and quietly breaks `to`-marked addressing, NIP-22
   * root scope and every `id` in the workspace, because the id is a hash of the
   * tags.
   */
  async accepts(event: NostrEvent): Promise<Verdict> {
    const client = await this.clientFor(event.pubkey)
    try {
      await client.publish(event)
    } catch (error) {
      if (error instanceof PublishError) return { ok: false, why: error.reason }
      throw error
    }
    let served: NostrEvent | undefined
    try {
      ;[served] = await client.query([{ ids: [event.id], limit: 1 }])
    } catch (error) {
      return { ok: false, why: `accepted, then the read-back was refused: ${describe(error)}` }
    }
    if (!served) return { ok: false, why: 'accepted, then not served back' }
    if (JSON.stringify(canonical(served)) !== JSON.stringify(canonical(event))) {
      return { ok: false, why: 'served back altered — compare tags and content byte for byte' }
    }
    return { ok: true }
  }

  /** Did the relay refuse it, and in what words? */
  async refuses(event: NostrEvent): Promise<Verdict> {
    const client = await this.clientFor(event.pubkey)
    try {
      await client.publish(event)
      return { ok: false, why: 'stored it' }
    } catch (error) {
      if (error instanceof PublishError) return { ok: true, why: error.reason }
      throw error
    }
  }

  async query(filter: Filter, who: LocalSigner = this.owner): Promise<NostrEvent[]> {
    const client = await this.client(who)
    try {
      return await client.query([filter])
    } catch (error) {
      if (error instanceof SubscriptionClosed) return []
      throw error
    }
  }

  /**
   * Poll until something appears, paced at 1200ms.
   *
   * Not tuned for latency: khatru's filter limiter *closes the subscription*
   * rather than queueing when a client exceeds `QUORUM_FILTERS_PER_MINUTE`,
   * which defaults to 120. A suite polling twice a second dies three sections
   * later as an unexplained CLOSED, and the CLOSED then reads as "the relay
   * serves nothing" — a false accusation produced entirely by the suite's own
   * impatience.
   */
  async waitFor<T>(
    find: () => Promise<T | undefined>,
    ms: number = this.patienceMs,
  ): Promise<T | undefined> {
    const deadline = Date.now() + ms
    for (;;) {
      const found = await find()
      if (found !== undefined) return found
      if (Date.now() >= deadline) return undefined
      await sleep(1200)
    }
  }

  private async clientFor(pubkey: string): Promise<RelayClient> {
    const who = this.signers.get(pubkey)
    if (!who) throw new SuiteError(`no connection for ${pubkey.slice(0, 8)}`)
    return this.client(who)
  }
}

export interface Verdict {
  ok: boolean
  why?: string
}

/**
 * Which profiles this relay implements, established by asking rather than by
 * being told.
 *
 * The probe is a kind 8104 with no `alt` tag. That is invalid under the NIP's
 * one universal envelope rule, and it is a rule with no NIP-29, encryption or
 * capability machinery behind it — so a relay that refuses it is validating
 * Quorum events, and a relay that stores it is a generic relay doing its job.
 * Nothing else about the relay's configuration can move this answer, which is
 * why it is the probe rather than, say, a capability check that a permissive
 * Quorum deployment would also pass.
 *
 * Service profiles are not probed here. Each service section asks its own
 * question, because "does this relay project threads" and "does this relay sign
 * checkpoints" are separately configurable and a single answer for both would
 * be wrong for most deployments.
 */
export async function detectProfile(
  session: Session,
  thread: EventRef,
): Promise<{ profiles: Profile[]; why: string }> {
  const verdict = await session.refuses(await altless(session, thread))
  return verdict.ok
    ? { profiles: ['any', 'quorum'], why: `validates Quorum events — ${verdict.why}` }
    : {
        profiles: ['any'],
        why:
          'stores a Quorum kind with no `alt` tag, so it is a generic relay; the Quorum ' +
          'policy checks below are reported as not applicable rather than as failures',
      }
}

/**
 * A valid kind 8104 with its `alt` tag taken off, and nothing else wrong.
 *
 * Shared by {@link detectProfile} and the envelope section, which ask the same
 * question for different purposes — one to decide what to run, the other to
 * report the answer. Two separately-written copies of "a summary with no alt"
 * could drift into two different events, and the section would then be
 * reporting a rule the profile was not established on.
 */
export async function altless(session: Session, thread: EventRef): Promise<NostrEvent> {
  return session.owner.sign(
    withoutTag(
      build({
        kind: Kinds.Summary,
        pubkey: session.owner.publicKey,
        group: session.group,
        thread,
        counter: session.next(),
        body: {
          text: 'a probe: this event is valid except that its alt tag has been removed',
          from_event: thread.id,
          to_event: thread.id,
          covers: 1,
          method: 'extractive',
        },
      }),
      TagName.Alt,
    ),
  )
}

/**
 * Deliberate damage, in three shapes.
 *
 * Every refusal check starts from an event `build()` produced and breaks
 * exactly one thing about it. That is not stylistic: an event assembled by hand
 * to be wrong is usually wrong in several ways at once, so the relay's refusal
 * proves only that *something* was wrong with it — and the check's name then
 * claims a rule the relay may not have. One mutation on an otherwise-valid
 * event is the only version of this that tests what it says it tests.
 */
export function withoutTag(event: UnsignedEvent, name: string): UnsignedEvent {
  return { ...event, tags: event.tags.filter((tag) => tag[0] !== name) }
}

export function replaceTag(event: UnsignedEvent, tag: string[]): UnsignedEvent {
  return { ...event, tags: [...event.tags.filter((t) => t[0] !== tag[0]), tag] }
}

export function withTag(event: UnsignedEvent, tag: string[]): UnsignedEvent {
  return { ...event, tags: [...event.tags, tag] }
}

async function readNip11(wsUrl: string): Promise<RelayInfo> {
  const http = wsUrl.replace(/^ws/, 'http')
  try {
    const response = await fetch(http, { headers: { Accept: 'application/nostr+json' } })
    if (!response.ok) return {}
    return (await response.json()) as RelayInfo
  } catch {
    return {}
  }
}

/**
 * The event as a relay is entitled to serve it back.
 *
 * Relays are not required to preserve key order in the JSON object, so the
 * comparison in {@link Session.accepts} is over a re-serialisation with the
 * NIP-01 field order, not over the bytes as sent. Tags and content are compared
 * exactly, because those are what the id commits to.
 *
 * Both sides go through this, and the first version of the check did not — it
 * compared a canonicalised copy of what was sent against the served object as
 * it arrived, so every honest relay in the world "served back altered". A
 * conformance suite's own idea of equality is the last place a shortcut
 * belongs: the failure was total, uniform, and worded as an accusation.
 */
function canonical(event: NostrEvent): NostrEvent {
  return {
    id: event.id,
    pubkey: event.pubkey,
    created_at: event.created_at,
    kind: event.kind,
    tags: event.tags,
    content: event.content,
    sig: event.sig,
  }
}

export function now(): number {
  return Math.floor(Date.now() / 1000)
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

export function describe(error: unknown): string {
  const text = error instanceof Error ? error.message : String(error)
  return text.split('\n')[0]!.slice(0, 200)
}
