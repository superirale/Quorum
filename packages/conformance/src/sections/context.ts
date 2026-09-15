/**
 * The context packer, and the one property that makes it safe to have two.
 *
 * Packing is a NIP-90 job: a kind 5600 addressed to a packer's pubkey, a kind
 * 6600 back, or a kind 7000 saying why not. That shape is deliberate and it is
 * the reason this whole section is a **service** rather than a requirement. A
 * packer is addressed by pubkey, so it is swappable and never a privileged
 * endpoint; a relay that hosts none is conformant and its clients pack locally,
 * which is what every client on an encrypted channel already does, because a
 * relay that cannot read the channel cannot pack it.
 *
 * **Which is exactly why `determinism` below is a MUST.** The packer exists
 * twice — once in Go inside the relay, once in TypeScript inside the SDK — and
 * the algorithm is deterministic and extractive precisely so the two can be held
 * to producing the same bytes. If they can, the relay-side packer is an
 * optimisation and nothing depends on it. If they cannot, then an agent's
 * context silently depends on where it was packed, and `algorithm:
 * extractive-v1` in the body is a claim about nothing: from inside a handler the
 * two paths are indistinguishable, so the only place this can be checked is from
 * outside, holding both answers at once. That is this suite's job and almost
 * nobody else's.
 *
 * The comparison is the honest version of it. This section gathers the events
 * *before* asking, with the same four filters the relay's own `gather` uses —
 * the root by id, the thread by `E`, the projection by `d`, and the workspace's
 * agent manifests, which are not about the thread at all and are what makes
 * provenance more than guesswork. A golden fixture cannot catch the divergence
 * that matters here: it is the input to the pure function, so both
 * implementations can agree on it perfectly while *gathering different events*
 * to pack.
 */

import {
  ContextPackRequestBody,
  Kinds,
  TagName,
  buildThread,
  canonicalJson,
  refTo,
} from '@quorum/protocol'
import { LocalSigner, contextRequest, packContext, threadFilter } from '@quorum/sdk'
import type { EventRef, NostrEvent } from '@quorum/protocol'
import { type Session } from '../harness.ts'
import { held, section, type Ctx } from '../section.ts'
import type { Section } from '../report.ts'
import type { SpecimenSet } from '../specimens.ts'

/** How long to wait for a job answer. A packer answers in one round trip or not at all. */
const PATIENCE_MS = 8000

/**
 * Half of an oversize pack, in characters.
 *
 * Two of these plus the JSON around them clears 65,535 with room to spare,
 * while each one stays comfortably under it — a single event's content has the
 * same ceiling, so the specimen has to be assembled from pieces that each fit.
 */
const OVERSIZE_CHARS = 40_000

export async function context(
  session: Session,
  group: string,
  set: SpecimenSet,
  ctx: Ctx,
): Promise<Section> {
  const run = section(
    'context',
    'Relay-side context packing, and whether it gives the same answer as packing locally.',
    ctx,
  )
  const { owner } = session
  const packer = session.info.pubkey

  const noPacker = packer
    ? false
    : 'this relay publishes no `pubkey` in its NIP-11 document, so there is no packer to address ' +
      'a kind 5600 to. A context DVM that cannot be found is the same as one that does not exist'

  // Gathered before anything is asked, so that nothing can land in between and
  // turn an honest packer into a byte mismatch.
  const local = noPacker ? [] : await gather(session, group, set)

  const asked = noPacker
    ? undefined
    : await session.craft(owner, {
        ...contextRequest(packer!, ContextPackRequestBody.parse({ thread: set.thread.id, budget_tokens: 4000 })),
        group,
        counter: session.next(),
      })

  const answer = asked
    ? await (async () => {
        const sent = await session.accepts(asked)
        if (!sent.ok) return undefined
        return session.waitFor(async () => {
          const [found] = await session.query({
            kinds: [Kinds.ContextPackResult, Kinds.JobFeedback],
            '#e': [asked.id],
            '#h': [group],
            limit: 1,
          })
          return found
        }, PATIENCE_MS)
      })()
    : undefined

  const noService =
    noPacker ||
    (answer
      ? false
      : `nothing answered a kind 5600 within ${PATIENCE_MS / 1000}s. Relay-side context packing ` +
        'is an optional service — the SDK packs the same algorithm locally, and has to, because ' +
        'on an encrypted channel the relay cannot read a word of the thread')

  await run.check(
    {
      id: 'dvm',
      what: 'answers a kind 5600 context request addressed to the pubkey it publishes',
      level: 'MAY',
      profile: 'service',
      unless: noService,
    },
    async () => ({
      ok: true,
      why:
        answer!.kind === Kinds.ContextPackResult
          ? `packed it: a kind 6600 of ${answer!.content.length} bytes`
          : `declined it in a kind 7000: ${statusOf(answer!) ?? 'with no reason given'}`,
    }),
  )

  await run.check(
    {
      id: 'author',
      what: 'signs its answer with the pubkey the request was addressed to',
      level: 'MUST',
      profile: 'service',
      unless: noService,
    },
    async () =>
      // A workspace may hold several packers and they are allowed to disagree —
      // different budgets, different retention, different gather bounds. An
      // answer signed by anyone other than the packer that was asked leaves a
      // requester unable to say whose answer they got, which is the one thing
      // addressing by pubkey exists to make possible.
      held(
        answer!.pubkey === packer,
        `the answer is signed by ${answer!.pubkey.slice(0, 8)}… and the request was addressed ` +
          `to ${packer!.slice(0, 8)}…`,
      ),
  )

  await run.check(
    {
      id: 'determinism',
      what: 'packs a thread byte-identically to the same algorithm run locally',
      level: 'MUST',
      profile: 'service',
      unless:
        noService ||
        (answer!.kind === Kinds.ContextPackResult
          ? false
          : 'the relay declined to pack this thread, so there is nothing to compare — see ' +
            '`context/oversize`, which is the case where declining is the right answer'),
    },
    async () => {
      const mine = canonicalJson(
        packContext({
          thread: set.thread.id,
          requester: owner.publicKey,
          events: local,
          budget_tokens: 4000,
        }),
      )
      if (answer!.content === mine) {
        return { ok: true, why: `${mine.length} bytes, from two implementations, identical` }
      }
      // Reported as two numbers rather than a diff, because the difference is
      // almost never in the compaction and almost always in the gather: an
      // implementation missing one of the four filters produces a perfectly
      // well-formed pack of the wrong events, and the byte count is what says
      // so at a glance.
      return {
        ok: false,
        why:
          `${answer!.content.length} bytes from this relay and ${mine.length} from the same ` +
          `algorithm over the ${local.length} events it serves for this thread. Both claim ` +
          '`extractive-v1`, so an agent’s context now depends on where it was packed, and ' +
          'nothing in either body says which one produced it',
      }
    },
  )

  await run.check(
    {
      id: 'oversize',
      what: 'refuses a pack it cannot deliver, in words, rather than trimming it',
      level: 'MUST',
      profile: 'service',
      unless: noService,
    },
    async () => {
      // The specimen is a thread, not a budget, and that is the whole
      // difficulty of asking this question honestly. `budget_tokens` cannot
      // manufacture an oversize pack: the mandatory-keep set is what a budget
      // may not touch, and everything optional is cut at 400 characters, so a
      // gigantic budget over a small thread produces a small pack and a relay
      // answering it has done nothing wrong. What overflows is a thread whose
      // *mandatory* half already exceeds what one event can carry — the last
      // ten events of any thread are kept verbatim — so this builds one.
      const big = await oversizeThread(session, group)
      const request = await session.craft(owner, {
        ...contextRequest(packer!, ContextPackRequestBody.parse({ thread: big.id })),
        group,
        counter: session.next(),
      })
      const sent = await session.accepts(request)
      if (!sent.ok) return { ok: false, why: `the request itself was refused: ${sent.why}` }
      const reply = await session.waitFor(async () => {
        const [found] = await session.query({
          kinds: [Kinds.ContextPackResult, Kinds.JobFeedback],
          '#e': [request.id],
          '#h': [group],
          limit: 1,
        })
        return found
      }, PATIENCE_MS)
      if (!reply) {
        return {
          ok: false,
          why: 'nothing came back at all. A packer that goes quiet leaves the caller waiting on ' +
            'a job it cannot distinguish from a slow one',
        }
      }
      if (reply.kind === Kinds.ContextPackResult) {
        return {
          ok: false,
          why:
            `packed it into ${reply.content.length} bytes over a thread holding ` +
            `${OVERSIZE_CHARS * 2} characters that the algorithm keeps verbatim — so something ` +
            'was dropped, under the same `algorithm` the SDK packer publishes, with nothing in ' +
            'the body saying so',
        }
      }
      // The reason has to be in the `status` tag and not in `content`, and that
      // is a consequence of encryption rather than of NIP-90 convention:
      // `content` is what a sealed event encrypts, so a refusal whose text was
      // sealed would be unreadable by exactly the client that needs it — the
      // one that asked the wrong packer because it holds no key.
      const reason = statusOf(reply)
      return held(
        reason !== undefined && reason.length > 0,
        'refused in a kind 7000 with nothing in its `status` tag. The reason must travel in a ' +
          'tag rather than in `content`, or it is unreadable on exactly the channels where a ' +
          'client is most likely to have asked the wrong packer',
      )
    },
  )

  await run.check(
    {
      id: 'addressed',
      what: 'stays silent on a context request addressed to somebody else',
      level: 'MUST',
      profile: 'service',
      unless: noService,
    },
    async () => {
      // The same request, addressed to a key that has never existed. A packer
      // that answered everything it could answer would leave a requester unable
      // to say whose pack they are reading — and two packers are allowed to
      // differ, which is the entire reason this is addressed by pubkey rather
      // than being an endpoint on the relay.
      const elsewhere = await session.craft(owner, {
        ...contextRequest(
          LocalSigner.generate().publicKey,
          ContextPackRequestBody.parse({ thread: set.thread.id }),
        ),
        group,
        counter: session.next(),
      })
      const sent = await session.accepts(elsewhere)
      if (!sent.ok) return { ok: false, why: `the request itself was refused: ${sent.why}` }
      const overheard = await session.waitFor(async () => {
        const [found] = await session.query({
          kinds: [Kinds.ContextPackResult, Kinds.JobFeedback],
          '#e': [elsewhere.id],
          '#h': [group],
          limit: 1,
        })
        return found
      }, 4000)
      return held(
        overheard === undefined,
        `answered with a kind ${overheard?.kind} a request addressed to a stranger’s pubkey`,
      )
    },
  )

  return run.done()
}

/**
 * The four filters, which are the part worth getting right.
 *
 * The fourth is the one an implementation drops, because nothing about it is
 * thread-scoped: the workspace's kind 38103 manifests. Without them provenance
 * is derived from the event set alone, so an agent with no manifest comes back
 * labelled as a human colleague and `renderContext` stops fencing it. No error,
 * no warning — a prompt injection arriving in the model's context looking like
 * a teammate's words.
 */
async function gather(
  session: Session,
  group: string,
  set: SpecimenSet,
): Promise<NostrEvent[]> {
  const [root, inThread, state, manifests] = await Promise.all([
    session.query({ ids: [set.thread.id], limit: 1 }),
    session.query({ ...threadFilter({ group, threadId: set.thread.id }), limit: 500 }),
    session.query({
      kinds: [Kinds.ThreadState],
      [`#${TagName.Identifier}`]: [set.thread.id],
      [`#${TagName.Group}`]: [group],
      limit: 5,
    }),
    session.query({
      kinds: [Kinds.AgentManifest],
      [`#${TagName.Group}`]: [group],
      limit: 200,
    }),
  ])
  // Deduplicated, because the relay's own gather is: an event matched by two
  // filters is one event, and a packer that counted it twice would pack the
  // sentence twice. Doing it differently here would report the relay as
  // non-deterministic for a difference this function invented.
  const seen = new Map<string, NostrEvent>()
  for (const event of [...root, ...inThread, ...state, ...manifests]) {
    if (!seen.has(event.id)) seen.set(event.id, event)
  }
  return [...seen.values()]
}

/**
 * A thread whose mandatory-keep set alone will not fit in one event.
 *
 * Two messages rather than three hundred, because the number that has to be
 * exceeded is a *byte* count — eventstore writes an event's content length as a
 * uint16 — and the cheapest honest way to exceed it is a couple of long
 * messages inside the verbatim window. A conformance run that published a
 * five-hundred-message thread to ask one question would be charging the relay
 * it is testing for the privilege.
 */
async function oversizeThread(session: Session, group: string): Promise<EventRef> {
  const { owner } = session
  const root = session.vet(
    await owner.sign(
      buildThread({
        pubkey: owner.publicKey,
        group,
        title: 'A thread too large to pack',
        text: 'Opened so that the packer can be asked what it does with a pack it cannot deliver.',
        counter: session.next(),
      }),
    ),
  )
  const thread = refTo(root)
  const opened = await session.accepts(root)
  if (!opened.ok) throw new Error(`the oversize thread root was refused: ${opened.why}`)

  for (const n of [1, 2]) {
    const sent = await session.accepts(
      await session.craft(owner, {
        kind: Kinds.ChatMessage,
        group,
        thread,
        counter: session.next(),
        // Filler rather than prose, and it is the length that is the specimen.
        text: `part ${n} of an oversize thread: ` + 'x'.repeat(OVERSIZE_CHARS),
      }),
    )
    if (!sent.ok) throw new Error(`a ${OVERSIZE_CHARS}-character message was refused: ${sent.why}`)
  }
  return thread
}

/** NIP-90's `["status", "error", "<why>"]`, reduced to the why. */
function statusOf(event: NostrEvent): string | undefined {
  const tag = event.tags.find((t) => t[0] === 'status')
  return tag?.[2] ?? tag?.[1]
}
