/**
 * One honest event of every kind the protocol defines.
 *
 * This is the input to the Option A claim — *every Quorum event is valid on any
 * generic relay* — so the list has to be complete, and completeness has to be
 * checked rather than believed. {@link specimens} therefore enumerates
 * `SUPPORTED_KINDS` from `@quorum/protocol` and refuses to return a set that
 * does not account for every entry. A kind added to the protocol with no
 * specimen written for it fails the suite loudly, instead of quietly never
 * being tested — which is how a conformance suite comes to certify a relay
 * against a protocol it is two versions behind.
 *
 * Bodies are written out rather than generated from the JSON Schemas. Producing
 * a valid instance from a schema is a project of its own, and one that would
 * produce specimens nobody had read: the interesting content here is that each
 * body is a *plausible* one — an approval request a human could answer, a
 * thread op a relay could fold — because several relay policies are cross-field
 * and would pass over a body full of placeholder strings. What is generated is
 * the coverage check, which is the part that rots.
 *
 * Three kinds are absent from every published set, each for a stated reason,
 * and {@link specimens} accounts for them explicitly rather than by omission.
 */

import {
  Kinds,
  SUPPORTED_KINDS,
  buildComment,
  buildThread,
  digest,
  kindName,
  mlsKeyPackageTags,
  refTo,
  type EventRef,
  type NostrEvent,
} from '@quorum/protocol'
import type { LocalSigner } from '@quorum/sdk'
import { SuiteError, type Session } from './harness.ts'

export interface Specimen {
  kind: number
  /** The kind's name from the protocol, for the report line. */
  name: string
  event: NostrEvent
}

export interface SpecimenSet {
  /** The thread root every threaded specimen hangs from. */
  thread: EventRef
  /** Kinds a relay must store and serve back. */
  stored: Specimen[]
  /**
   * Kinds a relay must route and must *not* store. Separated because
   * "accepted and readable afterwards" is the wrong success condition for an
   * ephemeral event — a relay that stored a heartbeat would pass a naive
   * round-trip check while breaking the one property the 20000–29999 range has.
   */
  ephemeral: Specimen[]
  /**
   * The NIP-09 deletion request, separated for a third reason again: NIP-09
   * says a relay SHOULD go on serving one, and SHOULD is not what the `stored`
   * loop asserts. See `keeps-deletions` in the interop section.
   */
  deletion: Specimen
}

/**
 * Kinds only the relay may sign, so a member-authored specimen is a forgery.
 *
 * Not an omission from the Option A claim: a conforming client never emits one,
 * so "can a client publish this to a generic relay" is not a question the
 * protocol asks. Both get their own refusal check in the ordering and threads
 * sections, which is the direction that matters.
 */
export const RELAY_AUTHORED: readonly number[] = Object.freeze([
  Kinds.Checkpoint,
  Kinds.ThreadState,
])

/** Filler that satisfies a length constraint without pretending to be real. */
const base64ish = 'A'.repeat(180)
const hex32 = (byte: string) => byte.repeat(64)

export async function specimens(session: Session, group: string): Promise<SpecimenSet> {
  const { owner, member } = session
  const next = () => session.next(owner)

  const root = await owner.sign(
    buildThread({
      pubkey: owner.publicKey,
      group,
      title: 'Conformance run',
      text: 'A thread opened by @quorum/conformance so that threaded kinds have a root.',
      counter: next(),
    }),
  )
  const thread = refTo(root)

  const stored: Specimen[] = [{ kind: root.kind, name: 'Thread', event: root }]
  const ephemeral: Specimen[] = []

  const add = (event: NostrEvent) => {
    const name = kindName(event.kind) ?? `kind ${event.kind}`
    const bucket = event.kind >= 20000 && event.kind < 30000 ? ephemeral : stored
    bucket.push({ kind: event.kind, name, event })
    return event
  }

  // --- borrowed kinds: what a generic client already understands -------------

  add(
    await session.craft(owner, {
      kind: Kinds.ChatMessage,
      group,
      text: 'A plain NIP-C7 chat message, which is the whole of the interop claim in one event.',
      counter: next(),
    }),
  )

  add(
    session.vet(
      await owner.sign(
        buildComment({
          pubkey: owner.publicKey,
          group,
          text: 'A NIP-22 comment in the thread above.',
          thread,
          counter: next(),
        }),
      ),
    ),
  )

  // NIP-09. A request, not a command: the relay may honour it or not, and the
  // check is only that the request itself travels. It names an event that does
  // not exist so that honouring it deletes nothing this run depends on.
  //
  // Not `add`ed, because the `stored` loop is a MUST and this is not one. NIP-09
  // says a relay "SHOULD continue to publish/share the deletion request events
  // indefinitely", which is a recommendation with a real reason behind it and no
  // interoperability claim resting on it.
  const deletionRequest = session.vet(
    await owner.sign({
      pubkey: owner.publicKey,
      created_at: Math.floor(Date.now() / 1000),
      kind: Kinds.DeletionRequest,
      tags: [
        ['h', group],
        ['e', hex32('d')],
        ['k', String(Kinds.ChatMessage)],
      ],
      content: 'a deletion request naming an event that was never published',
    }),
  )
  const deletion: Specimen = {
    kind: deletionRequest.kind,
    name: kindName(deletionRequest.kind) ?? 'Deletion request',
    event: deletionRequest,
  }

  // NIP-90 job feedback. Published here by an ordinary member on purpose: 7000
  // is not reserved to the relay, because the packer must stay swappable.
  add(
    session.vet(
      await owner.sign({
        pubkey: owner.publicKey,
        created_at: Math.floor(Date.now() / 1000),
        kind: Kinds.JobFeedback,
        tags: [
          ['h', group],
          ['status', 'processing'],
          ['e', thread.id],
          ['p', member.publicKey],
        ],
        content: '',
      }),
    ),
  )

  // A KeyPackage. `d` is the channel id rather than random bytes — the Quorum
  // divergence from Marmot — and the relay enforces exactly that.
  add(
    await session.craft(owner, {
      kind: Kinds.MlsKeyPackage,
      group,
      d: group,
      text: base64ish,
      counter: next(),
      tags: mlsKeyPackageTags({
        ref: hex32('a'),
        ciphersuites: [1],
        extensions: [1, 2, 3],
        proposals: [],
      }),
    }),
  )

  // --- the action chain ------------------------------------------------------

  const input = { env: 'staging', replicas: 2 }
  const proposal = add(
    await session.craft(owner, {
      kind: Kinds.Action,
      group,
      thread,
      counter: next(),
      body: {
        name: 'deploy.staging',
        status: 'proposed',
        summary: 'Deploy the current build to staging',
        input,
        input_digest: digest(input),
      },
    }),
  )

  const request = add(
    await session.craft(owner, {
      kind: Kinds.ApprovalRequest,
      group,
      thread,
      to: [member.publicKey],
      counter: next(),
      body: {
        title: 'Deploy to staging',
        summary: 'Two replicas, current build. Reversible.',
        risk: 'low',
        input_digest: digest(input),
      },
    }),
  )

  // Signed by the member, because they are who the request addressed. A
  // response from anyone else is the thing `RejectUnaskedApprovals` exists to
  // refuse, and publishing one here would record that refusal as an interop
  // failure.
  add(
    await session.craft(member, {
      kind: Kinds.ApprovalResponse,
      group,
      thread,
      parent: refTo(request),
      counter: session.next(member),
      body: { decision: 'approved', input_digest: digest(input) },
    }),
  )

  // --- the rest of the regular kinds ----------------------------------------

  add(
    await session.craft(owner, {
      kind: Kinds.Summary,
      group,
      thread,
      counter: next(),
      body: {
        text: 'A deploy to staging was proposed and approved.',
        from_event: thread.id,
        to_event: request.id,
        covers: 3,
        method: 'extractive',
      },
    }),
  )

  add(
    await session.craft(owner, {
      kind: Kinds.Error,
      group,
      thread,
      counter: next(),
      body: { code: 'upstream_timeout', message: 'the build server did not answer', retryable: true },
    }),
  )

  add(
    await session.craft(owner, {
      kind: Kinds.Artifact,
      group,
      thread,
      counter: next(),
      body: { name: 'build.log', mime: 'text/plain', size: 4096 },
    }),
  )

  add(
    await session.craft(owner, {
      kind: Kinds.Handoff,
      group,
      thread,
      to: [member.publicKey],
      counter: next(),
      body: { to: member.publicKey, reason: 'the deploy needs a human to watch it' },
    }),
  )

  add(
    await session.craft(owner, {
      kind: Kinds.ThreadOp,
      group,
      thread,
      counter: next(),
      body: { op: 'set_status', status: 'working' },
    }),
  )

  add(
    await session.craft(owner, {
      kind: Kinds.ChannelKey,
      group,
      to: [member.publicKey],
      counter: next(),
      body: { epoch: 1, key: base64ish, recipient: member.publicKey },
    }),
  )

  add(
    await session.craft(owner, {
      kind: Kinds.MlsWelcome,
      group,
      to: [member.publicKey],
      counter: next(),
      body: {
        epoch: 0,
        invite: base64ish,
        recipient: member.publicKey,
        key_package: hex32('a'),
      },
    }),
  )

  add(
    await session.craft(owner, {
      kind: Kinds.MlsCommit,
      group,
      counter: next(),
      body: { epoch: await freeEpoch(session, group), commit: base64ish, adds: [member.publicKey] },
    }),
  )

  // --- ephemeral -------------------------------------------------------------
  //
  // No `counter` on any of these, and that is a rule rather than an omission: a
  // relay stores none of them, so a number spent on a heartbeat is a sequence
  // position no reader can ever backfill.

  // The `action` tag is not decoration: `scope` defaults to `action`, so an
  // interrupt naming nothing is the easy one to publish by accident and the
  // dangerous one to receive — an agent reading it has to guess whether "stop"
  // meant this action or everything in the thread. It names the proposal above,
  // which nothing is running, so honouring it stops nothing.
  add(
    await session.craft(owner, {
      kind: Kinds.Interrupt,
      group,
      thread,
      action: proposal.id,
      body: { mode: 'cancel', scope: 'action', reason: 'a conformance run, not a real cancel' },
    }),
  )

  add(
    await session.craft(owner, {
      kind: Kinds.Lease,
      group,
      thread,
      body: { instance: 'conformance', epoch: 1, ttl_seconds: 60 },
    }),
  )

  add(
    await session.craft(owner, {
      kind: Kinds.Presence,
      group,
      body: { status: 'online', activity: 'running a conformance suite', ttl_seconds: 90 },
    }),
  )

  // --- addressable -----------------------------------------------------------

  add(
    await session.craft(owner, {
      kind: Kinds.CapabilityGrant,
      group,
      d: 'conformance-grant',
      counter: next(),
      body: {
        grantee: member.publicKey,
        grant: { resource: 'action:deploy', actions: ['invoke'], scope: { env: 'staging' } },
        issued_at: Math.floor(Date.now() / 1000),
      },
    }),
  )

  add(
    await session.craft(owner, {
      kind: Kinds.AgentManifest,
      group,
      d: 'conformance',
      counter: next(),
      body: {
        name: 'conformance',
        description: 'the suite that published this event, announcing itself',
        operator: owner.publicKey,
      },
    }),
  )

  add(
    await session.craft(owner, {
      kind: Kinds.AgentMemory,
      group,
      d: 'conformance/last-run',
      counter: next(),
      body: { value: { relay: session.url }, updated_at: Math.floor(Date.now() / 1000) },
    }),
  )

  add(
    await session.craft(owner, {
      kind: Kinds.AgentCursor,
      group,
      d: 'conformance',
      counter: next(),
      body: { watermarks: {}, in_flight: [], completed_ahead: [] },
    }),
  )

  add(
    await session.craft(owner, {
      kind: Kinds.Delegation,
      group,
      d: 'conformance-delegation',
      counter: next(),
      body: { delegate: member.publicKey, resources: ['action:deploy'] },
    }),
  )

  // The policy says `plaintext`, which is what this workspace already is. A
  // specimen that switched the channel to `nip44` would invalidate every
  // plaintext specimen published after it — including, on a second run against
  // the same group, all of them.
  add(
    await session.craft(owner, {
      kind: Kinds.ChannelPolicy,
      group,
      d: group,
      counter: next(),
      body: { enc: 'plaintext', reason: 'a conformance run', changed_at: Math.floor(Date.now() / 1000) },
    }),
  )

  // --- the context DVM pair --------------------------------------------------

  add(
    await session.craft(owner, {
      kind: Kinds.ContextPackRequest,
      group,
      counter: next(),
      body: { thread: thread.id, budget_tokens: 2000, verbatim_only: false },
    }),
  )

  add(
    await session.craft(owner, {
      kind: Kinds.ContextPackResult,
      group,
      counter: next(),
      body: {
        thread: thread.id,
        segments: [],
        used_tokens: 0,
        budget_tokens: 2000,
        dropped_events: 0,
        algorithm: 'extractive-v1',
      },
    }),
  )

  assertComplete(stored, ephemeral, deletion)
  return { thread, stored, ephemeral, deletion }
}

/**
 * Every supported kind is accounted for, or the run stops.
 *
 * A missing specimen is a suite bug that presents as good news — one fewer
 * check, all of them green — which is the failure mode a conformance tool has
 * no way to notice from its own output.
 */
function assertComplete(stored: Specimen[], ephemeral: Specimen[], deletion: Specimen): void {
  const covered = new Set([
    ...stored.map((s) => s.kind),
    ...ephemeral.map((s) => s.kind),
    deletion.kind,
    ...RELAY_AUTHORED,
  ])
  const missing = SUPPORTED_KINDS.filter((kind) => !covered.has(kind))
  if (missing.length > 0) {
    throw new SuiteError(
      `no specimen for kind${missing.length === 1 ? '' : 's'} ${missing.join(', ')}: ` +
        'the protocol defines them and this suite would have reported a relay conformant ' +
        'without ever publishing one',
    )
  }
}

/**
 * An epoch this channel holds no kind 8112 for.
 *
 * A commit specimen cannot simply say `epoch: 0`. The reference relay
 * serialises commits — at most one per channel per epoch — so the second run
 * against a workspace `--group` pointed it at is refused, correctly, and the
 * suite records a relay doing exactly the right thing as a MUST failure. Asked
 * rather than randomised, because the check this feeds is worded "an epoch it
 * holds none for", and a number picked by a die is a different claim.
 */
export async function freeEpoch(session: Session, group: string): Promise<number> {
  const held = await session.query({ kinds: [Kinds.MlsCommit], '#h': [group], limit: 200 })
  let highest = -1
  for (const event of held) {
    try {
      const { epoch } = JSON.parse(event.content) as { epoch?: unknown }
      if (typeof epoch === 'number' && epoch > highest) highest = epoch
    } catch {
      // A body this suite cannot read is one it cannot collide with either.
    }
  }
  return highest + 1
}

/** A second, identical copy of an event — for the dedupe check. */
export async function republish(
  who: LocalSigner,
  event: NostrEvent,
): Promise<NostrEvent> {
  return who.sign({
    pubkey: event.pubkey,
    created_at: event.created_at,
    kind: event.kind,
    tags: event.tags,
    content: event.content,
  })
}
