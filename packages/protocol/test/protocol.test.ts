import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { test, describe } from 'node:test'
import { fileURLToPath } from 'node:url'

import {
  ADDRESS_MARKER,
  AddressableKinds,
  DvmKinds,
  EphemeralKinds,
  Kinds,
  QUORUM_KINDS,
  RegularKinds,
  addressees,
  build,
  buildComment,
  buildThread,
  CROSS_FIELD_RULES,
  canonicalJson,
  computeId,
  defaultAlt,
  digest,
  digestEquals,
  isAddressable,
  isControlPlane,
  isEphemeral,
  isAddressedTo,
  redactedAlt,
  validateEnvelope,
  validateEvent,
  verifyEvent,
  type NostrEvent,
} from '../src/index.ts'

const here = dirname(fileURLToPath(import.meta.url))
const fixture = JSON.parse(
  readFileSync(join(here, '..', 'fixtures', 'deploy-approval.json'), 'utf8'),
) as {
  group: string
  thread: string
  action: string
  input_digest: string
  events: NostrEvent[]
}

const ADA = fixture.events[0]!.pubkey
const BOT = fixture.events[1]!.pubkey
const GROUP = fixture.group
const THREAD = { id: fixture.thread, kind: Kinds.Thread, pubkey: ADA }

/** Turn an unsigned event into something shaped like a signed one, for tag tests. */
function stub(unsigned: ReturnType<typeof build>): NostrEvent {
  return { ...unsigned, id: computeId(unsigned), sig: '0'.repeat(128) }
}

const errorCodes = (event: NostrEvent) =>
  validateEvent(event).issues.filter((i) => i.severity === 'error').map((i) => i.code)

describe('kind allocation', () => {
  test('every Quorum kind is distinct', () => {
    assert.equal(new Set(QUORUM_KINDS).size, QUORUM_KINDS.length)
  })

  test('kinds sit in the NIP-01 range that matches their storage semantics', () => {
    for (const kind of Object.values(RegularKinds)) {
      assert.ok(kind >= 1000 && kind < 10000, `${kind} should be regular`)
    }
    for (const kind of Object.values(EphemeralKinds)) {
      assert.ok(isEphemeral(kind), `${kind} should be ephemeral`)
    }
    for (const kind of Object.values(AddressableKinds)) {
      assert.ok(isAddressable(kind), `${kind} should be addressable`)
    }
    for (const kind of Object.values(DvmKinds)) {
      assert.ok(kind >= 5000 && kind < 7000, `${kind} should be in the NIP-90 range`)
    }
  })

  test('a NIP-90 job result is exactly 1000 above its request', () => {
    assert.equal(DvmKinds.ContextPackResult - DvmKinds.ContextPackRequest, 1000)
  })

  test('control-plane kinds are exactly the ephemeral ones', () => {
    // M0 finding #4: a handler blocked awaiting approval deadlocks the queue
    // that would deliver its own answer, so control-plane traffic must bypass
    // it. Nostr gives this to us as a property of the kind number rather than
    // a hand-maintained list — but only if the two never drift apart.
    for (const kind of Object.values(EphemeralKinds)) assert.ok(isControlPlane(kind))
    for (const kind of Object.values(RegularKinds)) assert.ok(!isControlPlane(kind))
  })
})

describe('addressing', () => {
  // The regression test for M0 finding #1. The spike's agent deployed to
  // production because a seeded system message *described* how to mention it,
  // and the SDK matched "@deploy" in body text. Addressing must be a tag, and
  // it must be distinguishable from every other reason a pubkey appears.

  test('only a `to`-marked p tag counts as addressing', () => {
    const event = stub(
      build({
        kind: RegularKinds.Error,
        pubkey: BOT,
        group: GROUP,
        thread: THREAD,
        to: [ADA],
        mention: ['ff'.repeat(32)],
        counter: 1,
        body: { code: 'nope', message: 'could not parse the request' },
      }),
    )

    assert.deepEqual(addressees(event.tags), [ADA])
    assert.ok(isAddressedTo(event.tags, ADA))
    assert.ok(!isAddressedTo(event.tags, 'ff'.repeat(32)), 'a mention is not an address')
  })

  test('a parent with no thread is refused rather than silently dropped', () => {
    // It used to be dropped: `build()` emitted the scope tags only when a
    // thread was present, so asking for a parent and nothing else produced an
    // event with no `e` tag at all — a reply referring to nothing. Everything
    // downstream rejects that event, but each of them reports it as malformed
    // somewhere far from the line that built it. Found while writing the
    // console's tests, where it cost an afternoon.
    assert.throws(
      () =>
        build({
          kind: RegularKinds.ApprovalResponse,
          pubkey: ADA,
          group: GROUP,
          parent: { id: 'aa'.repeat(32), kind: RegularKinds.ApprovalRequest, pubkey: BOT },
          counter: 1,
          body: { decision: 'approved' },
        }),
      /needs a `thread`/,
    )
  })

  test('a NIP-22 parent author is not addressed by that alone', () => {
    // The collision that forced the marker: NIP-22 says a comment MUST p-tag
    // the parent's author. Without the marker, every reply would look like an
    // instruction to whoever spoke last.
    const comment = stub(
      buildComment({ pubkey: ADA, group: GROUP, text: 'thanks', thread: THREAD, counter: 9 }),
    )
    assert.ok(comment.tags.some((t) => t[0] === 'p' && t[1] === ADA))
    assert.deepEqual(addressees(comment.tags), [])
  })

  test('being addressed wins over being merely mentioned', () => {
    const comment = stub(
      buildComment({
        pubkey: BOT,
        group: GROUP,
        text: 'done',
        thread: THREAD,
        to: [ADA],
        counter: 9,
      }),
    )
    const adaTags = comment.tags.filter((t) => t[0] === 'p' && t[1] === ADA)
    assert.equal(adaTags.length, 1, 'one p tag per pubkey, not a contradictory pair')
    assert.equal(adaTags[0]![3], ADDRESS_MARKER)
  })

  test('an approval request nobody is addressed to is invalid', () => {
    const orphan = stub(
      build({
        kind: RegularKinds.ApprovalRequest,
        pubkey: BOT,
        group: GROUP,
        thread: THREAD,
        counter: 1,
        body: { title: 'Do the thing', summary: 'the thing', risk: 'low' },
      }),
    )
    assert.ok(errorCodes(orphan).includes('not_addressed'))
  })

  test('a quorum larger than the number of approvers is rejected', () => {
    const impossible = stub(
      build({
        kind: RegularKinds.ApprovalRequest,
        pubkey: BOT,
        group: GROUP,
        thread: THREAD,
        to: [ADA],
        counter: 1,
        body: { title: 'Wire the money', summary: 'a lot of it', risk: 'high', required: 2 },
      }),
    )
    assert.ok(errorCodes(impossible).includes('unreachable_quorum'))
  })
})

describe('the alt tag', () => {
  test('build always produces one for a Quorum kind', () => {
    for (const kind of [RegularKinds.Action, RegularKinds.Checkpoint, EphemeralKinds.Presence]) {
      const alt = defaultAlt(kind, {})
      assert.ok(alt.length > 0 && !alt.includes('\n'))
    }
  })

  test('a missing alt is an error, not a warning', () => {
    const event = stub(
      build({
        kind: RegularKinds.Error,
        pubkey: BOT,
        group: GROUP,
        thread: THREAD,
        counter: 1,
        body: { code: 'x', message: 'y' },
      }),
    )
    event.tags = event.tags.filter((t) => t[0] !== 'alt')
    assert.ok(errorCodes(event).includes('missing_alt'))
  })

  test('encrypted events get an alt that leaks nothing', () => {
    const alt = redactedAlt(RegularKinds.ApprovalRequest)
    assert.match(alt, /^Encrypted /)
    assert.ok(!alt.includes('risk'))
  })

  test('an unknown future kind still renders', () => {
    // The forward-compatibility contract: a v0.1 reader meeting kind 8199 from
    // a v0.9 peer gets a sentence rather than a blank.
    assert.equal(defaultAlt(8199, {}), 'Quorum event (kind 8199)')
  })
})

describe('canonical JSON and digests', () => {
  test('key order does not change the digest', () => {
    const a = { env: 'production', ref: 'a1b2c3d', service: 'payments-api' }
    const b = { service: 'payments-api', env: 'production', ref: 'a1b2c3d' }
    assert.equal(canonicalJson(a), canonicalJson(b))
    assert.equal(digest(a), digest(b))
  })

  test('nested keys are sorted too', () => {
    assert.equal(canonicalJson({ b: 1, a: { d: 2, c: 3 } }), '{"a":{"c":3,"d":2},"b":1}')
  })

  test('undefined members are dropped, matching JSON.stringify', () => {
    assert.equal(canonicalJson({ a: 1, b: undefined }), '{"a":1}')
  })

  test('non-finite numbers throw rather than silently differ across languages', () => {
    assert.throws(() => canonicalJson({ x: Number.NaN }), /non-finite/)
    assert.throws(() => canonicalJson({ x: Number.POSITIVE_INFINITY }), /non-finite/)
  })

  test('the fixture digest is stable', () => {
    // A golden value. If this changes, every previously signed approval in the
    // wild now binds to a payload nobody can reproduce.
    assert.equal(
      digest({ env: 'production', ref: 'a1b2c3d', service: 'payments-api' }),
      fixture.input_digest,
    )
  })

  test('digestEquals rejects mismatches and undefined', () => {
    assert.ok(digestEquals('ab'.repeat(32), 'ab'.repeat(32)))
    assert.ok(!digestEquals('ab'.repeat(32), 'ac'.repeat(32)))
    assert.ok(!digestEquals(undefined, 'ab'.repeat(32)))
  })
})

describe('action chains', () => {
  const base = { kind: RegularKinds.Action, pubkey: BOT, group: GROUP, thread: THREAD, counter: 1 }

  test('a proposal must bind to its input digest', () => {
    const noDigest = stub(
      build({
        ...base,
        body: { name: 'deploy.production', status: 'proposed', summary: 'ship it' },
      }),
    )
    assert.ok(errorCodes(noDigest).includes('missing_input_digest'))
  })

  test('a later status must name the chain it belongs to', () => {
    const orphanStatus = stub(
      build({
        ...base,
        body: { name: 'deploy.production', status: 'running', summary: 'ship it' },
      }),
    )
    assert.ok(errorCodes(orphanStatus).includes('missing_action_tag'))
  })

  test('a well-formed chain validates', () => {
    const running = stub(
      build({
        ...base,
        action: fixture.action,
        body: { name: 'deploy.production', status: 'running', summary: 'ship it' },
      }),
    )
    assert.deepEqual(errorCodes(running), [])
  })
})

describe('approvals', () => {
  test('an approval request tied to an action must name its digest', () => {
    const loose = stub(
      build({
        kind: RegularKinds.ApprovalRequest,
        pubkey: BOT,
        group: GROUP,
        thread: THREAD,
        action: fixture.action,
        to: [ADA],
        counter: 1,
        body: { title: 'Deploy', summary: 'to production', risk: 'high' },
      }),
    )
    assert.ok(
      errorCodes(loose).includes('missing_input_digest'),
      'otherwise approving once approves the action name forever',
    )
  })

  test('an edited approval must carry the digest of what it edited to', () => {
    const request = fixture.events.find((e) => e.kind === RegularKinds.ApprovalRequest)!
    const sneaky = stub(
      build({
        kind: RegularKinds.ApprovalResponse,
        pubkey: ADA,
        group: GROUP,
        thread: THREAD,
        parent: { id: request.id, kind: request.kind, pubkey: request.pubkey },
        to: [BOT],
        counter: 1,
        body: {
          decision: 'approved',
          input_digest: fixture.input_digest,
          modified_input: { env: 'production', ref: 'deadbeef', service: 'payments-api' },
        },
      }),
    )
    assert.ok(errorCodes(sneaky).includes('missing_modified_digest'))
  })

  test('a response must answer a request, not just sit in the thread', () => {
    // Every threaded event has an `e` tag — a top-level NIP-22 comment points
    // it at the thread root — so "has a parent" is trivially true. The parent's
    // *kind* is the part that means something.
    const floating = stub(
      build({
        kind: RegularKinds.ApprovalResponse,
        pubkey: ADA,
        group: GROUP,
        thread: THREAD,
        to: [BOT],
        counter: 1,
        body: { decision: 'approved', input_digest: fixture.input_digest },
      }),
    )
    assert.ok(errorCodes(floating).includes('bad_parent_kind'))
  })
})

describe('the envelope', () => {
  test('everything build() emits passes validation', () => {
    const cases = [
      build({
        kind: RegularKinds.Artifact,
        pubkey: BOT,
        group: GROUP,
        thread: THREAD,
        counter: 1,
        body: { name: 'plan.md', mime: 'text/markdown' },
      }),
      build({
        kind: EphemeralKinds.Presence,
        pubkey: BOT,
        group: GROUP,
        counter: 2,
        body: { status: 'busy', activity: 'deploying' },
      }),
      build({
        kind: AddressableKinds.CapabilityGrant,
        pubkey: ADA,
        group: GROUP,
        d: 'grant-1',
        counter: 3,
        body: {
          grantee: BOT,
          grant: { resource: 'action:deploy.production', actions: ['invoke'] },
        },
      }),
    ]
    for (const unsigned of cases) {
      const result = validateEvent(stub(unsigned))
      assert.deepEqual(
        result.issues.filter((i) => i.severity === 'error'),
        [],
        `kind ${unsigned.kind}`,
      )
    }
  })

  test('an addressable kind without a `d` tag is invalid', () => {
    const event = stub(
      build({
        kind: AddressableKinds.AgentMemory,
        pubkey: BOT,
        group: GROUP,
        d: 'k',
        counter: 1,
        body: { value: 1 },
      }),
    )
    event.tags = event.tags.filter((t) => t[0] !== 'd')
    assert.ok(errorCodes(event).includes('missing_d'))
  })

  test('a missing counter warns but does not reject', () => {
    // Rejecting would break generic clients, which know nothing of Quorum and
    // will never emit one. The cost is only that this author's readers lose gap
    // detection for them.
    const event = stub(
      build({
        kind: RegularKinds.Error,
        pubkey: BOT,
        group: GROUP,
        thread: THREAD,
        body: { code: 'x', message: 'y' },
      }),
    )
    const result = validateEvent(event)
    assert.ok(result.valid)
    assert.ok(result.issues.some((i) => i.code === 'missing_counter' && i.severity === 'warning'))
  })

  test('a thread reference must point at a kind:11 root', () => {
    const event = stub(
      build({
        kind: RegularKinds.Error,
        pubkey: BOT,
        group: GROUP,
        thread: { ...THREAD, kind: 1 },
        counter: 1,
        body: { code: 'x', message: 'y' },
      }),
    )
    assert.ok(errorCodes(event).includes('bad_root_kind'))
  })

  test('the envelope validates without the body, as on an encrypted channel', () => {
    const event = stub(
      build({
        kind: RegularKinds.ApprovalRequest,
        pubkey: BOT,
        group: GROUP,
        thread: THREAD,
        to: [ADA],
        counter: 1,
        enc: 'nip44',
        body: { title: 'Deploy', summary: 'to production', risk: 'high' },
      }),
    )
    // Stand in for ciphertext: the body is unreadable, the envelope is not.
    event.content = 'AqrX9…ciphertext…'
    const result = validateEvent(event)
    assert.ok(result.valid, JSON.stringify(result.issues))
    assert.equal(result.body, undefined, 'no body should be parsed from ciphertext')
  })

  test('a non-Quorum kind is left alone', () => {
    const comment = stub(
      buildComment({ pubkey: ADA, group: GROUP, text: 'hi', thread: THREAD, counter: 1 }),
    )
    const result = validateEnvelope(comment)
    assert.ok(result.valid)
    assert.ok(result.issues.some((i) => i.code === 'not_quorum_kind'))
  })
})

describe('interrupts and spend', () => {
  test('an action-scoped interrupt must name the action it stops', () => {
    // The default scope is `action`, so this is the shape you get by forgetting
    // — and it is the ambiguous one: an agent reading it cannot tell whether
    // "stop" meant this action or everything in the thread.
    const event = stub(
      build({
        kind: EphemeralKinds.Interrupt,
        pubkey: ADA,
        group: GROUP,
        thread: THREAD,
        body: { mode: 'cancel', reason: 'wrong version' },
      }),
    )
    assert.ok(errorCodes(event).includes('missing_action_tag'))
  })

  test('naming the action, or scoping to the thread, both pass', () => {
    const named = stub(
      build({
        kind: EphemeralKinds.Interrupt,
        pubkey: ADA,
        group: GROUP,
        thread: THREAD,
        action: fixture.action,
        body: { mode: 'cancel' },
      }),
    )
    assert.deepEqual(errorCodes(named), [])

    const whole = stub(
      build({
        kind: EphemeralKinds.Interrupt,
        pubkey: ADA,
        group: GROUP,
        thread: THREAD,
        body: { mode: 'pause', scope: 'thread', reason: 'stop, all of it' },
      }),
    )
    assert.deepEqual(errorCodes(whole), [])
  })

  test('a steer with no instruction warns', () => {
    const event = stub(
      build({
        kind: EphemeralKinds.Interrupt,
        pubkey: ADA,
        group: GROUP,
        thread: THREAD,
        action: fixture.action,
        body: { mode: 'steer' },
      }),
    )
    const result = validateEvent(event)
    assert.ok(result.valid, 'a vague steer is not worth rejecting')
    assert.ok(result.issues.some((i) => i.code === 'steer_without_instruction'))
  })

  test('add_spend is a thread op like any other', () => {
    const event = stub(
      build({
        kind: RegularKinds.ThreadOp,
        pubkey: BOT,
        group: GROUP,
        thread: THREAD,
        counter: 1,
        body: { op: 'add_spend', cost: { tokens_in: 8200, tokens_out: 410 }, note: 'one turn' },
      }),
    )
    assert.deepEqual(errorCodes(event), [])
  })

  test('its alt carries no amount', () => {
    // `alt` is plaintext even where the body is not, and a running total is
    // exactly the kind of number a workspace would rather not broadcast.
    const alt = defaultAlt(RegularKinds.ThreadOp, {
      op: 'add_spend',
      cost: { usd: 412.5 },
    })
    assert.equal(alt, 'Spend reported')
    assert.ok(!alt.includes('412'))
  })
})

describe('handing a member a key', () => {
  // 8110 and 8111 are the same shape in two encryption modes: one member's way
  // in, addressed to them, naming them again in the body.
  const CAT = 'c'.repeat(64)
  const PAYLOAD = 'A'.repeat(140)

  const welcome = (over: Record<string, unknown>) =>
    stub(
      build({
        kind: RegularKinds.MlsWelcome,
        pubkey: ADA,
        group: GROUP,
        counter: 1,
        body: {
          epoch: 1,
          invite: PAYLOAD,
          recipient: BOT,
          key_package: 'a'.repeat(64),
        },
        ...over,
      } as Parameters<typeof build>[0]),
    )

  test('a Welcome nobody is addressed by is invisible to the member it is for', () => {
    // Not an error anyone would see at publish time: the relay stores it, the
    // signature verifies, the body is well formed. It is simply never returned
    // by the `#p` filter every reader uses, so the invitee waits forever for a
    // Welcome that was published a week ago.
    assert.ok(errorCodes(welcome({})).includes('not_addressed'))
    assert.deepEqual(errorCodes(welcome({ to: [BOT] })), [])
  })

  test('the tag that routes it and the body that names it must agree', () => {
    const crossed = welcome({ to: [CAT] })
    assert.ok(errorCodes(crossed).includes('recipient_mismatch'))
  })

  test('one member per event, because the second reader cannot tell why it failed', () => {
    const both = welcome({ to: [BOT, CAT] })
    assert.ok(errorCodes(both).includes('many_recipients'))
  })

  test('the same rule holds for a nip44 channel key', () => {
    const key = stub(
      build({
        kind: RegularKinds.ChannelKey,
        pubkey: ADA,
        group: GROUP,
        to: [CAT],
        counter: 1,
        body: { epoch: 2, key: PAYLOAD, recipient: BOT },
      }),
    )
    assert.ok(errorCodes(key).includes('recipient_mismatch'))
  })
})

describe('a channel policy states an epoch only where one can be known', () => {
  const policy = (body: Record<string, unknown>) =>
    stub(
      build({
        kind: AddressableKinds.ChannelPolicy,
        pubkey: ADA,
        group: GROUP,
        d: GROUP,
        counter: 1,
        body,
      }),
    )

  test('an mls policy must not carry one', () => {
    // The ratchet advances on every commit by any member, and the relay stores
    // commits it cannot read. A number here is stale the moment somebody adds
    // a member, and stale in the direction that locks a writer out.
    assert.ok(errorCodes(policy({ enc: 'mls', epoch: 1 })).includes('mls_policy_epoch'))
    assert.deepEqual(errorCodes(policy({ enc: 'mls' })), [])
  })

  test('a nip44 policy must', () => {
    assert.ok(errorCodes(policy({ enc: 'nip44' })).includes('missing_epoch'))
    assert.deepEqual(errorCodes(policy({ enc: 'nip44', epoch: 1 })), [])
  })

  test('and plaintext is silent either way, because there is no key to name', () => {
    assert.deepEqual(errorCodes(policy({ enc: 'plaintext' })), [])
  })
})

describe('the golden transcript', () => {
  test('every event verifies', () => {
    for (const event of fixture.events) {
      assert.ok(verifyEvent(event), `kind ${event.kind} failed signature verification`)
    }
  })

  test('every event validates', () => {
    for (const event of fixture.events) {
      const result = validateEvent(event, { verifySignature: true })
      assert.ok(
        result.valid,
        `kind ${event.kind}: ${result.issues.filter((i) => i.severity === 'error').map((i) => i.code).join(', ')}`,
      )
    }
  })

  test('tampering with content invalidates the id', () => {
    const [first] = fixture.events
    const tampered = { ...first!, content: `${first!.content} (also drop the database)` }
    assert.ok(!verifyEvent(tampered))
    assert.ok(errorCodes(tampered).length === 0, 'the tags are still fine — only the id is not')
    assert.ok(!validateEvent(tampered, { verifySignature: true }).valid)
  })

  test('the approval binds to the exact input that was proposed', () => {
    const proposed = fixture.events.find(
      (e) => e.kind === RegularKinds.Action && JSON.parse(e.content).status === 'proposed',
    )!
    const response = fixture.events.find((e) => e.kind === RegularKinds.ApprovalResponse)!

    const proposedBody = JSON.parse(proposed.content)
    const responseBody = JSON.parse(response.content)

    // Recompute rather than trust: this is the check an agent must do before
    // acting, and the one an auditor does months later with no server involved.
    assert.equal(digest(proposedBody.input), proposedBody.input_digest)
    assert.ok(digestEquals(responseBody.input_digest, proposedBody.input_digest))
  })

  test('the whole thread hangs off one kind:11 root', () => {
    const root = fixture.events.find((e) => e.kind === Kinds.Thread)!
    assert.equal(root.id, fixture.thread)
    for (const event of fixture.events) {
      if (event.kind === Kinds.Thread || isAddressable(event.kind)) continue
      const E = event.tags.find((t) => t[0] === 'E')
      assert.equal(E?.[1], fixture.thread, `kind ${event.kind} is not in the thread`)
    }
  })

  test('a generic NIP-7D/NIP-22 client sees a readable conversation', () => {
    // The interop claim, checked rather than asserted: strip every kind a
    // generic client does not know, and what remains must still be a coherent
    // thread with human-readable text.
    const generic = fixture.events.filter((e) => e.kind === Kinds.Thread || e.kind === Kinds.Comment)
    assert.ok(generic.length >= 3)
    assert.equal(generic[0]!.kind, Kinds.Thread)
    assert.ok(generic[0]!.tags.some((t) => t[0] === 'title'))
    for (const event of generic) {
      assert.ok(event.content.length > 0, 'plain text, not JSON')
      assert.doesNotThrow(() => event.content)
    }
  })

  test('an old client renders the agent-specific kinds via alt alone', () => {
    const unknownToThem = fixture.events.filter(
      (e) => e.kind !== Kinds.Thread && e.kind !== Kinds.Comment,
    )
    assert.ok(unknownToThem.length > 0)
    for (const event of unknownToThem) {
      const alt = event.tags.find((t) => t[0] === 'alt')?.[1]
      assert.ok(alt && alt.length > 0, `kind ${event.kind} has no alt to fall back to`)
    }
  })
})

describe('event ids', () => {
  test('the same body from two authors produces the same content bytes', () => {
    // Content-addressing is what gives idempotency for free: a replayed publish
    // is deduped by the relay rather than by bookkeeping we would have to write.
    const body = { code: 'timeout', message: 'upstream did not answer', retryable: true }
    const a = build({
      kind: RegularKinds.Error,
      pubkey: BOT,
      group: GROUP,
      thread: THREAD,
      counter: 1,
      created_at: 1,
      body,
    })
    const b = build({
      kind: RegularKinds.Error,
      pubkey: BOT,
      group: GROUP,
      thread: THREAD,
      counter: 1,
      created_at: 1,
      body: { retryable: true, message: 'upstream did not answer', code: 'timeout' },
    })
    assert.equal(a.content, b.content)
    assert.equal(computeId(a), computeId(b))
  })

  test('created_at is part of the id, so replays need memoised events', () => {
    // Worth pinning: M0's `once()` memoises the *signed event*, not the body,
    // precisely because a replayed publish one second later is a different id.
    const make = (created_at: number) =>
      build({
        kind: RegularKinds.Error,
        pubkey: BOT,
        group: GROUP,
        thread: THREAD,
        counter: 1,
        created_at,
        body: { code: 'x', message: 'y' },
      })
    assert.notEqual(computeId(make(1)), computeId(make(2)))
  })
})

describe('build() guards', () => {
  test('a JSON body on a plain-text kind is refused', () => {
    assert.throws(
      () => build({ kind: Kinds.Comment, pubkey: BOT, group: GROUP, body: { text: 'hi' } }),
      /plain text/,
    )
  })

  test('a missing body on a JSON kind is refused', () => {
    assert.throws(
      () => build({ kind: RegularKinds.Error, pubkey: BOT, group: GROUP }),
      /requires a JSON body/,
    )
  })

  test('a body that fails its schema is refused at build time', () => {
    assert.throws(() =>
      build({
        kind: RegularKinds.Action,
        pubkey: BOT,
        group: GROUP,
        thread: THREAD,
        body: { name: 'x', status: 'not-a-status', summary: 'y' },
      }),
    )
  })

  test('a thread root carries its title where NIP-7D expects it', () => {
    const thread = buildThread({
      pubkey: ADA,
      group: GROUP,
      title: 'Ship it',
      text: 'please',
      counter: 1,
    })
    assert.equal(thread.kind, 11)
    assert.equal(thread.tags.find((t) => t[0] === 'title')?.[1], 'Ship it')
  })
})

describe('the cross-field rules are published, not only enforced', () => {
  // Four times now, a rule expressible only in TypeScript has turned out to be
  // a rule the Go relay does not have: the resource names, the UNSEALED_KINDS
  // table, the `mls` policy epoch, and — found by `@quorum/conformance` asking
  // both implementations the same question — a proposed action with no
  // `input_digest`, refused here and stored there.
  //
  // `CROSS_FIELD_RULES` is the answer: the codes go into schemas/index.json and
  // the relay refuses to boot when it is published one it does not implement.
  // Which makes the table load-bearing in a new way. A code published here and
  // raised by nothing would require every other implementation to enforce a
  // rule that does not exist, and a rule raised here and published nowhere is
  // the original problem again. So the table is executed: one violating event
  // per code, built the way a confused client would build it.

  const violations: Record<string, () => NostrEvent> = {
    missing_input_digest: () =>
      stub(
        build({
          kind: RegularKinds.Action,
          pubkey: BOT,
          group: GROUP,
          thread: THREAD,
          counter: 1,
          body: { name: 'deploy.production', status: 'proposed', summary: 'ship it' },
        }),
      ),
    missing_action_tag: () =>
      stub(
        build({
          kind: RegularKinds.Action,
          pubkey: BOT,
          group: GROUP,
          thread: THREAD,
          counter: 1,
          body: { name: 'deploy.production', status: 'running', summary: 'ship it' },
        }),
      ),
    unreachable_quorum: () =>
      stub(
        build({
          kind: RegularKinds.ApprovalRequest,
          pubkey: BOT,
          group: GROUP,
          thread: THREAD,
          to: [ADA],
          counter: 1,
          body: { title: 'Deploy', summary: 'to production', risk: 'high', required: 2 },
        }),
      ),
    missing_modified_digest: () =>
      stub(
        build({
          kind: RegularKinds.ApprovalResponse,
          pubkey: ADA,
          group: GROUP,
          thread: THREAD,
          parent: { id: fixture.action, kind: RegularKinds.ApprovalRequest, pubkey: BOT },
          counter: 1,
          body: {
            decision: 'approved',
            input_digest: fixture.input_digest,
            modified_input: { replicas: 2 },
          },
        }),
      ),
    many_recipients: () =>
      stub(
        build({
          kind: RegularKinds.ChannelKey,
          pubkey: ADA,
          group: GROUP,
          to: [BOT, 'c'.repeat(64)],
          counter: 1,
          body: { epoch: 2, key: 'A'.repeat(140), recipient: BOT },
        }),
      ),
    recipient_mismatch: () =>
      stub(
        build({
          kind: RegularKinds.ChannelKey,
          pubkey: ADA,
          group: GROUP,
          to: ['c'.repeat(64)],
          counter: 1,
          body: { epoch: 2, key: 'A'.repeat(140), recipient: BOT },
        }),
      ),
    mls_policy_epoch: () =>
      stub(
        build({
          kind: AddressableKinds.ChannelPolicy,
          pubkey: ADA,
          group: GROUP,
          d: GROUP,
          counter: 1,
          body: { enc: 'mls', epoch: 1 },
        }),
      ),
    missing_epoch: () =>
      stub(
        build({
          kind: AddressableKinds.ChannelPolicy,
          pubkey: ADA,
          group: GROUP,
          d: GROUP,
          counter: 1,
          body: { enc: 'nip44' },
        }),
      ),
    bad_thread_d: () =>
      stub(
        build({
          kind: AddressableKinds.ThreadState,
          pubkey: ADA,
          group: GROUP,
          d: 'the-deploy-thread',
          counter: 1,
          body: { status: 'open' },
        }),
      ),
  }

  for (const rule of CROSS_FIELD_RULES) {
    test(`${rule.code}: ${rule.what}`, () => {
      const violate = violations[rule.code]
      assert.ok(violate, `${rule.code} is published and nothing here violates it`)
      assert.ok(
        errorCodes(violate()).includes(rule.code),
        `${rule.code} is published but this event did not raise it`,
      )
    })
  }

  test('and nothing is enforced that is not published', () => {
    // The other direction, and the one `crossErr` already refuses at the point
    // of use — this is the assertion that says so out loud, and that the table
    // is a table rather than a list that happens to be right today.
    assert.deepEqual(
      Object.keys(violations).sort(),
      CROSS_FIELD_RULES.map((rule) => rule.code).sort(),
    )
  })

  test('every rule names the kinds it applies to, and they are Quorum kinds', () => {
    for (const rule of CROSS_FIELD_RULES) {
      assert.ok(rule.kinds.length > 0, `${rule.code} applies to nothing`)
      for (const kind of rule.kinds) {
        assert.ok(QUORUM_KINDS.includes(kind), `${rule.code} names kind ${kind}, which is not ours`)
      }
    }
  })
})
