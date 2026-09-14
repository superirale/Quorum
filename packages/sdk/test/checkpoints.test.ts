/**
 * Ordering integrity, layer 3, from the reader's side.
 *
 * The milestone claim — "a relay withholding an event is caught and proven" —
 * is the last describe block, and it runs against a relay that really is
 * withholding: the fake relay commits to what it *holds* and then stops serving
 * one of those events. That is the only arrangement in which the check has
 * anything to catch. A relay that excluded what it was hiding would be
 * committing to the lie and would never contradict itself; the real relay has
 * no such option, because it signs before it decides to misbehave.
 */

import assert from 'node:assert/strict'
import { after, before, describe, it } from 'node:test'
import { Kinds, MERKLE_ALGORITHM, merkleRoot, type NostrEvent } from '@quorum/protocol'
import { FakeRelay } from '@quorum/test-kit'
import {
  LocalSigner,
  RelayClient,
  checkChain,
  checkpointFilter,
  checkpointFor,
  checkpoints,
  inWindow,
  isCommittedKind,
  verifyWindow,
  verifyWithholdingProof,
  windowFilter,
  withholdingProof,
  type Checkpoint,
  type WithholdingProof,
} from '../src/index.ts'
import { Actor } from './harness.ts'

const GROUP = 'payments'

const now = (): number => Math.floor(Date.now() / 1000)

/** Rewrite a checkpoint's window. Unsigned — only `checkChain` reads this. */
function rewindow(chain: Checkpoint[], index: number, patch: Partial<Checkpoint['body']>): Checkpoint[] {
  return chain.map((link, i) => (i === index ? { ...link, body: { ...link.body, ...patch } } : link))
}

describe('isCommittedKind', () => {
  it('covers regular kinds and nothing that can be superseded', () => {
    // The same rule as `Committed` in the relay's checkpoint package and
    // `committed` in the fake relay. Three copies, because the two languages
    // cannot import from each other and test-kit is a dependency of the SDK —
    // so this list is where a divergence surfaces. A client applying a
    // different filter is computing a different tree, and will accuse an
    // honest relay of withholding.
    for (const kind of [1, 9, 11, 1111, 8101, 8103, 8108, 8109]) {
      assert.ok(isCommittedKind(kind), `kind ${kind} should be committed to`)
    }
    for (const kind of [0, 3, 10002, 28101, 28103, 38101, 38102, 38103]) {
      assert.ok(!isCommittedKind(kind), `kind ${kind} should not be committed to`)
    }
  })
})

describe('reading checkpoints', () => {
  let relay: FakeRelay
  let ada: Actor

  before(async () => {
    relay = await FakeRelay.start()
    ada = await Actor.create(relay.url, GROUP)
    await ada.chat('one')
  })
  after(async () => {
    ada.close()
    await relay.stop()
  })

  it('parses what the relay signed, oldest window first', () => {
    const first = relay.checkpoint('reading', { from: 0, to: 100 })
    const second = relay.checkpoint('reading', { from: 101, to: 200 })

    const chain = checkpoints([second, first], relay.pubkey)
    assert.deepEqual(
      chain.map((c) => c.event.id),
      [first.id, second.id],
    )
    assert.equal(chain[0]!.body.algorithm, MERKLE_ALGORITHM)
    assert.equal(chain[0]!.relay, relay.pubkey)
    assert.equal(chain[0]!.group, 'reading')
    assert.equal(checkpoints([first, second], 'f'.repeat(64)).length, 0, 'another relay is not this one')
  })

  it('drops a checkpoint whose signature does not hold', () => {
    // The whole value of a checkpoint is that it is signed. An unverified one
    // is a suggestion from whoever happened to be on the socket, and the relay
    // is exactly the party positioned to substitute one.
    const real = relay.checkpoint(GROUP, { from: 0, to: now() })
    const forged: NostrEvent = { ...real, content: real.content.replace(/"count":\d+/, '"count":0') }

    assert.equal(checkpoints([real]).length, 1)
    assert.equal(checkpoints([forged]).length, 0)
  })

  it('drops one that names an algorithm we do not implement', () => {
    // `algorithm` exists so that a verifier never guesses, and guessing is
    // exactly what accepting an unknown name would be: a root we cannot
    // recompute must not be treated as one we checked.
    const real = checkpoints([relay.checkpoint(GROUP, { from: 0, to: now() })])[0]!
    const body = JSON.parse(real.event.content) as Record<string, unknown>
    body['algorithm'] = 'sha256-merkle-v2'
    assert.equal(checkpoints([{ ...real.event, content: JSON.stringify(body) }]).length, 0)
  })

  it('builds filters that name the group', () => {
    const point = checkpoints([relay.checkpoint(GROUP, { from: 10, to: 20 })])[0]!
    assert.deepEqual(checkpointFilter(GROUP, relay.pubkey), {
      kinds: [Kinds.Checkpoint],
      '#h': [GROUP],
      authors: [relay.pubkey],
    })
    assert.deepEqual(windowFilter(point), { '#h': [GROUP], since: 10, until: 20 })
  })
})

describe('the chain', () => {
  let relay: FakeRelay

  before(async () => {
    relay = await FakeRelay.start()
  })
  after(async () => {
    await relay.stop()
  })

  it('links by the previous checkpoint id, not by its root', () => {
    // Two consecutive quiet windows have identical roots, so chaining on the
    // root would leave them indistinguishable and a relay could present either
    // as the one it signed. An id commits to the bounds and the count too.
    const first = relay.checkpoint('quiet', { from: 0, to: 100 })
    const second = relay.checkpoint('quiet', { from: 101, to: 200 })
    const chain = checkpoints([first, second])

    assert.equal(chain[0]!.body.merkle_root, chain[1]!.body.merkle_root, 'both windows are empty')
    assert.notEqual(chain[0]!.event.id, chain[1]!.event.id)
    assert.equal(chain[1]!.body.prev, first.id)
    assert.equal(chain[0]!.body.prev, undefined, 'the first for a group has no prev')
    assert.ok(checkChain(chain).ok)
  })

  it('reports a removed link', () => {
    const a = relay.checkpoint('removed', { from: 0, to: 100 })
    relay.checkpoint('removed', { from: 101, to: 200 })
    const c = relay.checkpoint('removed', { from: 201, to: 300 })

    // Drop the middle one and c's `prev` names an event that is not the one
    // before it. This is what removing a checkpoint from the log looks like.
    const check = checkChain(checkpoints([a, c]))
    assert.equal(check.ok, false)
    assert.deepEqual(
      check.broken.map((x) => x.event.id),
      [c.id],
    )
  })

  it('reports a gap and an overlap', () => {
    const a = relay.checkpoint('cut', { from: 0, to: 100 })
    const b = relay.checkpoint('cut', { from: 101, to: 200 })
    const linked = checkpoints([a, b])
    assert.ok(checkChain(linked).ok, 'the unedited pair is a chain')

    // Linked correctly, but nobody committed to the seconds in between.
    const gapped = checkChain(rewindow(linked, 1, { from: 150 }))
    assert.equal(gapped.ok, false)
    assert.equal(gapped.gaps.length, 1)
    assert.equal(gapped.gaps[0]!.seconds, 49)

    // Two signed claims over the same seconds, which is what re-cutting
    // history into windows that suit you requires.
    const overlapped = checkChain(rewindow(linked, 1, { from: 50 }))
    assert.equal(overlapped.ok, false)
    assert.equal(overlapped.overlaps.length, 1)
  })
})

describe('verifying a window', () => {
  let relay: FakeRelay
  let ada: Actor
  let sent: NostrEvent[]
  let point: Checkpoint

  before(async () => {
    relay = await FakeRelay.start()
    ada = await Actor.create(relay.url, GROUP)
    sent = []
    for (const text of ['one', 'two', 'three', 'four']) sent.push(await ada.chat(text))
    point = checkpoints([relay.checkpoint(GROUP, { from: 0, to: now() + 30 })])[0]!
  })
  after(async () => {
    ada.close()
    await relay.stop()
  })

  it('agrees when we hold the set that was committed to', () => {
    assert.deepEqual(verifyWindow(point, sent), { verdict: 'agrees', count: 4 })
  })

  it('is unmoved by order and by duplicates', () => {
    // A subscription delivers in whatever order it delivers, and overlapping
    // filters serve the same event twice. Neither is an accusation, and a
    // check that called them one would cry wolf on every reconnect.
    assert.equal(verifyWindow(point, [sent[3]!, sent[1]!, sent[0]!, sent[2]!, sent[1]!]).verdict, 'agrees')
  })

  it('ignores what the window does not cover', () => {
    // Distinct ids, so that a filter failing to exclude one of these changes
    // the root rather than being absorbed by deduplication.
    const later: NostrEvent = { ...sent[0]!, id: 'a'.repeat(64), created_at: point.body.to + 1 }
    const projection: NostrEvent = { ...sent[0]!, id: 'b'.repeat(64), kind: 38101 }
    const elsewhere: NostrEvent = {
      ...sent[0]!,
      id: 'c'.repeat(64),
      tags: sent[0]!.tags.map((tag) => (tag[0] === 'h' ? ['h', 'other-group'] : tag)),
    }

    assert.deepEqual(inWindow([later, projection, elsewhere], point), [])
    assert.equal(verifyWindow(point, [...sent, later, projection, elsewhere]).verdict, 'agrees')
  })

  it('says short when we hold fewer than were committed to', () => {
    // Deliberately not an accusation. We may simply not have asked for
    // everything — a client's backfill window is its own business — and a
    // function unable to tell those apart would be useless for both.
    assert.deepEqual(verifyWindow(point, sent.slice(0, 2)), { verdict: 'short', held: 2, committed: 4 })
  })

  it('says disagrees when we hold as many and they are not the same events', async () => {
    const stranger = await ada.chat('never committed to')
    assert.deepEqual(verifyWindow(point, [...sent.slice(0, 3), stranger]), {
      verdict: 'disagrees',
      held: 4,
      committed: 4,
    })
  })

  it('finds the checkpoint covering an event', () => {
    assert.equal(checkpointFor([point], sent[0]!)?.event.id, point.event.id)
    assert.equal(checkpointFor([], sent[0]!), undefined)
  })
})

describe('a relay withholding an event is caught and proven', () => {
  let relay: FakeRelay
  let ada: Actor
  let mirror: NostrEvent[]
  let hidden: NostrEvent
  let point: Checkpoint
  let served: NostrEvent[]

  before(async () => {
    relay = await FakeRelay.start()
    ada = await Actor.create(relay.url, GROUP)

    mirror = []
    for (const text of ['one', 'two', 'the inconvenient one', 'four', 'five']) {
      mirror.push(await ada.chat(text))
    }
    hidden = mirror[2]!

    // Commit first, then start lying. The order the real relay has no choice
    // about: it signs on a timer and cannot know what it will later wish it
    // had not committed to.
    point = checkpoints([relay.checkpoint(GROUP, { from: 0, to: now() + 30 })])[0]!
    relay.withhold(hidden.id)

    // A fresh reader with no memory of the channel: everything it knows about
    // this window, it got from the relay just now.
    const reader = new RelayClient({ url: relay.url, signer: LocalSigner.generate(), reconnect: false })
    await reader.connect()
    served = await reader.query([windowFilter(point)])
    reader.close()
  })
  after(async () => {
    ada.close()
    await relay.stop()
  })

  it('the relay really is serving a short set', () => {
    assert.equal(served.length, 4, 'the relay served everything — nothing is being withheld')
    assert.ok(!served.some((event) => event.id === hidden.id))
  })

  it('completeness alone says only that something is missing', () => {
    assert.deepEqual(verifyWindow(point, served), { verdict: 'short', held: 4, committed: 5 })
  })

  it('putting the event back reproduces the signed root, which names it', () => {
    const proof = withholdingProof(point, served, mirror)
    assert.ok(proof, 'no proof was produced')
    assert.deepEqual(
      proof.withheld.map((event) => event.id),
      [hidden.id],
    )
    assert.deepEqual(verifyWithholdingProof(proof), {
      proven: true,
      relay: relay.pubkey,
      group: GROUP,
      withheld: [hidden.id],
    })
  })

  it('and it holds with no relay, no keys and no network', async () => {
    // Round-tripped through JSON because that is what the artifact is for:
    // something one party sends another. Nothing in the check reads anything
    // but the bytes.
    const proof = withholdingProof(point, served, mirror)!
    await relay.stop()
    const copy = JSON.parse(JSON.stringify(proof)) as WithholdingProof
    assert.equal(verifyWithholdingProof(copy).proven, true)
  })

  describe('and the ways it has to fail', () => {
    let proof: WithholdingProof
    let elsewhen: Checkpoint

    before(() => {
      proof = withholdingProof(point, served, mirror)!
      elsewhen = checkpoints([relay.checkpoint(GROUP, { from: 10 ** 9, to: 10 ** 9 + 100 })])[0]!
    })

    it('an honest relay produces no proof at all', () => {
      // The negative control. Without it every assertion above would still
      // pass against an implementation that called everybody a liar.
      assert.equal(withholdingProof(point, mirror, mirror), undefined)
      assert.deepEqual(verifyWindow(point, mirror), { verdict: 'agrees', count: 5 })
      assert.equal(merkleRoot(mirror.map((event) => event.id)), point.body.merkle_root)
    })

    it('a forged event cannot be passed off as withheld', () => {
      // The step easiest to skip. Without it anyone could invent an event and
      // get a failure that reads as an accusation gone wrong rather than as a
      // fabrication.
      const forged: NostrEvent = { ...hidden, content: 'something else entirely' }
      const verdict = verifyWithholdingProof({ ...proof, withheld: [forged] })
      assert.equal(verdict.proven, false)
      assert.match(verdict.reason, /not validly signed/)
    })

    it('an event from outside the committed window proves nothing', () => {
      const verdict = verifyWithholdingProof({
        checkpoint: elsewhen.event,
        served: [],
        withheld: [hidden],
      })
      assert.equal(verdict.proven, false)
      assert.match(verdict.reason, /outside the committed window/)
    })

    it('an event the relay did serve is not withheld', () => {
      const verdict = verifyWithholdingProof({ ...proof, served: [...proof.served, hidden.id] })
      assert.equal(verdict.proven, false)
      assert.match(verdict.reason, /served set/)
    })

    it('no proof is offered when the arithmetic does not close', () => {
      // We hold an extra event the relay never committed to. That is a
      // disagreement, not a demonstration, and emitting a "proof" that cannot
      // be completed would be worse than emitting nothing, in the one place
      // where being wrong is expensive.
      const unrelated: NostrEvent = { ...hidden, id: 'd'.repeat(64) }
      assert.equal(withholdingProof(point, served, [unrelated]), undefined)
      assert.equal(withholdingProof(point, served, []), undefined, 'nothing held, nothing to show')
    })
  })
})
