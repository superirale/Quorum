/**
 * The suite, run end to end against a relay that has never heard of Quorum.
 *
 * This is the fixture the whole package is shaped around, and it is not here to
 * exercise the code paths. `FakeRelay` implements NIP-01, NIP-42 and the four
 * kind ranges and *nothing else* — no NIP-29 membership, no Quorum validation,
 * no policies at all — which makes it the closest thing in this repo to the
 * generic relay Option A is a promise about. So:
 *
 * - **It must come out conformant.** A generic relay carrying every Quorum kind
 *   is the central design claim, and a suite that marked it down would be
 *   reporting the protocol's own thesis as a defect. Every `quorum` check must
 *   land on `n/a` with a reason, and not one on `fail`.
 * - **It is the control against the suite becoming reference-relay-shaped.** A
 *   conformance suite developed only against the implementation it ships with
 *   ends up testing that implementation's habits: a tag order, an error string,
 *   a projection nobody else offers. Running here every time is what keeps the
 *   checks about the spec.
 * - **And it must not report a dead relay as a perfect one**, which is the
 *   failure mode a suite made mostly of refusal checks has by construction. The
 *   last test points the same run at a relay that refuses everything and
 *   requires it to stop and say so.
 */

import assert from 'node:assert/strict'
import { after, before, describe, it } from 'node:test'
import { FakeRelay } from '@quorum/test-kit'
import { conformant, render, tally, toJson } from '../src/report.ts'
import { run } from '../src/run.ts'
import type { Check, Report } from '../src/report.ts'

/** Short, because nothing relay-authored is ever coming on this fixture. */
const PATIENCE_MS = 1200

function allChecks(report: Report): Check[] {
  return report.sections.flatMap((section) => section.checks)
}

describe('a generic relay', () => {
  let relay: FakeRelay
  let report: Report

  before(async () => {
    relay = await FakeRelay.start()
    report = await run({ url: relay.url, patienceMs: PATIENCE_MS })
  })

  after(async () => {
    await relay.stop()
  })

  it('is conformant, which is the whole of Option A', () => {
    const failures = allChecks(report).filter((c) => c.outcome === 'fail' && c.level === 'MUST')
    assert.deepEqual(
      failures.map((c) => `${c.id}: ${c.detail}`),
      [],
      'a relay implementing no Quorum policy at all must still carry every Quorum event',
    )
    assert.equal(conformant(report), true)
  })

  it('fails a SHOULD and is conformant anyway', () => {
    // The fixture serves no NIP-11 document, which is a real shortcoming with
    // real consequences — no pubkey means no checkpoint verification and no
    // packer to address — and it is a SHOULD, so it prints in red and exits
    // zero. Pinned rather than tolerated: a SHOULD that failed a run would be a
    // MUST with a gentler name, and the spec would then be lying about which
    // is which. If this ever starts passing, the assertion below is what says
    // the SHOULD/MUST split is no longer being exercised at all.
    const soft = allChecks(report).filter((c) => c.outcome === 'fail')
    assert.deepEqual(
      soft.map((c) => c.id),
      ['discovery/nip11'],
    )
    assert.equal(soft[0]!.level, 'SHOULD')
    assert.equal(conformant(report), true)
  })

  it('is detected as generic rather than assumed to be one', () => {
    assert.deepEqual(report.implements, ['any'])
    const envelope = report.sections.find((s) => s.name === 'envelope')
    assert.ok(envelope, 'the envelope section ran')
    const alt = envelope.checks.find((c) => c.id === 'envelope/alt')
    assert.ok(alt, 'the alt check is in the report even though it does not apply')
    assert.equal(alt.outcome, 'n/a')
    assert.match(String(alt.detail), /generic relay/)
  })

  it('stores and serves back one honest event of every kind', () => {
    const interop = report.sections.find((s) => s.name === 'interop')
    assert.ok(interop)
    const stores = interop.checks.filter((c) => c.id.startsWith('interop/stores-'))
    assert.ok(stores.length > 0, 'the interop section published specimens')
    assert.deepEqual(
      stores.filter((c) => c.outcome !== 'pass').map((c) => c.id),
      [],
    )
  })

  it('rules out every Quorum-policy check with a reason rather than a cross', () => {
    const quorum = allChecks(report).filter((c) => c.profile === 'quorum')
    assert.ok(quorum.length > 20, `only ${quorum.length} quorum checks — has a section stopped early?`)
    for (const check of quorum) {
      assert.equal(check.outcome, 'n/a', `${check.id} ran against a relay outside its profile`)
      assert.ok(check.detail, `${check.id} was ruled out with no reason given`)
    }
  })

  it('asks every question it says it asks', () => {
    // A `skip` is this suite failing to ask, not the relay failing to answer,
    // and against a fixture with no moving parts there is nothing legitimate
    // to be blocked by. Every one is a bug here.
    const skipped = allChecks(report).filter((c) => c.outcome === 'skip')
    assert.deepEqual(
      skipped.map((c) => `${c.id}: ${c.detail}`),
      [],
    )
  })

  it('offers no relay-side service, and says so for each one separately', () => {
    // Not one answer for all three: the thread projection, checkpoints and the
    // context DVM are separately configurable, so a single detected verdict
    // would be wrong for most real deployments.
    const services = allChecks(report).filter((c) => c.profile === 'service')
    assert.ok(services.length > 0)
    assert.deepEqual(
      services.filter((c) => c.outcome === 'pass' || c.outcome === 'fail').map((c) => c.id),
      [],
    )
    const reasons = new Set(services.map((c) => c.detail))
    assert.ok(reasons.size > 1, 'every service was ruled out by the same sentence')
  })

  it('renders a report that names what was not asked as well as what was', () => {
    const text = render(report)
    assert.match(text, /Quorum conformance/)
    assert.match(text, /conformant/)
    assert.doesNotMatch(text, /not conformant/)
    // `n/a` lines are hidden without --verbose and listed with it; the list of
    // things a relay does not do is most of what a reader wants.
    assert.ok(render(report, { verbose: true }).length > text.length)
  })

  it('serialises to JSON a CI job can diff check by check', () => {
    const parsed = JSON.parse(toJson(report)) as Report
    assert.equal(parsed.url, relay.url)
    assert.deepEqual(
      allChecks(parsed).map((c) => c.id),
      allChecks(report).map((c) => c.id),
    )
    // Ids are unique, or "your relay fails encryption/leak" names two things.
    const ids = allChecks(parsed).map((c) => c.id)
    assert.equal(new Set(ids).size, ids.length)
  })

  it('counts MUST, SHOULD and MAY apart', () => {
    const must = tally(report, 'MUST')
    assert.ok(must.passed > 0)
    assert.equal(must.failed, 0)
    assert.ok(must.notApplicable > 0, 'a generic relay must have MUST checks ruled out, not passed')
  })
})

describe('a relay that refuses everything', () => {
  it('is reported as a run that did not happen, not as a run that went well', async () => {
    // The failure mode this whole suite has by construction: most of it is
    // refusal checks, and a relay that is down refuses everything. Without this
    // stop, an unreachable relay scores better than a real one.
    const relay = await FakeRelay.start({ reject: () => 'this relay is not accepting events' })
    try {
      const report = await run({ url: relay.url, patienceMs: PATIENCE_MS })
      assert.equal(conformant(report), false)
      const stop = allChecks(report).find((c) => c.id === 'run/reachable')
      assert.ok(stop, 'the run recorded why it stopped')
      assert.equal(stop.outcome, 'fail')
      // And it stopped: the refusal sections must never have run, because each
      // of them would have passed.
      assert.deepEqual(
        report.sections.map((s) => s.name),
        ['interop', 'run'],
      )
    } finally {
      await relay.stop()
    }
  })
})
