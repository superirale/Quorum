/**
 * What CI is allowed to conclude from a conformance report.
 *
 * The suite's own exit code answers one question — did a MUST fail — and that
 * is the right thing for it to answer, because it is pointed at somebody
 * else's relay and a SHOULD that exits non-zero is a MUST with a softer name.
 * CI is pointed at *this* relay, which is a different position to argue from:
 * we know which SHOULDs it fails and why, and we know which checks cannot run
 * against a workspace created seconds ago. So the two things the exit code
 * cannot say are said here.
 *
 * The failure this exists to catch is a green run that asked nothing. A check
 * that throws becomes `skip`, a profile the probe fails to detect turns forty
 * checks into `n/a`, and both of those exit zero. That is the suite being
 * careful — it must never report its own bug as somebody's non-conformance —
 * and it is exactly why the count has to be pinned from outside.
 *
 * Usage: node conformance-gate.mjs <report.json>
 */

import { readFileSync } from 'node:fs'

/**
 * SHOULDs the reference relay is known to fail, each with the reason it is
 * still open. Written out rather than counted, because "one SHOULD failure" is
 * satisfied by a different one.
 *
 * `interop/keeps-deletions`: khatru v0.17.7 branches on kind 5 in its message
 * loop (handlers.go:215-221) and calls handleDeleteRequest instead of
 * AddEvent, so no RejectEvent policy runs and the request is never stored —
 * which NIP-09 asks a relay to keep serving. Unfixable on the pin; see
 * apps/relay/README.md, Known gaps.
 */
const KNOWN_FAILURES = new Set(['interop/keeps-deletions'])

/**
 * Checks that cannot run against a workspace this run created, with the reason
 * each one is unreachable rather than merely absent.
 *
 * The four `ordering/*` ones are arithmetic, not impatience: a window may only
 * be signed once it can no longer receive an honest event, so the relay closes
 * windows a clock-skew behind the present and cuts one every 300s. A six-second
 * run has no closed window and waiting longer does not produce one. They are
 * covered by the second, documented recipe in packages/conformance/README.md —
 * --group and --key against a workspace with history — which is a separate run.
 *
 * `cross-field/bad_thread_d` is unreachable by anyone: kind 38101 is
 * relay-signed, so there is no client that can publish a malformed one to ask
 * the question with.
 */
const KNOWN_NOT_APPLICABLE = new Set([
  'ordering/checkpoints',
  'ordering/author',
  'ordering/window',
  'ordering/chain',
  'cross-field/bad_thread_d',
])

/** Profiles the reference relay must be *detected* to implement. */
const REQUIRED_PROFILES = ['any', 'quorum']

const path = process.argv[2]
if (!path) {
  console.error('usage: conformance-gate.mjs <report.json>')
  process.exit(2)
}

let report
try {
  report = JSON.parse(readFileSync(path, 'utf8'))
} catch (error) {
  // Distinguished from a failing relay on purpose. An unparseable or missing
  // report means the run did not happen — the relay never came up, the suite
  // threw on connect, or pnpm's banner landed on stdout — and reporting that
  // as non-conformance would be the accusation the suite is built to avoid.
  console.error(`the run did not happen: no readable report at ${path}`)
  console.error(`  ${error.message}`)
  process.exit(2)
}

const checks = report.sections.flatMap((section) => section.checks)
const problems = []

for (const profile of REQUIRED_PROFILES) {
  if (!report.implements?.includes(profile)) {
    problems.push(
      `the '${profile}' profile was not detected, so every check in it reported n/a and passed ` +
        `for the wrong reason. detectProfile probes with a kind 8104 missing its alt tag; ` +
        `implements was [${(report.implements ?? []).join(', ')}]`,
    )
  }
}

for (const check of checks) {
  if (check.outcome === 'fail' && check.level === 'MUST') {
    problems.push(`MUST failed: ${check.id} — ${check.detail ?? check.what}`)
  } else if (check.outcome === 'fail' && !KNOWN_FAILURES.has(check.id)) {
    problems.push(`${check.level} failed and is not a known gap: ${check.id} — ${check.detail ?? check.what}`)
  } else if (check.outcome === 'skip') {
    // Never a verdict on the relay, always a question that went unasked.
    problems.push(`not asked: ${check.id} — ${check.detail ?? check.what}`)
  } else if (check.outcome === 'n/a' && !KNOWN_NOT_APPLICABLE.has(check.id)) {
    problems.push(
      `n/a and not in the known set: ${check.id} — ${check.detail ?? check.what}. ` +
        `If this is a new optional check, add it to KNOWN_NOT_APPLICABLE with the reason it ` +
        `cannot run here; if it is not, the relay stopped offering something it used to.`,
    )
  }
}

for (const id of KNOWN_FAILURES) {
  if (!checks.some((check) => check.id === id && check.outcome === 'fail')) {
    problems.push(
      `${id} is listed as a known gap and did not fail. If it was fixed, delete it from ` +
        `KNOWN_FAILURES here and from Known gaps in apps/relay/README.md.`,
    )
  }
}

const counted = checks.filter((check) => check.outcome === 'pass').length
if (problems.length === 0) {
  console.log(`conformance: ${counted} checks passed, ${KNOWN_FAILURES.size} known gap(s), nothing skipped`)
  process.exit(0)
}

console.error(`conformance gate failed (${problems.length}):`)
for (const problem of problems) console.error(`  - ${problem}`)
process.exit(1)
