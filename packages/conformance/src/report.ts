/**
 * What a conformance run says, and what it deliberately refuses to say.
 *
 * The temptation with a suite like this is one number: "37/42, 88% conformant".
 * That number is meaningless here, and the reason is Option A. Quorum's central
 * claim is that **every Quorum event is valid on any generic relay** — so a
 * plain strfry with no idea what a kind 8102 is *passes the claim that matters*
 * and fails every relay-policy check in this file. Scored naively it looks
 * broken. It is not: it is doing exactly what Option A asks of it.
 *
 * So results are grouped by {@link Profile} rather than totalled, and a check
 * outside the profile a relay implements is reported as {@link Outcome} `n/a`
 * with the reason attached. A suite that cannot tell "this relay does not
 * claim to do X" from "this relay claims X and gets it wrong" would accuse
 * honest implementations, and the first false accusation is the last time
 * anybody reads the output. That is the same rule the withholding proof in
 * `packages/sdk/src/checkpoints.ts` is built around, arriving in a second place.
 */

/** Who a check applies to. */
export type Profile =
  /**
   * Option A: true of *every* relay, generic or Quorum. A failure here means
   * Quorum events cannot live on this relay at all, which is the one result
   * that invalidates the protocol's central design decision rather than the
   * relay's configuration.
   */
  | 'any'
  /**
   * A relay that validates Quorum events and enforces the policies in the NIP.
   * Detected rather than assumed — see `detectProfile` in `harness.ts`. A
   * generic relay reports `n/a` here and is not penalised.
   */
  | 'quorum'
  /**
   * Relay-side services the spec allows a relay to offer and never requires:
   * the thread projection, checkpoints, the context DVM. Absence is a valid
   * configuration, so these report `n/a` when a relay does not offer them and
   * `fail` only when it offers one and gets it wrong.
   */
  | 'service'

/** How strongly the spec asks for it, in RFC 2119 terms. */
export type Level = 'MUST' | 'SHOULD' | 'MAY'

export type Outcome =
  | 'pass'
  /** The relay did the wrong thing. Only this is an accusation. */
  | 'fail'
  /** Not applicable: outside the profile this relay implements. */
  | 'n/a'
  /** Could not be run — a missing precondition, not a verdict on the relay. */
  | 'skip'

export interface Check {
  /**
   * A stable, citable identifier: `section/slug`. Stable across versions on
   * purpose, because the useful thing to be able to say in a bug report is
   * "your relay fails `encryption/enc-needs-policy`" rather than "check 19".
   */
  id: string
  /** One line, in the present tense, stating what the relay does. */
  what: string
  level: Level
  profile: Profile
  /** The `spec/nip-quorum.md` heading this check is derived from. */
  section: string
  outcome: Outcome
  /**
   * Why, in the relay's own words where there are any.
   *
   * A refusal check records the reject message the relay sent rather than
   * paraphrasing it, because the message is the part an operator has to act on
   * and a friendlier summary written here would be hiding what they are
   * actually going to see.
   */
  detail?: string
}

export interface Section {
  name: string
  /** One sentence on what this group of checks is about. */
  about: string
  checks: Check[]
}

export interface Report {
  url: string
  /** The relay's NIP-11 document, as far as it served one. */
  relay: RelayInfo
  /** Which profiles this relay was found to implement. */
  implements: Profile[]
  sections: Section[]
  /** Protocol version the suite was built from, not the relay's. */
  suite: string
}

export interface RelayInfo {
  name?: string
  description?: string
  software?: string
  version?: string
  pubkey?: string
  supported_nips?: number[]
}

/** Counts, by level, over the checks that actually applied. */
export interface Tally {
  passed: number
  failed: number
  skipped: number
  notApplicable: number
}

export function tally(report: Report, level: Level): Tally {
  const counts: Tally = { passed: 0, failed: 0, skipped: 0, notApplicable: 0 }
  for (const section of report.sections) {
    for (const check of section.checks) {
      if (check.level !== level) continue
      if (check.outcome === 'pass') counts.passed += 1
      else if (check.outcome === 'fail') counts.failed += 1
      else if (check.outcome === 'skip') counts.skipped += 1
      else counts.notApplicable += 1
    }
  }
  return counts
}

/**
 * Did anything the relay claims to do turn out to be wrong?
 *
 * Only a failed MUST counts, and only inside a profile this relay was detected
 * to implement — a `n/a` never fails a run. A failed SHOULD is printed loudly
 * and exits zero, because a SHOULD that exits non-zero is a MUST with a softer
 * name, and the spec would then be lying about which is which.
 */
export function conformant(report: Report): boolean {
  return tally(report, 'MUST').failed === 0
}

const GREEN = '\x1b[32m'
const RED = '\x1b[31m'
const YELLOW = '\x1b[33m'
const DIM = '\x1b[2m'
const BOLD = '\x1b[1m'
const OFF = '\x1b[0m'

const MARK: Record<Outcome, string> = {
  pass: `${GREEN}✔${OFF}`,
  fail: `${RED}✘${OFF}`,
  'n/a': `${DIM}–${OFF}`,
  skip: `${YELLOW}?${OFF}`,
}

/**
 * The section-by-section report, as text.
 *
 * `n/a` checks are listed rather than hidden, because the list of things a
 * relay does *not* do is most of what somebody choosing a relay wants to know,
 * and a report that silently omitted them would read as a clean bill of health
 * for a relay that enforces nothing.
 */
export function render(report: Report, options: { verbose?: boolean } = {}): string {
  const out: string[] = []
  const info = report.relay

  out.push(`${BOLD}Quorum conformance${OFF} — ${report.url}`)
  out.push(
    `${DIM}${[
      info.name ?? 'unnamed relay',
      info.software ? info.software.replace(/^https?:\/\//, '') : undefined,
      info.version ? `protocol ${info.version}` : undefined,
      info.supported_nips?.length ? `NIPs ${info.supported_nips.join(', ')}` : undefined,
    ]
      .filter(Boolean)
      .join(' · ')}${OFF}`,
  )
  out.push(`${DIM}suite ${report.suite} · profiles ${report.implements.join(', ')}${OFF}`)
  out.push('')

  for (const section of report.sections) {
    const applicable = section.checks.filter((c) => c.outcome !== 'n/a')
    const failed = applicable.filter((c) => c.outcome === 'fail').length
    const heading =
      applicable.length === 0
        ? `${DIM}not offered${OFF}`
        : failed === 0
          ? `${GREEN}${applicable.filter((c) => c.outcome === 'pass').length}/${applicable.length}${OFF}`
          : `${RED}${failed} failed${OFF}`

    out.push(`${BOLD}${section.name}${OFF}  ${heading}`)
    out.push(`  ${DIM}${section.about}${OFF}`)
    for (const check of section.checks) {
      if (check.outcome === 'n/a' && !options.verbose) continue
      out.push(`  ${MARK[check.outcome]} ${check.what}  ${DIM}${check.level} · ${check.id}${OFF}`)
      if (check.detail && (check.outcome !== 'pass' || options.verbose)) {
        out.push(`      ${DIM}${check.detail}${OFF}`)
      }
    }
    out.push('')
  }

  const must = tally(report, 'MUST')
  const should = tally(report, 'SHOULD')
  const may = tally(report, 'MAY')
  out.push(
    `${BOLD}MUST${OFF} ${must.passed} passed, ${must.failed} failed · ` +
      `${BOLD}SHOULD${OFF} ${should.passed} passed, ${should.failed} failed · ` +
      `${BOLD}MAY${OFF} ${may.passed} offered, ${may.notApplicable + may.skipped} not`,
  )
  out.push(
    conformant(report)
      ? `${GREEN}conformant${OFF} for ${report.implements.join(' + ')}`
      : `${RED}not conformant${OFF}: ${must.failed} MUST ${must.failed === 1 ? 'check' : 'checks'} failed`,
  )
  if (must.skipped + should.skipped > 0) {
    out.push(
      `${DIM}${must.skipped + should.skipped} skipped — a missing precondition, not a verdict${OFF}`,
    )
  }
  return out.join('\n')
}

/**
 * The same report as JSON, for a CI job that wants to diff two runs.
 *
 * Deliberately the whole structure rather than a summary: the interesting diff
 * between two versions of a relay is which individual check changed, and a
 * summary cannot answer that.
 */
export function toJson(report: Report): string {
  return JSON.stringify(report, null, 2)
}
