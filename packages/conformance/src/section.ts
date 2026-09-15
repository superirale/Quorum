/**
 * How a section is written, and the three rules it enforces on every check.
 *
 * 1. **A check outside the relay's profile never runs.** It reports `n/a` with
 *    the reason the profile was ruled out, so the operator of a generic relay
 *    reads "not applicable — this relay does not validate Quorum events" rather
 *    than forty red crosses.
 * 2. **An exception is never a failure.** A thrown error means the suite could
 *    not ask the question — a socket dropped, a precondition was not met, the
 *    suite itself built something invalid — and reporting that as the relay
 *    doing the wrong thing is the accusation `report.ts` exists to prevent. It
 *    becomes `skip`, with the error attached.
 * 3. **Every check states what the relay does, in the present tense.** Not
 *    "test that…", not a rule number. The report is read by somebody deciding
 *    whether to run their workspace on this relay, and a list of assertions is
 *    not an answer to that question.
 */

import type { Check, Level, Outcome, Profile, Section } from './report.ts'
import { SuiteError, describe, type Verdict } from './harness.ts'

/** What the run knows before any section starts. */
export interface Ctx {
  profiles: Profile[]
  /** Why each absent profile is absent, as a sentence for the `n/a` detail. */
  absent: Partial<Record<Profile, string>>
  /** Emitted as each check settles, so a slow run is watchable. */
  onCheck?: (check: Check) => void
}

export interface CheckSpec {
  /** The slug half of the id; the section supplies the rest. */
  id: string
  what: string
  level: Level
  profile: Profile
  /**
   * A reason this particular check does not apply, even though its profile
   * does. Service sections use it after probing: "this relay signs no
   * checkpoints" is a configuration, not a fault.
   */
  unless?: string | false | undefined
}

export class SectionRun {
  readonly checks: Check[] = []

  // Assigned in the body rather than as parameter properties: everything here
  // runs under `node --experimental-strip-types`, which erases types without
  // compiling them, and a parameter property is syntax that has to be compiled.
  private readonly name: string
  private readonly about: string
  private readonly ctx: Ctx

  constructor(name: string, about: string, ctx: Ctx) {
    this.name = name
    this.about = about
    this.ctx = ctx
  }

  /**
   * Run one check.
   *
   * `probe` returns a {@link Verdict}: `ok` is the relay doing the right thing,
   * and `why` is recorded either way — on a pass it is the relay's own words
   * for a refusal that was supposed to happen, on a failure it is what happened
   * instead.
   */
  async check(spec: CheckSpec, probe: () => Promise<Verdict>): Promise<Verdict> {
    const base = {
      id: `${this.name}/${spec.id}`,
      what: spec.what,
      level: spec.level,
      profile: spec.profile,
      section: this.name,
    }

    if (!this.ctx.profiles.includes(spec.profile)) {
      return this.record({
        ...base,
        outcome: 'n/a',
        detail: this.ctx.absent[spec.profile] ?? `outside the ${spec.profile} profile`,
      })
    }
    if (spec.unless) {
      return this.record({ ...base, outcome: 'n/a', detail: spec.unless })
    }

    try {
      const verdict = await probe()
      return this.record({
        ...base,
        outcome: verdict.ok ? 'pass' : 'fail',
        ...(verdict.why ? { detail: verdict.why } : {}),
      })
    } catch (error) {
      // A SuiteError is this suite's own bug and is labelled as one, because an
      // operator staring at a report has no other way to tell it apart from
      // something their relay did.
      const prefix = error instanceof SuiteError ? 'suite error: ' : 'could not ask: '
      return this.record({ ...base, outcome: 'skip', detail: prefix + describe(error) })
    }
  }

  /** Record a verdict reached without a probe — an observation already made. */
  note(spec: CheckSpec, outcome: Outcome, detail?: string): void {
    void this.record({
      id: `${this.name}/${spec.id}`,
      what: spec.what,
      level: spec.level,
      profile: spec.profile,
      section: this.name,
      outcome,
      ...(detail ? { detail } : {}),
    })
  }

  done(): Section {
    return { name: this.name, about: this.about, checks: this.checks }
  }

  private record(check: Check): Verdict {
    this.checks.push(check)
    this.ctx.onCheck?.(check)
    return { ok: check.outcome === 'pass', ...(check.detail ? { why: check.detail } : {}) }
  }
}

export function section(name: string, about: string, ctx: Ctx): SectionRun {
  return new SectionRun(name, about, ctx)
}

/** `{ ok: true }` when `condition`, otherwise a failure carrying `why`. */
export function held(condition: boolean, why: string): Verdict {
  return condition ? { ok: true } : { ok: false, why }
}
