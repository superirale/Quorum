/**
 * `@quorum/conformance` — is this relay one a Quorum workspace can run on?
 *
 * The library half of the same thing `npx @quorum/conformance <url>` does, for
 * a CI job that wants the structure rather than the text. {@link run} returns a
 * {@link Report}; {@link render} turns one into the terminal output, and
 * {@link conformant} answers the only yes/no question the suite is willing to
 * answer.
 *
 * There is deliberately no score. See the header of `report.ts`: under Option A
 * a generic relay that has never heard of Quorum passes the claim that matters
 * and fails every relay-policy check, so a percentage would rank it below a
 * broken Quorum relay.
 */

export { run, type RunOptions } from './run.ts'
export {
  conformant,
  render,
  tally,
  toJson,
  type Check,
  type Level,
  type Outcome,
  type Profile,
  type RelayInfo,
  type Report,
  type Section,
  type Tally,
} from './report.ts'
export { Session, SuiteError, type SessionOptions, type Verdict } from './harness.ts'
export { specimens, type Specimen, type SpecimenSet } from './specimens.ts'
