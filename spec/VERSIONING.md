# Versioning and breaking changes

The protocol version is a single `MAJOR.MINOR` string. It lives in one place —
`PROTOCOL_VERSION` in `packages/protocol/src/version.ts` — and travels on the wire in the
optional `quorum` tag. It is currently **0.1**, and the `0.` says the thing it usually says:
the kind numbers are provisional and the NIP has not merged.

This document is the written policy the version string refers to. `CHANGELOG.md` is the record
of what has actually changed under it.

## What the two numbers mean

**MINOR** — anything a deployed reader can ignore without being wrong:

- a new kind;
- a new optional field in a body;
- a new optional tag;
- a new value in an open-ended enumeration where the spec already says readers must tolerate
  unknown values;
- a relay-side service becoming available.

**MAJOR** — anything a deployed reader would get wrong by carrying on:

- removing or repurposing a kind;
- adding a required field to a body, or making an optional one required;
- changing what a tag means, including adding a marker position or changing what position 4 of
  a `p` tag signifies;
- changing a digest, canonicalisation or Merkle rule — anything that alters the bytes two
  implementations must agree on;
- narrowing what a validator accepts, which includes closing a rule that had been unenforced;
- **a forced reallocation of kind numbers**, even though nothing else about the protocol moves.
  A kind number is an identifier other people's code has hardcoded.

A MAJOR bump requires a migration note in `CHANGELOG.md` saying what an existing reader sees if
it does nothing, and what it should do instead. A bump with no such note is not finished.

## Why a reader can ignore anything at all

Two rules in the NIP make MINOR safe, and both are load-bearing rather than polite:

**Validators MUST be non-strict.** An unknown kind and an unknown body field are ignored, never
rejected. `@quorum/protocol`'s validators and the committed JSON Schemas are non-strict for
exactly this reason, and so is the Go relay reading those same schemas. A strict validator
anywhere in the chain converts every MINOR addition into a MAJOR one for everybody downstream of
it.

**Every Quorum kind carries `alt`.** A client that has never heard of a kind renders its NIP-31
fallback text rather than hiding the event, so a new kind degrades to a readable line in a thread
instead of a silent hole in one. This is the rule most likely to be skipped by an implementer in
a hurry and the most expensive to retrofit, because retrofitting it means re-publishing history.

The consequence worth stating: **a MINOR bump is only safe because of what other people's
implementations already do.** If a widely deployed client turns out to reject unknown fields, the
addition that exposed it is breaking in practice whatever this document says, and the version
number should follow the world rather than the rule.

## What is not a breaking change, and looks like one

- **Fixing a divergence between two implementations of the same rule.** If the TypeScript
  validator enforced something the Go relay did not, making the relay enforce it is not a new
  rule — it is the existing rule reaching a second implementation. It still gets a changelog
  entry, because from the outside it is indistinguishable from a narrowing; see the 2026-09-15
  entry, which is the fourth time this has happened.
- **Adding a conformance check.** The suite asking a question it had not asked before does not
  change the protocol. A relay that starts failing was already non-conformant.
- **Relaxing a validator.** Accepting something previously refused breaks no reader that was
  already refusing to produce it.

## How a change lands

In this order, because every reversal of it has cost something:

1. **Write the spec text first.** M10's whole framing was wrong until the spec pass corrected it,
   and that pass happened before any MLS code existed.
2. **Change `packages/protocol`**, regenerate `schemas/` — including `schemas/index.json`, which
   publishes the envelope requirements, the resource names, `UNSEALED_KINDS` and the cross-field
   rule table as *data*. This is how a rule reaches the Go relay and `scripts/validate.py`
   without being hand-copied into either.
3. **Add a probe to `packages/conformance`** if the rule is one a relay enforces. The cross-field
   section is driven by the published table, so a new rule with no probe fails the section rather
   than quietly going unasked.
4. **Bump `PROTOCOL_VERSION`** and write the changelog entry.

A rule that exists in one language is a rule the other implementation does not have. That
sentence is the title of a commit and the summary of four separate incidents: `ConfirmResourceNames`,
`UNSEALED_KINDS` drift, `RejectMlsPolicyEpoch`, and the two cross-field rules the conformance
suite found. Publishing rules as data is the only mechanism here that has actually stopped it.

## Stability promises

- **Conformance check ids are stable across versions.** `encryption/enc-without-policy` means the
  same thing in a year, because the useful sentence in a bug report is "your relay fails this
  check" and not "check 19".
- **The committed schemas and fixtures are part of the spec, not test data.** A second
  implementation validating against `schemas/` and `fixtures/` is validating against the
  normative artefact. Changing a fixture's bytes is a spec change.
- **`spec/nip-quorum.md` is the document that would be submitted as a NIP.** Anything in it that
  the repository does not implement is a defect in one of the two, and the spec is not where the
  discrepancy gets resolved quietly.

## Until the NIP merges

Kind numbers in the 8100/28100/38100 ranges were checked free against the registry of kinds on
2026-09-11 and are re-checkable with `pnpm --filter @quorum/protocol check-registry`. They are
provisional. If the registry forces a reallocation, that is a MAJOR bump with a migration note,
and it is the single most likely MAJOR bump this protocol will ever have.
