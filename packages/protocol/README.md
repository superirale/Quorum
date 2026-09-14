# @quorum/protocol

Kind allocation, tag conventions, validators and JSON Schema for Quorum — an
agent-first messaging protocol on Nostr.

This package is the normative artifact. The NIP text in [`spec/nip-quorum.md`](../../spec/nip-quorum.md)
explains the design; this package is what implementations validate against.

## Install

```sh
pnpm add @quorum/protocol
```

## What's in here

| Path | |
| --- | --- |
| `src/kinds.ts` | Kind allocation, checked against the registry of kinds |
| `src/tags.ts` | Tag names, the `to` address marker, readers and writers |
| `src/event.ts` | NIP-01 event schema, id computation, signature verification |
| `src/digest.ts` | RFC 8785 canonical JSON and content digests |
| `src/bodies/*.ts` | Zod schema for every kind's `content` body |
| `src/validate.ts` | Three-layer validation, returns structured issues |
| `src/build.ts` | Construct valid unsigned events |
| `src/alt.ts` | Fallback-text rules and defaults |
| `src/resources.ts` | The capability resource names, including the three the relay enforces |
| `src/merkle.ts` | `sha256-merkle-sorted-v1`, the tree a checkpoint commits with |
| `src/cost.ts` | Adding up what a task cost and deciding when it has cost enough |
| `src/nip44.ts` | NIP-44 v2, implemented against the reference vectors |
| `src/seal.ts` | Sealing an event: the derived nonce, and which kinds stay in the clear |
| `src/mls.ts` | The `mls` envelope: the three bindings between an MLSMessage and its event. No RFC 9420 — the ratchet is the SDK's |
| `src/mls-keys.ts` | The KeyPackage event (30443): its tag contract, the `0x`-hex id lists, and a parser that refuses every other spelling |
| `src/bodies/encryption.ts` | The channel policy (38107), the wrapped channel key (8110), the MLS Welcome (8111) and the MLS commit (8112) |
| `schemas/` | **Generated, committed.** JSON Schema for every body |
| `fixtures/` | **Generated, committed.** A signed golden transcript, the Merkle vectors, and `nip44-v2.json` |

## Usage

```ts
import { build, digest, validateEvent, RegularKinds } from '@quorum/protocol'

const input = { service: 'api', version: '1.4.2' }

const unsigned = build({
  kind: RegularKinds.Action,
  pubkey: agentPubkey,
  group: 'payments',
  thread: threadRoot,          // { id, pubkey, kind } of the kind-11 root
  to: [humanPubkey],           // `p` tags with the `to` marker
  counter: 7,                  // per-author; gap detection needs it
  body: {
    name: 'deploy.production',
    status: 'proposed',
    summary: 'Deploy api v1.4.2 to production',
    input,
    input_digest: digest(input),
  },
})

const result = validateEvent(signed, { verifySignature: true })
if (!result.valid) console.error(result.issues)
```

`build()` returns an **unsigned** event. Signing belongs to the SDK, which owns
the signer abstraction (local key / NIP-07 / NIP-46); a protocol package that
touched private keys would have to take a position on key custody, and it has no
business doing that.

`build()` fills the NIP-22 scope tags, generates an `alt` from the body if you
don't supply one, serialises the body as canonical JSON, and validates before
returning — so a body that fails its schema is a build-time error rather than an
event someone else has to reject.

You compute `input_digest` yourself with `digest()`. It is not filled in for you,
because the digest must cover the input the caller actually intends to execute —
deriving it from whatever happened to be in the body would make it a restatement
of that body rather than an independent commitment to it, and an approval bound
to a self-derived digest attests to nothing.

### Validation has three layers

Because on encrypted channels only the first two are available.

```ts
parseNostrEvent(input)    // 1. is it a Nostr event at all (NIP-01)
validateEnvelope(event)   // 2. tag rules — works on encrypted events
validateBody(event)       // 3. content against its schema — plaintext only
```

Issues carry stable machine-readable codes (`not_addressed`, `bad_parent_kind`,
`missing_input_digest`, …) rather than prose, and are returned rather than
thrown: a relay validating a stream needs to reject one event and carry on, not
unwind.

## Generated files are committed

`schemas/` and `fixtures/` are checked into git on purpose.

The JSON Schema is what a Go relay, a Rust agent or a Python harness validates
against, and none of them can run Zod. Generated at install time it would exist
only inside TypeScript's world — precisely the world it is meant to escape.
Committed, protocol drift shows up in review as a diff on a schema file instead
of as a surprise in someone else's implementation. A test fails if they are
stale.

`schemas/index.json` also publishes the per-kind envelope requirements
(`threaded`, `addressed`, `parentKind`) as data, so other languages enforce the
same table rather than a hand-copied version of it that drifts.

```sh
pnpm --filter @quorum/protocol schemas    # regenerate schemas/
pnpm --filter @quorum/protocol fixtures   # regenerate fixtures/
```

## Cross-language check

The point of the JSON Schema is that another language can use it. That claim is
tested rather than asserted:

```sh
pnpm --filter @quorum/protocol test:python
```

`scripts/validate.py` uses only the Python standard library and reads only
`schemas/` and `fixtures/` — never `src/`. If it ever needs to import from the
TypeScript, the protocol is not actually language-independent and this claim is
false.

Its `--self-test` mode tampers with the golden transcript eight ways and requires
every one to be rejected. Seven of the eight recompute the event id after
mutating, which is the whole point: leave the stale id in place and the id check
catches everything, proving only that sha256 works while the envelope and body
rules go untested.

It verifies well-formedness, not authenticity — schnorr verification needs
secp256k1, which is not in the standard library. Use `verifyEvent()` or any Nostr
library for that.

## Tests

```sh
pnpm --filter @quorum/protocol test
```

## Version

Kind numbers are provisional until the NIP PR merges. See `src/version.ts` for
the full versioning policy; briefly, a new kind or optional field is MINOR, and
anything that could break a deployed reader is MAJOR.
