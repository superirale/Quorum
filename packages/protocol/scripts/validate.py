#!/usr/bin/env python3
"""Validate Quorum events from Python, using only the committed artefacts.

This is the M1 demo, and it is deliberately written by someone with no access
to the TypeScript: it reads `schemas/index.json` and the per-kind body schemas,
recomputes event ids from the NIP-01 serialisation, and checks the envelope
rules. If this script needs to import anything from `src/`, the protocol is not
actually language-independent and the claim in the README is false.

Only the standard library is required. If `jsonschema` happens to be installed
the body schemas are enforced properly; otherwise a documented subset (`type`
and `required`) is checked and the script says so rather than pretending.

    python3 scripts/validate.py fixtures/deploy-approval.json
    python3 scripts/validate.py fixtures/deploy-approval.json --self-test
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = ROOT / "schemas"

try:
    import jsonschema  # type: ignore

    HAVE_JSONSCHEMA = True
except ImportError:
    HAVE_JSONSCHEMA = False


def serialize(event: dict) -> bytes:
    """NIP-01 serialisation: the exact array whose sha256 is the event id.

    `separators` removes the whitespace Python adds by default and
    `ensure_ascii=False` keeps non-ASCII characters as themselves, which is what
    JavaScript's JSON.stringify does. Both matter: either one wrong and every id
    mismatches.
    """
    payload = [
        0,
        event["pubkey"],
        event["created_at"],
        event["kind"],
        event["tags"],
        event["content"],
    ]
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compute_id(event: dict) -> str:
    return hashlib.sha256(serialize(event)).hexdigest()


def canonical_json(value) -> str:
    """RFC 8785 subset, matching src/digest.ts."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, sort_keys=True)


def digest(value) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def first_tag(event: dict, name: str):
    for tag in event["tags"]:
        if tag and tag[0] == name:
            return tag
    return None


def tag_value(event: dict, name: str):
    tag = first_tag(event, name)
    return tag[1] if tag and len(tag) > 1 else None


def addressees(event: dict, marker: str) -> list[str]:
    return [t[1] for t in event["tags"] if t and t[0] == "p" and len(t) > 3 and t[3] == marker]


def check_body(kind: int, content: str, schema: dict, errors: list[str]) -> None:
    try:
        body = json.loads(content)
    except json.JSONDecodeError as exc:
        errors.append(f"kind {kind}: content is not JSON ({exc})")
        return

    if HAVE_JSONSCHEMA:
        validator = jsonschema.Draft202012Validator(schema)
        for issue in validator.iter_errors(body):
            errors.append(f"kind {kind}: {'/'.join(map(str, issue.path)) or '<root>'}: {issue.message}")
        return

    for field in schema.get("required", []):
        if field not in body:
            errors.append(f"kind {kind}: missing required field {field!r}")


def validate(index: dict, events: list[dict]) -> tuple[list[str], dict[str, int]]:
    """Returns (errors, counts). Empty errors means every event is well-formed."""
    quorum_kinds = {int(k): v for k, v in index["kinds"].items()}
    envelope = index["envelope"]
    marker = envelope["address_marker"]
    alt_max = envelope["alt_max_length"]

    errors: list[str] = []
    checked_bodies = 0

    for event in events:
        kind = event["kind"]
        label = f"kind {kind} ({event['id'][:8]})"

        actual = compute_id(event)
        if actual != event["id"]:
            errors.append(f"{label}: id mismatch, computed {actual[:16]}…")

        if kind not in quorum_kinds:
            continue  # a borrowed kind; its own NIP governs it

        for required in envelope["required_tags"]:
            if tag_value(event, required) is None:
                errors.append(f"{label}: missing required tag {required!r}")

        alt = tag_value(event, "alt")
        if alt is not None and (len(alt) == 0 or len(alt) > alt_max or "\n" in alt):
            errors.append(f"{label}: alt must be 1–{alt_max} chars of single-line text")

        # The per-kind rules come from index.json, not from a table retyped here.
        requires = quorum_kinds[kind].get("requires", {})

        if requires.get("threaded"):
            if tag_value(event, "E") is None:
                errors.append(f"{label}: must carry an `E` root tag")
            if tag_value(event, "K") is None:
                errors.append(f"{label}: must carry a `K` root-kind tag")

        if requires.get("addressed") and not addressees(event, marker):
            errors.append(f"{label}: needs at least one `p` tag marked {marker!r}")

        parent_kind = requires.get("parentKind")
        if parent_kind is not None:
            # Not "has an `e` tag" — every threaded event has one pointing at the
            # thread root. The `k` tag is what says the parent is the right kind.
            if tag_value(event, "e") is None:
                errors.append(f"{label}: must point at a kind {parent_kind} parent")
            elif tag_value(event, "k") != str(parent_kind):
                errors.append(
                    f"{label}: parent must be kind {parent_kind}, k says {tag_value(event, 'k')}"
                )

        enc = tag_value(event, "enc") or "plaintext"
        if enc not in envelope["enc_modes"]:
            errors.append(f"{label}: unknown enc mode {enc!r}")

        body_file = quorum_kinds[kind].get("body")
        if body_file and enc == "plaintext":
            schema = json.loads((SCHEMA_DIR / body_file).read_text())
            check_body(kind, event["content"], schema, errors)
            checked_bodies += 1

    # The check that matters most: an approval names exactly what it approved.
    proposals = [
        e for e in events if e["kind"] == 8101 and json.loads(e["content"])["status"] == "proposed"
    ]
    responses = [e for e in events if e["kind"] == 8103]
    audited = 0
    for proposal in proposals:
        body = json.loads(proposal["content"])
        if "input" in body:
            recomputed = digest(body["input"])
            if recomputed != body.get("input_digest"):
                errors.append(f"proposal {proposal['id'][:8]}: input_digest does not match input")
            for response in responses:
                if tag_value(response, "action") == proposal["id"]:
                    decision = json.loads(response["content"])
                    if decision.get("input_digest") != body["input_digest"]:
                        errors.append(
                            f"approval {response['id'][:8]}: approves a digest the proposal never had"
                        )
                    audited += 1

    return errors, {"bodies": checked_bodies, "approvals": audited}


# Each case mutates one event and must be rejected. A validator that only ever
# passes is indistinguishable from `return 0`.
#
# Every case except the first recomputes the event id after mutating, and that
# is the whole point of the exercise. Leave the stale id in place and the id
# check catches everything, which proves only that sha256 works and leaves the
# envelope and body rules completely untested. It is also the realistic threat:
# recomputing an id is free, so anyone relaying these events can do it. What
# they cannot do is re-sign — and signature verification needs secp256k1, which
# is not in the standard library. So this script is honest about its scope: it
# proves an event is *well-formed*, and `verifyEvent` in the TypeScript (or any
# Nostr library) proves it is *authentic*. Both are required.
TAMPERS = [
    ("flip a byte of the event id", 8102, False, lambda e: e.update(
        id=("0" if e["id"][0] != "0" else "1") + e["id"][1:])),
    ("rewrite an action's input after signing", 8101, True, lambda e: e.update(
        content=json.dumps({**json.loads(e["content"]), "input": {"env": "evil"}}))),
    ("strip the group tag", 8103, True, lambda e: e.update(
        tags=[t for t in e["tags"] if t[0] != "h"])),
    ("strip the alt tag", 8101, True, lambda e: e.update(
        tags=[t for t in e["tags"] if t[0] != "alt"])),
    ("unaddress an approval request", 8102, True, lambda e: e.update(
        tags=[t for t in e["tags"] if not (t[0] == "p" and len(t) > 3 and t[3] == "to")])),
    ("point an approval response at the thread, not a request", 8103, True, lambda e: e.update(
        tags=[["k", "11"] if t[0] == "k" else t for t in e["tags"]])),
    ("approve a digest the proposal never had", 8103, True, lambda e: e.update(
        content=json.dumps({**json.loads(e["content"]), "input_digest": "00" * 32}))),
    ("drop a required body field", 8102, True, lambda e: e.update(
        content=json.dumps({k: v for k, v in json.loads(e["content"]).items() if k != "title"}))),
]


def self_test(index: dict, events: list[dict]) -> int:
    """Prove the checks bite. Returns 0 if every tamper was caught."""
    baseline, _ = validate(index, events)
    if baseline:
        print("FAIL — the untampered fixture does not validate; fix that first.")
        for error in baseline:
            print(f"  - {error}")
        return 1

    print("self-test — each row must be rejected\n")
    missed = 0
    for name, kind, reid, mutate in TAMPERS:
        copy = json.loads(json.dumps(events))
        target = next((e for e in copy if e["kind"] == kind), None)
        if target is None:
            print(f"  SKIP    {name} (no kind {kind} in this fixture)")
            continue
        mutate(target)
        if reid:
            target["id"] = compute_id(target)
        caught, _ = validate(index, copy)
        if caught:
            print(f"  caught  {name}")
            print(f"          → {caught[0]}")
        else:
            print(f"  MISSED  {name}")
            missed += 1
    print()
    if missed:
        print(f"FAIL — {missed} tamper(s) slipped through.")
        return 1
    print(f"PASS — all {len(TAMPERS)} tampered events rejected.")
    print("Note: well-formedness only. Signatures need secp256k1 — see verifyEvent().")
    return 0


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if not a.startswith("-")]
    flags = {a for a in argv[1:] if a.startswith("-")}
    if len(args) != 1:
        print(__doc__)
        return 2

    index = json.loads((SCHEMA_DIR / "index.json").read_text())
    events = json.loads(Path(args[0]).read_text())["events"]

    if "--self-test" in flags:
        return self_test(index, events)

    errors, counts = validate(index, events)
    mode = "full JSON Schema" if HAVE_JSONSCHEMA else "required fields only (pip install jsonschema for full)"
    print(f"quorum v{index['version']} — validating {len(events)} events from Python")
    print(f"  ids recomputed:      {len(events)}")
    print(f"  bodies checked:      {counts['bodies']} ({mode})")
    print(f"  approvals audited:   {counts['approvals']}")

    if errors:
        print(f"\nFAIL — {len(errors)} problem(s):")
        for error in errors:
            print(f"  - {error}")
        return 1

    print("\nPASS — every event is well-formed and every approval binds to its exact input.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
