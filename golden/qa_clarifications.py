"""Additive fixtures that pin what the frozen ``qa/v1`` text left implicit.

Two files are generated here, and ``golden/qa.json`` and ``golden/qa_canon_vectors.json`` are not touched:

* ``golden/qa_canon_vectors_addendum.json``: self-contained canonicalization vectors, in the same shape as the base
  vector file, plus three annotated sections: the ``expected_hash`` of a predicate, the digest of a value, and the
  ordering of every set-valued record field. An independent implementation of the ``rcv1`` rules needs only this
  file for them.
* ``golden/qa_clarifications.json``: refusal and classification fixtures for the integrity codes added within
  ``qa/v1``, the idempotency-key rule, the optional ``FaultRecovery.reason_code`` and the identity boundary of
  engine limits and kill-switch state.

Regenerate with ``python -m golden.qa_clarifications``. Nothing here reads a clock or a random source.
"""
from __future__ import annotations

import collections
import copy
import dataclasses
import hashlib
import json
import pathlib
import unicodedata
from typing import Any, Dict, List

from golden import qa as base_golden
from golden import qa_samples as S
from runtime_contracts import canonical
from runtime_contracts.models.verification import Check, Determinism, Verdict
from runtime_contracts.qa import (Action, ActionKind, AssertionIntegrityError, AssertionSpec, Budget,
                                  CheckProgramRef, EvidenceLevel, FaultRecovery, FixtureRef, Outcome, PlanGate,
                                  PlanItem, Predicate, PredicateOp, QAContractError, QAPlan, RecoveryReason,
                                  RecoveryResult, RecoveryStrategy, ResourceClaim, ReviewItem, RunManifest,
                                  SuppressedReason, TestSpec, action_value_digest, check_batch_not_halted,
                                  classify_refusal, idempotency_key_violations, json_value_digest,
                                  load_pinned_assertion_set, value_digest, verify_check_program,
                                  verify_pin_well_formed)
from runtime_contracts.qa.base import QA_CONTRACT_ID
from runtime_contracts.qa.enums import ResultCode, PostconditionResult
from runtime_contracts.qa.manifest import StepResult
from runtime_contracts.protocol.secrets import SecretRef

HERE = pathlib.Path(__file__).parent
ADDENDUM_PATH = HERE / "qa_canon_vectors_addendum.json"
CLARIFICATIONS_PATH = HERE / "qa_clarifications.json"
BASE_VECTORS_PATH = HERE / "qa_canon_vectors.json"

ADDENDUM_VERSION = "1"
CLARIFICATIONS_VERSION = "1"


def _json(value: Any) -> Any:
    return canonical.canonicalize(value)


def _entry(entry_id: str, why: str, value: Any) -> Dict[str, Any]:
    text = canonical.canonical_json(value)
    return {"id": entry_id, "why": why, "input": _json(value), "canonical_json": text,
            "sha256_hex": hashlib.sha256(text.encode("utf-8")).hexdigest(), "rcv1": canonical.content_hash(value)}


def _text_of(form: Any) -> str:
    return canonical.canonical_json(form)


# ── 1. expected_hash of a predicate ────────────────────────────────────────────────────────────────────────

def _predicate_cases() -> List[Dict[str, Any]]:
    nfd = unicodedata.normalize("NFD", "café")
    made = [
        ("equals_string", PredicateOp.EQUALS, "Saved", "the reference predicate"),
        ("equals_nfd_string", PredicateOp.EQUALS, nfd, "expected is NFC-normalized: an NFD spelling hashes as NFC"),
        ("equals_nfc_string", PredicateOp.EQUALS, "café", "the NFC spelling of the same expected"),
        ("not_equals", PredicateOp.NOT_EQUALS, "Error", "op is part of the hash"),
        ("contains", PredicateOp.CONTAINS, "ok", "a substring predicate"),
        ("matches", PredicateOp.MATCHES, "/saved$", "a pattern predicate"),
        ("exists", PredicateOp.EXISTS, None, "no expected: the hashed form is {op} alone"),
        ("absent", PredicateOp.ABSENT, None, "no expected: the hashed form is {op} alone"),
        ("less_than", PredicateOp.LESS_THAN, "10.5", "a canonical decimal string stays a string"),
        ("greater_than_zero", PredicateOp.GREATER_THAN, "0", "zero is the string 0"),
        ("equals_integer", PredicateOp.EQUALS, 5, "an integer expected is an integer in the canonical form"),
        ("equals_boolean", PredicateOp.EQUALS, True, "a boolean expected"),
        ("equals_list", PredicateOp.EQUALS, [1, "a"], "a list keeps its order"),
        ("equals_object", PredicateOp.EQUALS, {"b": 1, "a": 2}, "an object's keys are sorted"),
    ]
    out = []
    for cid, op, expected, why in made:
        p = Predicate(op, expected)
        form = {"op": op.value}
        if expected is not None:
            form["expected"] = expected if cid != "equals_nfd_string" else nfd
        entry = _entry(f"predicate:{cid}", why, form)
        assert entry["rcv1"] == p.digest, cid
        out.append({"id": cid, "why": why, "op": op.value, "expected": form.get("expected"),
                    "hashed_form_vector": entry["id"], "expected_hash": p.digest, "_entry": entry})
    return out


def _predicate_relations() -> List[Dict[str, Any]]:
    a = S.ui_assertion("a-saved")
    other = S.ui_assertion("a-other-id", test_id="elsewhere", requirement_ref="REQ-OTHER")
    return [
        {"why": "expected_hash depends on op and expected only: two assertions with different ids, locators and "
                "requirement refs but the same predicate share it",
         "assertions": [_json(a.canonical_form()), _json(other.canonical_form())],
         "assertion_hashes": [a.assertion_hash, other.assertion_hash], "expected_hash": a.expected_hash,
         "expected_hash_equal": a.expected_hash == other.expected_hash == Predicate(PredicateOp.EQUALS, "Saved").digest,
         "assertion_hashes_differ": a.assertion_hash != other.assertion_hash},
        {"why": "expected_hash is not the hash of the assertion: it never equals assertion_hash",
         "assertions": [_json(a.canonical_form())], "assertion_hashes": [a.assertion_hash],
         "expected_hash": a.expected_hash, "expected_hash_equal": True,
         "assertion_hashes_differ": a.assertion_hash != a.expected_hash},
    ]


# ── 2. value digest, state hash, idempotency key ───────────────────────────────────────────────────────────

def _value_digest_cases() -> List[Dict[str, Any]]:
    nfd = unicodedata.normalize("NFD", "café")
    ref = SecretRef(provider="vault", namespace="tenant-a", path="kv/app", key="token", version="3")
    strings = [
        ("string_plain", "hunter2", "the digest of a string is rcv1 over its quoted canonical JSON text"),
        ("string_empty", "", "the empty string has a digest"),
        ("string_nfc", "café", "NFC spelling"),
        ("string_nfd", nfd, "an NFD spelling digests as its NFC form"),
        ("string_with_quote", 'say "hi"', "quote and backslash are escaped in the hashed text"),
        ("string_non_ascii", "中 \U0001f600", "non-ASCII is hashed as UTF-8, not as \\u escapes"),
    ]
    out = []
    for cid, value, why in strings:
        entry = _entry(f"value-digest:{cid}", why, value)
        assert entry["rcv1"] == value_digest(value) == json_value_digest(value), cid
        out.append({"id": cid, "why": why, "kind": "string", "value": value, "digest": value_digest(value),
                    "hashed_form_vector": entry["id"], "_entry": entry})
    for cid, value, why in [("json_integer", 7, "a non-string value is hashed as its canonical JSON text"),
                            ("json_list", [3, 1, "x"], "a list keeps its order"),
                            ("json_object", {"b": "2", "a": "1"}, "an object's keys are sorted")]:
        entry = _entry(f"value-digest:{cid}", why, value)
        assert entry["rcv1"] == json_value_digest(value), cid
        out.append({"id": cid, "why": why, "kind": "json", "value": value, "digest": json_value_digest(value),
                    "hashed_form_vector": entry["id"], "_entry": entry})
    form = _json(ref.canonical_form())
    entry = _entry("value-digest:secret_ref", "an action that carries a SecretRef digests the reference, never the "
                   "secret: rcv1 over the reference's canonical form", form)
    assert entry["rcv1"] == ref.fingerprint() == action_value_digest(Action(ActionKind.FILL, secret_ref=ref))
    out.append({"id": "secret_ref", "why": entry["why"], "kind": "secret_ref", "value": form,
                "digest": ref.fingerprint(), "hashed_form_vector": entry["id"], "_entry": entry})
    return out


def _receipt_cases() -> List[Dict[str, Any]]:
    first = S.action_receipt("s1", 1)
    second = S.action_receipt("s1", 2)
    other_step = S.action_receipt("s2", 1, idempotency_key="idem-s2-1")
    moved = S.action_receipt("s1", 1, state_after_hash=S.h(77))
    slower = S.action_receipt("s1", 1, duration_ms=9999)
    rekeyed = S.action_receipt("s1", 1, idempotency_key="idem-s1-other")
    rekeyed_second = S.action_receipt("s1", 2, idempotency_key="idem-s1-other")
    cases = {
        "receipt_attempt_1": (first, "attempt 1 of step s1"),
        "receipt_attempt_2": (second, "attempt 2 of step s1: same idempotency_key as attempt 1, a different receipt "
                                      "(the attempt number is identity)"),
        "receipt_other_step": (other_step, "step s2 has its own key"),
        "receipt_state_after_changed": (moved, "state hashes are identity: another state_after_hash is another "
                                               "receipt"),
        "receipt_duration_changed": (slower, "duration_ms is custody: it does not change the receipt hash"),
        "receipt_key_changed": (rekeyed, "the idempotency key is identity: another key is another receipt"),
        "receipt_attempt_2_rekeyed": (rekeyed_second, "attempt 2 of step s1 under a key that differs from "
                                                      "attempt 1"),
    }
    out = []
    for cid, (receipt, why) in cases.items():
        entry = _entry(f"qa-clarification:{cid}", why, receipt.canonical_form())
        assert entry["rcv1"] == receipt.content_hash
        out.append({"id": cid, "why": why, "hash": receipt.content_hash, "_entry": entry,
                    "run_id": receipt.run_id, "step_id": receipt.step_id, "attempt": receipt.attempt,
                    "idempotency_key": receipt.idempotency_key})
    return out


# ── 3. ordering of set-valued fields ───────────────────────────────────────────────────────────────────────

SET_RULES: List[Dict[str, Any]] = [
    {"record": "TestSpec", "field": "assertions", "elements": "AssertionSpec", "order": "element_key",
     "key": "assertion_id"},
    {"record": "TestSpec", "field": "fixtures", "elements": "FixtureRef", "order": "element_key", "key": "id"},
    {"record": "TestSpec", "field": "depends_on", "elements": "string", "order": "value"},
    {"record": "TestSpec", "field": "allowed_side_effects", "elements": "enum", "order": "value"},
    {"record": "TestSpec", "field": "sensitivity_labels", "elements": "string", "order": "value"},
    {"record": "QAPlan", "field": "items", "elements": "PlanItem", "order": "element_key", "key": "spec_ref"},
    {"record": "QAPlan", "field": "lanes", "elements": "string", "order": "value"},
    {"record": "QAPlan", "field": "gates", "elements": "PlanGate", "order": "element_key", "key": "item"},
    {"record": "QAPlan", "field": "resource_claims", "elements": "ResourceClaim", "order": "element_key",
     "key": "resource"},
    {"record": "PlanGate", "field": "after", "elements": "string", "order": "value"},
    {"record": "QAPolicyDecision", "field": "scope", "elements": "string", "order": "value"},
    {"record": "FaultDetection", "field": "evidence_refs", "elements": "EvidenceRef", "order": "canonical_text"},
    {"record": "ReviewItem", "field": "evidence_refs", "elements": "EvidenceRef", "order": "canonical_text"},
    {"record": "RunManifest", "field": "versions", "elements": "VersionPin", "order": "element_key",
     "key": "component"},
    {"record": "RunManifest", "field": "assertions_declared", "elements": "string", "order": "value"},
    {"record": "RunManifest", "field": "assertions_executed", "elements": "string", "order": "value"},
    {"record": "RunManifest", "field": "assertions_skipped", "elements": "SkippedAssertion",
     "order": "element_key", "key": "assertion_id"},
    {"record": "RunManifest", "field": "step_results", "elements": "StepResult", "order": "element_key",
     "key": "step_id"},
    {"record": "RunManifest", "field": "assertion_results", "elements": "AssertionResult", "order": "element_key",
     "key": "assertion_id"},
    {"record": "CleanupReport", "field": "released", "elements": "string", "order": "value"},
    {"record": "CleanupReport", "field": "leaked", "elements": "string", "order": "value"},
    {"record": "Step", "field": "permitted_recovery", "elements": "enum", "order": "value"},
    {"record": "ObserveRequest", "field": "capture", "elements": "enum", "order": "value"},
    {"record": "Check", "field": "evidence_refs", "elements": "string", "order": "value",
     "note": "Check is the reused verification type embedded as AssertionResult.check; its canonical form sorts "
             "the pins and does not remove a pin listed twice, so a producer lists each pin once"},
]

#: Ordered, not sets: the listed order is identity.
ORDERED_FIELDS: List[Dict[str, str]] = [
    {"record": "TestSpec", "field": "steps"}, {"record": "TestSpec", "field": "preconditions"},
    {"record": "TestSpec", "field": "cleanup"}, {"record": "RunManifest", "field": "seeds"},
    {"record": "RunManifest", "field": "fault_events"}, {"record": "StepResult", "field": "receipts"},
    {"record": "LocatorDescriptor", "field": "frame_path"},
    {"record": "FaultRecovery", "field": "candidates_rejected_reasons"},
    {"record": "AssertionSubject", "field": "inputs"}, {"record": "AssertionSubject", "field": "subject_alternates"},
    {"record": "CheckSubject", "field": "inputs"}, {"record": "LocateResult", "field": "candidates"},
]


def _spec_for_ordering() -> TestSpec:
    return S.ui_spec(
        "ordering-spec",
        assertions=(S.ui_assertion("a-1"), S.ui_assertion("a-10", expected="Ten"), S.url_assertion("a-2")),
        fixtures=(FixtureRef(id="seed-a", content_hash=S.d(9)), FixtureRef(id="seed-b", content_hash=S.d(3))),
        depends_on=(f"zeta-spec@{S.h(2)}", f"alpha-spec@{S.h(8)}"),
        allowed_side_effects=(S.SideEffect.WRITES_INTERNAL, S.SideEffect.NONE),
        sensitivity_labels=("pii", "internal", "Confidential"))


def _plan_for_ordering() -> QAPlan:
    refs = [f"{n}-spec@{S.h(i)}" for i, n in enumerate(("a", "b", "c"), 1)]
    deadlines = (300000, 120000, 200000)
    lanes = (("lane-a", 0), ("lane-a", 1), ("lane-b", 0))
    items = tuple(PlanItem(spec_ref=r, lane=lane, order=order, budget=Budget(deadline_ms=dl, max_recovery_attempts=1),
                           recovery_ceiling=2, evidence_level=EvidenceLevel.STANDARD)
                  for r, dl, (lane, order) in zip(refs, deadlines, lanes))
    # a waits for c and b waits for a and c: with lane order a -> b the edges c -> a -> b never cycle
    gates = (PlanGate(item=refs[0], after=(refs[2],)), PlanGate(item=refs[1], after=(refs[0], refs[2])))
    return QAPlan(items=items, lanes=("lane-b", "lane-a"), max_parallel=2, coverage_contract=S.CoverageContract.FULL,
                  planner=S.PLANNER, gates=gates,
                  resource_claims=(ResourceClaim(resource="browser_slots", amount=3),
                                   ResourceClaim(resource="cpu_slots", amount=1)),
                  action_policy_ref=S.h(9))


def _manifest_with_results() -> RunManifest:
    spec = S.ui_spec("ordering-results", assertions=(S.ui_assertion("a-1"), S.ui_assertion("a-2", expected="Two"),
                                                     S.ui_assertion("a-3", expected="Three")))
    actual = {"a-1": "Zulu", "a-2": "Mike", "a-3": "Alpha"}
    results = tuple(S.assertion_result(a, spec, actual=actual[a.assertion_id]) for a in spec.assertions)
    return S.run_manifest(spec, assertion_results=results, fault_events=(),
                          versions=(S.VersionPin(component="runtime-contracts", version="0.3.14"),
                                    S.VersionPin(component="agent-harness", version="0.1.0"),
                                    S.VersionPin(component="browser-driver", version="1.2.3")))


def _manifest_with_steps() -> RunManifest:
    spec = S.ui_spec("ordering-steps", assertions=(S.ui_assertion("a-1"), S.ui_assertion("a-2", expected="Two"),
                                                   S.url_assertion("a-3")))
    a1 = spec.assertions[0]
    steps = (StepResult(step_id="s1", result=ResultCode.OK, postcondition=PostconditionResult.SATISFIED,
                        receipts=(S.h(61),)),
             StepResult(step_id="s2", result=ResultCode.ACTION_TIMEOUT, postcondition=PostconditionResult.NOT_SATISFIED,
                        receipts=(S.h(62), S.h(63))),
             StepResult(step_id="s3", result=ResultCode.LOCATOR_NOT_FOUND,
                        postcondition=PostconditionResult.NOT_EVALUATED, receipts=(S.h(64),)))
    skipped = (S.SkippedAssertion(assertion_id="a-3", reason_code=S.SkipReason.BUDGET_EXHAUSTED),
               S.SkippedAssertion(assertion_id="a-2", reason_code=S.SkipReason.NOT_REACHED))
    return S.run_manifest(spec, assertions_executed=(a1.assertion_id,), assertions_skipped=skipped,
                          assertion_results=(S.assertion_result(a1, spec),), outcome=Outcome.INCONCLUSIVE,
                          step_results=steps, fault_events=())


def _manifest_with_ids() -> RunManifest:
    ids = ("a-9", "a-10", "B-1", "a-1")
    spec = S.ui_spec("ordering-ids", assertions=tuple(S.ui_assertion(i) for i in ids))
    return S.run_manifest(spec, fault_events=())


def _review_item_with_refs() -> ReviewItem:
    a = S.evidence(1, "shot-a")
    b = dataclasses.replace(S.evidence(2, "shot-b"), content_hash=S.d(3))
    c = dataclasses.replace(S.evidence(3, "shot-c"), content_hash=S.d(2))
    a = dataclasses.replace(a, content_hash=S.d(9))
    return ReviewItem(review_item_id="ri-order", run_id="run-1", reason="ASSERTION_INTEGRITY",
                      evidence_refs=(a, b, c), created_at="2026-10-30T10:00:06Z")


def _with(form: Dict[str, Any], path: List[str], value: Any) -> Dict[str, Any]:
    """A copy of ``form`` with the value at ``path`` replaced."""
    if len(path) == 1:
        return dict(form, **{path[0]: value})
    return dict(form, **{path[0]: _with(form[path[0]], path[1:], value)})


def _set_ordering_cases() -> List[Dict[str, Any]]:
    spec, plan = _spec_for_ordering(), _plan_for_ordering()
    m_results, m_steps, m_ids, review = (_manifest_with_results(), _manifest_with_steps(), _manifest_with_ids(),
                                         _review_item_with_refs())
    m_pins = S.assertion_result(check=Check(
        check_id="a-saved", verdict=Verdict.PASS, determinism=Determinism.DETERMINISTIC, detail="",
        evidence_refs=tuple(S.evidence(n).pin() for n in (5, 2, 9))))
    specs = [
        # (id, why, record, field, element rule, key)
        ("fixtures_by_id", "fixtures sort by id; sorting by canonical text would put content_hash first and "
                           "reverse them", spec, "fixtures", "element_key", "id"),
        ("plan_items_by_spec_ref", "items sort by spec_ref; the canonical text of an item starts with its budget",
         plan, "items", "element_key", "spec_ref"),
        ("plan_gates_by_item", "gates sort by item; the canonical text of a gate starts with its after list",
         plan, "gates", "element_key", "item"),
        ("plan_resource_claims_by_resource", "claims sort by resource; the canonical text starts with the amount",
         plan, "resource_claims", "element_key", "resource"),
        ("assertion_results_by_assertion_id", "results sort by assertion_id; the canonical text of a result "
                                              "starts with actual", m_results, "assertion_results", "element_key",
         "assertion_id"),
        ("step_results_by_step_id", "step results sort by step_id; the canonical text starts with the postcondition",
         m_steps, "step_results", "element_key", "step_id"),
        ("evidence_refs_by_canonical_text", "evidence_refs is the one object set ordered by canonical JSON text; "
                                            "ordering by ref would give another order", review, "evidence_refs",
         "canonical_text", None),
        ("plan_lanes_natural", "string sets sort by Unicode code point: lane-a before lane-b", plan, "lanes", "value",
         None),
        ("policy_scope_natural", "scope sorts by Unicode code point", S.policy_decision(
            scope=("ui:hover", "ui:click", "ui:fill")), "scope", "value", None),
        ("cleanup_released_natural", "released and leaked sort by Unicode code point", S.CleanupReport(
            handle_id="s1", verified=True, released=("page", "context", "browser")), "released", "value", None),
        ("check_evidence_pins_natural", "the pins of the embedded Check sort as strings", m_pins,
         "check.evidence_refs", "value", None),
        ("assertions_by_assertion_id_control", "control: for assertions both rules agree, because assertion_id is "
                                               "the first key of the canonical text", spec, "assertions",
         "element_key", "assertion_id"),
        ("versions_by_component_control", "control: component is the first key, so both rules agree",
         m_results, "versions", "element_key", "component"),
        ("assertion_skips_by_assertion_id_control", "control: assertion_id is the first key, so both rules agree",
         m_steps, "assertions_skipped", "element_key", "assertion_id"),
        ("assertion_ids_natural", "string sets sort by Unicode code point: a-1 < a-10 < a-9, and upper case "
                                  "sorts before lower case", m_ids, "assertions_declared", "value", None),
        ("depends_on_natural", "string sets sort by Unicode code point", spec, "depends_on", "value", None),
        ("sensitivity_labels_natural", "upper case sorts before lower case", spec, "sensitivity_labels", "value",
         None),
        ("allowed_side_effects_natural", "enum sets sort by member value", spec, "allowed_side_effects", "value",
         None),
    ]
    out = []
    for cid, why, rec, fname, rule, key in specs:
        form = _json(rec.canonical_form())
        path = fname.split(".")
        holder = form
        for step in path[:-1]:
            holder = holder[step]
        leaf = path[-1]
        canonical_listing = holder[leaf]
        by_text = sorted(canonical_listing, key=_text_of)
        if rule == "element_key":
            other = by_text
        elif rule == "canonical_text":
            other = sorted(canonical_listing, key=lambda f: f["ref"])
        else:
            other = list(reversed(canonical_listing))
        listed = list(reversed(canonical_listing))
        if listed == canonical_listing:
            listed = canonical_listing[1:] + canonical_listing[:1]
        differs = other != canonical_listing
        record_listed = _with(form, path, listed)
        record_other = _with(form, path, other)
        entry = _entry(f"set-order:{cid}", why, form)
        assert entry["rcv1"] == rec.content_hash, cid
        # the model reproduces the same hash from the listed order
        assert type(rec).from_json(_json(record_listed)).content_hash == rec.content_hash, cid
        out.append({
            "id": cid, "why": why, "record": type(rec).__name__, "field": fname, "order": rule,
            "key": key, "listed": listed, "canonical": canonical_listing,
            "other_rule_order": other if rule != "value" else None,
            "orders_differ": differs if rule != "value" else None,
            "record_listed": record_listed, "vector": entry["id"], "rcv1": rec.content_hash,
            "rcv1_if_ordered_the_other_way": canonical.content_hash(record_other) if differs and rule != "value"
            else None,
            "_entry": entry})
    return out


def _set_ordering_refusals() -> List[Dict[str, Any]]:
    spec = _spec_for_ordering()
    form = _json(spec.canonical_form())
    dup = dict(form, fixtures=form["fixtures"] + [form["fixtures"][0]])
    return [{"id": "duplicate_set_element", "operation": "parse_test_spec",
             "why": "a set lists each element once: the same fixture id twice is refused, not deduplicated",
             "input": dup, "expect": {"refused": True, "code": "DUPLICATE_ENTRY"}}]


# ── 4. distinct integrity refusals ─────────────────────────────────────────────────────────────────────────

_INTEGRITY = {"run_outcome": "INCONCLUSIVE", "run_reason": "ASSERTION_INTEGRITY"}


def _refused(code: str) -> Dict[str, Any]:
    return {"refused": True, "code": code, **_INTEGRITY}


def _integrity_fixtures() -> List[Dict[str, Any]]:
    spec = S.ui_spec()
    pin = spec.assertion_set_hash
    forms = [_json(a.canonical_form()) for a in spec.assertions]
    script = S.script_assertion()
    ref = _json(script.check_program_ref.canonical_form())
    good = script.check_program_ref.program_hash
    return [
        {"id": "pin_malformed_wrong_prefix", "operation": "verify_pin_well_formed",
         "why": "a pin spelled with another prefix is malformed, not merely unknown",
         "input": {"pin": "sha256:" + "a" * 64}, "expect": _refused("ASSERTION_PIN_MALFORMED")},
        {"id": "pin_malformed_truncated", "operation": "verify_pin_well_formed",
         "why": "a truncated digest is never accepted", "input": {"pin": "rcv1:" + "a" * 63},
         "expect": _refused("ASSERTION_PIN_MALFORMED")},
        {"id": "pin_malformed_uppercase_hex", "operation": "verify_pin_well_formed",
         "why": "digests are lower-case hex", "input": {"pin": "rcv1:" + "A" * 64},
         "expect": _refused("ASSERTION_PIN_MALFORMED")},
        {"id": "pin_malformed_not_a_string", "operation": "verify_pin_well_formed",
         "why": "a pin that is not a string is malformed", "input": {"pin": None},
         "expect": _refused("ASSERTION_PIN_MALFORMED")},
        {"id": "pin_well_formed_control", "operation": "verify_pin_well_formed",
         "why": "control: rcv1: and 64 lower-case hex digits", "input": {"pin": pin}, "expect": {"refused": False}},
        {"id": "pin_malformed_is_checked_before_the_store", "operation": "load_pinned_assertion_set",
         "why": "a malformed pin is refused as malformed whatever the store holds", "input": {"pin": "rcv1:xyz",
                                                                                              "stored": forms},
         "expect": _refused("ASSERTION_PIN_MALFORMED")},
        {"id": "pin_not_found", "operation": "load_pinned_assertion_set",
         "why": "a well-formed pin the store does not hold", "input": {"pin": S.h(404), "stored": None},
         "expect": _refused("ASSERTION_PIN_NOT_FOUND")},
        {"id": "pin_found_but_content_differs", "operation": "load_pinned_assertion_set",
         "why": "the store holds a set under the pin but it does not hash to the pin: that is the content-hash "
                "case and keeps ASSERTION_HASH_MISMATCH", "input": {"pin": pin, "stored": [forms[0]]},
         "expect": _refused("ASSERTION_HASH_MISMATCH")},
        {"id": "pin_found_control", "operation": "load_pinned_assertion_set",
         "why": "control: a stored set that hashes to its pin loads", "input": {"pin": pin, "stored": forms},
         "expect": {"refused": False}},
        {"id": "program_unregistered", "operation": "verify_check_program",
         "why": "the registry has no entry for the program the assertion names",
         "input": {"check_program_ref": ref, "registered_hash": None},
         "expect": _refused("ASSERTION_PROGRAM_UNREGISTERED")},
        {"id": "program_hash_differs", "operation": "verify_check_program",
         "why": "the registry holds the program under a different hash: a different program is a different "
                "assertion", "input": {"check_program_ref": ref, "registered_hash": S.d(999)},
         "expect": _refused("ASSERTION_PROGRAM_MISMATCH")},
        {"id": "program_registered_control", "operation": "verify_check_program",
         "why": "control: the registry holds the frozen hash", "input": {"check_program_ref": ref,
                                                                         "registered_hash": good},
         "expect": {"refused": False}},
        {"id": "batch_halted_by_an_integrity_refusal", "operation": "check_batch_not_halted",
         "why": "any call after an integrity refusal in the same batch is refused with BATCH_HALTED; the halting "
                "refusal keeps its own code", "input": {"halted_by": "ASSERTION_PIN_NOT_FOUND"},
         "expect": _refused("BATCH_HALTED")},
        {"id": "batch_running_control", "operation": "check_batch_not_halted",
         "why": "control: a batch no refusal has halted", "input": {"halted_by": None},
         "expect": {"refused": False}},
    ]


def _classification_cases() -> List[Dict[str, Any]]:
    integrity = ["INCONCLUSIVE", "ASSERTION_INTEGRITY"]
    rows = [
        ("ASSERTION_INTEGRITY", integrity, "the outcome reason itself"),
        ("ASSERTION_HASH_MISMATCH", integrity, "an original code"),
        ("EXECUTOR_MISMATCH", integrity, "an original code"),
        ("EXPECTED_MISMATCH", integrity, "an original code"),
        ("RECOVERY_PAYLOAD_REJECTED", integrity, "an original code"),
        ("COVERAGE_VIOLATION", integrity, "an original code"),
        ("ASSERTION_PROGRAM_MISMATCH", integrity, "added within qa/v1"),
        ("ASSERTION_PROGRAM_UNREGISTERED", integrity, "added within qa/v1"),
        ("ASSERTION_PIN_NOT_FOUND", integrity, "added within qa/v1"),
        ("ASSERTION_PIN_MALFORMED", integrity, "added within qa/v1"),
        ("BATCH_HALTED", integrity, "added within qa/v1"),
        ("SPEC_INVALID", None, "known and not an integrity refusal: classified by the caller's own rules"),
        ("CHECK_PROGRAM_REF_REQUIRED", None, "known and not an integrity refusal (a test defect)"),
        ("A_CODE_FROM_A_LATER_VERSION", integrity, "an unknown code fails closed to an integrity violation"),
        ("", integrity, "an empty code is unknown"),
    ]
    return [{"code": code, "classification": cls, "why": why} for code, cls, why in rows]


def _older_consumer_cases() -> Dict[str, Any]:
    """What a consumer that only knows the codes of the original text does with each added code."""
    return {"known_codes": sorted(_ORIGINAL_KNOWN),
            "why": "a consumer built before the added codes does not know them; it classifies each as an unknown "
                   "code, which is INCONCLUSIVE(ASSERTION_INTEGRITY) and halts the batch: the same outcome the "
                   "added code itself maps to",
            "cases": [{"code": c, "classification": ["INCONCLUSIVE", "ASSERTION_INTEGRITY"]}
                      for c in ("ASSERTION_PROGRAM_MISMATCH", "ASSERTION_PROGRAM_UNREGISTERED",
                                "ASSERTION_PIN_NOT_FOUND", "ASSERTION_PIN_MALFORMED", "BATCH_HALTED")]}


#: Every code the original qa/v1 text defined (``base.Code`` at the first release candidate).
_ORIGINAL_KNOWN = {
    "INVALID_FIELD", "MISSING_FIELD", "UNKNOWN_FIELD", "UNKNOWN_ENUM_VALUE", "DUPLICATE_ENTRY", "FLOAT_REFUSED",
    "SCHEMA_MISMATCH", "SCHEMA_VERSION_UNSUPPORTED", "HASH_MISMATCH", "ASSERTION_INTEGRITY",
    "ASSERTION_HASH_MISMATCH", "EXECUTOR_MISMATCH", "EXPECTED_MISMATCH", "RECOVERY_PAYLOAD_REJECTED",
    "COVERAGE_VIOLATION", "UNSUPPORTED_COVERAGE_CONTRACT", "PLAN_INVALID", "SPEC_INVALID",
    "CHECK_PROGRAM_REF_REQUIRED", "RECORD_INCONSISTENT", "FAULT_BINDING_MISMATCH"}


# ── 5. recovery reason ─────────────────────────────────────────────────────────────────────────────────────

def _recovery(**kw) -> FaultRecovery:
    base = dict(detection_ref=S.h(70), attempted=True, strategy=RecoveryStrategy.SEMANTIC_LOCATOR,
                result=RecoveryResult.NOT_RECOVERED, postcondition_verified=False, attempts=1,
                candidates_considered=3, candidates_rejected_reasons=("NAME_MISMATCH", "NOT_UNIQUE", "ROLE_MISMATCH"))
    base.update(kw)
    return FaultRecovery(**base)


def _recovery_cases() -> List[Dict[str, Any]]:
    cases = [
        ("recovered_without_reason", _recovery(result=RecoveryResult.RECOVERED, postcondition_verified=True,
                                               candidates_rejected_reasons=("NOT_UNIQUE",), candidates_considered=2),
         "a recovery that recovered carries no reason_code; its hash is what it always was"),
        ("not_recovered_without_reason", _recovery(), "the same recovery before reason_code existed"),
        ("not_recovered_no_candidate", _recovery(reason_code=RecoveryReason.NO_CANDIDATE),
         "candidates were considered and each rejected, and the recovery as a whole says why it did not recover"),
        ("stopped_before_any_candidate", _recovery(candidates_considered=0, candidates_rejected_reasons=(),
                                                   attempts=1, reason_code=RecoveryReason.NO_UI_TARGET),
         "no candidate was considered, so candidates_rejected_reasons is empty by rule; reason_code is the only "
         "place the reason fits"),
        ("suppressed_by_kill_switch", _recovery(attempted=False, strategy=RecoveryStrategy.NONE, attempts=0,
                                                result=RecoveryResult.NOT_ATTEMPTED, candidates_considered=0,
                                                candidates_rejected_reasons=(),
                                                suppressed_reason=SuppressedReason.KILL_SWITCH,
                                                reason_code=RecoveryReason.KILL_SWITCH),
         "the effect of the kill switch on this fault; the switch's own state is not recorded"),
        ("rejected_reasons_reordered", _recovery(candidates_rejected_reasons=("ROLE_MISMATCH", "NOT_UNIQUE",
                                                                              "NAME_MISMATCH")),
         "candidates_rejected_reasons is a list: the same codes in another order are another record"),
    ]
    out = []
    for cid, rec, why in cases:
        entry = _entry(f"qa-clarification:fault_recovery_{cid}", why, rec.canonical_form())
        assert entry["rcv1"] == rec.content_hash
        out.append({"id": cid, "why": why, "hash": rec.content_hash, "_entry": entry})
    return out


def _recovery_refusals() -> List[Dict[str, Any]]:
    ok = _json(_recovery(reason_code=RecoveryReason.NO_CANDIDATE).canonical_form())
    recovered = _json(_recovery(result=RecoveryResult.RECOVERED, postcondition_verified=True).canonical_form())
    return [
        {"id": "recovered_with_reason_code", "operation": "parse_fault_recovery",
         "why": "RECOVERED carries no reason_code",
         "input": {**recovered, "reason_code": "NO_CANDIDATE"},
         "expect": {"refused": True, "code": "RECORD_INCONSISTENT"}},
        {"id": "unknown_reason_code", "operation": "parse_fault_recovery",
         "why": "an unknown reason_code is non-certifying: the record is refused, never read as something else",
         "input": {**ok, "reason_code": "SOMETHING_FROM_A_LATER_VERSION"},
         "expect": {"refused": True, "code": "UNKNOWN_ENUM_VALUE"}},
        {"id": "more_rejections_than_candidates", "operation": "parse_fault_recovery",
         "why": "candidates_rejected_reasons holds at most one code per candidate considered",
         "input": {**ok, "candidates_considered": 1}, "expect": {"refused": True, "code": "RECORD_INCONSISTENT"}},
        {"id": "reason_code_control", "operation": "parse_fault_recovery",
         "why": "control: a not-recovered record with a reason_code parses", "input": ok,
         "expect": {"refused": False}},
    ]


# ── 6. what is not in the manifest ─────────────────────────────────────────────────────────────────────────

def _identity_boundary() -> Dict[str, Any]:
    good = _json(S.run_manifest().canonical_form())
    return {
        "why": "engine limits (operator caps, recovery limits) and kill-switch state are not manifest fields and "
               "never enter qa/v1 identity. A manifest carrying such a key is refused as an unknown field; the "
               "effect of the kill switch on one fault is recorded as FaultRecovery.suppressed_reason.",
        "refusals": [
            {"id": f"manifest_with_{key}", "operation": "parse_run_manifest",
             "why": f"{key} is not a RunManifest field", "input": {**good, key: value},
             "expect": {"refused": True, "code": "UNKNOWN_FIELD"}}
            for key, value in (("kill_switch", {"engaged": True}), ("engine_limits", {"max_attempts_per_step": 2}),
                               ("operator_caps", {"max_retries": 1}))],
        "manifest_fields_that_describe_the_run": ["counters", "resource_limits", "recovery_enabled",
                                                   "model_recovery_enabled"],
        "custody_counters": ["cost", "infrastructure_ms", "model_calls", "tokens"],
        "where_the_effect_is_recorded": {"record": "FaultRecovery", "field": "suppressed_reason",
                                         "member": "KILL_SWITCH"},
    }


# ── execution of the new fixture operations ────────────────────────────────────────────────────────────────

def run_fixture(op: str, data: Any) -> Dict[str, Any]:
    """What this implementation does with a clarification fixture's input."""
    try:
        if op == "verify_pin_well_formed":
            verify_pin_well_formed(data["pin"])
        elif op == "load_pinned_assertion_set":
            stored = None if data["stored"] is None else [AssertionSpec.from_json(a) for a in data["stored"]]
            load_pinned_assertion_set(data["pin"], stored)
        elif op == "verify_check_program":
            verify_check_program(CheckProgramRef(**data["check_program_ref"]), data["registered_hash"])
        elif op == "check_batch_not_halted":
            check_batch_not_halted(data["halted_by"])
        elif op == "parse_fault_recovery":
            FaultRecovery.from_json(data)
        elif op == "parse_run_manifest":
            RunManifest.from_json(data)
        elif op == "parse_test_spec":
            TestSpec.from_json(data)
        else:  # pragma: no cover - a fixture bug
            raise ValueError(f"unknown fixture operation {op}")
    except AssertionIntegrityError as exc:
        return {"refused": True, "code": exc.code, "run_outcome": exc.run_outcome, "run_reason": exc.run_reason}
    except QAContractError as exc:
        return {"refused": True, "code": exc.code}
    return {"refused": False}


def _checked(fixtures: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    for fx in fixtures:
        got = run_fixture(fx["operation"], copy.deepcopy(fx["input"]))
        if got != fx["expect"]:
            raise AssertionError(f"fixture {fx['id']}: intended {fx['expect']}, implementation gives {got}")
    return fixtures


def _check_classification(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    for row in rows:
        got = classify_refusal(row["code"])
        got = None if got is None else [got[0].value, got[1]]
        assert got == row["classification"], row
    return rows


# ── assembly ───────────────────────────────────────────────────────────────────────────────────────────────

def _strip(item: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in item.items() if k != "_entry"}


def addendum() -> Dict[str, Any]:
    predicates, digests = _predicate_cases(), _value_digest_cases()
    receipts, orderings = _receipt_cases(), _set_ordering_cases()
    recoveries = _recovery_cases()
    vectors = [x["_entry"] for x in [*predicates, *digests, *receipts, *recoveries, *orderings]]
    ids = [v["id"] for v in vectors]
    assert len(ids) == len(set(ids)), "duplicate vector id"
    base_sha = hashlib.sha256(BASE_VECTORS_PATH.read_bytes()).hexdigest()
    return {
        "vector_set": "runtime-contracts/qa/canonical-vectors-addendum",
        "addendum_version": ADDENDUM_VERSION,
        "contract": QA_CONTRACT_ID,
        "canonicalization": canonical.CANONICALIZATION_VERSION,
        "extends": {"file": "golden/qa_canon_vectors.json", "sha256": base_sha,
                    "relation": "additive: that file is unchanged and still authoritative for everything it holds"},
        "version_note": ("addendum_version 1. A later addendum adds vectors or sections and never edits an entry "
                         "here. `vectors` and `refusals` have the shape of the base vector file, so a runner for "
                         "the base file runs them unchanged; `predicates`, `value_digests` and `set_ordering` are "
                         "annotated views of entries in `vectors` that say which rule each entry pins. A consumer "
                         "that does not know this file loses nothing the base file promised."),
        "how_to_use": (
            "1. For each entry in `vectors`, canonicalize `input` under rcv1: the bytes must equal `canonical_json`, "
            "their SHA-256 must equal `sha256_hex`, and `rcv1` is 'rcv1:' + sha256_hex. 2. `predicates`: "
            "`expected_hash` is the rcv1 of the canonical form of {op, expected} (expected omitted when absent) and "
            "nothing else of the assertion. 3. `value_digests`: `digest` is the rcv1 of the canonical JSON text of "
            "the value (a string is hashed with its quotes, after NFC); for a SecretRef it is the rcv1 of the "
            "reference's canonical form. 4. `set_ordering.cases`: take `record_listed`, order the named field by "
            "the case's `order` (`element_key`: by the named key of each element; `canonical_text`: by the "
            "canonical JSON text of each element; `value`: by the value, strings by Unicode code point and enums "
            "by member value), and the result must equal `canonical` and hash to `rcv1`. Ordering by the other "
            "rule gives `other_rule_order` and `rcv1_if_ordered_the_other_way`, which are wrong."),
        "vectors": vectors,
        "refusals": [{"id": "value_digest_of_a_float", "why": "a float value has no digest: carry decimals as strings",
                      "input": {"v": 1.5}, "expect": "refused"}],
        "predicates": [_strip(p) for p in predicates],
        "predicate_relations": _predicate_relations(),
        "value_digests": [_strip(d) for d in digests],
        "idempotency_receipts": [_strip(r) for r in receipts],
        "fault_recoveries": [_strip(r) for r in recoveries],
        "set_ordering": {
            "rules": SET_RULES, "ordered_not_sets": ORDERED_FIELDS,
            "statement": ("A set-valued field is sorted before hashing and its listed order is not identity. The "
                          "order is by the field's element key where the field names one, by the canonical JSON "
                          "text of the element where it says `canonical_text`, and by the value itself for strings "
                          "(Unicode code point, after NFC) and enums (member value). Duplicates are refused. A "
                          "field not listed under `rules` is ordered and its order is identity."),
            "cases": [_strip(c) for c in orderings],
            "refusals": _set_ordering_refusals()},
    }


def clarifications() -> Dict[str, Any]:
    golden_cases = json.loads(base_golden.CASES_PATH.read_text())["cases"]
    receipts = _receipt_cases()
    by_id = {r["id"]: r for r in receipts}
    idempotency_cases = [
        {"id": "same_key_across_attempts", "why": "two attempts of one step share one key: the target can recognise "
                                                  "a replay", "receipts": ["receipt_attempt_1", "receipt_attempt_2"],
         "violations": []},
        {"id": "one_key_per_step", "why": "different steps carry different keys",
         "receipts": ["receipt_attempt_1", "receipt_attempt_2", "receipt_other_step"], "violations": []},
        {"id": "key_changes_between_attempts", "why": "a replay that arrives under a new key cannot be recognised",
         "receipts": ["receipt_attempt_1", "receipt_attempt_2_rekeyed"],
         "violations": ["IDEMPOTENCY_KEY_CHANGED_ACROSS_ATTEMPTS"]},
    ]
    keys = ("run_id", "step_id", "attempt", "idempotency_key")
    shared_case = {"id": "key_shared_by_two_steps", "why": "two steps of one run must not share a key: the target "
                                                           "would treat the second as a replay of the first",
                   "receipts": [{k: by_id["receipt_attempt_1"][k] for k in keys},
                                {**{k: by_id["receipt_other_step"][k] for k in keys},
                                 "idempotency_key": by_id["receipt_attempt_1"]["idempotency_key"]}],
                   "violations": ["IDEMPOTENCY_KEY_SHARED_ACROSS_STEPS"]}
    idempotency_cases.append(shared_case)
    record = collections.namedtuple("R", keys)
    for case in idempotency_cases:
        if case is not shared_case:
            case["receipts"] = [{k: by_id[r][k] for k in keys} for r in case["receipts"]]
        got = idempotency_key_violations([record(**r) for r in case["receipts"]])
        assert list(got) == case["violations"], case["id"]
    fault_recovery_hash = golden_cases["fault_recovery"]["hash"]
    recoveries = {r["id"]: r for r in _recovery_cases()}
    return {
        "fixture_set": "runtime-contracts/qa/clarifications",
        "clarifications_version": CLARIFICATIONS_VERSION,
        "contract": QA_CONTRACT_ID,
        "canonicalization": canonical.CANONICALIZATION_VERSION,
        "version_note": ("clarifications_version 1. Additive to qa/v1: no entry restates or replaces an entry of "
                         "golden/qa.json, and nothing here changes a hash defined there. A later version adds "
                         "entries and never edits one."),
        "idempotency": {
            "rule": ("The idempotency key is per step: every attempt of one step in one run carries the same key, "
                     "and different steps of one run carry different keys. It is an opaque identifier of the "
                     "Ident shape; no consumer parses it."),
            "cases": idempotency_cases,
            "receipt_hashes": {r["id"]: r["hash"] for r in receipts}},
        "state_and_value_digests": {
            "rule": ("state_before_hash, state_after_hash and Checkpoint.state_hash are opaque rcv1 hashes of "
                     "whatever the producer defines as the observable state; qa/v1 specifies their shape, their "
                     "identity status and one relation (a blocked action leaves them equal), not their derivation. "
                     "Value digests are defined in golden/qa_canon_vectors_addendum.json."),
            "identity_relations": [
                {"why": "state_after_hash is identity", "differ": ["receipt_attempt_1", "receipt_state_after_changed"]},
                {"why": "duration_ms is custody", "equal": ["receipt_attempt_1", "receipt_duration_changed"]},
                {"why": "the idempotency key is identity", "differ": ["receipt_attempt_1", "receipt_key_changed"]},
                {"why": "the attempt number is identity", "differ": ["receipt_attempt_1", "receipt_attempt_2"]}]},
        "refusals": _checked(_integrity_fixtures()),
        "classification": {
            "rule": ("Every integrity refusal classifies as INCONCLUSIVE(ASSERTION_INTEGRITY) and halts the batch. "
                     "A code a consumer does not know classifies the same way. A known code that is not an "
                     "integrity refusal has no classification here (null)."),
            "cases": _check_classification(_classification_cases()),
            "older_consumer": _older_consumer_cases()},
        "fault_recovery": {
            "reason_code_vocabulary": [m.value for m in RecoveryReason],
            "existing_golden_fault_recovery_hash": fault_recovery_hash,
            "hashes": {k: v["hash"] for k, v in recoveries.items()},
            "relations": [
                {"why": "reason_code is identity", "differ": ["not_recovered_without_reason",
                                                               "not_recovered_no_candidate"]},
                {"why": "candidates_rejected_reasons is ordered", "differ": ["not_recovered_without_reason",
                                                                              "rejected_reasons_reordered"]}],
            "refusals": _checked(_recovery_refusals())},
        "identity_boundary": {**{k: v for k, v in _identity_boundary().items() if k != "refusals"},
                              "refusals": _checked(_identity_boundary()["refusals"])},
    }


def _dump(doc: Any) -> str:
    return json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def main() -> None:
    ADDENDUM_PATH.write_text(_dump(addendum()), encoding="utf-8")
    CLARIFICATIONS_PATH.write_text(_dump(clarifications()), encoding="utf-8")
    print(f"wrote {ADDENDUM_PATH.name} and {CLARIFICATIONS_PATH.name}")


if __name__ == "__main__":
    main()
