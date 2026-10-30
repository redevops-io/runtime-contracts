"""Language-neutral golden vectors for the ``qa/v1`` contracts.

A port in another language reproduces these hashes from the same inputs, or it does not conform. Nothing here
reads a clock or a random source: every value is fixed (``golden/qa_samples.py``).

Three files are generated; regenerate with ``python -m golden.qa``:

* ``golden/qa.json``: one case per ``qa/v1`` schema (the identity form as ``input``, custody apart, the expected
  ``rcv1`` hash), the hash relations that must hold (equal and different), and the frozen-assertion refusal
  cases: what each guard must refuse and with which code.
* ``golden/qa_canon_vectors.json``: self-contained. Primitive canonicalization vectors plus every ``qa.json``
  input, each with its canonical bytes and the SHA-256 hex digest. An independent implementation of the published
  canonicalization rules (the harness has one, ``canon-v1``) consumes only this file and must reproduce every
  digest and refuse every refusal case. It needs neither this package nor the other fixture file.
* ``golden/qa.schema.json`` and ``golden/qa.inventory.json`` come from ``runtime_contracts.qa.schema_export`` and
  ``runtime_contracts.qa.inventory``.

Released golden hashes are never rewritten. A new optional field gets new cases and leaves the old ones unchanged,
which is how additive-only is demonstrated.
"""
from __future__ import annotations

import collections.abc
import copy
import dataclasses
import hashlib
import json
import pathlib
import unicodedata
from typing import Any, Dict, List

from golden import qa_samples as S
from runtime_contracts import canonical
from runtime_contracts.models.verification import Check, Verdict
from runtime_contracts.qa import (Action, ActionKind, AssertionIntegrityError, AssertionResult, AssertionSpec,
                                  AssertionSubject,
                                  CheckSubject, CheckTier, FaultEvent, LocatorCandidate, LocatorDescriptor,
                                  Outcome, Predicate, PredicateOp, QAContractError, QAPlan, RunManifest,
                                  SubjectKind, TestSpec, assertion_set_hash, check_result_matches_assertion,
                                  classify_coverage, outcome_to_verdict, parse_recovery_candidate,
                                  verify_assertion_set, verify_manifest_against_spec)
from runtime_contracts.qa.base import QA_CONTRACT_ID, QA_SCHEMA_VERSION, QARecord, QAValue
from runtime_contracts.qa.registry import RECORDS

HERE = pathlib.Path(__file__).parent
CASES_PATH = HERE / "qa.json"
VECTORS_PATH = HERE / "qa_canon_vectors.json"


def _json_ready(value: Any) -> Any:
    """Plain, sorted, null-free JSON for a canonical form."""
    return canonical.canonicalize(value)


def _record_case(obj: QARecord, why: str) -> Dict[str, Any]:
    case = {"why": why, "schema_id": obj.SCHEMA_ID, "input": _json_ready(obj.canonical_form()),
            "hash": obj.content_hash}
    custody = obj.to_json().get("custody")
    if custody:
        case["custody"] = custody
    return case


def _value_case(obj: QAValue, why: str) -> Dict[str, Any]:
    return {"why": why, "type": type(obj).__name__, "input": _json_ready(obj.canonical_form()),
            "hash": obj.value_hash()}


def _set_form(assertions) -> Dict[str, Any]:
    return {"assertions": sorted((_json_ready(a.canonical_form()) for a in assertions),
                                 key=lambda f: f["assertion_id"]),
            "hash": assertion_set_hash(assertions)}


# ── fixtures ───────────────────────────────────────────────────────────────────────────────────────────────

SPEC = S.ui_spec()


def _resource_spec() -> TestSpec:
    return S.ui_spec("infra-manifest", steps=(S.resource_step(),),
                     assertions=(S.ui_assertion("a-resource-note", requirement_ref=None),), allowed_side_effects=())


def record_cases() -> Dict[str, Any]:
    a1, a2 = SPEC.assertions
    receipt = S.action_receipt()
    blocked = S.action_receipt(
        result=S.ResultCode.ACTION_BLOCKED_BY_POLICY, state_after_hash=S.h(41),
        policy_decision_ref=S.policy_decision(decision=S.PolicyDecisionKind.DENY, rule_id=None).content_hash,
        postcondition=S.Postcondition(declared="url ends /saved", result=S.PostconditionResult.NOT_EVALUATED))
    skipped = S.run_manifest(
        assertions_executed=(a1.assertion_id,),
        assertions_skipped=(S.SkippedAssertion(assertion_id=a2.assertion_id, reason_code=S.SkipReason.NOT_REACHED),),
        assertion_results=(S.assertion_result(a1, SPEC),), outcome=Outcome.INCONCLUSIVE)
    integrity = S.run_manifest(
        assertions_executed=(a1.assertion_id,), assertion_results=(S.assertion_result(a1, SPEC),),
        outcome=Outcome.INCONCLUSIVE, outcome_reason="ASSERTION_INTEGRITY")
    indeterminate = S.assertion_result(a1, SPEC, verdict=Verdict.INDETERMINATE,
                                       check=Check(check_id=a1.assertion_id, verdict=Verdict.INDETERMINATE),
                                       reason_code="SUBJECT_UNRESOLVED", actual=None)
    fe = S.fault_event()
    return {
        "assertion_spec_playwright": _record_case(a1, "a frozen UI assertion: executor, requirement_ref and expected "
                                                       "are all hashed"),
        "assertion_spec_without_requirement_ref": _record_case(
            S.ui_assertion(requirement_ref=None), "absent requirement_ref is null and null is dropped, so this "
                                                  "hashes as an assertion from before the field existed"),
        "test_spec_ui": _record_case(SPEC, "a UI spec; author is custody and is not in the hash"),
        "test_spec_resource": _record_case(_resource_spec(), "a spec with a resource-target step (manifest path)"),
        "qa_plan": _record_case(S.plan_for([SPEC.spec_ref, _resource_spec().spec_ref]),
                                "static lanes, one gate, coverage_contract FULL; rationale_ref is custody"),
        "observation": _record_case(S.observation(), "observation; timestamps and duration are custody"),
        "action_receipt": _record_case(receipt, "an attempt with the authored locator and a satisfied postcondition"),
        "action_receipt_blocked_by_policy": _record_case(
            blocked, "a denied action still cites its policy decision and changed nothing"),
        "policy_decision": _record_case(S.policy_decision(), "a ui_action allow decision; reason is custody"),
        "locator_candidate": _record_case(
            LocatorCandidate(strategy=S.LocatorStrategy.SEMANTIC_ALTERNATE, role="button", name="Save"),
            "the only thing recovery may express: a locator to try"),
        "observed_value_resolved": _record_case(
            S.ObservedValue(resolution=S.Resolution.RESOLVED, match_count=1, value="Saved", observation_id="obs-s1-after"),
            "what assert_ read; no expected and no verdict"),
        "observed_value_ambiguous": _record_case(
            S.ObservedValue(resolution=S.Resolution.AMBIGUOUS, match_count=3), "resolution fact only"),
        "assertion_result_pass": _record_case(S.assertion_result(a1, SPEC),
                                              "verifier output; embeds Check, mirrors executor"),
        "assertion_result_indeterminate": _record_case(indeterminate, "an unresolved subject is indeterminate with "
                                                                      "a reason, never a pass"),
        "fault_detection": _record_case(fe.detection, "detection, hashed first"),
        "fault_recovery": _record_case(fe.recovery, "recovery binds to the detection by hash; cost is custody"),
        "fault_event": _record_case(fe, "detection and recovery as two embedded records"),
        "run_manifest_pass": _record_case(S.run_manifest(), "declared == executed, nothing skipped, PASS"),
        "run_manifest_inconclusive_skipped": _record_case(
            skipped, "an assertion skipped with a reason: INCONCLUSIVE, consistent accounting"),
        "run_manifest_assertion_integrity": _record_case(
            integrity, "declared != executed + skipped: only INCONCLUSIVE(ASSERTION_INTEGRITY) can be recorded"),
        "checkpoint": _record_case(S.Checkpoint(checkpoint_id="cp-1", run_id="run-1", step_index=2, state_hash=S.h(51),
                                                fixture_snapshot_id="snap-1", taken_at="2026-10-30T10:00:02Z"),
                                   "in-run resume point; no storage state"),
        "review_item": _record_case(
            S.ReviewItem(review_item_id="ri-1", run_id="run-1", reason="ASSERTION_INTEGRITY",
                         evidence_refs=(S.evidence(1), S.evidence(2)), suggested_change_ref=S.h(52),
                         created_at="2026-10-30T10:00:06Z"), "an INCONCLUSIVE run always creates one"),
        "review_record": _record_case(
            S.ReviewRecord(review_item_ref=S.h(53), decision=S.ReviewDecision.ACCEPT, reviewer_id="rev-1",
                           review_minutes=4), "appended later; reviewer and minutes are custody"),
        "cleanup_report": _record_case(S.CleanupReport(handle_id="s1", verified=True, released=("page", "context")),
                                       "verified cleanup"),
    }


def value_cases() -> Dict[str, Any]:
    """One case per nested value type, so every type's identity is pinned on its own."""
    from runtime_contracts import qa
    prog = S.CheckProgramRef(id="image-pinned", version="1.0.0", program_hash=S.d(6))
    image = S.ResourceRef(kind=S.ResourceKind.IMAGE_DIGEST, digest=S.d(2))
    plan = S.plan_for([SPEC.spec_ref, _resource_spec().spec_ref])
    receipt, manifest = S.action_receipt(), S.run_manifest()
    cand = qa.LocateCandidate(candidate_ref="c1", role="button", name="Save", visible=True, enabled=True, unique=True)
    made = [
        ("component_ref", S.ADAPTER, "{id, version} of whatever produced something"),
        ("locator_descriptor", LocatorDescriptor(role="button", name="Save", frame_path=("outer", "inner")),
         "frame_path order is meaning"),
        ("resource_ref_manifest_path", S.ResourceRef(kind=S.ResourceKind.MANIFEST_PATH, path="k8s/deploy.yaml"),
         "MANIFEST_PATH carries only a case-relative path"),
        ("resource_ref_image_digest", image, "IMAGE_DIGEST carries only a digest"),
        ("resource_ref_namespace_object",
         S.ResourceRef(kind=S.ResourceKind.NAMESPACE_OBJECT, api_version="apps/v1", object_kind="Deployment",
                       namespace="web", name="api"), "NAMESPACE_OBJECT carries the four typed fields"),
        ("check_program_ref", prog, "a registered program pinned by the full sha256 of its source"),
        ("step_target_ui", S.ui_step().target, "tagged target kind=ui"),
        ("step_target_resource", S.resource_step().target, "tagged target kind=resource"),
        ("action_click", Action(ActionKind.CLICK), "an action with no value"),
        ("step_ui", S.ui_step(), "a UI step"),
        ("step_resource", S.resource_step(), "a resource step with a MANIFEST_PATH reference"),
        ("predicate_equals", Predicate(PredicateOp.EQUALS, "Saved"), "expected_hash is the hash of this value"),
        ("assertion_subject_ui", SPEC.assertions[0].subject, "a UI element subject"),
        ("test_target", SPEC.target, "app, build and environment profile"),
        ("fixture_ref", SPEC.fixtures[0], "a fixture pinned by digest"),
        ("budget", SPEC.budget, "hard caps for one run"),
        ("plan_item", plan.items[0], "a spec in a lane at a position"),
        ("plan_gate", plan.gates[0], "a start condition between items"),
        ("resource_claim", plan.resource_claims[0], "a declarative claim"),
        ("observation_source", S.observation().source, "which adapter and browser observed"),
        ("tool_ref", receipt.tool, "the tool that acted"),
        ("locator_used", receipt.locator_used, "the locator actually used and how it was chosen"),
        ("action_record", receipt.action, "the action taken; value digest only"),
        ("postcondition", receipt.postcondition, "declared, observed, result"),
        ("recovery_cost", S.fault_event().recovery.cost, "recovery cost (custody on the recovery record)"),
        ("skipped_assertion", qa.SkippedAssertion(assertion_id="a-url", reason_code=S.SkipReason.NOT_REACHED),
         "a skipped assertion with its reason"),
        ("version_pin", manifest.versions[0], "a pinned dependency"),
        ("model_ref", qa.ModelRef(provider="fake", model_id="fake-1", parameters={"temperature": "0"}),
         "model identity; parameters are decimal strings, not floats"),
        ("step_result", manifest.step_results[0], "how a step ended, with its receipts"),
        ("counters", manifest.counters, "cost counters (custody on the manifest)"),
        ("session_profile", qa.SessionProfile(egress_profile="operator-default", redaction_policy_id=S.h(31)),
         "downloads, popups and file choosers denied by default"),
        ("session_handle", qa.SessionHandle(session_id="sess-1"), "opaque session id"),
        ("observe_request", qa.ObserveRequest(step_id="s1", phase=S.Phase.AFTER,
                                              capture=(qa.CaptureKind.SCREENSHOT, qa.CaptureKind.A11Y_SNAPSHOT)),
         "what to capture"),
        ("locate_candidate", cand, "a sole candidate is unique"),
        ("locate_result", qa.LocateResult(candidates=(cand,)), "every candidate, not the first"),
        ("resolved_target", qa.ResolvedTarget(candidate_ref="c1", locator=LocatorDescriptor(role="button"),
                                              strategy=S.LocatorStrategy.AUTHORED), "what locate produced"),
        ("action_request", qa.ActionRequest(step_id="s1", action=Action(ActionKind.CLICK), idempotency_key="idem-1",
                                            policy_decision_ref=S.h(9)), "an action cannot be built without a decision"),
        ("action_outcome", qa.ActionOutcome(result=S.ResultCode.OK), "a raw result, no verdict"),
        ("reset_result", qa.ResetResult(scope=qa.ResetScope.FIXTURE, ok=True), "reset outcome"),
        ("check_profile_offline", qa.CheckProfile(tier=CheckTier.OFFLINE, case_root_digest=S.d(1)),
         "offline: no disposable proof"),
        ("check_profile_k", qa.CheckProfile(tier=CheckTier.K, case_root_digest=S.d(1), disposable_proof_ref=S.h(2)),
         "tier K requires the disposable-cluster proof"),
        ("workspace_handle", qa.WorkspaceHandle(workspace_id="ws-1"), "opaque workspace id"),
        ("resolved_resource", qa.ResolvedResource(ref=image, content_digest=S.d(3)), "a reference and its digest"),
        ("check_subject", CheckSubject(check_program_ref=prog, inputs=(image,), tier=CheckTier.OFFLINE),
         "program, inputs and tier; never an expected value"),
    ]
    return {name: _value_case(obj, why) for name, obj, why in made}


def assertion_sets() -> Dict[str, Any]:
    a1, a2 = S.ui_assertion("a-saved"), S.url_assertion("a-url")
    cafe = S.ui_assertion("a-saved", expected="café")
    cafe_nfd = S.ui_assertion("a-saved", expected=unicodedata.normalize("NFD", "café"))
    # an NFD string survives construction as NFC, so the NFD form is built from the raw dict instead
    nfd_raw = _json_ready(cafe.canonical_form())
    nfd_raw["predicate"]["expected"] = unicodedata.normalize("NFD", "café")
    changed_locator = dataclasses.replace(a1, subject=AssertionSubject(
        kind=SubjectKind.UI_ELEMENT, locator=LocatorDescriptor(test_id="save-status", frame_path=("f",))))
    return {
        "reference": {"why": "the reference set", **_set_form([a1, a2])},
        "order_variation": {"why": "listing order is a property of the builder, not the set", **_set_form([a2, a1])},
        "unicode_nfc": {"why": "expected written in NFC", **_set_form([cafe])},
        "unicode_nfd": {"why": "expected written in NFD hashes as NFC",
                        "assertions": [nfd_raw],
                        "hash": canonical.content_hash({
                            "schema_id": "runtime-contracts/qa/assertion-set", "schema_version": QA_SCHEMA_VERSION,
                            "assertions": [nfd_raw]})},
        "expected_changed": {"why": "changing expected changes the set hash",
                             **_set_form([S.ui_assertion("a-saved", expected="Different"), a2])},
        "locator_descriptor_changed": {"why": "the frozen locator is part of the assertion",
                                       **_set_form([changed_locator, a2])},
        "requirement_ref_changed": {"why": "requirement_ref is hashed",
                                    **_set_form([S.ui_assertion("a-saved", requirement_ref="REQ-OTHER"), a2])},
        "requirement_ref_removed": {"why": "removing requirement_ref changes the hash",
                                    **_set_form([S.ui_assertion("a-saved", requirement_ref=None), a2])},
        "operator_changed": {"why": "the predicate op is hashed",
                             **_set_form([S.ui_assertion("a-saved", op=PredicateOp.CONTAINS), a2])},
    }


RELATIONS: List[Dict[str, Any]] = [
    {"why": "assertion order does not matter", "equal": ["reference", "order_variation"]},
    {"why": "NFC and NFD spellings of expected hash the same", "equal": ["unicode_nfc", "unicode_nfd"]},
    {"why": "any change to expected, locator, requirement_ref or op changes the set hash",
     "differ": [["reference", "expected_changed"], ["reference", "locator_descriptor_changed"],
                ["reference", "requirement_ref_changed"], ["reference", "requirement_ref_removed"],
                ["reference", "operator_changed"]]},
]


def hash_properties() -> Dict[str, Any]:
    a = S.ui_assertion()
    form = _json_ready(a.canonical_form())
    without = {k: v for k, v in form.items() if k != "requirement_ref"}
    explicit_null = dict(without, requirement_ref=None)
    spec_a, spec_b = S.ui_spec(author="author-1"), S.ui_spec(author="someone-else")
    return {
        "absent_equals_null": {
            "why": "an explicit null and an omitted key hash identically",
            "omitted": canonical.content_hash(without), "explicit_null": canonical.content_hash(explicit_null)},
        "custody_excluded": {
            "why": "author is custody: two specs differing only in author share spec_hash",
            "spec_hash_a": spec_a.spec_hash, "spec_hash_b": spec_b.spec_hash},
    }


# ── frozen-assertion refusal cases ─────────────────────────────────────────────────────────────────────────

def _edit_assertion(spec: TestSpec, index: int, path, value) -> Dict[str, Any]:
    form = _json_ready(spec.assertions[index].canonical_form())
    node = form
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    return form


def _refusal_fixtures() -> List[Dict[str, Any]]:
    a1, a2 = SPEC.assertions
    pinned = SPEC.assertion_set_hash
    forms = [_json_ready(a.canonical_form()) for a in SPEC.assertions]
    res_ok = _json_ready(S.assertion_result(a1, SPEC).canonical_form())
    manifest_ok = S.run_manifest()
    other_spec = S.ui_spec(assertions=(S.ui_assertion(expected="x"), a2))
    return [
        {"id": "expected_edited_after_pinning", "operation": "verify_assertion_set",
         "why": "an assertion's expected value is edited after the set hash was pinned: refuse, evaluate nothing",
         "input": {"pinned_assertion_set_hash": pinned,
                   "assertions": [_edit_assertion(SPEC, 0, ("predicate", "expected"), "Hacked"), forms[1]]},
         "expect": {"refused": True, "code": "ASSERTION_HASH_MISMATCH", "run_outcome": "INCONCLUSIVE",
                    "run_reason": "ASSERTION_INTEGRITY"}},
        {"id": "locator_edited_after_pinning", "operation": "verify_assertion_set",
         "why": "a frozen locator descriptor is edited after pinning",
         "input": {"pinned_assertion_set_hash": pinned,
                   "assertions": [_edit_assertion(SPEC, 0, ("subject", "locator", "test_id"), "other"), forms[1]]},
         "expect": {"refused": True, "code": "ASSERTION_HASH_MISMATCH", "run_outcome": "INCONCLUSIVE",
                    "run_reason": "ASSERTION_INTEGRITY"}},
        {"id": "requirement_ref_edited_after_pinning", "operation": "verify_assertion_set",
         "why": "requirement_ref is part of the frozen assertion",
         "input": {"pinned_assertion_set_hash": pinned,
                   "assertions": [_edit_assertion(SPEC, 0, ("requirement_ref",), "REQ-OTHER"), forms[1]]},
         "expect": {"refused": True, "code": "ASSERTION_HASH_MISMATCH", "run_outcome": "INCONCLUSIVE",
                    "run_reason": "ASSERTION_INTEGRITY"}},
        {"id": "assertion_removed", "operation": "verify_assertion_set",
         "why": "dropping an assertion is a change", "input": {"pinned_assertion_set_hash": pinned,
                                                               "assertions": [forms[0]]},
         "expect": {"refused": True, "code": "ASSERTION_HASH_MISMATCH", "run_outcome": "INCONCLUSIVE",
                    "run_reason": "ASSERTION_INTEGRITY"}},
        {"id": "assertion_added", "operation": "verify_assertion_set",
         "why": "adding an assertion is a change",
         "input": {"pinned_assertion_set_hash": pinned,
                   "assertions": [*forms, _json_ready(S.ui_assertion("a-extra").canonical_form())]},
         "expect": {"refused": True, "code": "ASSERTION_HASH_MISMATCH", "run_outcome": "INCONCLUSIVE",
                    "run_reason": "ASSERTION_INTEGRITY"}},
        {"id": "assertions_unchanged_control", "operation": "verify_assertion_set",
         "why": "control: untouched assertions verify", "input": {"pinned_assertion_set_hash": pinned,
                                                                  "assertions": forms},
         "expect": {"refused": False}},
        {"id": "spec_file_edited_between_load_and_verify", "operation": "parse_test_spec",
         "why": "the stored content_hash no longer matches the edited bytes: hash mismatch, no evaluation",
         "input": {**SPEC.to_json(), "assertions": [
             {**SPEC.to_json()["assertions"][0],
              "predicate": {**SPEC.to_json()["assertions"][0]["predicate"], "expected": "Hacked"}},
             SPEC.to_json()["assertions"][1]]},
         "expect": {"refused": True, "code": "HASH_MISMATCH"}},
        {"id": "verifier_handed_a_different_expected", "operation": "check_result_matches_assertion",
         "why": "a result computed against another expected value is refused",
         "input": {"assertion": _json_ready(a1.canonical_form()),
                   "result": _json_ready(S.assertion_result(S.ui_assertion(expected="Other"), SPEC).canonical_form())},
         "expect": {"refused": True, "code": "EXPECTED_MISMATCH", "run_outcome": "INCONCLUSIVE",
                    "run_reason": "ASSERTION_INTEGRITY"}},
        {"id": "result_executor_differs_from_assertion", "operation": "check_result_matches_assertion",
         "why": "AssertionResult.executor must equal the frozen assertion's executor",
         "input": {"assertion": _json_ready(a1.canonical_form()), "result": {**res_ok, "executor": "SCRIPT"}},
         "expect": {"refused": True, "code": "EXECUTOR_MISMATCH", "run_outcome": "INCONCLUSIVE",
                    "run_reason": "ASSERTION_INTEGRITY"}},
        {"id": "result_matches_control", "operation": "check_result_matches_assertion",
         "why": "control: a faithful result is accepted",
         "input": {"assertion": _json_ready(a1.canonical_form()), "result": res_ok}, "expect": {"refused": False}},
        {"id": "recovery_proposes_expected", "operation": "parse_recovery_candidate",
         "why": "a hostile recoverer returns a changed expected value",
         "input": {"strategy": "SEMANTIC_ALTERNATE", "role": "button", "expected": "Anything"},
         "expect": {"refused": True, "code": "RECOVERY_PAYLOAD_REJECTED", "run_outcome": "INCONCLUSIVE",
                    "run_reason": "ASSERTION_INTEGRITY"}},
        {"id": "recovery_extra_field", "operation": "parse_recovery_candidate",
         "why": "a candidate with any field beyond the strict schema",
         "input": {"strategy": "MODEL_CANDIDATE", "test_id": "save", "selector": "#save"},
         "expect": {"refused": True, "code": "RECOVERY_PAYLOAD_REJECTED", "run_outcome": "INCONCLUSIVE",
                    "run_reason": "ASSERTION_INTEGRITY"}},
        {"id": "recovery_returns_an_assertion_object", "operation": "parse_recovery_candidate",
         "why": "a recovery payload carrying an assertion",
         "input": {"strategy": "MODEL_CANDIDATE", "role": "button", "assertion": forms[0]},
         "expect": {"refused": True, "code": "RECOVERY_PAYLOAD_REJECTED", "run_outcome": "INCONCLUSIVE",
                    "run_reason": "ASSERTION_INTEGRITY"}},
        {"id": "recovery_candidate_control", "operation": "parse_recovery_candidate",
         "why": "control: a strict candidate is accepted",
         "input": {"strategy": "SEMANTIC_ALTERNATE", "role": "button", "name": "Save"}, "expect": {"refused": False}},
        {"id": "manifest_pins_a_different_assertion_set", "operation": "verify_manifest_against_spec",
         "why": "the run pinned an assertion set the spec does not hold",
         "input": {"spec": _json_ready(SPEC.canonical_form()),
                   "manifest": _json_ready(S.run_manifest(other_spec).canonical_form())},
         "expect": {"refused": True, "code": "ASSERTION_HASH_MISMATCH", "run_outcome": "INCONCLUSIVE",
                    "run_reason": "ASSERTION_INTEGRITY"}},
        {"id": "manifest_run_of_the_spec_control", "operation": "verify_manifest_against_spec",
         "why": "control: a manifest of this spec is accepted",
         "input": {"spec": _json_ready(SPEC.canonical_form()), "manifest": _json_ready(manifest_ok.canonical_form())},
         "expect": {"refused": False}},
        {"id": "coverage_declared_not_accounted", "operation": "classify_coverage",
         "why": "declared assertion neither executed nor skipped", "input": {"declared": ["a", "b"],
                                                                              "executed": ["a"], "skipped": []},
         "expect": {"classification": ["INCONCLUSIVE", "ASSERTION_INTEGRITY"]}},
        {"id": "coverage_executed_and_skipped", "operation": "classify_coverage",
         "why": "executed and skipped overlap", "input": {"declared": ["a", "b"], "executed": ["a", "b"],
                                                          "skipped": ["b"]},
         "expect": {"classification": ["INCONCLUSIVE", "ASSERTION_INTEGRITY"]}},
        {"id": "coverage_executed_not_declared", "operation": "classify_coverage",
         "why": "an assertion ran that the spec never declared", "input": {"declared": ["a"],
                                                                          "executed": ["a", "z"], "skipped": []},
         "expect": {"classification": ["INCONCLUSIVE", "ASSERTION_INTEGRITY"]}},
        {"id": "coverage_consistent_control", "operation": "classify_coverage",
         "why": "control: declared == executed + skipped, disjoint", "input": {"declared": ["a", "b"],
                                                                              "executed": ["a"], "skipped": ["b"]},
         "expect": {"classification": None}},
        {"id": "manifest_claims_pass_with_broken_accounting", "operation": "parse_run_manifest",
         "why": "a manifest that breaks the accounting cannot claim PASS",
         "input": {**_json_ready(S.run_manifest(assertions_executed=(a1.assertion_id,),
                                                assertion_results=(S.assertion_result(a1, SPEC),),
                                                outcome=Outcome.INCONCLUSIVE,
                                                outcome_reason="ASSERTION_INTEGRITY").canonical_form()),
                   "outcome": "PASS", "outcome_reason": None},
         "expect": {"refused": True, "code": "COVERAGE_VIOLATION", "run_outcome": "INCONCLUSIVE",
                    "run_reason": "ASSERTION_INTEGRITY"}},
        {"id": "plan_coverage_subset", "operation": "parse_qa_plan",
         "why": "SUBSET is a reserved value every validator rejects",
         "input": {**_json_ready(S.plan_for([SPEC.spec_ref]).canonical_form()), "coverage_contract": "SUBSET"},
         "expect": {"refused": True, "code": "UNSUPPORTED_COVERAGE_CONTRACT"}},
        {"id": "plan_dynamic_dispatch_field", "operation": "parse_qa_plan",
         "why": "a plan has no field through which dynamic dispatch could be requested",
         "input": {**_json_ready(S.plan_for([SPEC.spec_ref]).canonical_form()), "work_stealing": True},
         "expect": {"refused": True, "code": "UNKNOWN_FIELD"}},
        {"id": "unknown_executor_is_non_certifying", "operation": "parse_assertion_spec",
         "why": "an executor value this version does not define fails closed",
         "input": {**_json_ready(a1.canonical_form()), "executor": "TELEPATHY"},
         "expect": {"refused": True, "code": "UNKNOWN_ENUM_VALUE"}},
        {"id": "unknown_schema_version", "operation": "parse_assertion_spec",
         "why": "a reader refuses an unknown major",
         "input": {**_json_ready(a1.canonical_form()), "schema_version": "1.0"},
         "expect": {"refused": True, "code": "SCHEMA_VERSION_UNSUPPORTED"}},
        {"id": "unknown_outcome_maps_to_indeterminate", "operation": "outcome_to_verdict",
         "why": "an outcome this version does not define can never be read as a pass",
         "input": {"outcome": "GREAT"}, "expect": {"verdict": "INDETERMINATE"}},
        {"id": "recovery_rewrites_the_detection", "operation": "parse_fault_event",
         "why": "recovery.detection_ref must be the hash of the detection it responds to",
         "input": {**_json_ready(S.fault_event().canonical_form()),
                   "detection": {**_json_ready(S.fault_event().detection.canonical_form()),
                                 "signal": "ASSERTION_FAILED", "claimed_class": "PRODUCT_DEFECT_SUSPECTED"}},
         "expect": {"refused": True, "code": "FAULT_BINDING_MISMATCH"}},
    ]


def run_refusal(op: str, data: Any) -> Dict[str, Any]:
    """What this implementation does with a refusal fixture's input. Used to generate and to check the fixtures."""
    try:
        if op == "verify_assertion_set":
            verify_assertion_set([AssertionSpec.from_json(a) for a in data["assertions"]],
                                 data["pinned_assertion_set_hash"])
        elif op == "parse_test_spec":
            TestSpec.from_json(data)
        elif op == "check_result_matches_assertion":
            check_result_matches_assertion(AssertionResult.from_json(data["result"]),
                                           AssertionSpec.from_json(data["assertion"]))
        elif op == "parse_recovery_candidate":
            parse_recovery_candidate(data)
        elif op == "verify_manifest_against_spec":
            verify_manifest_against_spec(RunManifest.from_json(data["manifest"]), TestSpec.from_json(data["spec"]))
        elif op == "classify_coverage":
            found = classify_coverage(data["declared"], data["executed"], data["skipped"])
            return {"classification": None if found is None else [found[0].value, found[1]]}
        elif op == "parse_run_manifest":
            RunManifest.from_json(data)
        elif op == "parse_qa_plan":
            QAPlan.from_json(data)
        elif op == "parse_assertion_spec":
            AssertionSpec.from_json(data)
        elif op == "parse_fault_event":
            FaultEvent.from_json(data)
        elif op == "outcome_to_verdict":
            return {"verdict": outcome_to_verdict(data["outcome"]).value}
        else:  # pragma: no cover - a fixture bug
            raise ValueError(f"unknown refusal operation {op}")
    except AssertionIntegrityError as exc:
        return {"refused": True, "code": exc.code, "run_outcome": exc.run_outcome, "run_reason": exc.run_reason}
    except QAContractError as exc:
        return {"refused": True, "code": exc.code}
    return {"refused": False}


def refusal_cases() -> List[Dict[str, Any]]:
    fixtures = _refusal_fixtures()
    for fx in fixtures:
        got = run_refusal(fx["operation"], copy.deepcopy(fx["input"]))
        if got != fx["expect"]:
            raise AssertionError(f"refusal fixture {fx['id']}: intended {fx['expect']}, implementation gives {got}")
    return fixtures


# ── assembly ───────────────────────────────────────────────────────────────────────────────────────────────

def cases() -> Dict[str, Any]:
    return {
        "contract": QA_CONTRACT_ID,
        "canonicalization": canonical.CANONICALIZATION_VERSION,
        "schema_version": QA_SCHEMA_VERSION,
        "schemas": {cls.SCHEMA_ID: cls.SCHEMA_VERSION for cls in RECORDS},
        "cases": record_cases(),
        "values": value_cases(),
        "assertion_sets": assertion_sets(),
        "relations": RELATIONS,
        "hash_properties": hash_properties(),
        "refusals": refusal_cases(),
    }


# ── the self-contained vector file for independent canonicalizers ──────────────────────────────────────────

_PRIMITIVES: List[Dict[str, Any]] = [
    {"id": "key_order", "why": "map keys are sorted", "input": {"b": 1, "a": 2}},
    {"id": "nested_key_order", "why": "sorting is recursive", "input": {"z": {"y": 1, "x": 2}, "a": [{"d": 1, "c": 2}]}},
    {"id": "null_dropped_in_map", "why": "absent and null are the same thing", "input": {"a": 1, "b": None}},
    {"id": "null_kept_in_list", "why": "a null inside a list is an element, not an absent key", "input": {"a": [1, None]}},
    {"id": "empty_containers", "why": "empty list and empty map are values", "input": {"a": [], "b": {}}},
    {"id": "integers", "why": "integers are written without exponent or fraction",
     "input": {"zero": 0, "neg": -7, "big": 9007199254740991}},
    {"id": "booleans", "why": "booleans are true and false", "input": {"t": True, "f": False}},
    {"id": "decimal_string_stays_a_string", "why": "fractional values are carried as canonical decimal strings",
     "input": {"amount": "12.5", "zero": "0"}},
    {"id": "nfc_normalization", "why": "strings are NFC; NFD input hashes as NFC",
     "input": {"name": "café"}},
    {"id": "nfc_in_keys", "why": "keys are NFC too", "input": {"café": 1}},
    {"id": "string_escapes", "why": "quote, backslash, newline, tab and C0 controls are escaped; '/' and DEL are not",
     "input": {"s": "q\" b\\ n\n t\t c\u0001 d\u007f /"}},
    {"id": "non_ascii_is_not_escaped", "why": "ensure_ascii is off: the bytes are UTF-8, not \\u escapes",
     "input": {"s": "é 中 \U0001f600  "}},
    {"id": "key_order_is_code_point_order",
     "why": "keys sort by Unicode code point, not by UTF-16 code unit: U+E000 sorts before U+1F600",
     "input": {"\U0001f600": 2, "": 1}},
    {"id": "list_order_is_preserved", "why": "only maps are unordered", "input": {"a": [3, 1, 2]}},
    {"id": "compact_separators", "why": "no spaces after ',' or ':'", "input": {"a": 1, "b": [1, 2]}},
    {"id": "top_level_scalar", "why": "a bare string is canonicalizable", "input": "plain"},
]

_REFUSALS: List[Dict[str, Any]] = [
    {"id": "float_refused", "why": "a float has no canonical form; carry decimals as strings", "input": {"a": 1.5}},
    {"id": "float_that_is_integral_refused", "why": "1.0 is still a float", "input": {"a": 1.0}},
    {"id": "float_in_list_refused", "why": "refusal is recursive", "input": {"a": [1, 2.5]}},
]


def _canon_entry(entry_id: str, why: str, value: Any, hash_of_record: str = None) -> Dict[str, Any]:
    text = canonical.canonical_json(value)
    out = {"id": entry_id, "why": why, "input": value, "canonical_json": text,
           "sha256_hex": hashlib.sha256(text.encode("utf-8")).hexdigest(),
           "rcv1": canonical.content_hash(value)}
    if hash_of_record is not None:
        assert out["rcv1"] == hash_of_record, f"{entry_id}: the case hash disagrees with rcv1 of its input"
    return out


def canon_vectors() -> Dict[str, Any]:
    all_cases = cases()
    vectors = [_canon_entry(p["id"], p["why"], p["input"]) for p in _PRIMITIVES]
    for name, case in all_cases["cases"].items():
        vectors.append(_canon_entry(f"qa:{name}", case["why"], case["input"], case["hash"]))
    for name, case in all_cases["values"].items():
        vectors.append(_canon_entry(f"qa-value:{name}", case["why"], case["input"], case["hash"]))
    for name, case in all_cases["assertion_sets"].items():
        wrapped = {"schema_id": "runtime-contracts/qa/assertion-set", "schema_version": QA_SCHEMA_VERSION,
                   "assertions": case["assertions"]}
        vectors.append(_canon_entry(f"qa-assertion-set:{name}", case["why"], wrapped, case["hash"]))
    return {
        "vector_set": "runtime-contracts/qa/canonical-vectors",
        "contract": QA_CONTRACT_ID,
        "canonicalization": canonical.CANONICALIZATION_VERSION,
        "how_to_use": (
            "For each entry in `vectors`, canonicalize `input` under rcv1 and compare: the canonical bytes must "
            "equal `canonical_json` (UTF-8), SHA-256 of those bytes must equal `sha256_hex`, and `rcv1` is "
            "'rcv1:' + sha256_hex. For each entry in `refusals`, canonicalization must be refused. Rules: map keys "
            "sorted by Unicode code point; a null map value is dropped; strings NFC (keys too); floats refused; "
            "lists keep order; compact separators; UTF-8 without \\u escaping of non-ASCII. A decimal is a string."),
        "vectors": vectors,
        "refusals": [{"id": r["id"], "why": r["why"], "input": r["input"], "expect": "refused"} for r in _REFUSALS],
    }


def _dump(doc: Any) -> str:
    return json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def main() -> None:
    CASES_PATH.write_text(_dump(cases()), encoding="utf-8")
    VECTORS_PATH.write_text(_dump(canon_vectors()), encoding="utf-8")
    print(f"wrote {CASES_PATH.name} and {VECTORS_PATH.name}")


if __name__ == "__main__":
    main()
