"""The frozen-assertion refusal cases in golden/qa.json: what each guard must refuse, and with which code.

The same fixtures are the contract a second implementation (the harness verifier, with its independent canon-v1)
must reproduce: the same input, the same refusal code.
"""
from __future__ import annotations

import copy
import json

import pytest

from golden.qa import CASES_PATH, run_refusal

REFUSALS = json.loads(CASES_PATH.read_text())["refusals"]
IDS = [r["id"] for r in REFUSALS]


@pytest.mark.parametrize("fx", REFUSALS, ids=IDS)
def test_each_case_behaves_as_documented(fx):
    assert run_refusal(fx["operation"], copy.deepcopy(fx["input"])) == fx["expect"]


def test_ids_are_unique_and_each_case_states_why():
    assert len(set(IDS)) == len(IDS)
    assert all(r["why"] for r in REFUSALS)


def test_every_refusal_has_a_control_that_is_accepted():
    """Each refusing operation is paired with an input it accepts, so a refusal is not just a blanket failure."""
    refused_ops = {r["operation"] for r in REFUSALS if r["expect"].get("refused") or "classification" in r["expect"]}
    controls = {r["operation"] for r in REFUSALS
                if r["expect"].get("refused") is False or r["expect"].get("classification") is None
                and "classification" in r["expect"]}
    uncontrolled = {op for op in refused_ops if op in {"verify_assertion_set", "check_result_matches_assertion",
                                                       "parse_recovery_candidate", "verify_manifest_against_spec",
                                                       "classify_coverage"}} - controls
    assert not uncontrolled, uncontrolled


def test_the_mutation_fixtures_required_by_the_immutable_assertion_rule_are_present():
    needed = {
        "a hostile recoverer returns a changed expected": "recovery_proposes_expected",
        "a hostile recoverer returns an extra field": "recovery_extra_field",
        "a hostile recoverer returns an assertion object": "recovery_returns_an_assertion_object",
        "a spec edited between load and verify": "spec_file_edited_between_load_and_verify",
        "a mismatched assertion_set_hash": "manifest_pins_a_different_assertion_set",
        "a verifier handed a different expected": "verifier_handed_a_different_expected",
        "an edited expected": "expected_edited_after_pinning",
        "executor mismatch": "result_executor_differs_from_assertion",
        "declared/executed/skipped violation": "coverage_declared_not_accounted",
        "SUBSET coverage": "plan_coverage_subset",
    }
    missing = {what: fid for what, fid in needed.items() if fid not in IDS}
    assert not missing, missing


def test_every_integrity_refusal_ends_the_run_inconclusive_assertion_integrity():
    for r in REFUSALS:
        e = r["expect"]
        if e.get("refused") and "run_outcome" in e:
            assert (e["run_outcome"], e["run_reason"]) == ("INCONCLUSIVE", "ASSERTION_INTEGRITY"), r["id"]
        if "classification" in e and e["classification"] is not None:
            assert e["classification"] == ["INCONCLUSIVE", "ASSERTION_INTEGRITY"], r["id"]
