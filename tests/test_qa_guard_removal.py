"""Mutation tests: remove a guard and the refusal it provides disappears.

A refusal fixture that still refuses with its guard removed proves nothing about that guard. For each fixture the
guard that is supposed to produce the refusal is replaced with a no-op, and the fixture must stop being refused (or
stop being refused for that reason). If a refactor makes a guard decorative, this fails.

Each guard is a named module-level function precisely so that it can be removed here.
"""
from __future__ import annotations

import copy
import dataclasses
import importlib
import json

import pytest

from golden import qa_samples as S
from golden.qa import CASES_PATH, run_refusal
from runtime_contracts.models.verification import Determinism, Verdict
from runtime_contracts.qa import (AssertionSpec, AssertionSubject, CoverageContract, Executor, FaultRecovery,
                                  PermittedRecovery, Predicate, PredicateOp, QAContractError, RecoveryResult,
                                  RecoveryStrategy, ResourceKind, ResourceRef, ResultCode, SubjectKind)
from runtime_contracts.qa import plan as plan_module

FIXTURES = {r["id"]: r for r in json.loads(CASES_PATH.read_text())["refusals"]}

#: fixture id -> (module, guard function). The guard removed in the second column is the only thing that should
#: stand between the hostile input and acceptance.
GUARDS = {
    "expected_edited_after_pinning": ("runtime_contracts.qa.integrity", "_guard_assertion_set_hash"),
    "locator_edited_after_pinning": ("runtime_contracts.qa.integrity", "_guard_assertion_set_hash"),
    "requirement_ref_edited_after_pinning": ("runtime_contracts.qa.integrity", "_guard_assertion_set_hash"),
    "assertion_removed": ("runtime_contracts.qa.integrity", "_guard_assertion_set_hash"),
    "assertion_added": ("runtime_contracts.qa.integrity", "_guard_assertion_set_hash"),
    "spec_file_edited_between_load_and_verify": ("runtime_contracts.qa.base", "_guard_stored_hash"),
    "verifier_handed_a_different_expected": ("runtime_contracts.qa.conformance", "_guard_result_expected"),
    "result_executor_differs_from_assertion": ("runtime_contracts.qa.conformance", "_guard_result_executor"),
    "recovery_proposes_expected": ("runtime_contracts.qa.conformance", "_guard_candidate_keys"),
    "recovery_extra_field": ("runtime_contracts.qa.conformance", "_guard_candidate_keys"),
    "recovery_returns_an_assertion_object": ("runtime_contracts.qa.conformance", "_guard_candidate_keys"),
    "manifest_pins_a_different_assertion_set": ("runtime_contracts.qa.conformance", "_guard_manifest_pins"),
    "manifest_claims_pass_with_broken_accounting": ("runtime_contracts.qa.manifest", "_guard_manifest_integrity"),
    "plan_coverage_subset": ("runtime_contracts.qa.plan", "_guard_full_coverage"),
    "recovery_rewrites_the_detection": ("runtime_contracts.qa.fault", "_guard_fault_binding"),
    "unknown_schema_version": ("runtime_contracts.qa.base", "_guard_schema_identity"),
}


@pytest.mark.parametrize("fid", sorted(GUARDS))
def test_removing_the_guard_removes_the_refusal(fid, monkeypatch):
    fx = FIXTURES[fid]
    assert run_refusal(fx["operation"], copy.deepcopy(fx["input"])) == fx["expect"], "the guard-in-place baseline"
    module, name = GUARDS[fid]
    mod = importlib.import_module(module)
    assert callable(getattr(mod, name)), f"{module}.{name} is not a function any more"
    monkeypatch.setattr(mod, name, lambda *a, **k: None)
    after = run_refusal(fx["operation"], copy.deepcopy(fx["input"]))
    assert after != fx["expect"], f"{fid} is still refused with {name} removed: the guard is not what refuses it"
    assert after.get("code") != fx["expect"]["code"], f"{fid}: a different guard now produces the same code"


def test_every_refusal_fixture_that_is_an_error_names_its_guard():
    """New refusal fixtures need a guard-removal entry, or this fails and says which."""
    controlled = set(GUARDS)
    # these refuse through the codec's type checks, not a named guard; they are covered by their own unit tests
    through_types = {"plan_dynamic_dispatch_field", "unknown_executor_is_non_certifying"}
    through_functions = {"coverage_declared_not_accounted", "coverage_executed_and_skipped",
                         "coverage_executed_not_declared", "unknown_outcome_maps_to_indeterminate"}
    unaccounted = [f for f, r in FIXTURES.items()
                   if r["expect"].get("refused") and f not in controlled | through_types]
    assert not unaccounted, f"refusal fixtures with no guard-removal test: {unaccounted}"


class TestCoverageClassification:
    """The accounting is a pure function; removing its checks must make the broken accounting pass silently."""

    def test_removing_the_coverage_check_accepts_a_broken_accounting(self, monkeypatch):
        from runtime_contracts.qa import integrity
        monkeypatch.setattr(integrity, "coverage_violations", lambda *a, **k: ())
        assert integrity.classify_coverage(["a", "b"], ["a"], []) is None

    def test_with_the_check_in_place_it_is_integrity(self):
        from runtime_contracts.qa import classify_coverage
        assert classify_coverage(["a", "b"], ["a"], []) is not None


def _non_deterministic_assertion():
    return dataclasses.replace(S.ui_assertion(), determinism=Determinism.NON_DETERMINISTIC)


def _assertion_that_passes_when_unresolvable():
    return dataclasses.replace(S.ui_assertion(), on_unresolvable=Verdict.PASS)


def _playwright_assertion_reading_resource_inputs():
    return AssertionSpec(
        assertion_id="a", executor=Executor.PLAYWRIGHT,
        subject=AssertionSubject(kind=SubjectKind.RESOURCE_INPUTS,
                                 inputs=(ResourceRef(kind=ResourceKind.MANIFEST_PATH, path="a"),)),
        predicate=Predicate(PredicateOp.EXISTS), verifier_id="v", verifier_version_range=">=1")


def _blind_retry_of_an_unmarked_step():
    return dataclasses.replace(S.ui_step(), permitted_recovery=(PermittedRecovery.RETRY_SAME,))


def _recovery_called_recovered_without_its_postcondition():
    return FaultRecovery(detection_ref="rcv1:" + "0" * 64, attempted=True, strategy=RecoveryStrategy.RETRY_SAME,
                         result=RecoveryResult.RECOVERED, postcondition_verified=False, attempts=1)


class TestConstructionGuards:
    """Guards that live in constructors rather than the refusal fixtures."""

    def test_removing_the_full_coverage_guard_would_accept_subset(self, monkeypatch):
        monkeypatch.setattr(plan_module, "_guard_full_coverage", lambda *a, **k: None)
        assert S.plan_for([S.ui_spec().spec_ref], coverage=CoverageContract.SUBSET).coverage_contract is \
            CoverageContract.SUBSET

    @pytest.mark.parametrize("module,guard,build", [
        ("runtime_contracts.qa.spec", "_guard_determinism", _non_deterministic_assertion),
        ("runtime_contracts.qa.spec", "_guard_on_unresolvable", _assertion_that_passes_when_unresolvable),
        ("runtime_contracts.qa.spec", "_guard_has_assertions", lambda: S.ui_spec(assertions=())),
        ("runtime_contracts.qa.spec", "_guard_side_effects_allowed", lambda: S.ui_spec(allowed_side_effects=())),
        ("runtime_contracts.qa.spec", "_guard_recovery_is_safe", _blind_retry_of_an_unmarked_step),
        ("runtime_contracts.qa.spec", "_guard_executor_matches_subject",
         _playwright_assertion_reading_resource_inputs),
        ("runtime_contracts.qa.records", "_guard_postcondition_follows_result",
         lambda: S.action_receipt(result=ResultCode.ACTION_TIMEOUT)),
        ("runtime_contracts.qa.records", "_guard_result_shape", lambda: S.assertion_result(actual=None)),
        ("runtime_contracts.qa.fault", "_guard_result_is_judged_by_the_postcondition",
         _recovery_called_recovered_without_its_postcondition),
        ("runtime_contracts.qa.manifest", "_guard_pass_is_earned",
         lambda: S.run_manifest(fault_events=(S.fault_event(recovered=False),))),
    ])
    def test_each_construction_guard_is_what_refuses(self, module, guard, build, monkeypatch):
        with pytest.raises(QAContractError):
            build()
        monkeypatch.setattr(importlib.import_module(module), guard, lambda *a, **k: None)
        try:
            build()                      # accepted with the guard gone: the guard was the refusal
        except QAContractError as exc:
            pytest.fail(f"{guard} removed but construction is still refused ({exc}); the guard is decorative")
