"""RunManifest: pins, outcome and the assertion accounting (declared, executed, skipped)."""
from __future__ import annotations

import dataclasses

import pytest

from golden.qa_samples import (action_receipt, assertion_result, fault_event, h, run_manifest, ui_assertion, ui_spec,
                               url_assertion, ADAPTER, PLANNER)
from runtime_contracts.models.verification import Check, Determinism, Verdict
from runtime_contracts.qa import (AssertionIntegrityError, Code, Counters, ModelRef, Outcome, PostconditionResult,
                                  QAContractError, ResultCode, RunManifest, SkippedAssertion, SkipReason,
                                  StepResult, classify_coverage, coverage_violations, integrity_violations)

SPEC = ui_spec()
A1, A2 = SPEC.assertion_ids


def failing_result(assertion):
    return assertion_result(assertion, SPEC, verdict=Verdict.FAIL,
                            check=Check(check_id=assertion.assertion_id, verdict=Verdict.FAIL), actual="Error")


def skipped_manifest(**kw):
    """A run that executed A1 and skipped A2 (outcome INCONCLUSIVE, not PASS)."""
    base = dict(assertions_executed=(A1,), assertions_skipped=(SkippedAssertion(assertion_id=A2,
                                                                                reason_code=SkipReason.NOT_REACHED),),
                assertion_results=(assertion_result(SPEC.assertions[0], SPEC),), outcome=Outcome.INCONCLUSIVE)
    base.update(kw)
    return run_manifest(**base)


class TestBasics:
    def test_round_trip_and_custody(self):
        m = run_manifest()
        again = RunManifest.from_json(m.to_json())
        assert again == m and again.counters == m.counters and again.started_at == m.started_at

    def test_counters_and_wall_time_are_custody_and_money_is_a_decimal_string(self):
        a = run_manifest(counters=Counters(tokens=1, cost="1.5"), started_at="a")
        b = run_manifest(counters=Counters(tokens=900, cost="20"), started_at="b", finished_at=None)
        assert a.content_hash == b.content_hash
        with pytest.raises(QAContractError):
            Counters(cost="1.50")      # not the canonical spelling
        with pytest.raises(QAContractError):
            Counters(cost=1.5)         # a float

    def test_pins_are_identity(self):
        base = run_manifest().content_hash
        assert run_manifest(seeds=(7, 12)).content_hash != base
        assert run_manifest(browser="chromium 131").content_hash != base
        assert run_manifest(egress_policy_id=h(77)).content_hash != base
        assert run_manifest(adapter=dataclasses.replace(ADAPTER, version="0.2.0")).content_hash != base
        assert run_manifest(sandbox_image_digest="sha256:" + "9" * 64).content_hash != base

    def test_planner_is_hashed_and_absent_without_a_plan(self):
        no_plan = run_manifest(plan_hash=None, planner=None)
        assert no_plan.planner is None and no_plan.content_hash != run_manifest().content_hash
        with pytest.raises(QAContractError):
            run_manifest(planner=None)
        with pytest.raises(QAContractError):
            run_manifest(plan_hash=None)

    def test_model_recovery_needs_recovery_and_a_recorded_model(self):
        with pytest.raises(QAContractError):
            run_manifest(model_recovery_enabled=True)
        with pytest.raises(QAContractError):
            run_manifest(recovery_enabled=False, model_recovery_enabled=True,
                         model=ModelRef(provider="fake", model_id="fake-1"))
        ok = run_manifest(model_recovery_enabled=True, model=ModelRef(provider="fake", model_id="fake-1"))
        assert ok.model_recovery_enabled

    def test_trace_id_is_32_hex(self):
        with pytest.raises(QAContractError):
            run_manifest(trace_id="abc")

    def test_the_manifest_has_no_ground_truth_or_track(self):
        names = {f.name for f in dataclasses.fields(RunManifest)}
        assert not names & {"track", "case_id", "truth_class", "defect_present", "false_pass", "missed_defect"}

    def test_a_manifest_is_not_a_place_to_record_a_review(self):
        assert not {f.name for f in dataclasses.fields(RunManifest)} & {"review_minutes", "reviewer", "decision"}


class TestAssertionAccounting:
    def test_sets_are_order_independent_and_hashed(self):
        a = run_manifest(assertions_declared=(A2, A1), assertions_executed=(A2, A1))
        b = run_manifest()
        assert a == b and a.content_hash == b.content_hash
        assert run_manifest(plan_hash=h(1)).assertions_declared == b.assertions_declared

    def test_skipped_carries_a_reason_code(self):
        m = skipped_manifest()
        assert m.assertions_skipped[0].reason_code is SkipReason.NOT_REACHED
        j = m.to_json()
        j["assertions_skipped"][0]["reason_code"] = "BORED"
        j.pop("content_hash")
        with pytest.raises(QAContractError, match=Code.UNKNOWN_ENUM_VALUE):
            RunManifest.from_json(j)

    def test_every_skip_reason_is_representable(self):
        assert {r.value for r in SkipReason} == {
            "NOT_REACHED", "PRECONDITION_UNMET", "POLICY_DENIED", "BUDGET_EXHAUSTED", "SUBJECT_UNRESOLVED",
            "ENVIRONMENT", "HALTED_INTEGRITY"}

    def test_the_skip_reason_changes_the_hash(self):
        a = skipped_manifest()
        b = skipped_manifest(assertions_skipped=(SkippedAssertion(assertion_id=A2, reason_code=SkipReason.POLICY_DENIED),))
        assert a.content_hash != b.content_hash

    def test_a_consistent_skip_is_an_inconclusive_run_not_an_integrity_error(self):
        m = skipped_manifest()
        assert m.outcome is Outcome.INCONCLUSIVE and m.outcome_reason is None
        assert coverage_violations(m.assertions_declared, m.assertions_executed,
                                   [s.assertion_id for s in m.assertions_skipped]) == ()

    @pytest.mark.parametrize("declared,executed,skipped,expected", [
        (("a", "b"), ("a", "b"), (), ()),
        (("a", "b"), ("a",), ("b",), ()),
        (("a", "b"), ("a",), (), ("DECLARED_UNACCOUNTED",)),
        (("a", "b"), ("a", "b"), ("b",), ("EXECUTED_AND_SKIPPED",)),
        (("a",), ("a", "z"), (), ("EXECUTED_NOT_DECLARED",)),
        (("a",), ("a",), ("z",), ("SKIPPED_NOT_DECLARED",)),
        (("a", "b"), (), (), ("DECLARED_UNACCOUNTED",)),
    ])
    def test_the_coverage_invariants(self, declared, executed, skipped, expected):
        assert coverage_violations(declared, executed, skipped) == expected
        assert (classify_coverage(declared, executed, skipped) is not None) == bool(expected)

    def test_a_violation_classifies_as_inconclusive_assertion_integrity(self):
        assert classify_coverage(("a", "b"), ("a",), ()) == (Outcome.INCONCLUSIVE, "ASSERTION_INTEGRITY")
        assert classify_coverage(("a",), ("a",), ()) is None

    @pytest.mark.parametrize("claimed", [Outcome.PASS, Outcome.PRODUCT_FAIL, Outcome.TEST_DEFECT,
                                         Outcome.ENVIRONMENT_FAIL])
    def test_a_manifest_that_breaks_the_accounting_cannot_claim_anything_but_integrity(self, claimed):
        with pytest.raises(AssertionIntegrityError) as e:
            run_manifest(assertions_executed=(A1,), assertion_results=(assertion_result(SPEC.assertions[0], SPEC),),
                         outcome=claimed)
        assert e.value.code == Code.COVERAGE_VIOLATION
        assert (e.value.run_outcome, e.value.run_reason) == ("INCONCLUSIVE", "ASSERTION_INTEGRITY")

    def test_the_violation_can_be_recorded_as_inconclusive_assertion_integrity(self):
        m = run_manifest(assertions_executed=(A1,), assertion_results=(assertion_result(SPEC.assertions[0], SPEC),),
                         outcome=Outcome.INCONCLUSIVE, outcome_reason="ASSERTION_INTEGRITY")
        assert m.outcome_reason == "ASSERTION_INTEGRITY"
        assert RunManifest.from_json(m.to_json()) == m

    def test_overlap_between_executed_and_skipped_is_an_integrity_violation(self):
        with pytest.raises(AssertionIntegrityError):
            run_manifest(assertions_skipped=(SkippedAssertion(assertion_id=A1, reason_code=SkipReason.NOT_REACHED),),
                         outcome=Outcome.INCONCLUSIVE)

    def test_integrity_claimed_without_a_violation_is_refused(self):
        with pytest.raises(QAContractError):
            run_manifest(outcome=Outcome.INCONCLUSIVE, outcome_reason="ASSERTION_INTEGRITY")

    def test_results_must_match_the_executed_set(self):
        with pytest.raises(AssertionIntegrityError):
            run_manifest(assertion_results=(assertion_result(SPEC.assertions[0], SPEC),))

    def test_results_produced_under_a_different_assertion_set_are_an_integrity_violation(self):
        other = ui_spec(assertions=(ui_assertion(expected="x"), url_assertion()))
        with pytest.raises(AssertionIntegrityError):
            run_manifest(assertion_results=tuple(assertion_result(a, other) for a in SPEC.assertions))

    def test_integrity_violations_names_each_breach(self):
        found = integrity_violations(declared=("a", "b"), executed=("a",), skipped=(), results=[("a", "x")],
                                     assertion_set_hash="y")
        assert found == ("DECLARED_UNACCOUNTED", "RESULT_FOR_A_DIFFERENT_ASSERTION_SET")

    def test_duplicates_inside_a_list_are_refused(self):
        with pytest.raises(QAContractError) as e:
            run_manifest(assertions_declared=(A1, A1, A2))
        assert e.value.code == Code.DUPLICATE_ENTRY


class TestPassIsEarned:
    def test_a_clean_run_passes(self):
        assert run_manifest().outcome is Outcome.PASS

    def test_pass_needs_something_declared(self):
        with pytest.raises(QAContractError):
            run_manifest(assertions_declared=(), assertions_executed=(), assertion_results=())

    def test_pass_refuses_any_skip(self):
        with pytest.raises(QAContractError):
            skipped_manifest(outcome=Outcome.PASS)

    def test_pass_refuses_a_failed_assertion_in_its_own_record(self):
        with pytest.raises(QAContractError, match="did not pass"):
            run_manifest(assertion_results=(failing_result(SPEC.assertions[0]),
                                            assertion_result(SPEC.assertions[1], SPEC)))

    def test_pass_refuses_an_indeterminate_assertion(self):
        indeterminate = assertion_result(SPEC.assertions[0], SPEC, verdict=Verdict.INDETERMINATE,
                                         check=Check(check_id=A1, verdict=Verdict.INDETERMINATE))
        with pytest.raises(QAContractError):
            run_manifest(assertion_results=(indeterminate, assertion_result(SPEC.assertions[1], SPEC)))

    def test_pass_refuses_a_failed_step(self):
        bad = StepResult(step_id="s1", result=ResultCode.ACTION_TIMEOUT, postcondition=PostconditionResult.NOT_EVALUATED,
                         receipts=(h(1),))
        with pytest.raises(QAContractError, match="step"):
            run_manifest(step_results=(bad,))

    def test_pass_refuses_a_fault_that_was_not_recovered_by_its_postcondition(self):
        with pytest.raises(QAContractError, match="fault"):
            run_manifest(fault_events=(fault_event(recovered=False),))

    def test_an_unrecovered_fault_is_fine_in_a_run_that_is_not_a_pass(self):
        m = skipped_manifest(fault_events=(fault_event(recovered=False),))
        assert m.fault_events[0].recovery.postcondition_verified is False

    def test_product_fail_needs_a_deterministic_fail(self):
        with pytest.raises(QAContractError):
            run_manifest(outcome=Outcome.PRODUCT_FAIL)
        m = run_manifest(outcome=Outcome.PRODUCT_FAIL,
                         assertion_results=(failing_result(SPEC.assertions[0]),
                                            assertion_result(SPEC.assertions[1], SPEC)))
        assert m.outcome is Outcome.PRODUCT_FAIL

    def test_other_outcomes_are_not_constrained_by_the_results(self):
        assert run_manifest(outcome=Outcome.ENVIRONMENT_FAIL).outcome is Outcome.ENVIRONMENT_FAIL
        assert run_manifest(outcome=Outcome.TEST_DEFECT, outcome_reason="BASELINE_CONFORMANCE").outcome_reason

    def test_unknown_outcome_fails_closed(self):
        j = run_manifest().to_json()
        j["outcome"] = "GREAT"
        j.pop("content_hash")
        with pytest.raises(QAContractError, match=Code.UNKNOWN_ENUM_VALUE):
            RunManifest.from_json(j)


def test_a_fault_event_id_appears_once():
    second = dataclasses.replace(fault_event(1), fault_event_id="fe-0")
    with pytest.raises(QAContractError) as e:
        skipped_manifest(fault_events=(fault_event(0), second))
    assert e.value.code == Code.DUPLICATE_ENTRY


def test_step_results_record_the_receipts_of_each_attempt():
    r1, r2 = action_receipt(attempt=1), action_receipt(attempt=2)
    s = StepResult(step_id="s1", result=ResultCode.OK, postcondition=PostconditionResult.SATISFIED,
                   receipts=(r1.content_hash, r2.content_hash))
    assert s.attempts == 2
    with pytest.raises(QAContractError):
        StepResult(step_id="s1", result=ResultCode.OK, postcondition=PostconditionResult.SATISFIED, receipts=())
