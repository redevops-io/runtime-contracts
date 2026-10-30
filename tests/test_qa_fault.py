"""FaultEvent: separate detection and recovery records, recorded in that order and bound by hash."""
from __future__ import annotations

import dataclasses

import pytest

from golden.qa_samples import DETECTOR, evidence, fault_event, h
from runtime_contracts.qa import (ClaimedClass, Code, FaultDetection, FaultEvent, FaultRecovery, FaultSignal,
                                  QAContractError, RecoveryCost, RecoveryResult, RecoveryStrategy,
                                  SuppressedReason)


def detection(**kw):
    base = dict(detected=True, signal=FaultSignal.LOCATOR_NOT_FOUND, claimed_class=ClaimedClass.BENIGN_DRIFT,
                detector=DETECTOR)
    base.update(kw)
    return FaultDetection(**base)


def recovery(det, **kw):
    base = dict(detection_ref=det.content_hash, attempted=True, strategy=RecoveryStrategy.SEMANTIC_LOCATOR,
                result=RecoveryResult.RECOVERED, postcondition_verified=True, attempts=1)
    base.update(kw)
    return FaultRecovery(**base)


class TestOrderAndBinding:
    def test_detection_has_its_own_hash_and_does_not_depend_on_recovery(self):
        e = fault_event()
        assert e.detection.content_hash.startswith("rcv1:")
        again = fault_event(recovered=False)
        assert again.detection.content_hash == e.detection.content_hash   # recovery changed; detection did not
        assert again.recovery.content_hash != e.recovery.content_hash

    def test_recovery_references_the_detection_by_hash(self):
        e = fault_event()
        assert e.recovery.detection_ref == e.detection.content_hash and e.recovery.responds_to(e.detection)

    def test_recovery_cannot_rewrite_what_was_detected(self):
        det = detection()
        rewritten = detection(signal=FaultSignal.ASSERTION_FAILED, claimed_class=ClaimedClass.PRODUCT_DEFECT_SUSPECTED)
        with pytest.raises(QAContractError) as e:
            FaultEvent(fault_event_id="fe", step_id="s1", sequence=0, detection=rewritten, recovery=recovery(det))
        assert e.value.code == Code.FAULT_BINDING_MISMATCH

    def test_the_two_records_round_trip_independently(self):
        e = fault_event()
        assert FaultDetection.from_json(e.detection.to_json()) == e.detection
        assert FaultRecovery.from_json(e.recovery.to_json()) == e.recovery
        assert FaultEvent.from_json(e.to_json()) == e

    def test_timings_and_costs_are_custody(self):
        det = detection(detected_at_ms_into_step=1)
        assert det.content_hash == detection(detected_at_ms_into_step=9999).content_hash
        r1, r2 = recovery(det, cost=RecoveryCost(ms=1)), recovery(det, cost=RecoveryCost(tokens=50, ms=900))
        assert r1.content_hash == r2.content_hash

    def test_evidence_in_the_detection_is_identity(self):
        assert detection(evidence_refs=(evidence(1),)).content_hash != detection().content_hash


class TestRecoveryIsJudgedByThePostcondition:
    def test_recovered_exactly_when_the_postcondition_was_verified(self):
        det = detection()
        with pytest.raises(QAContractError):
            recovery(det, result=RecoveryResult.RECOVERED, postcondition_verified=False)
        with pytest.raises(QAContractError):
            recovery(det, result=RecoveryResult.NOT_RECOVERED, postcondition_verified=True)
        assert recovery(det, result=RecoveryResult.NOT_RECOVERED, postcondition_verified=False)

    def test_the_run_outcome_is_not_a_field_of_either_record(self):
        for cls in (FaultDetection, FaultRecovery, FaultEvent):
            assert not {f.name for f in dataclasses.fields(cls)} & {"outcome", "run_outcome", "final_outcome"}


class TestRepresentability:
    def test_a_miss_is_not_detected(self):
        miss = detection(detected=False, signal=FaultSignal.NONE, claimed_class=ClaimedClass.UNKNOWN)
        e = FaultEvent(fault_event_id="fe", step_id="s1", sequence=0, detection=miss,
                       recovery=recovery(miss, attempted=False, strategy=RecoveryStrategy.NONE,
                                         result=RecoveryResult.NOT_ATTEMPTED, postcondition_verified=False,
                                         attempts=0))
        assert not e.detection.detected

    def test_a_false_alarm_is_a_detection_with_a_claim(self):
        alarm = detection(claimed_class=ClaimedClass.PRODUCT_DEFECT_SUSPECTED)
        e = FaultEvent(fault_event_id="fe", step_id="s1", sequence=0, detection=alarm,
                       recovery=recovery(alarm, attempted=False, strategy=RecoveryStrategy.NONE,
                                         result=RecoveryResult.NOT_ATTEMPTED, postcondition_verified=False,
                                         attempts=0))
        assert e.detection.detected and not e.recovery.attempted

    def test_a_mis_recovery_is_recovered_with_a_verified_postcondition(self):
        """The contract records RECOVERED; whether the target was the right one is decided against ground truth
        by a scorer that is not part of this package."""
        assert fault_event(recovered=True).recovery.result is RecoveryResult.RECOVERED

    @pytest.mark.parametrize("reason", [r for r in SuppressedReason if r is not SuppressedReason.NONE])
    def test_a_suppressed_recovery_names_why(self, reason):
        det = detection()
        r = recovery(det, attempted=False, strategy=RecoveryStrategy.RETRY_SAME, suppressed_reason=reason,
                     result=RecoveryResult.NOT_ATTEMPTED, postcondition_verified=False, attempts=0)
        assert r.suppressed_reason is reason

    def test_detection_shape_rules(self):
        with pytest.raises(QAContractError):
            detection(signal=FaultSignal.NONE)
        with pytest.raises(QAContractError):
            detection(detected=False)
        with pytest.raises(QAContractError):
            detection(detected=False, signal=FaultSignal.NONE, claimed_class=ClaimedClass.ENVIRONMENT)

    def test_attempt_shape_rules(self):
        det = detection()
        with pytest.raises(QAContractError):
            recovery(det, strategy=RecoveryStrategy.NONE)
        with pytest.raises(QAContractError):
            recovery(det, attempts=0)
        with pytest.raises(QAContractError):
            recovery(det, suppressed_reason=SuppressedReason.KILL_SWITCH)
        with pytest.raises(QAContractError):
            recovery(det, attempted=False, strategy=RecoveryStrategy.NONE, attempts=1,
                     result=RecoveryResult.NOT_ATTEMPTED, postcondition_verified=False)

    def test_no_recovery_when_nothing_was_detected(self):
        miss = detection(detected=False, signal=FaultSignal.NONE, claimed_class=ClaimedClass.UNKNOWN)
        with pytest.raises(QAContractError):
            FaultEvent(fault_event_id="fe", step_id="s1", sequence=0, detection=miss, recovery=recovery(miss))

    def test_rejection_reasons_do_not_exceed_candidates_considered(self):
        with pytest.raises(QAContractError):
            recovery(detection(), candidates_considered=1, candidates_rejected_reasons=("A", "B"))

    def test_unknown_enum_members_fail_closed(self):
        j = detection().to_json()
        j["signal"] = "MYSTERY"
        j.pop("content_hash")
        with pytest.raises(QAContractError, match=Code.UNKNOWN_ENUM_VALUE):
            FaultDetection.from_json(j)

    def test_vocabularies_match_the_adapter_contract(self):
        assert {s.value for s in FaultSignal} == {
            "NONE", "LOCATOR_NOT_FOUND", "LOCATOR_AMBIGUOUS", "ACTION_TIMEOUT", "TRANSITION_NOT_OBSERVED",
            "ASSERTION_FAILED", "ASSERTION_UNRESOLVABLE", "ENV_UNHEALTHY", "POLICY_DENIED", "NETWORK_BLOCKED",
            "UNEXPECTED_OVERLAY", "SESSION_LOST"}
        assert {s.value for s in RecoveryStrategy} == {
            "NONE", "RETRY_SAME", "SEMANTIC_LOCATOR", "MODEL_CANDIDATE", "RESET_FIXTURE", "CHECKPOINT_RESUME",
            "ESCALATE_REVIEW"}
        assert {s.value for s in SuppressedReason} == {
            "NONE", "NOT_PERMITTED", "NON_IDEMPOTENT", "POLICY_DENIED", "BUDGET_EXHAUSTED", "KILL_SWITCH"}
        assert {s.value for s in RecoveryResult} == {"NOT_ATTEMPTED", "RECOVERED", "NOT_RECOVERED", "ABORTED"}
        assert {s.value for s in ClaimedClass} == {"BENIGN_DRIFT", "PRODUCT_DEFECT_SUSPECTED", "ENVIRONMENT",
                                                   "UNKNOWN"}
