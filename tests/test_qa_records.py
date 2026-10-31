"""Run-side records: Observation, ActionReceipt, AssertionResult, ObservedValue and friends."""
from __future__ import annotations

import dataclasses

import pytest

from golden.qa_samples import (action_receipt, assertion_result, d, evidence, h, observation, policy_decision,
                               script_assertion, ui_assertion, ui_spec)
from runtime_contracts.models.verification import Check, Determinism, Verdict
from runtime_contracts.protocol.evidence import EvidenceRef
from runtime_contracts.qa import (ActionKind, ActionReceipt, ActionRecord, AssertionResult, Checkpoint, CleanupReport,
                                  Code, Executor, LocatorStrategy, LocatorUsed, ObservedValue, Phase,
                                  PolicyDecisionKind, Postcondition, PostconditionResult, QAContractError,
                                  QAPolicyDecision,
                                  Resolution, ResourceKind, ResourceRef, ResultCode, ReviewDecision, ReviewItem,
                                  ReviewRecord)
from runtime_contracts.qa.base import value_digest


def raises(code):
    return pytest.raises(QAContractError, match=code)


class TestObservation:
    def test_round_trip_and_custody(self):
        o = observation()
        again = type(o).from_json(o.to_json())
        assert again == o and again.observed_at == "2026-10-30T10:00:00Z"

    def test_timestamps_and_durations_are_custody(self):
        assert observation().content_hash == observation(observed_at=None, duration_ms=9999).content_hash

    def test_what_was_seen_is_identity(self):
        base = observation().content_hash
        assert observation(url="https://app.example.test/other").content_hash != base
        assert observation(phase=Phase.BEFORE).content_hash != base
        assert observation(screenshot_ref=evidence(9)).content_hash != base
        assert observation(redaction_policy_id=h(77)).content_hash != base

    @pytest.mark.parametrize("bad", [
        EvidenceRef(ref="x", content_hash="sha256:" + "0" * 16),
        EvidenceRef(ref="x", content_hash=""),
        EvidenceRef(ref="x", content_hash="md5:" + "0" * 32),
    ])
    def test_evidence_refs_need_a_full_width_digest(self, bad):
        with pytest.raises(QAContractError):
            observation(screenshot_ref=bad)

    def test_a_captured_artifact_requires_redaction_applied(self):
        with raises(Code.RECORD_INCONSISTENT):
            observation(redaction_applied=False)
        assert observation(redaction_applied=False, a11y_snapshot_ref=None, screenshot_ref=None).redaction_applied is False

    @pytest.mark.parametrize("url", ["https://user:pw@host/x", "http://token@host/", "https://a@b.test/?q=1"])
    def test_urls_carry_no_credentials(self, url):
        with pytest.raises(QAContractError):
            observation(url=url)

    def test_an_at_sign_after_the_host_is_fine(self):
        assert observation(url="https://host.test/users/@me").url.endswith("@me")

    def test_dom_meta_is_bounded(self):
        with pytest.raises(QAContractError):
            observation(dom_meta={"k": "x" * 5000})


class TestActionReceipt:
    def test_round_trip_and_custody(self):
        r = action_receipt(recovery_rationale="why")
        assert ActionReceipt.from_json(r.to_json()) == r
        assert r.content_hash == action_receipt(recovery_rationale="other", duration_ms=1).content_hash

    def test_policy_decision_ref_is_required(self):
        j = action_receipt().to_json()
        del j["policy_decision_ref"]
        j.pop("content_hash")
        with raises(Code.MISSING_FIELD):
            ActionReceipt.from_json(j)

    @pytest.mark.parametrize("bad", ["", "policy-1", "rcv1:abc", "sha256:" + "0" * 64])
    def test_policy_decision_ref_is_a_full_rcv1_hash(self, bad):
        with pytest.raises(QAContractError):
            action_receipt(policy_decision_ref=bad)

    def test_the_ref_can_point_at_the_recorded_decision(self):
        assert action_receipt().policy_decision_ref == policy_decision().content_hash

    def test_a_denied_action_is_still_a_receipt_that_cites_its_decision(self):
        deny = policy_decision(decision=PolicyDecisionKind.DENY, rule_id=None, reason="default deny")
        r = action_receipt(result=ResultCode.ACTION_BLOCKED_BY_POLICY, policy_decision_ref=deny.content_hash,
                           state_after_hash=h(41),
                           postcondition=Postcondition(declared="url ends /saved",
                                                       result=PostconditionResult.NOT_EVALUATED))
        assert r.result is ResultCode.ACTION_BLOCKED_BY_POLICY

    def test_a_blocked_action_changed_nothing(self):
        with raises(Code.RECORD_INCONSISTENT):
            action_receipt(result=ResultCode.ACTION_BLOCKED_BY_POLICY, state_after_hash=h(99),
                           postcondition=Postcondition(declared="d", result=PostconditionResult.NOT_EVALUATED))

    def test_exactly_one_of_locator_or_resource_is_used(self):
        res = ResourceRef(kind=ResourceKind.MANIFEST_PATH, path="a.yaml")
        with raises(Code.RECORD_INCONSISTENT):
            action_receipt(locator_used=None)
        with raises(Code.RECORD_INCONSISTENT):
            action_receipt(resource_used=res)
        ok = action_receipt(locator_used=None, resource_used=res, action=ActionRecord(kind=ActionKind.RESOLVE))
        assert ok.resource_used == res

    def test_the_locator_actually_used_is_recorded_with_its_strategy(self):
        r = action_receipt(locator_used=LocatorUsed(descriptor=action_receipt().locator_used.descriptor,
                                                    strategy=LocatorStrategy.SEMANTIC_ALTERNATE))
        assert r.content_hash != action_receipt().content_hash
        assert r.canonical_form()["locator_used"]["strategy"] == "SEMANTIC_ALTERNATE"

    def test_a_value_action_records_a_digest_never_the_value(self):
        digest = value_digest("hunter2")
        r = action_receipt(action=ActionRecord(kind=ActionKind.FILL, value_digest=digest))
        assert "hunter2" not in str(r.to_json())
        with raises(Code.RECORD_INCONSISTENT):
            action_receipt(action=ActionRecord(kind=ActionKind.FILL))
        with raises(Code.RECORD_INCONSISTENT):
            action_receipt(action=ActionRecord(kind=ActionKind.CLICK, value_digest=digest))

    def test_a_failed_action_cannot_have_a_satisfied_postcondition(self):
        with raises(Code.RECORD_INCONSISTENT):
            action_receipt(result=ResultCode.ACTION_TIMEOUT)

    def test_an_evaluated_postcondition_says_what_was_observed(self):
        with raises(Code.RECORD_INCONSISTENT):
            action_receipt(postcondition=Postcondition(declared="d", result=PostconditionResult.NOT_SATISFIED))

    def test_attempt_is_positive_and_the_envelope_binding_is_a_hash(self):
        with pytest.raises(QAContractError):
            action_receipt(attempt=0)
        assert action_receipt(execution_binding=h(5)).execution_binding == h(5)
        with pytest.raises(QAContractError):
            action_receipt(execution_binding="envelope-1")

    def test_result_is_a_closed_set_and_unknown_fails_closed(self):
        j = action_receipt().to_json()
        j["result"] = "KINDA_OK"
        j.pop("content_hash")
        with pytest.raises(QAContractError, match=Code.UNKNOWN_ENUM_VALUE):
            ActionReceipt.from_json(j)

    def test_idempotency_key_is_required(self):
        j = action_receipt().to_json()
        del j["idempotency_key"]
        j.pop("content_hash")
        with raises(Code.MISSING_FIELD):
            ActionReceipt.from_json(j)


class TestPolicyDecision:
    def test_round_trip(self):
        p = policy_decision()
        assert QAPolicyDecision.from_json(p.to_json()) == p

    def test_reason_and_time_are_custody(self):
        assert policy_decision(reason="a", decided_at=None).content_hash == policy_decision(reason="b").content_hash

    def test_the_decision_and_its_subject_are_identity(self):
        base = policy_decision().content_hash
        assert policy_decision(decision=PolicyDecisionKind.DENY).content_hash != base
        assert policy_decision(step_id="s2").content_hash != base

    def test_no_matching_rule_is_representable(self):
        assert policy_decision(rule_id=None).rule_id is None

    def test_only_ui_action_decisions_are_recorded(self):
        with pytest.raises(QAContractError):
            policy_decision(phase="tool")

    def test_only_allow_deny_and_require_approval_exist(self):
        assert {k.value for k in PolicyDecisionKind} == {"ALLOW", "DENY", "REQUIRE_APPROVAL"}


class TestAssertionResult:
    def test_pass_round_trip_and_custody(self):
        r = assertion_result()
        assert AssertionResult.from_json(r.to_json()) == r
        assert r.content_hash == assertion_result(evaluated_at=None).content_hash

    def test_it_mirrors_the_executor_and_embeds_a_check(self):
        r = assertion_result(script_assertion(), ui_spec())
        assert r.executor is Executor.SCRIPT and isinstance(r.check, Check)
        assert r.verdict is Verdict.PASS and r.determinism is Determinism.DETERMINISTIC
        assert r.evidence_refs == r.check.evidence_refs

    def test_the_executor_is_in_the_hash(self):
        a = assertion_result()
        b = dataclasses.replace(a, executor=Executor.SCRIPT)
        assert a.content_hash != b.content_hash

    def test_the_embedded_check_names_the_same_assertion(self):
        with raises(Code.RECORD_INCONSISTENT):
            assertion_result(check=Check(check_id="other", verdict=Verdict.PASS, evidence_refs=()), actual="x")

    def test_a_gating_assertion_is_never_not_applicable(self):
        with raises(Code.RECORD_INCONSISTENT):
            assertion_result(check=Check(check_id="a-saved", verdict=Verdict.NOT_APPLICABLE), reason_code="X",
                             actual=None)

    def test_a_conclusive_verdict_must_be_deterministic(self):
        with raises(Code.RECORD_INCONSISTENT):
            assertion_result(check=Check(check_id="a-saved", verdict=Verdict.PASS,
                                         determinism=Determinism.NON_DETERMINISTIC), actual="x")

    def test_a_non_deterministic_judgement_is_indeterminate_evidence_not_a_gate(self):
        r = assertion_result(verdict=Verdict.INDETERMINATE,
                             check=Check(check_id="a-saved", verdict=Verdict.INDETERMINATE,
                                         determinism=Determinism.NON_DETERMINISTIC),
                             reason_code="MODEL_ONLY_EVIDENCE")
        assert r.verdict is Verdict.INDETERMINATE

    def test_indeterminate_states_why_and_conclusive_does_not(self):
        with raises(Code.RECORD_INCONSISTENT):
            assertion_result(check=Check(check_id="a-saved", verdict=Verdict.INDETERMINATE), reason_code=None)
        with raises(Code.RECORD_INCONSISTENT):
            assertion_result(reason_code="SUBJECT_UNRESOLVED")

    def test_a_conclusive_verdict_records_what_was_read(self):
        with raises(Code.RECORD_INCONSISTENT):
            assertion_result(actual=None)
        digest = value_digest("secret value")
        assert assertion_result(actual=None, actual_digest=digest).actual_digest == digest
        with raises(Code.RECORD_INCONSISTENT):
            assertion_result(actual="x", actual_digest=digest)

    def test_unresolved_and_ambiguous_subjects_are_indeterminate_with_a_reason(self):
        for reason in ("SUBJECT_UNRESOLVED", "SUBJECT_AMBIGUOUS", "PRECONDITION_UNMET", "ASSERTION_HASH_MISMATCH"):
            r = assertion_result(verdict=Verdict.INDETERMINATE, check=Check(check_id="a-saved",
                                                                            verdict=Verdict.INDETERMINATE),
                                 reason_code=reason, actual=None)
            assert r.reason_code == reason

    def test_evidence_must_be_pinned_with_a_full_width_digest(self):
        with pytest.raises(QAContractError):
            assertion_result(check=Check(check_id="a-saved", verdict=Verdict.PASS, evidence_refs=("shot",)),
                             actual="x")

    def test_it_repeats_both_hashes(self):
        a, spec = ui_assertion(), ui_spec()
        r = assertion_result(a, spec)
        assert r.assertion_set_hash == spec.assertion_set_hash and r.expected_hash == a.expected_hash

    def test_unknown_executor_fails_closed(self):
        j = assertion_result().to_json()
        j["executor"] = "TELEPATHY"
        j.pop("content_hash")
        with pytest.raises(QAContractError, match=Code.UNKNOWN_ENUM_VALUE):
            AssertionResult.from_json(j)


class TestObservedValue:
    def test_resolved_unresolved_and_ambiguous_shapes(self):
        assert ObservedValue(resolution=Resolution.RESOLVED, match_count=1, value="Saved").value == "Saved"
        assert ObservedValue(resolution=Resolution.UNRESOLVED, match_count=0).match_count == 0
        assert ObservedValue(resolution=Resolution.AMBIGUOUS, match_count=3).match_count == 3

    @pytest.mark.parametrize("kwargs", [
        dict(resolution=Resolution.RESOLVED, match_count=2, value="x"),
        dict(resolution=Resolution.RESOLVED, match_count=0),
        dict(resolution=Resolution.UNRESOLVED, match_count=1),
        dict(resolution=Resolution.UNRESOLVED, match_count=0, value="x"),
        dict(resolution=Resolution.AMBIGUOUS, match_count=1),
        dict(resolution=Resolution.AMBIGUOUS, match_count=2, value="x"),
        dict(resolution=Resolution.RESOLVED, match_count=1, value="x", value_digest=h(1)),
    ])
    def test_inconsistent_shapes_are_refused(self, kwargs):
        with pytest.raises(QAContractError):
            ObservedValue(**kwargs)

    def test_it_has_no_verdict_and_no_expected(self):
        names = {f.name for f in dataclasses.fields(ObservedValue)}
        assert not names & {"verdict", "expected", "expected_hash", "passed", "ok", "result", "check"}

    def test_a_sensitive_value_travels_as_a_digest(self):
        v = ObservedValue(resolution=Resolution.RESOLVED, match_count=1, value_digest=value_digest("pii"))
        assert v.value is None and ObservedValue.from_json(v.to_json()) == v


class TestCheckpointReviewCleanup:
    def test_checkpoint(self):
        c = Checkpoint(checkpoint_id="cp-1", run_id="run-1", step_index=2, state_hash=h(1), fixture_snapshot_id="snap-1",
                       taken_at="t")
        assert Checkpoint.from_json(c.to_json()) == c
        assert c.content_hash == dataclasses.replace(c, taken_at="later").content_hash
        assert not {f.name for f in dataclasses.fields(Checkpoint)} & {"storage_state", "cookies", "session"}

    def test_review_item_and_record(self):
        item = ReviewItem(review_item_id="ri-1", run_id="run-1", reason="ASSERTION_INTEGRITY",
                          evidence_refs=(evidence(2), evidence(1)), suggested_change_ref=h(3), created_at="t")
        assert ReviewItem.from_json(item.to_json()) == item
        assert item.evidence_refs == tuple(sorted(item.evidence_refs, key=lambda e: e.ref))
        rec = ReviewRecord(review_item_ref=item.content_hash, decision=ReviewDecision.ACCEPT, reviewer_id="rev-1",
                           review_minutes=4)
        assert rec.content_hash == dataclasses.replace(rec, reviewer_id="rev-2", review_minutes=9).content_hash
        assert rec.content_hash != dataclasses.replace(rec, decision=ReviewDecision.REJECT).content_hash

    def test_cleanup_cannot_be_verified_with_leaks(self):
        ok = CleanupReport(handle_id="s1", verified=True, released=("ctx", "page"))
        assert CleanupReport.from_json(ok.to_json()) == ok
        with raises(Code.RECORD_INCONSISTENT):
            CleanupReport(handle_id="s1", verified=True, leaked=("tmpdir",))
        assert CleanupReport(handle_id="s1", verified=False, leaked=("tmpdir",)).verified is False
