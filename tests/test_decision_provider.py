"""Contract tests for bounded DecisionProvider results.

The provider may rank or score permitted options, but it cannot mint new
actions, bypass abstain policy, or produce non-replayable results.
"""
from __future__ import annotations

import pytest

from runtime_contracts.protocol import (
    AbstainReason,
    DecisionProviderRequest,
    DecisionProviderResult,
    QuestionKind,
    ScoreSemantics,
    StaticDecisionProvider,
    validate_decision,
)


def _request(**overrides) -> DecisionProviderRequest:
    base = dict(
        decision_id="decision-1",
        tenant_id="tenant-a",
        purpose="receivables_dispute_triage",
        question_kind=QuestionKind.CHOICE,
        evidence_view_ref="ctx:tenant-a:invoice-9@known-2026-01-15",
        permitted_options=("HOLD", "COLLECT"),
        constraints_ref="policy:receivables@v1",
        as_of="2026-01-15T00:00:00Z",
        known_at="2026-01-15T00:00:00Z",
        latency_budget_ms=50,
        max_cost="USD 0.001",
        data_classification="synthetic",
        metadata={"scenario_id": "crossapp-dispute-hold-0001"},
    )
    base.update(overrides)
    return DecisionProviderRequest(**base)


def test_request_identity_is_stable_and_policy_sensitive() -> None:
    req = _request()
    assert req.identity() == _request().identity()
    assert req.identity() != _request(permitted_options=("HOLD", "COLLECT", "ESCALATE")).identity()
    assert req.identity() != _request(constraints_ref="policy:receivables@v2").identity()


def test_static_provider_returns_replayable_valid_result() -> None:
    provider = StaticDecisionProvider("rules", "ruleset:receivables@v1")

    result = validate_decision(provider, _request())

    assert result.selected_option == "HOLD"
    assert result.input_digest == _request().identity()
    assert result.response_digest
    assert result.is_valid_for(_request())


def test_result_rejects_action_outside_permitted_options() -> None:
    req = _request()
    result = DecisionProviderResult(
        decision_id=req.decision_id,
        provider_id="classifier",
        model_pin="tiny-choice@sha256:abc",
        output_kind=req.question_kind,
        option_scores={"HOLD": 0.2, "COLLECT": 0.8, "WRITE_OFF": 0.99},
        score_semantics=ScoreSemantics.RANK_SCORE,
        selected_option="WRITE_OFF",
        abstained=False,
        input_digest=req.identity(),
    )

    errors = result.validation_errors(req)

    assert "selected_option must be one of permitted_options" in errors
    assert any("unknown options: WRITE_OFF" in error for error in errors)


def test_class_probability_scores_must_sum_to_one() -> None:
    req = _request()
    result = DecisionProviderResult(
        decision_id=req.decision_id,
        provider_id="probability-model",
        model_pin="calibrated@v1",
        output_kind=req.question_kind,
        option_scores={"HOLD": 0.6, "COLLECT": 0.6},
        score_semantics=ScoreSemantics.CLASS_PROB,
        selected_option="HOLD",
        abstained=False,
        input_digest=req.identity(),
    )

    assert "class_prob option_scores must sum to 1.0" in result.validation_errors(req)


def test_outcome_probabilities_do_not_have_sum_constraint() -> None:
    req = _request()
    result = DecisionProviderResult(
        decision_id=req.decision_id,
        provider_id="uplift-model",
        model_pin="outcome@v1",
        output_kind=req.question_kind,
        option_scores={"HOLD": 0.7, "COLLECT": 0.4},
        score_semantics=ScoreSemantics.OUTCOME_PROB,
        selected_option="HOLD",
        abstained=False,
        input_digest=req.identity(),
    )

    assert result.validation_errors(req) == ()


def test_abstention_must_be_allowed_and_explained() -> None:
    req = _request(abstain_allowed=False)
    result = DecisionProviderResult(
        decision_id=req.decision_id,
        provider_id="tiny-model",
        model_pin="tiny@v1",
        output_kind=req.question_kind,
        option_scores={},
        score_semantics=ScoreSemantics.RANK_SCORE,
        selected_option=None,
        abstained=True,
        abstain_reason=AbstainReason.OUT_OF_DISTRIBUTION,
        input_digest=req.identity(),
    )

    assert "request does not allow abstention" in result.validation_errors(req)


def test_validate_decision_fails_closed_for_bad_provider_output() -> None:
    class BadProvider:
        provider_id = "bad"
        model_pin = "bad@v1"

        def decide(self, request: DecisionProviderRequest) -> DecisionProviderResult:
            return DecisionProviderResult(
                decision_id="wrong",
                provider_id=self.provider_id,
                model_pin=self.model_pin,
                output_kind=request.question_kind,
                option_scores={"HOLD": float("inf")},
                score_semantics=ScoreSemantics.RANK_SCORE,
                selected_option="HOLD",
                abstained=False,
                input_digest="wrong",
            )

    with pytest.raises(ValueError) as exc:
        validate_decision(BadProvider(), _request())

    assert "decision_id does not match request" in str(exc.value)
    assert "input_digest does not match request" in str(exc.value)
    assert "score for 'HOLD' must be finite" in str(exc.value)
