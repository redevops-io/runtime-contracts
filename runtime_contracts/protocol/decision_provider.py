"""Bounded DecisionProvider protocol.

Decision providers score or select from an already-permitted option set. They
are proposal engines only: they do not grant authorization, perform writes, or
replace deterministic policy checks, approval gates, idempotency, or independent
readback. This protocol is intentionally small so rules, compact classifiers,
larger LLM adapters, and learned policies can all be benchmarked under the same
decision/request/result identity.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Mapping, Protocol

from .seal import content_hash

DECISION_PROVIDER_CONTRACT_VERSION = "decision-provider/v1"
_TOLERANCE = 1e-6


class QuestionKind(str, Enum):
    PREDICATE = "predicate"
    CHOICE = "choice"
    SCORE = "score"
    RUBRIC = "rubric"


class ScoreSemantics(str, Enum):
    CLASS_PROB = "class_prob"        # mutually exclusive class probabilities; scores sum to 1
    OUTCOME_PROB = "outcome_prob"    # per-option probability of a future outcome; no sum constraint
    RANK_SCORE = "rank_score"        # higher is better, only order is meaningful
    UTILITY = "utility"              # expected utility in the declared utility units
    RUBRIC_SCORE = "rubric_score"    # rubric-local score


class AbstainReason(str, Enum):
    LOW_CONFIDENCE = "low_confidence"
    OUT_OF_DISTRIBUTION = "out_of_distribution"
    POLICY_GAP = "policy_gap"
    BUDGET_EXCEEDED = "budget_exceeded"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    INVALID_REQUEST = "invalid_request"


def _enum_value(value: object) -> str:
    return value.value if hasattr(value, "value") else str(value)


@dataclass(frozen=True)
class DecisionProviderRequest:
    """A typed ask for a bounded decision.

    `permitted_options` is supplied by deterministic policy before the provider
    is called; a valid result may only select from that set or abstain when the
    request permits it.
    """
    decision_id: str
    tenant_id: str
    purpose: str
    question_kind: QuestionKind | str
    evidence_view_ref: str
    permitted_options: tuple[str, ...]
    constraints_ref: str
    as_of: str
    known_at: str
    abstain_allowed: bool = True
    latency_budget_ms: int = 100
    max_cost: str = ""
    data_classification: str = "synthetic"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def canonical_form(self) -> dict[str, Any]:
        return {
            "contract_version": DECISION_PROVIDER_CONTRACT_VERSION,
            "decision_id": self.decision_id,
            "tenant_id": self.tenant_id,
            "purpose": self.purpose,
            "question_kind": _enum_value(self.question_kind),
            "evidence_view_ref": self.evidence_view_ref,
            "permitted_options": list(self.permitted_options),
            "constraints_ref": self.constraints_ref,
            "as_of": self.as_of,
            "known_at": self.known_at,
            "abstain_allowed": self.abstain_allowed,
            "latency_budget_ms": self.latency_budget_ms,
            "max_cost": self.max_cost,
            "data_classification": self.data_classification,
            "metadata": dict(sorted(self.metadata.items())),
        }

    def identity(self) -> str:
        return content_hash(self.canonical_form())

    digest = identity

    def validation_errors(self) -> tuple[str, ...]:
        errors: list[str] = []
        for field_name in (
            "decision_id",
            "tenant_id",
            "purpose",
            "question_kind",
            "evidence_view_ref",
            "constraints_ref",
            "as_of",
            "known_at",
        ):
            if not getattr(self, field_name):
                errors.append(f"{field_name} is required")
        try:
            QuestionKind(_enum_value(self.question_kind))
        except ValueError:
            errors.append(f"unknown question_kind {self.question_kind!r}")
        if not self.permitted_options:
            errors.append("permitted_options is required")
        if len(set(self.permitted_options)) != len(self.permitted_options):
            errors.append("permitted_options contains duplicates")
        if self.latency_budget_ms <= 0:
            errors.append("latency_budget_ms must be positive")
        if not self.data_classification:
            errors.append("data_classification is required")
        return tuple(errors)


@dataclass(frozen=True)
class DecisionProviderResult:
    decision_id: str
    provider_id: str
    model_pin: str
    output_kind: QuestionKind | str
    option_scores: Mapping[str, float]
    score_semantics: ScoreSemantics | str
    selected_option: str | None
    abstained: bool
    input_digest: str
    response_digest: str = ""
    calibration_pin: str = ""
    abstain_reason: AbstainReason | str | None = None
    uncertainty: Mapping[str, float] = field(default_factory=dict)
    usage: Mapping[str, Any] = field(default_factory=dict)

    def canonical_form(self) -> dict[str, Any]:
        return {
            "contract_version": DECISION_PROVIDER_CONTRACT_VERSION,
            "decision_id": self.decision_id,
            "provider_id": self.provider_id,
            "model_pin": self.model_pin,
            "output_kind": _enum_value(self.output_kind),
            "option_scores": dict(sorted((k, float(v)) for k, v in self.option_scores.items())),
            "score_semantics": _enum_value(self.score_semantics),
            "selected_option": self.selected_option,
            "abstained": self.abstained,
            "input_digest": self.input_digest,
            "calibration_pin": self.calibration_pin,
            "abstain_reason": _enum_value(self.abstain_reason) if self.abstain_reason else None,
            "uncertainty": dict(sorted((k, float(v)) for k, v in self.uncertainty.items())),
            "usage": dict(sorted(self.usage.items())),
        }

    def identity(self) -> str:
        return content_hash(self.canonical_form())

    fingerprint = identity

    def with_response_digest(self) -> "DecisionProviderResult":
        return DecisionProviderResult(
            decision_id=self.decision_id,
            provider_id=self.provider_id,
            model_pin=self.model_pin,
            output_kind=self.output_kind,
            option_scores=self.option_scores,
            score_semantics=self.score_semantics,
            selected_option=self.selected_option,
            abstained=self.abstained,
            input_digest=self.input_digest,
            response_digest=self.identity(),
            calibration_pin=self.calibration_pin,
            abstain_reason=self.abstain_reason,
            uncertainty=self.uncertainty,
            usage=self.usage,
        )

    def validation_errors(self, request: DecisionProviderRequest) -> tuple[str, ...]:
        errors = list(request.validation_errors())
        if self.decision_id != request.decision_id:
            errors.append("decision_id does not match request")
        if self.input_digest != request.identity():
            errors.append("input_digest does not match request")
        if not self.provider_id:
            errors.append("provider_id is required")
        if not self.model_pin:
            errors.append("model_pin is required")
        try:
            QuestionKind(_enum_value(self.output_kind))
        except ValueError:
            errors.append(f"unknown output_kind {self.output_kind!r}")
        try:
            semantics = ScoreSemantics(_enum_value(self.score_semantics))
        except ValueError:
            errors.append(f"unknown score_semantics {self.score_semantics!r}")
            semantics = None
        if self.abstained and self.selected_option is not None:
            errors.append("abstained result must not select an option")
        if self.abstained and not request.abstain_allowed:
            errors.append("request does not allow abstention")
        if self.abstained and not self.abstain_reason:
            errors.append("abstained result must include abstain_reason")
        if not self.abstained and self.selected_option not in request.permitted_options:
            errors.append("selected_option must be one of permitted_options")
        unknown_options = sorted(set(self.option_scores) - set(request.permitted_options))
        if unknown_options:
            errors.append(f"option_scores contains unknown options: {', '.join(unknown_options)}")
        for option, score in self.option_scores.items():
            if not isinstance(score, (int, float)) or not math.isfinite(float(score)):
                errors.append(f"score for {option!r} must be finite")
        for key, value in self.uncertainty.items():
            if not isinstance(value, (int, float)) or not math.isfinite(float(value)):
                errors.append(f"uncertainty value for {key!r} must be finite")
        if semantics in (ScoreSemantics.CLASS_PROB, ScoreSemantics.OUTCOME_PROB):
            for option, score in self.option_scores.items():
                if float(score) < 0.0 or float(score) > 1.0:
                    errors.append(f"probability score for {option!r} must be in [0, 1]")
        if semantics is ScoreSemantics.CLASS_PROB and self.option_scores:
            total = sum(float(score) for score in self.option_scores.values())
            if abs(total - 1.0) > _TOLERANCE:
                errors.append("class_prob option_scores must sum to 1.0")
        return tuple(errors)

    def is_valid_for(self, request: DecisionProviderRequest) -> bool:
        return not self.validation_errors(request)


class DecisionProvider(Protocol):
    provider_id: str
    model_pin: str

    def decide(self, request: DecisionProviderRequest) -> DecisionProviderResult: ...


class StaticDecisionProvider:
    """Deterministic provider for fixtures and conformance tests."""

    def __init__(
        self,
        provider_id: str,
        model_pin: str,
        scorer: Callable[[DecisionProviderRequest], Mapping[str, float]] | None = None,
        *,
        score_semantics: ScoreSemantics = ScoreSemantics.RANK_SCORE,
    ) -> None:
        self.provider_id = provider_id
        self.model_pin = model_pin
        self.score_semantics = score_semantics
        self._scorer = scorer

    def decide(self, request: DecisionProviderRequest) -> DecisionProviderResult:
        request_errors = request.validation_errors()
        if request_errors:
            raise ValueError("; ".join(request_errors))
        scores = dict(
            self._scorer(request)
            if self._scorer
            else {
                option: float(len(request.permitted_options) - idx)
                for idx, option in enumerate(request.permitted_options)
            }
        )
        selected = max(scores, key=scores.get) if scores else None
        result = DecisionProviderResult(
            decision_id=request.decision_id,
            provider_id=self.provider_id,
            model_pin=self.model_pin,
            output_kind=request.question_kind,
            option_scores=scores,
            score_semantics=self.score_semantics,
            selected_option=selected,
            abstained=selected is None,
            abstain_reason=AbstainReason.LOW_CONFIDENCE if selected is None else None,
            input_digest=request.identity(),
        ).with_response_digest()
        result_errors = result.validation_errors(request)
        if result_errors:
            raise ValueError("; ".join(result_errors))
        return result


def validate_decision(
    provider: DecisionProvider,
    request: DecisionProviderRequest,
) -> DecisionProviderResult:
    """Run a provider and enforce the bounded decision contract fail-closed."""
    result = provider.decide(request)
    errors = result.validation_errors(request)
    if errors:
        raise ValueError("; ".join(errors))
    return result if result.response_digest else result.with_response_digest()


__all__ = [
    "DECISION_PROVIDER_CONTRACT_VERSION",
    "AbstainReason",
    "DecisionProvider",
    "DecisionProviderRequest",
    "DecisionProviderResult",
    "QuestionKind",
    "ScoreSemantics",
    "StaticDecisionProvider",
    "validate_decision",
]
