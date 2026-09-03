"""Conformance for the verification-ladder rules.

The two rules that keep cost-optimized verification honest: fail-closed (must reach the
tier) and no-lone-model-at-the-final-gate. The cheapest-sufficient *selection* is a planner
algorithm tested in the Mission Runtime; here we pin the rule it must select within.
"""
from runtime_contracts.models import (
    AssuranceTier, VerificationRequirement, VerifierDescriptor, is_sufficient, tier_rank,
)
from runtime_contracts.models.capability import Estimate
from runtime_contracts.models.verification import Determinism


def _v(tier, det=Determinism.DETERMINISTIC, vid="verify.x"):
    return VerifierDescriptor(verifier_id=vid, tier=tier, determinism=det)


def test_tier_order_is_monotonic():
    ranks = [tier_rank(t) for t in (
        AssuranceTier.STRUCTURAL, AssuranceTier.DETERMINISTIC, AssuranceTier.EVIDENTIAL,
        AssuranceTier.SEMANTIC, AssuranceTier.ENSEMBLE, AssuranceTier.HUMAN)]
    assert ranks == sorted(ranks) == list(range(6))


def test_fail_closed_below_the_bar():
    req = VerificationRequirement(min_tier=AssuranceTier.EVIDENTIAL)
    assert not is_sufficient(_v(AssuranceTier.STRUCTURAL), req)
    assert not is_sufficient(_v(AssuranceTier.DETERMINISTIC), req)
    assert is_sufficient(_v(AssuranceTier.EVIDENTIAL), req)
    assert is_sufficient(_v(AssuranceTier.HUMAN), req)          # above the bar is fine


def test_lone_model_cannot_close_the_final_gate():
    req = VerificationRequirement(min_tier=AssuranceTier.SEMANTIC)  # deterministic-final ON
    semantic_model = _v(AssuranceTier.SEMANTIC, Determinism.NON_DETERMINISTIC)
    assert not is_sufficient(semantic_model, req)                  # evidence, not proof
    # …but an ensemble or a human of a non-deterministic nature may close it.
    assert is_sufficient(_v(AssuranceTier.ENSEMBLE, Determinism.NON_DETERMINISTIC), req)
    assert is_sufficient(_v(AssuranceTier.HUMAN, Determinism.NON_DETERMINISTIC), req)


def test_deterministic_verifier_at_tier_closes_the_gate():
    req = VerificationRequirement(min_tier=AssuranceTier.SEMANTIC)
    # A deterministic verifier that reaches the tier is a valid final gate.
    assert is_sufficient(_v(AssuranceTier.SEMANTIC, Determinism.DETERMINISTIC), req)


def test_relaxing_deterministic_final_admits_a_model():
    # Low-risk, reversible work may accept a lone model verdict — but only by saying so.
    req = VerificationRequirement(min_tier=AssuranceTier.SEMANTIC,
                                  require_deterministic_final=False)
    assert is_sufficient(_v(AssuranceTier.SEMANTIC, Determinism.NON_DETERMINISTIC), req)


def test_descriptor_is_canonical():
    d = VerifierDescriptor(verifier_id="verify.schema", tier=AssuranceTier.STRUCTURAL,
                           cost=Estimate(low="0", high="0", unit="usd"), gating=True)
    cf = d.canonical_form()
    assert cf["verifier_id"] == "verify.schema" and cf["gating"] is True
    assert cf["tier"] == "STRUCTURAL"
