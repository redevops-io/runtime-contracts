"""Capability registry + gated acquisition for intelligence providers (§5, §8, §10, §11).

A DecisionCase asks the registry for a *capability*; the registry matches entitled providers (cheapest first,
so provider replacement / fallback / cost comparison are possible), and `gated_acquire` applies the deterministic
gates — entitlement, PII-purpose, budget, and the "can this evidence change the action?" value test — before
spending money, then drives the §11 fallback ladder across providers. The decision-VALUE estimate is supplied by
the caller (Discovery's job); everything else here is contract-level and deterministic.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from .intelligence import (
    AcquisitionFailure, AcquisitionResult, Capability, CostEstimate, EvidenceRequest, EvidenceValueRecord,
    IntelligenceProvider, PII_CAPABILITIES, PlannerFallback,
)

# failures worth trying the next provider for vs. failures that should stop the ladder.
_RETRYABLE = frozenset({
    AcquisitionFailure.UNAVAILABLE, AcquisitionFailure.RATE_LIMITED, AcquisitionFailure.NO_MATCH,
    AcquisitionFailure.LOW_CONFIDENCE, AcquisitionFailure.STALE, AcquisitionFailure.OUTSIDE_PROVIDER_COVERAGE,
})


@dataclass(frozen=True)
class GateDecision:
    acquire: bool
    reason: str
    fallback: Optional[PlannerFallback] = None
    failure: Optional[AcquisitionFailure] = None


class IntelligenceRegistry:
    def __init__(self) -> None:
        self._providers: dict[str, IntelligenceProvider] = {}

    def register(self, provider: IntelligenceProvider) -> IntelligenceProvider:
        self._providers[provider.provider_id] = provider
        return provider

    def get(self, provider_id: str) -> Optional[IntelligenceProvider]:
        return self._providers.get(provider_id)

    def all(self) -> tuple[IntelligenceProvider, ...]:
        return tuple(self._providers.values())

    def providers_for(self, capability: Capability) -> tuple[IntelligenceProvider, ...]:
        return tuple(p for p in self._providers.values() if capability in p.capabilities())

    def match(self, request: EvidenceRequest) -> tuple[IntelligenceProvider, ...]:
        """Entitled providers offering the capability, cheapest estimated cost first (§5 cost comparison)."""
        cands = [p for p in self.providers_for(request.capability)
                 if p.check_entitlement(request.tenant, request.capability)]
        cands.sort(key=lambda p: p.estimate_cost(request).money)
        return tuple(cands)


def decide_acquire(request: EvidenceRequest, *, entitled: bool, cost: CostEstimate,
                   value_estimate: float, value_threshold: float = 0.1) -> GateDecision:
    """The §8 gate: acquire only if entitled, purpose-compliant, within budget, and the evidence could
    plausibly change the action. `value_estimate` (0..1) is the caller's estimate of decision-relevance."""
    if not entitled:
        return GateDecision(False, "not entitled", PlannerFallback.TRY_ALTERNATE_PROVIDER,
                            AcquisitionFailure.NOT_ENTITLED)
    # governance (§10): a PII lookup must declare an allowed purpose — never enrich a person just because we can.
    if request.capability in PII_CAPABILITIES and not request.purpose.strip():
        return GateDecision(False, "PII capability requires an allowed purpose", PlannerFallback.ABSTAIN)
    if cost.money > request.max_cost:
        return GateDecision(False, f"cost {cost.money} exceeds budget {request.max_cost}",
                            PlannerFallback.CONTINUE_WITH_LOCAL_EVIDENCE, AcquisitionFailure.BUDGET_EXCEEDED)
    if value_estimate < value_threshold:
        return GateDecision(False, "evidence cannot change the action",
                            PlannerFallback.CONTINUE_WITH_LOCAL_EVIDENCE)
    return GateDecision(True, "acquire")


def gated_acquire(registry: IntelligenceRegistry, request: EvidenceRequest, *,
                  value_estimate_fn: Callable[[EvidenceRequest], float] = lambda _r: 1.0,
                  value_threshold: float = 0.1) -> tuple[AcquisitionResult, EvidenceValueRecord, list[str]]:
    """Match → gate → acquire, walking the §11 fallback ladder across providers. Returns the result, an
    evidence-value ledger row (verified_outcome filled in later), and a human-readable trace."""
    trace: list[str] = []
    value = value_estimate_fn(request)
    candidates = registry.match(request)
    if not candidates:
        trace.append("no entitled provider for capability")
        rec = _record(request, "", requested=False, received=False, cost=0.0)
        return AcquisitionResult.failed(AcquisitionFailure.NOT_ENTITLED, "no provider"), rec, trace

    spent = 0.0
    last_failure = AcquisitionFailure.NO_MATCH
    for p in candidates:
        cost = p.estimate_cost(request)
        gate = decide_acquire(request, entitled=True, cost=cost, value_estimate=value,
                              value_threshold=value_threshold)
        if not gate.acquire:
            trace.append(f"{p.provider_id}: skip ({gate.reason})")
            if gate.failure in (AcquisitionFailure.NOT_ENTITLED,) or gate.fallback == PlannerFallback.TRY_ALTERNATE_PROVIDER:
                continue  # try the next provider
            # budget/PII/value gates stop the ladder — do not silently substitute a weaker provider. These are
            # decision-level skips (nothing acquired), so the ledger row is not attributed to a provider.
            rec = _record(request, "", requested=False, received=False, cost=spent)
            return AcquisitionResult.failed(gate.failure or AcquisitionFailure.BUDGET_EXCEEDED, gate.reason,
                                            spent), rec, trace
        res = p.acquire(request)
        spent += res.cost
        if res.ok and res.artifacts:
            trace.append(f"{p.provider_id}: acquired {len(res.artifacts)} artifact(s), cost {res.cost}")
            rec = _record(request, p.provider_id, requested=True, received=True, cost=spent)
            return AcquisitionResult.found(res.artifacts, cost=spent), rec, trace
        last_failure = res.failure or AcquisitionFailure.NO_MATCH
        trace.append(f"{p.provider_id}: {last_failure.value} ({res.detail})")
        if last_failure not in _RETRYABLE:
            break  # NOT_ENTITLED / BUDGET / LICENSE_BLOCKED / legal-authority failures don't retry-alternate
    rec = _record(request, "", requested=True, received=False, cost=spent)
    return AcquisitionResult.failed(last_failure, "all providers exhausted", spent), rec, trace


def _record(request: EvidenceRequest, provider: str, *, requested: bool, received: bool,
            cost: float) -> EvidenceValueRecord:
    return EvidenceValueRecord(
        decision_case_id=request.decision_case_id, capability=request.capability, provider=provider,
        evidence_requested=requested, evidence_received=received, cost=cost)


__all__ = ["IntelligenceRegistry", "GateDecision", "decide_acquire", "gated_acquire"]
