"""WP1 acceptance tests for the intelligence-provider contract (moat plan §15 + §19.7).

Pins the guarantees the whole external/professional-intelligence layer relies on: providers are replaceable
behind a capability, provenance/freshness/cost are explicit, entitlement + PII-purpose + budget are gated before
a call, the evidence-value gate skips lookups that can't change the action, the fallback ladder is honored
(without silently substituting a weaker provider), and legal authority/auto-execution rules hold.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from runtime_contracts.protocol import (
    AcquisitionFailure, AcquisitionResult, Capability, CostEstimate, EvidenceArtifact, EvidenceRef,
    EvidenceRequest, IntelligenceProvider, IntelligenceRegistry, LegalAuthorityLevel, LegalEvidenceArtifact,
    ProviderFamily, decide_acquire, gated_acquire, is_legal, may_auto_execute, requires_professional_review,
)


# ── fake providers (the plan's fake-provider pattern) ──────────────────────────────────────────────────
@dataclass
class FakeProvider:
    provider_id: str
    family: ProviderFamily = ProviderFamily.EXTERNAL_DATA
    caps: tuple[Capability, ...] = (Capability.PERSON_ENRICHMENT,)
    price: float = 0.5
    entitled_tenants: tuple[str, ...] = ("t",)
    result: str = "found"          # found | no_match | unavailable | license_blocked
    calls: list = field(default_factory=list)

    def capabilities(self): return self.caps
    def estimate_cost(self, request): return CostEstimate(money=self.price, latency_ms=10)
    def check_entitlement(self, tenant, capability): return tenant in self.entitled_tenants

    def acquire(self, request):
        self.calls.append(request)
        if self.result == "found":
            art = EvidenceArtifact(
                provider=self.provider_id, family=self.family, capability=request.capability,
                subject=(request.subject_refs or ("?",))[0],
                observations=({"field": "title", "value": "CTO"},),
                source_refs=(EvidenceRef(ref=f"{self.provider_id}:rec", content_hash="abc",
                                         source=self.provider_id),),
                retrieved_at="2026-09-25T00:00:00Z", freshness_s=3600, confidence=0.9,
                cost=self.price, license_scope="enrichment", raw_response_digest="deadbeef")
            return AcquisitionResult.found((art,), cost=self.price)
        if self.result == "unavailable":
            return AcquisitionResult.failed(AcquisitionFailure.UNAVAILABLE, "down")
        if self.result == "license_blocked":
            return AcquisitionResult.failed(AcquisitionFailure.LICENSE_BLOCKED, "no commercial license")
        return AcquisitionResult.failed(AcquisitionFailure.NO_MATCH)


def _req(**over) -> EvidenceRequest:
    base = dict(decision_case_id="dc1", capability=Capability.PERSON_ENRICHMENT, subject_refs=("person:1",),
                purpose="qualify inbound lead", tenant="t", max_cost=1.0)
    base.update(over)
    return EvidenceRequest(**base)


def test_provider_is_a_structural_protocol():
    assert isinstance(FakeProvider("apollo"), IntelligenceProvider)


def test_request_schema_is_stable_across_providers():
    reg = IntelligenceRegistry()
    reg.register(FakeProvider("apollo", price=0.9))
    reg.register(FakeProvider("dnb", price=0.3))
    r = _req()
    # swapping which provider serves the capability does not change the DecisionCase's request.
    res, rec, trace = gated_acquire(reg, r)
    assert res.ok and res.artifacts[0].provider == "dnb"   # cheapest entitled provider chosen
    assert rec.decision_case_id == "dc1"


def test_provenance_freshness_cost_are_explicit():
    reg = IntelligenceRegistry(); reg.register(FakeProvider("apollo"))
    res, _, _ = gated_acquire(reg, _req())
    a = res.artifacts[0]
    assert a.has_provenance()                 # provenance cannot be omitted (source_refs / raw digest)
    assert a.cost == 0.5 and a.freshness_s == 3600 and 0 <= a.confidence <= 1
    assert not a.is_stale(max_age_s=7200) and a.is_stale(max_age_s=1800)


def test_entitlement_checked_before_call():
    reg = IntelligenceRegistry(); reg.register(FakeProvider("apollo", entitled_tenants=("other",)))
    res, rec, _ = gated_acquire(reg, _req(tenant="t"))
    assert not res.ok and res.failure == AcquisitionFailure.NOT_ENTITLED
    assert rec.evidence_received is False


def test_pii_capability_requires_purpose():
    cost = CostEstimate(money=0.0)
    blocked = decide_acquire(_req(purpose=""), entitled=True, cost=cost, value_estimate=1.0)
    assert not blocked.acquire and "purpose" in blocked.reason.lower()
    ok = decide_acquire(_req(purpose="qualify lead"), entitled=True, cost=cost, value_estimate=1.0)
    assert ok.acquire


def test_budget_cap_prevents_the_call():
    p = FakeProvider("apollo", price=5.0)
    reg = IntelligenceRegistry(); reg.register(p)
    res, _, _ = gated_acquire(reg, _req(max_cost=1.0))
    assert not res.ok and res.failure == AcquisitionFailure.BUDGET_EXCEEDED
    assert p.calls == []                       # provider.acquire never invoked over budget


def test_value_gate_skips_when_evidence_cannot_change_action():
    p = FakeProvider("apollo")
    reg = IntelligenceRegistry(); reg.register(p)
    res, _, trace = gated_acquire(reg, _req(), value_estimate_fn=lambda r: 0.0)  # no decision relevance
    assert not res.ok and p.calls == []
    assert any("cannot change" in t for t in trace)


def test_fallback_tries_alternate_on_retryable_failure():
    reg = IntelligenceRegistry()
    reg.register(FakeProvider("flaky", price=0.1, result="unavailable"))   # cheapest, but down
    reg.register(FakeProvider("apollo", price=0.5, result="found"))
    res, _, trace = gated_acquire(reg, _req())
    assert res.ok and res.artifacts[0].provider == "apollo"
    assert any("unavailable" in t for t in trace)


def test_non_retryable_failure_stops_the_ladder():
    reg = IntelligenceRegistry()
    reg.register(FakeProvider("vt_free", price=0.1, result="license_blocked"))
    reg.register(FakeProvider("apollo", price=0.5, result="found"))
    res, _, _ = gated_acquire(reg, _req())
    # LICENSE_BLOCKED must NOT silently fall through to another provider and pretend equivalence.
    assert not res.ok and res.failure == AcquisitionFailure.LICENSE_BLOCKED


def test_legal_capability_flag_and_authority_gates():
    assert is_legal(Capability.LEGAL_RESEARCH) and not is_legal(Capability.PERSON_ENRICHMENT)
    assert may_auto_execute(LegalAuthorityLevel.L0_CLERICAL)
    assert not may_auto_execute(LegalAuthorityLevel.L1_APPROVED_TEMPLATE)
    assert not may_auto_execute(LegalAuthorityLevel.L3_JUDGMENT)
    assert requires_professional_review(LegalAuthorityLevel.L3_JUDGMENT)
    assert requires_professional_review(LegalAuthorityLevel.L4_PROFESSIONAL)
    assert not requires_professional_review(LegalAuthorityLevel.L1_APPROVED_TEMPLATE)


def test_generated_legal_proposition_is_not_authoritative():
    base = EvidenceArtifact(provider="cocounsel", family=ProviderFamily.PROFESSIONAL_INTELLIGENCE,
                            capability=Capability.LEGAL_RESEARCH, subject="q", raw_response_digest="d")
    generated = LegalEvidenceArtifact(artifact=base, authority_type="generated")
    grounded = LegalEvidenceArtifact(artifact=base, authority_type="primary_law",
                                     authority_refs=("Cal. Civ. Code § 1550",), source_status="good_law")
    assert not generated.is_authoritative()
    assert grounded.is_authoritative()


def test_evidence_value_record_tracks_change():
    reg = IntelligenceRegistry(); reg.register(FakeProvider("apollo"))
    _, rec, _ = gated_acquire(reg, _req())
    assert rec.evidence_requested and rec.evidence_received and rec.cost == 0.5
    from dataclasses import replace
    assert replace(rec, decision_before="skip", decision_after="call").changed_decision()
    assert not replace(rec, decision_before="call", decision_after="call").changed_decision()
