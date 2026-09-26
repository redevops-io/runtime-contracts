"""Contract tests for the decision-scoped intelligence layer (DecisionNeed / IntelligenceResult /
ProviderReceipt / provider health) that sits above the single-capability EvidenceRequest primitive.

Pins the guarantees the plan's §3 contract relies on: a need lowers cleanly to a broker request, its
policy envelope (provider gating, field-disclosure, confidence bar) is honoured, every answer carries
derived lineage + total spend + a stable replay fingerprint, per-call provider cost is receipted
separately, and provider health degrades gracefully to UNKNOWN (never "down") when unreported.
"""
from __future__ import annotations

from dataclasses import dataclass

from runtime_contracts.protocol import (
    AcquisitionFailure, Capability, DecisionNeed, EvidenceArtifact, EvidenceRef, HealthStatus,
    IntelligenceResult, ProviderFamily, ProviderHealth, ProviderReceipt, Sensitivity, provider_health,
)


def _need(**kw) -> DecisionNeed:
    base = dict(decision_case_id="dc1", capability=Capability.COMPANY_IDENTITY, question="who is ACME?",
                objective="onboard_supplier", subject_refs=("acme.example",), tenant="t",
                as_of="2026-09-26T00:00:00Z", known_at="2026-09-26T00:00:00Z")
    base.update(kw)
    return DecisionNeed(**base)


def _artifact(provider="gleif", cost=0.0, conf=0.9) -> EvidenceArtifact:
    return EvidenceArtifact(
        provider=provider, family=ProviderFamily.EXTERNAL_DATA, capability=Capability.COMPANY_IDENTITY,
        subject="acme.example", observations=({"field": "lei", "value": "5493..."},),
        source_refs=(EvidenceRef(ref=f"{provider}:rec", content_hash="abc", source=provider),),
        retrieved_at="2026-09-26T00:00:00Z", freshness_s=100, confidence=conf, cost=cost,
        license_scope="identity", raw_response_digest="deadbeef")


# ── DecisionNeed ────────────────────────────────────────────────────────────────────────────────────────
def test_identity_is_stable_and_field_sensitive():
    n = _need()
    assert n.identity() == _need().identity()
    assert n.identity() != _need(max_cost=5.0).identity()


def test_lowers_to_evidence_request_and_drops_prohibited_fields():
    n = _need(fields=("lei", "email"), prohibited_fields=("email",), freshness_limit_s=3600.0,
              purpose="", objective="onboard_supplier")
    r = n.to_evidence_request()
    assert r.capability is Capability.COMPANY_IDENTITY
    assert r.subject_refs == ("acme.example",)
    assert r.fields == ("lei",)                      # prohibited 'email' not disclosed to the provider
    assert r.max_age_s == 3600.0                     # freshness_limit_s → max_age_s
    assert r.purpose == "onboard_supplier"           # falls back to objective when purpose empty


def test_policy_predicates():
    n = _need(permitted_providers=("gleif",), prohibited_fields=("email",), min_confidence=0.8)
    assert n.permits_provider("gleif") and not n.permits_provider("apollo")
    assert _need().permits_provider("anyone")        # empty ⇒ any entitled provider
    assert n.discloses_field("lei") and not n.discloses_field("email")
    assert n.meets_confidence(0.8) and not n.meets_confidence(0.79)


# ── ProviderReceipt ─────────────────────────────────────────────────────────────────────────────────────
def test_receipt_from_artifact_and_failure():
    a = _artifact(cost=0.4)
    ok = ProviderReceipt.for_artifact(a, latency_ms=12)
    assert ok.ok and ok.cost == 0.4 and ok.artifact_id == a.identity() and ok.provider == "gleif"
    bad = ProviderReceipt.for_failure("apollo", Capability.COMPANY_IDENTITY, AcquisitionFailure.NO_MATCH,
                                      cost=0.0, detail="no record")
    assert not bad.ok and bad.failure is AcquisitionFailure.NO_MATCH and bad.artifact_id == ""


# ── IntelligenceResult ──────────────────────────────────────────────────────────────────────────────────
def test_result_aggregation_derives_lineage_cost_and_fingerprint():
    n = _need(min_confidence=0.8)
    a1, a2 = _artifact("gleif", cost=0.4), _artifact("opencorporates", cost=0.1, conf=0.85)
    receipts = (ProviderReceipt.for_artifact(a1), ProviderReceipt.for_artifact(a2))
    res = IntelligenceResult.from_artifacts(
        n, (a1, a2), receipts, answer="ACME Inc (LEI 5493...)", confidence=0.88,
        metrics={"match_score": 0.98}, produced_at="2026-09-26T00:01:00Z", expires_at="2026-12-01T00:00:00Z")
    assert res.decision_need_id == n.identity()                 # points back to the ask (replay key)
    assert res.evidence_event_ids == (a1.identity(), a2.identity())
    assert res.total_cost == 0.5                                # derived from receipts, cannot disagree
    assert res.tenant == "t" and res.as_of == n.as_of and res.known_at == n.known_at
    assert res.fingerprint() == res.identity()                 # identity is the fingerprint alias
    assert res.is_decision_grade(n)                             # clears confidence bar, no gaps
    assert not res.is_expired("2026-10-01T00:00:00Z") and res.is_expired("2027-01-01T00:00:00Z")


def test_result_below_confidence_or_with_gaps_is_not_decision_grade():
    n = _need(min_confidence=0.9)
    a = _artifact(cost=0.2)
    r = (ProviderReceipt.for_artifact(a),)
    low = IntelligenceResult.from_artifacts(n, (a,), r, answer="maybe", confidence=0.7)
    assert not low.is_decision_grade(n)                          # below the bar
    gapped = IntelligenceResult.from_artifacts(n, (a,), r, answer="ACME", confidence=0.95,
                                               unresolved_gaps=("ownership unknown",))
    assert not gapped.is_decision_grade(n)                       # confident but incomplete


def test_fingerprint_changes_with_content():
    n = _need()
    a = _artifact(cost=0.2)
    r = (ProviderReceipt.for_artifact(a),)
    base = IntelligenceResult.from_artifacts(n, (a,), r, answer="A", confidence=0.9)
    other = IntelligenceResult.from_artifacts(n, (a,), r, answer="B", confidence=0.9)
    assert base.fingerprint() != other.fingerprint()


# ── provider health (optional, non-breaking) ────────────────────────────────────────────────────────────
@dataclass
class _Bare:
    provider_id: str = "bare"

@dataclass
class _Healthy:
    provider_id: str = "hp"
    def health(self) -> ProviderHealth:
        return ProviderHealth(self.provider_id, HealthStatus.OK, checked_at="2026-09-26T00:00:00Z")

@dataclass
class _Broken:
    provider_id: str = "bp"
    def health(self) -> ProviderHealth:
        raise RuntimeError("probe failed")


def test_provider_health_degrades_gracefully():
    # a provider without health() is UNKNOWN — and UNKNOWN is still usable (not treated as down).
    h = provider_health(_Bare())
    assert h.status is HealthStatus.UNKNOWN and h.usable
    # a reporting provider returns its own health.
    assert provider_health(_Healthy()).status is HealthStatus.OK
    # a raising health() probe never takes down the broker; it degrades to UNAVAILABLE.
    broken = provider_health(_Broken())
    assert broken.status is HealthStatus.UNAVAILABLE and not broken.usable
