"""External / Professional Intelligence Provider protocol (WP1).

The moat plan (REDEVOPS_AGENTIC_APPS_COMPETITIVE_MOAT_API_INTEGRATION_AUDIT_PLAN.md) says: don't reimplement
incumbent data/network moats — put a first-class *evidence provider* layer behind Discovery Runtime. The
Runtime asks for a **capability** (never `call_apollo()`), a gate decides whether the evidence can change the
decision and is worth its cost, an adapter acquires it, and the result is a governed EvidenceArtifact carrying
provenance/cost/freshness/license. Later, verified-outcome accounting says whether buying it actually helped.

This module is the domain-neutral contract only — no provider SDKs, no network. Adapters (Apollo, Similarweb,
Stripe/Radar, Cloudflare TI, GLEIF/OpenSanctions/OpenCorporates, LexisNexis/CoCounsel, …) implement
`IntelligenceProvider` below; the open stack runs with only open adapters and no paid keys (§12).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional, Protocol, runtime_checkable

from .evidence import EvidenceRef
from .seal import content_hash

INTELLIGENCE_CONTRACT_VERSION = "1"


# ── capabilities (a DecisionCase asks for one of these, never a provider name) ──────────────────────────
class Capability(str, Enum):
    # sales / entity
    PERSON_SEARCH = "person_search"
    PERSON_ENRICHMENT = "person_enrichment"
    COMPANY_ENRICHMENT = "company_enrichment"
    COMPANY_IDENTITY = "company_identity"
    CORPORATE_HIERARCHY = "corporate_hierarchy"
    BENEFICIAL_OWNERSHIP = "beneficial_ownership"
    SANCTIONS_RISK = "sanctions_risk"
    # payments
    PAYMENT_FRAUD_SCORE = "payment_fraud_score"
    # market / web
    WEB_TRAFFIC_INTELLIGENCE = "web_traffic_intelligence"
    SEARCH_KEYWORD_INTELLIGENCE = "search_keyword_intelligence"
    BACKLINK_INTELLIGENCE = "backlink_intelligence"
    SOCIAL_LISTENING = "social_listening"
    # security
    DOMAIN_REPUTATION = "domain_reputation"
    IP_REPUTATION = "ip_reputation"
    PASSIVE_DNS = "passive_dns"
    MALWARE_REPUTATION = "malware_reputation"
    THREAT_INTELLIGENCE = "threat_intelligence"
    VULNERABILITY_EXPLOITABILITY = "vulnerability_exploitability"
    # marketing infra
    EMAIL_DELIVERY = "email_delivery"
    # supply / operations (Agentic Apps intelligence families — Supplier/Supply/Order)
    SUPPLIER_RESOLUTION = "supplier_resolution"
    DELIVERY_RELIABILITY = "delivery_reliability"
    CONFIRMATION_RELIABILITY = "confirmation_reliability"
    # legal (Professional Intelligence — §19)
    LEGAL_RESEARCH = "legal_research"
    LEGAL_AUTHORITY_LOOKUP = "legal_authority_lookup"
    LEGAL_DOCUMENT_DRAFT = "legal_document_draft"
    LEGAL_DOCUMENT_REVIEW = "legal_document_review"
    LEGAL_CLAUSE_REVIEW = "legal_clause_review"
    LEGAL_PRECEDENT_LOOKUP = "legal_precedent_lookup"
    LEGAL_JUDGMENT_REQUIRED = "legal_judgment_required"


_LEGAL_CAPABILITIES = frozenset({
    Capability.LEGAL_RESEARCH, Capability.LEGAL_AUTHORITY_LOOKUP, Capability.LEGAL_DOCUMENT_DRAFT,
    Capability.LEGAL_DOCUMENT_REVIEW, Capability.LEGAL_CLAUSE_REVIEW, Capability.LEGAL_PRECEDENT_LOOKUP,
    Capability.LEGAL_JUDGMENT_REQUIRED,
})
# PII-bearing capabilities require an allowed purpose + tenant isolation (§10).
PII_CAPABILITIES = frozenset({
    Capability.PERSON_SEARCH, Capability.PERSON_ENRICHMENT, Capability.BENEFICIAL_OWNERSHIP,
})


def is_legal(cap: Capability) -> bool:
    return cap in _LEGAL_CAPABILITIES


class ProviderFamily(str, Enum):
    EXTERNAL_DATA = "external_data"                    # enrichment / telemetry / network evidence
    PROFESSIONAL_INTELLIGENCE = "professional_intelligence"  # specialist research / interpretation / workflow
    INTERNAL_COMPUTED = "internal_computed"           # evidence computed from the tenant's OWN canonical data (cost 0)


class Sensitivity(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    PII = "pii"
    SENSITIVE_PII = "sensitive_pii"
    RESTRICTED = "restricted"


class AcquisitionFailure(str, Enum):
    UNAVAILABLE = "unavailable"
    RATE_LIMITED = "rate_limited"
    BUDGET_EXCEEDED = "budget_exceeded"
    NOT_ENTITLED = "not_entitled"
    NO_MATCH = "no_match"
    LOW_CONFIDENCE = "low_confidence"
    STALE = "stale"
    LICENSE_BLOCKED = "license_blocked"
    # legal (§19.7)
    NO_AUTHORITY_FOUND = "no_authority_found"
    JURISDICTION_UNRESOLVED = "jurisdiction_unresolved"
    CONFLICTING_AUTHORITY = "conflicting_authority"
    OUTSIDE_PROVIDER_COVERAGE = "outside_provider_coverage"
    STALE_AUTHORITY = "stale_authority"
    PROFESSIONAL_REVIEW_REQUIRED = "professional_review_required"


class PlannerFallback(str, Enum):
    CONTINUE_WITH_LOCAL_EVIDENCE = "continue_with_local_evidence"
    TRY_ALTERNATE_PROVIDER = "try_alternate_provider"
    REQUEST_HUMAN_EVIDENCE = "request_human_evidence"
    ABSTAIN = "abstain"
    DEFER = "defer"


# Legal authority / action levels (§19.3). Higher = more consequential; auto-execution stops at L1.
class LegalAuthorityLevel(int, Enum):
    L0_CLERICAL = 0            # document assembly from a deterministic template
    L1_APPROVED_TEMPLATE = 1   # draft from an approved org template — draft auto, human-approve before send
    L2_NOVEL = 2               # novel clause / jurisdiction-dependent — specialist + explicit human review
    L3_JUDGMENT = 3            # legal judgment/advice — LEGAL_JUDGMENT_REQUIRED
    L4_PROFESSIONAL = 4        # filing / representation — professional authorization required


def may_auto_execute(level: LegalAuthorityLevel) -> bool:
    """Only clerical/L0 may execute within ordinary authorization; everything else needs a human/professional
    gate before an external legal action. Evidence never grants execution permission on its own."""
    return level == LegalAuthorityLevel.L0_CLERICAL


def requires_professional_review(level: LegalAuthorityLevel) -> bool:
    return level >= LegalAuthorityLevel.L3_JUDGMENT


# ── requests + evidence ─────────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class EvidenceRequest:
    """A decision-scoped ask for a capability (§4.2). Names a capability, not a provider."""
    decision_case_id: str
    capability: Capability
    subject_refs: tuple[str, ...] = ()
    fields: tuple[str, ...] = ()
    purpose: str = ""
    tenant: str = ""
    max_cost: float = 0.0            # money ceiling for this lookup; 0 ⇒ free-only
    max_age_s: float = 0.0           # freshness ceiling in seconds; 0 ⇒ any age
    jurisdiction: str = ""
    sensitivity: Sensitivity = Sensitivity.PUBLIC
    deadline: Optional[str] = None

    def canonical_form(self) -> dict[str, Any]:
        return {
            "decision_case_id": self.decision_case_id, "capability": self.capability.value,
            "subject_refs": list(self.subject_refs), "fields": list(self.fields), "purpose": self.purpose,
            "tenant": self.tenant, "max_cost": self.max_cost, "max_age_s": self.max_age_s,
            "jurisdiction": self.jurisdiction, "sensitivity": self.sensitivity.value, "deadline": self.deadline,
        }

    def identity(self) -> str:
        return content_hash(self.canonical_form())


@dataclass(frozen=True)
class CostEstimate:
    money: float = 0.0
    latency_ms: float = 0.0
    currency: str = "USD"


@dataclass(frozen=True)
class EvidenceArtifact:
    """Normalized, governed evidence (§4.2). Carries provenance/cost/freshness/license — never a bare answer."""
    provider: str
    family: ProviderFamily
    capability: Capability
    subject: str
    observations: tuple[dict, ...] = ()
    source_refs: tuple[EvidenceRef, ...] = ()
    retrieved_at: str = ""
    effective_at: str = ""
    freshness_s: float = 0.0          # age of the underlying data at retrieval, seconds
    confidence: float = 0.0           # 0..1
    cost: float = 0.0
    license_scope: str = ""
    raw_response_digest: str = ""
    tenant: str = ""

    def canonical_form(self) -> dict[str, Any]:
        return {
            "provider": self.provider, "family": self.family.value, "capability": self.capability.value,
            "subject": self.subject, "observations": list(self.observations),
            "source_refs": [r.canonical_form() for r in self.source_refs],
            "retrieved_at": self.retrieved_at, "effective_at": self.effective_at,
            "freshness_s": self.freshness_s, "confidence": self.confidence, "cost": self.cost,
            "license_scope": self.license_scope, "raw_response_digest": self.raw_response_digest,
            "tenant": self.tenant,
        }

    def identity(self) -> str:
        return content_hash(self.canonical_form())

    def is_stale(self, max_age_s: float) -> bool:
        return bool(max_age_s) and self.freshness_s > max_age_s

    def has_provenance(self) -> bool:
        # provenance must never be omitted (§4.2, §15): a real source ref OR a raw-response digest.
        return bool(self.source_refs) or bool(self.raw_response_digest)


@dataclass(frozen=True)
class LegalEvidenceArtifact:
    """Legal provider results carry extra authority/temporal metadata (§19.6) — the underlying legal
    authorities must be preserved, not just an LLM conclusion."""
    artifact: EvidenceArtifact
    jurisdiction: str = ""
    authority_type: str = ""             # e.g. primary_law | secondary | practical_guidance | generated
    authority_refs: tuple[str, ...] = ()
    cited_passages: tuple[str, ...] = ()
    known_at: str = ""
    source_status: str = ""              # e.g. good_law | superseded | unknown
    provider_confidence: float = 0.0

    def canonical_form(self) -> dict[str, Any]:
        return {
            "artifact": self.artifact.canonical_form(), "jurisdiction": self.jurisdiction,
            "authority_type": self.authority_type, "authority_refs": list(self.authority_refs),
            "cited_passages": list(self.cited_passages), "known_at": self.known_at,
            "source_status": self.source_status, "provider_confidence": self.provider_confidence,
        }

    def identity(self) -> str:
        return content_hash(self.canonical_form())

    def is_authoritative(self) -> bool:
        # a generated proposition with no authority refs cannot be treated as authoritative (§19.7).
        return bool(self.authority_refs) and self.authority_type != "generated"


@dataclass(frozen=True)
class AcquisitionResult:
    """The outcome of an acquire() — either artifacts, or a normalized failure (never a silent weaker sub)."""
    ok: bool
    artifacts: tuple[EvidenceArtifact, ...] = ()
    failure: Optional[AcquisitionFailure] = None
    detail: str = ""
    cost: float = 0.0

    @staticmethod
    def found(artifacts: tuple[EvidenceArtifact, ...], cost: float = 0.0) -> "AcquisitionResult":
        return AcquisitionResult(ok=True, artifacts=tuple(artifacts), cost=cost)

    @staticmethod
    def failed(failure: AcquisitionFailure, detail: str = "", cost: float = 0.0) -> "AcquisitionResult":
        return AcquisitionResult(ok=False, failure=failure, detail=detail, cost=cost)


# ── provider protocol (adapters implement this; no provider types leak above the boundary) ────────────────
@runtime_checkable
class IntelligenceProvider(Protocol):
    provider_id: str
    family: ProviderFamily

    def capabilities(self) -> tuple[Capability, ...]: ...
    def estimate_cost(self, request: EvidenceRequest) -> CostEstimate: ...
    def check_entitlement(self, tenant: str, capability: Capability) -> bool: ...
    def acquire(self, request: EvidenceRequest) -> AcquisitionResult: ...


class ExternalDataProvider(IntelligenceProvider, Protocol):
    """enrichment / telemetry / network evidence."""


class ProfessionalIntelligenceProvider(IntelligenceProvider, Protocol):
    """specialist research / interpretation / domain-workflow evidence (legal, tax, …)."""


# ── evidence-value accounting (§8 / WP8) ──────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class EvidenceValueRecord:
    """Per-lookup ledger so the Runtime can later learn whether a provider/capability is worth its cost."""
    decision_case_id: str
    capability: Capability
    provider: str
    evidence_requested: bool
    evidence_received: bool
    cost: float
    decision_before: str = ""       # what the decision would have been without the evidence
    decision_after: str = ""        # the decision with it
    action: str = ""
    verified_outcome: Optional[str] = None   # filled in later when the outcome is verified

    def changed_decision(self) -> bool:
        return self.evidence_received and self.decision_before != self.decision_after

    def canonical_form(self) -> dict[str, Any]:
        return {
            "decision_case_id": self.decision_case_id, "capability": self.capability.value,
            "provider": self.provider, "evidence_requested": self.evidence_requested,
            "evidence_received": self.evidence_received, "cost": self.cost,
            "decision_before": self.decision_before, "decision_after": self.decision_after,
            "action": self.action, "verified_outcome": self.verified_outcome,
        }


# ── decision-scoped intelligence (the business layer above a single capability lookup) ────────────────────
# A DecisionNeed is the ask a *business decision* makes; the broker may resolve it with one or more
# EvidenceRequests and aggregates the resulting artifacts into one IntelligenceResult. This is the
# `DecisionNeed → Broker → provider calls → IntelligenceResult` spine — one level above EvidenceRequest,
# which stays the single-capability primitive.
@dataclass(frozen=True)
class DecisionNeed:
    """A typed, decision-scoped intelligence ask. Carries the business objective, the bi-temporal decision
    anchor (`as_of`/`known_at`, so a result is replayable against what was knowable then), and the policy
    envelope (cost/confidence/freshness ceilings, permitted providers, fields that must not be disclosed)."""
    decision_case_id: str
    capability: Capability
    question: str = ""
    objective: str = ""              # the decision this evidence informs
    subject_refs: tuple[str, ...] = ()
    fields: tuple[str, ...] = ()
    tenant: str = ""
    as_of: str = ""                  # decision valid-time anchor
    known_at: str = ""               # what was knowable at decision time (bi-temporal replay)
    horizon: str = ""                # decision horizon, e.g. "P30D"
    max_cost: float = 0.0            # money ceiling across the whole need; 0 ⇒ free-only
    min_confidence: float = 0.0      # a result below this is not decision-grade
    freshness_limit_s: float = 0.0   # freshness ceiling in seconds; 0 ⇒ any age
    permitted_providers: tuple[str, ...] = ()   # empty ⇒ any entitled provider
    prohibited_fields: tuple[str, ...] = ()     # fields that must NOT be disclosed to a provider
    purpose: str = ""
    jurisdiction: str = ""
    sensitivity: Sensitivity = Sensitivity.PUBLIC
    deadline: Optional[str] = None

    def canonical_form(self) -> dict[str, Any]:
        return {
            "decision_case_id": self.decision_case_id, "capability": self.capability.value,
            "question": self.question, "objective": self.objective, "subject_refs": list(self.subject_refs),
            "fields": list(self.fields), "tenant": self.tenant, "as_of": self.as_of, "known_at": self.known_at,
            "horizon": self.horizon, "max_cost": self.max_cost, "min_confidence": self.min_confidence,
            "freshness_limit_s": self.freshness_limit_s, "permitted_providers": list(self.permitted_providers),
            "prohibited_fields": list(self.prohibited_fields), "purpose": self.purpose,
            "jurisdiction": self.jurisdiction, "sensitivity": self.sensitivity.value, "deadline": self.deadline,
        }

    def identity(self) -> str:
        """Stable fingerprint of the ask — the replay key an IntelligenceResult points back to."""
        return content_hash(self.canonical_form())

    def to_evidence_request(self) -> EvidenceRequest:
        """Lower the need to a single-capability broker request. Provider gating, min-confidence and
        field-disclosure policy stay on the need (the broker reads them via the predicates below)."""
        disclosed = tuple(f for f in self.fields if self.discloses_field(f))
        return EvidenceRequest(
            decision_case_id=self.decision_case_id, capability=self.capability, subject_refs=self.subject_refs,
            fields=disclosed, purpose=self.purpose or self.objective, tenant=self.tenant,
            max_cost=self.max_cost, max_age_s=self.freshness_limit_s, jurisdiction=self.jurisdiction,
            sensitivity=self.sensitivity, deadline=self.deadline,
        )

    def permits_provider(self, provider_id: str) -> bool:
        return not self.permitted_providers or provider_id in self.permitted_providers

    def discloses_field(self, field_name: str) -> bool:
        return field_name not in self.prohibited_fields

    def meets_confidence(self, confidence: float) -> bool:
        return confidence >= self.min_confidence


@dataclass(frozen=True)
class ProviderReceipt:
    """One receipt per external provider call — cost ledgered separately from any model/subscription bill
    (§4.6: never hide provider cost). Ties a spend to the exact evidence it produced (or the failure)."""
    provider: str
    capability: Capability
    cost: float = 0.0
    currency: str = "USD"
    ok: bool = True
    failure: Optional[AcquisitionFailure] = None
    artifact_id: str = ""            # EvidenceArtifact.identity() when ok
    retrieved_at: str = ""
    latency_ms: float = 0.0
    license_scope: str = ""
    detail: str = ""

    def canonical_form(self) -> dict[str, Any]:
        return {
            "provider": self.provider, "capability": self.capability.value, "cost": self.cost,
            "currency": self.currency, "ok": self.ok,
            "failure": self.failure.value if self.failure else None, "artifact_id": self.artifact_id,
            "retrieved_at": self.retrieved_at, "latency_ms": self.latency_ms,
            "license_scope": self.license_scope, "detail": self.detail,
        }

    def identity(self) -> str:
        return content_hash(self.canonical_form())

    @staticmethod
    def for_artifact(artifact: "EvidenceArtifact", *, latency_ms: float = 0.0) -> "ProviderReceipt":
        return ProviderReceipt(
            provider=artifact.provider, capability=artifact.capability, cost=artifact.cost,
            ok=True, artifact_id=artifact.identity(), retrieved_at=artifact.retrieved_at,
            latency_ms=latency_ms, license_scope=artifact.license_scope,
        )

    @staticmethod
    def for_failure(provider: str, capability: Capability, failure: AcquisitionFailure, *,
                    cost: float = 0.0, detail: str = "", latency_ms: float = 0.0) -> "ProviderReceipt":
        return ProviderReceipt(provider=provider, capability=capability, cost=cost, ok=False,
                               failure=failure, detail=detail, latency_ms=latency_ms)


@dataclass(frozen=True)
class IntelligenceResult:
    """The aggregated answer to a DecisionNeed. Every answer carries confidence, evidence lineage, the
    per-call provider receipts, the total spend, assumptions/gaps, an expiry, and a stable fingerprint —
    so a decision can be replayed and audited (§3)."""
    decision_need_id: str            # DecisionNeed.identity() — the replay key
    capability: Capability
    answer: str = ""
    metrics: dict[str, Any] = field(default_factory=dict)   # structured metrics
    confidence: float = 0.0
    evidence_event_ids: tuple[str, ...] = ()   # EvidenceArtifact identities backing the answer
    provider_receipts: tuple[ProviderReceipt, ...] = ()
    assumptions: tuple[str, ...] = ()
    unresolved_gaps: tuple[str, ...] = ()
    total_cost: float = 0.0
    tenant: str = ""
    as_of: str = ""
    known_at: str = ""
    produced_at: str = ""
    expires_at: str = ""

    def canonical_form(self) -> dict[str, Any]:
        return {
            "decision_need_id": self.decision_need_id, "capability": self.capability.value,
            "answer": self.answer, "metrics": self.metrics, "confidence": self.confidence,
            "evidence_event_ids": list(self.evidence_event_ids),
            "provider_receipts": [r.canonical_form() for r in self.provider_receipts],
            "assumptions": list(self.assumptions), "unresolved_gaps": list(self.unresolved_gaps),
            "total_cost": self.total_cost, "tenant": self.tenant, "as_of": self.as_of,
            "known_at": self.known_at, "produced_at": self.produced_at, "expires_at": self.expires_at,
        }

    def fingerprint(self) -> str:
        """Stable replay fingerprint of the whole result (§3)."""
        return content_hash(self.canonical_form())

    identity = fingerprint

    def is_expired(self, now_iso: str) -> bool:
        return bool(self.expires_at) and now_iso >= self.expires_at

    def is_decision_grade(self, need: "DecisionNeed") -> bool:
        """The answer clears the need's confidence bar and left no unresolved gaps."""
        return need.meets_confidence(self.confidence) and not self.unresolved_gaps

    @staticmethod
    def from_artifacts(need: "DecisionNeed", artifacts: tuple["EvidenceArtifact", ...],
                       receipts: tuple["ProviderReceipt", ...], *, answer: str, confidence: float,
                       metrics: Optional[dict[str, Any]] = None, assumptions: tuple[str, ...] = (),
                       unresolved_gaps: tuple[str, ...] = (), produced_at: str = "",
                       expires_at: str = "") -> "IntelligenceResult":
        """Aggregate the artifacts + receipts of resolving a need into one result. Lineage and total spend
        are derived from the inputs so they can never silently disagree with the receipts."""
        return IntelligenceResult(
            decision_need_id=need.identity(), capability=need.capability, answer=answer,
            metrics=dict(metrics or {}), confidence=confidence,
            evidence_event_ids=tuple(a.identity() for a in artifacts), provider_receipts=tuple(receipts),
            assumptions=tuple(assumptions), unresolved_gaps=tuple(unresolved_gaps),
            total_cost=round(sum(r.cost for r in receipts), 6), tenant=need.tenant,
            as_of=need.as_of, known_at=need.known_at, produced_at=produced_at, expires_at=expires_at,
        )


# ── provider health (optional, non-breaking seam) ─────────────────────────────────────────────────────────
class HealthStatus(str, Enum):
    OK = "ok"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"            # provider does not report health


@dataclass(frozen=True)
class ProviderHealth:
    provider: str
    status: HealthStatus = HealthStatus.UNKNOWN
    detail: str = ""
    checked_at: str = ""
    latency_ms: float = 0.0

    @property
    def usable(self) -> bool:
        # UNKNOWN is treated as usable — a provider that simply doesn't report health is not "down".
        return self.status in (HealthStatus.OK, HealthStatus.DEGRADED, HealthStatus.UNKNOWN)

    def canonical_form(self) -> dict[str, Any]:
        return {"provider": self.provider, "status": self.status.value, "detail": self.detail,
                "checked_at": self.checked_at, "latency_ms": self.latency_ms}


@runtime_checkable
class SupportsHealth(Protocol):
    """Optional capability an IntelligenceProvider MAY implement so the broker can route around outages.
    Kept separate from IntelligenceProvider so existing adapters remain conformant without a health()."""
    provider_id: str
    def health(self) -> ProviderHealth: ...


def provider_health(provider: Any) -> ProviderHealth:
    """Health of a provider, degrading gracefully: UNKNOWN (still usable) when it implements no health()."""
    pid = getattr(provider, "provider_id", "?")
    if isinstance(provider, SupportsHealth):
        try:
            return provider.health()
        except Exception as exc:  # a health probe must never take down the broker
            return ProviderHealth(pid, HealthStatus.UNAVAILABLE, detail=f"health() raised: {exc!r}")
    return ProviderHealth(pid, HealthStatus.UNKNOWN, detail="no health() implemented")


__all__ = [
    "INTELLIGENCE_CONTRACT_VERSION", "Capability", "PII_CAPABILITIES", "is_legal", "ProviderFamily",
    "Sensitivity", "AcquisitionFailure", "PlannerFallback", "LegalAuthorityLevel", "may_auto_execute",
    "requires_professional_review", "EvidenceRequest", "CostEstimate", "EvidenceArtifact",
    "LegalEvidenceArtifact", "AcquisitionResult", "IntelligenceProvider", "ExternalDataProvider",
    "ProfessionalIntelligenceProvider", "EvidenceValueRecord",
    "DecisionNeed", "ProviderReceipt", "IntelligenceResult",
    "HealthStatus", "ProviderHealth", "SupportsHealth", "provider_health",
]
