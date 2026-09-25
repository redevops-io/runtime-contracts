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


__all__ = [
    "INTELLIGENCE_CONTRACT_VERSION", "Capability", "PII_CAPABILITIES", "is_legal", "ProviderFamily",
    "Sensitivity", "AcquisitionFailure", "PlannerFallback", "LegalAuthorityLevel", "may_auto_execute",
    "requires_professional_review", "EvidenceRequest", "CostEstimate", "EvidenceArtifact",
    "LegalEvidenceArtifact", "AcquisitionResult", "IntelligenceProvider", "ExternalDataProvider",
    "ProfessionalIntelligenceProvider", "EvidenceValueRecord",
]
