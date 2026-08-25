"""WorldEvent — the canonical entry point of a dataset world into the runtime stack.

A dataset world (FinanceBench, GLEIF/OpenSanctions, a government parcel snapshot, live GitHub/HN signals,
CrowdSec telemetry, τ-bench trajectories, a synthetic call transcript …) enters the stack as a stream of
:class:`WorldEvent`s. One event carries a *source record* — its canonical entity identities, its evidence
(by content-addressed reference, never a copy), its realism class, its permissions/tenant scope, its
optional ground truth, and the capabilities it may require — through Discovery → Planner → Mission →
Context → app capabilities **without losing identity or provenance**.

This replaces the old "fictional tenant" demo object: the same conceptual person/company/invoice/property
keeps one canonical identity as the mission crosses CRM, support, billing, security. Realism is explicit
(:class:`RealismClass`) so a seeded-demo record is never presented as a live customer's data.

Identity follows the package rule (``canonical.py``): the event *is* its content, so its semantic fields
participate in its hash; ``known_at`` (ingest time) and the optimizer hints (cost/latency/freshness) are
chain-of-custody / runtime metadata and are excluded from identity.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from enum import Enum
from typing import Any, Dict, Optional, Tuple

from ..canonical import content_hash
from ..protocol.evidence import EvidenceRef


class RealismClass(str, Enum):
    """How real the data behind an event is — the audit vocabulary, now a first-class contract so every
    evidence surface can label itself and no seeded record is mistaken for a live customer's."""
    REAL_LIVE = "REAL-LIVE"            # read live from an external / OSS system at request time
    REAL_SNAPSHOT = "REAL-SNAPSHOT"    # real public data, committed / downloaded as a file
    SEEDED_DEMO = "SEEDED-DEMO"        # a live OSS core serving seeded fictional data
    SYNTHETIC = "SYNTHETIC"            # deterministically generated, realistic data
    CANNED = "CANNED"                  # values hard-coded inline
    STUB = "STUB"                      # the action path performs no real write
    SIMULATED = "SIMULATED"            # deterministic / LLM logic, no data backend


#: Canonical business-object kinds a world entity can be (the shared semantics; vendor-specific fields ride
#: along as typed extensions in the payload, never forced into one universal schema).
class EntityKind(str, Enum):
    ORGANIZATION = "organization"; PERSON = "person"; EMPLOYEE = "employee"; CUSTOMER = "customer"
    ACCOUNT = "account"; CONTACT = "contact"; OPPORTUNITY = "opportunity"; CONTRACT = "contract"
    SUBSCRIPTION = "subscription"; INVOICE = "invoice"; PAYMENT = "payment"; EXPENSE = "expense"
    LEDGER_ENTRY = "ledger_entry"; TICKET = "ticket"; CONVERSATION = "conversation"; DOCUMENT = "document"
    ASSET = "asset"; IDENTITY = "identity"; PERMISSION = "permission"; FINDING = "finding"
    INCIDENT = "incident"; DEPLOYMENT = "deployment"; REPOSITORY = "repository"; SERVICE = "service"
    PROPERTY = "property"; VENDOR = "vendor"; PRODUCT = "product"; TASK = "task"; APPROVAL = "approval"


#: Known world event types (free-form for forward compatibility — a new type never forces a contract bump).
LEAD_RECEIVED = "lead.received"
TICKET_OPENED = "ticket.opened"
INVOICE_OVERDUE = "invoice.overdue"
USAGE_CHANGED = "usage.changed"
THREAT_DETECTED = "threat.detected"
SIGNAL_OBSERVED = "signal.observed"
ONBOARDING_REQUESTED = "onboarding.requested"
DEPLOYMENT_EVENT = "deployment.event"
KNOWN_EVENT_TYPES = frozenset({
    LEAD_RECEIVED, TICKET_OPENED, INVOICE_OVERDUE, USAGE_CHANGED, THREAT_DETECTED,
    SIGNAL_OBSERVED, ONBOARDING_REQUESTED, DEPLOYMENT_EVENT,
})


@dataclass(frozen=True)
class EntityRef:
    """A canonical entity identity carried across every app projection. ``entity_id`` is the stable logical
    id the Identity Graph maps to each system's native id; ``kind`` is a canonical business object."""
    entity_id: str
    kind: str = EntityKind.ORGANIZATION.value
    label: str = ""

    def canonical_form(self) -> Dict[str, Any]:
        return {"entity_id": self.entity_id, "kind": self.kind, "label": self.label or None}

    def ref(self) -> str:
        return content_hash(self.canonical_form())


@dataclass(frozen=True)
class GroundTruth:
    """The benchmarkable expectation for an event: what the situation is, the safe/unsafe actions, and the
    target outcome. Present only for worlds with ground truth; drives baselines + scorecards."""
    situation: str = ""
    safe_action: str = ""
    unsafe_action: str = ""
    target_outcome: str = ""

    def canonical_form(self) -> Dict[str, Any]:
        return {k: v for k, v in {
            "situation": self.situation, "safe_action": self.safe_action,
            "unsafe_action": self.unsafe_action, "target_outcome": self.target_outcome}.items() if v}


@dataclass(frozen=True)
class WorldEvent:
    """One source record entering the runtime as a governed, content-addressed event."""

    world_id: str
    dataset_id: str
    source_record_id: str
    event_type: str
    entity_ids: Tuple[EntityRef, ...] = ()
    observed_at: str = ""                       # valid-time: when observed in the source
    effective_at: str = ""                      # valid-time: when it takes effect
    known_at: str = ""                          # ingest-time (chain-of-custody; excluded from identity)
    evidence_refs: Tuple[EvidenceRef, ...] = ()  # content-addressed evidence (never a copy)
    content_hash: str = ""                      # rcv1 hash of the source payload (self-pinning)
    classification: str = RealismClass.SYNTHETIC.value
    data_classifications: Tuple[str, ...] = ()
    permissions: Tuple[str, ...] = ()
    tenant: str = ""
    ground_truth: Optional[GroundTruth] = None
    capability_requirements: Tuple[str, ...] = ()
    cost_hint: Optional[Decimal] = None         # optimizer metadata — excluded from identity
    latency_ms_hint: int = 0
    freshness_s: int = 0
    scenario_seed: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        ch = self.content_hash or (content_hash(self.payload) if self.payload else "")
        object.__setattr__(self, "content_hash", ch)

    def canonical_form(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "world_id": self.world_id, "dataset_id": self.dataset_id,
            "source_record_id": self.source_record_id, "event_type": self.event_type,
            "classification": self.classification,
        }
        if self.entity_ids:
            d["entity_ids"] = [e.canonical_form() for e in self.entity_ids]
        if self.observed_at:
            d["observed_at"] = self.observed_at
        if self.effective_at:
            d["effective_at"] = self.effective_at
        if self.evidence_refs:
            d["evidence_refs"] = [r.canonical_form() for r in self.evidence_refs]
        if self.content_hash:
            d["content_hash"] = self.content_hash
        if self.data_classifications:
            d["data_classifications"] = sorted(self.data_classifications)
        if self.ground_truth is not None:
            d["ground_truth"] = self.ground_truth.canonical_form()
        if self.capability_requirements:
            d["capability_requirements"] = sorted(self.capability_requirements)
        if self.scenario_seed:
            d["scenario_seed"] = self.scenario_seed
        return d

    def identity(self) -> str:
        """The ``rcv1:`` content hash of the event's semantic identity — stable across the whole stack, so
        provenance is verifiable at any hop (Discovery → Mission → Context → capability)."""
        return content_hash(self.canonical_form())

    def entity(self, kind: str) -> Optional[EntityRef]:
        """The first carried entity of ``kind`` (e.g. the customer, or the invoice), or None."""
        return next((e for e in self.entity_ids if e.kind == kind), None)

    def realism(self) -> RealismClass:
        return RealismClass(self.classification)
