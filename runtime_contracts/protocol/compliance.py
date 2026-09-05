"""ControlEvidence — the canonical, content-addressed evidence a control was satisfied.

Compliance is a *projection over the Runtime's existing truth*, not a second source of truth. The
open Runtime already produces the facts — mission events, governance decisions, security telemetry,
approvals, execution envelopes, verification outcomes, evidence lineage. This contract is the one
shape those streams are projected INTO so an (Enterprise) compliance engine can map them onto any
framework's controls without each integration inventing its own evidence model.

Division of responsibility (matches the AGPL-base / Enterprise split):
  * **Base (this contract + producers)** — emits ``ControlEvidence`` from what actually happened.
  * **Enterprise** — the ``Control`` catalog, framework mappings (EU AI Act / NIST AI RMF / ISO
    42001 …), continuous assessment, and reporting that *consume* this evidence.

``evidence_id`` is the content hash of the canonical form, so evidence is tamper-evident and
de-duplicable exactly like :class:`~..models.evidence.EvidenceRef` / an ``ExecutionEnvelope``.

The status vocabulary is deliberately explicit so a dashboard can never claim "97% compliant":
a control is ENFORCED (the runtime actively guarantees it), EVIDENCED (evidence supports it),
EXTERNAL_EVIDENCE_REQUIRED (an organizational fact must be supplied), NOT_APPLICABLE (scoped out),
or UNVERIFIED (no sufficient evidence).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Sequence, Tuple

try:  # match the import style used across protocol/ (falls back to the seal helper)
    from ..canonical import content_hash
except Exception:  # pragma: no cover
    from .seal import content_hash  # type: ignore

CONTRACT_VERSION = "control-evidence/v1"


class ControlStatus(str, Enum):
    """How well a control is substantiated. Never collapse these into a single percentage."""

    ENFORCED = "enforced"                              # the runtime actively guarantees it
    EVIDENCED = "evidenced"                            # the runtime holds evidence supporting it
    EXTERNAL_EVIDENCE_REQUIRED = "external_evidence_required"  # an organizational fact is needed
    NOT_APPLICABLE = "not_applicable"                  # scoped out by an applicability assessment
    UNVERIFIED = "unverified"                          # no sufficient evidence


class RuntimeStream(str, Enum):
    """Canonical names for the runtime streams a base producer projects into ``ControlEvidence``.

    This is the shared seam between the AGPL base (which emits ``ControlEvidence`` tagged with one of
    these on ``control_id``) and the Enterprise ``Control`` catalog (whose evidence requirements name
    the same strings), so neither side has to hard-code the other's identifiers. These are the
    runtime's *own* truth streams — not regulatory controls; the Enterprise engine maps a stream onto
    whatever framework controls it bears on. The values match the runtime-truth streams called out in
    this module's docstring plus capability inventory and model identity.
    """

    DURABLE_EVENT_LEDGER = "durable_event_ledger"          # append-only, hash-linked mission event log
    HITL_APPROVAL = "hitl_approval"                        # human decisions on parked tasks
    AUTHORITY_GRANT = "authority_grant"                    # governance authority grants/decisions
    EXECUTION_ENVELOPE = "execution_envelope"              # containment envelopes/receipts (membrane)
    VERIFICATION_RECEIPT = "verification_receipt"          # verification-ladder outcomes
    CAPABILITY_MANIFEST = "capability_manifest"            # registered capability/operator inventory
    EVIDENCE_LINEAGE = "evidence_lineage"                  # EvidenceRef provenance/lineage
    MODEL_VERSION_LOCK = "model_version_lock"              # pinned model/provider identity
    DATA_FLOW_CLASSIFICATION = "data_flow_classification"  # data-flow / PII classification
    RISK_ASSESSMENT = "risk_assessment"                    # recorded risk assessments


@dataclass(frozen=True)
class ControlEvidence:
    """One piece of evidence, projected from the runtime, that bears on a control for a subject."""

    control_id: str
    subject: str                                       # what the evidence is about (tenant/system/…)
    status: ControlStatus = ControlStatus.UNVERIFIED
    mission_id: str = ""
    event_ids: Tuple[str, ...] = ()                    # ledger events this evidence derives from
    artifact_refs: Tuple[str, ...] = ()                # EvidenceRef ids / artifact pins
    collector: str = ""                                # who projected it (e.g. "governance", "membrane")
    observed_at: str = ""                              # RFC3339/epoch string
    valid_from: str = ""
    valid_until: str = ""                              # empty ⇒ no stated expiry
    verification: str = ""                             # a verification ref/outcome, when applicable
    contract_version: str = CONTRACT_VERSION

    def canonical_form(self) -> Dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "control_id": self.control_id,
            "subject": self.subject,
            "status": self.status.value,
            "mission_id": self.mission_id,
            "event_ids": sorted(self.event_ids),
            "artifact_refs": sorted(self.artifact_refs),
            "collector": self.collector,
            "observed_at": self.observed_at,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "verification": self.verification,
        }

    @property
    def evidence_id(self) -> str:
        """Content-addressed identity ("rcv1:…") — any changed field yields a new id."""
        return content_hash(self.canonical_form())


class ControlEvidenceCollector:
    """Seam: something that projects runtime truth into ControlEvidence for one control.

    A ``Protocol`` by shape (not inherited): base producers implement it over the ledger/telemetry,
    and the Enterprise engine consumes whatever collectors are registered. Kept dependency-free so
    the contract carries no runtime imports.
    """

    control_id: str

    def collect(self, *, subject: str) -> Sequence[ControlEvidence]:  # pragma: no cover - shape only
        ...
