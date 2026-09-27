"""EvidenceEnvelope — the persisted row shape, and the projection from canonical events onto it.

The Historical Evidence Plane persists the *whole* runtime lifecycle, not just security. Every
persisted row is an :class:`EvidenceEnvelope`: a small set of first-class **identity** columns that
support causal traversal, bitemporal reconstruction, dedup and tamper verification *without decoding
the payload*, plus a content-addressed reference to the canonical artifact itself.

Two identities, kept separate on purpose (mirroring ``protocol/evidence.py``):

* **event identity** — ``event_id`` (the runtime's id for *this occurrence*), plus the causal columns
  (``parent_event_id`` / ``causation_id`` / ``correlation_id``) that let you walk a trajectory.
* **artifact identity** — ``content_hash`` (the ``rcv1:`` hash of the canonical payload) and
  ``payload_ref`` (the content-addressed handle). Equal content hash ⇒ the same artifact regardless of
  which event referenced it.

Bitemporality is explicit: ``event_time`` is *valid-time* (when the thing happened) and ``known_at`` is
*ingest-time* (when the plane learned it). ``known_at`` is chain-of-custody — it is **excluded from the
row's canonical identity**, the same way ``observed_at`` is excluded on ``ArtifactHandle``.

`project()` is the **persistence projection layer**: an explicit mapping from a versioned protocol
object onto an envelope. It is deliberately *not* a mechanical dataclass→table generator — persistence
layout must be free to evolve (flatten, normalize, keep old ``contract_version`` rows) without being
chained to every protocol edit.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Dict, Mapping, Optional

from ..canonical import content_hash

#: The canonical lifecycle families the plane can persist. A deployment need not enable every one;
#: naming them here means every backend spells them the same way. This is what lets the plane answer
#: "what did the system know, decide, authorize, execute and observe?" rather than being a security log.
EVIDENCE_FAMILIES = (
    "mission_events",
    "discovery_evidence",
    "verified_intents",
    "plan_artifacts",
    "context_decisions",
    "capability_events",
    "security_events",
    "governance_dispositions",
    "approvals",
    "execution_events",
    "reconciliation_results",
    "trace_spans",
    "policy_versions",
)


@dataclass(frozen=True)
class EvidenceEnvelope:
    """One persisted row: identity columns + a content-addressed canonical payload.

    The identity columns are queryable and traversable on their own; ``payload`` carries the canonical
    artifact (its ``rcv1:`` hash is ``content_hash``). ``known_at`` is ingest-time chain-of-custody and
    does not participate in ``identity()``."""

    event_id: str
    event_type: str
    family: str = "mission_events"
    tenant_id: str = ""
    artifact_id: str = ""
    mission_id: str = ""
    trace_id: str = ""
    parent_event_id: str = ""
    causation_id: str = ""
    correlation_id: str = ""
    contract_version: str = ""
    event_time: str = ""            # valid-time: when it happened
    known_at: str = ""              # ingest-time: when the plane learned it (chain-of-custody)
    content_hash: str = ""          # "rcv1:…" hash of the canonical payload
    payload_ref: str = ""           # content-addressed handle to the artifact (defaults to content_hash)
    payload: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Fill content addressing from the payload when not supplied — the row is self-pinning.
        ch = self.content_hash or (content_hash(self.payload) if self.payload else "")
        object.__setattr__(self, "content_hash", ch)
        if not self.payload_ref:
            object.__setattr__(self, "payload_ref", ch)
        if not self.event_id:
            object.__setattr__(self, "event_id", ch)

    # -- identity (excludes known_at; that is chain-of-custody) --
    def canonical_form(self) -> Dict[str, Any]:
        return {
            "artifact_id": self.artifact_id or None,
            "causation_id": self.causation_id or None,
            "content_hash": self.content_hash or None,
            "contract_version": self.contract_version or None,
            "correlation_id": self.correlation_id or None,
            "event_id": self.event_id,
            "event_time": self.event_time or None,
            "event_type": self.event_type,
            "family": self.family,
            "mission_id": self.mission_id or None,
            "parent_event_id": self.parent_event_id or None,
            "payload_ref": self.payload_ref or None,
            "tenant_id": self.tenant_id or None,
            "trace_id": self.trace_id or None,
        }

    def identity(self) -> str:
        """The ``rcv1:`` content hash of the row's identity columns (payload aside)."""
        return content_hash(self.canonical_form())

    def verify_payload(self) -> bool:
        """True iff the stored ``content_hash`` still matches the payload — tamper check."""
        return not self.payload or self.content_hash == content_hash(self.payload)

    #: Flat columns for a relational/columnar row — everything except the (opaque) payload dict.
    def row(self) -> Dict[str, Any]:
        r = {k: v for k, v in self.__dict__.items() if k != "payload"}
        return r

    def to_json(self) -> Dict[str, Any]:
        return dict(self.__dict__)

    @classmethod
    def from_json(cls, d: Mapping[str, Any]) -> "EvidenceEnvelope":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})

    def with_known_at(self, known_at: str) -> "EvidenceEnvelope":
        return replace(self, known_at=known_at)


def _payload_of(event: Any) -> Dict[str, Any]:
    """The canonical payload of a protocol object — its ``canonical_form()`` if it has one."""
    cf = getattr(event, "canonical_form", None)
    if callable(cf):
        return cf()
    if isinstance(event, Mapping):
        return dict(event)
    raise TypeError(f"cannot project {type(event).__name__}: no canonical_form() and not a mapping")


def project(
    event: Any,
    *,
    family: Optional[str] = None,
    tenant_id: str = "",
    contract_version: str = "",
    event_type: Optional[str] = None,
) -> EvidenceEnvelope:
    """Project a versioned protocol object (or a plain mapping) onto an :class:`EvidenceEnvelope`.

    Recognises the runtime's canonical event shapes and maps their identity fields onto columns; any
    other mapping is persisted generically under ``family`` (default ``mission_events``). This is the
    one place that knows a protocol object's layout — keep the coupling here, not in the backends."""
    g = lambda name, default="": getattr(event, name, default)
    payload = _payload_of(event)
    cls = type(event).__name__

    if cls == "RuntimeSecurityEvent":
        return EvidenceEnvelope(
            event_id=g("event_id"),
            event_type=event_type or str(g("event_type")),
            family=family or "security_events",
            tenant_id=tenant_id or getattr(g("principal", None), "tenant", "") or "",
            mission_id=g("mission_id"),
            parent_event_id=g("parent_event_id"),
            causation_id=g("causal_id"),
            contract_version=contract_version,
            event_time=g("occurred_at"),
            payload=payload,
        )
    if cls == "SecurityDecision":
        return EvidenceEnvelope(
            event_id="",  # decisions are content-addressed
            event_type=event_type or "security_decision",
            family=family or "security_events",
            tenant_id=tenant_id,
            artifact_id=g("resource"),
            contract_version=contract_version,
            payload=payload,
        )
    if cls == "GovernanceDisposition" or cls == "TrajectoryDisposition":
        return EvidenceEnvelope(
            event_id="",
            event_type=event_type or "governance_disposition",
            family=family or "governance_dispositions",
            tenant_id=tenant_id,
            contract_version=contract_version,
            payload=payload,
        )
    if cls == "TraceContext":
        return EvidenceEnvelope(
            event_id=g("span_id"),
            event_type=event_type or "trace_span",
            family=family or "trace_spans",
            tenant_id=tenant_id,
            mission_id=g("mission_id"),
            trace_id=g("trace_id"),
            parent_event_id=g("parent_span_id"),
            contract_version=contract_version,
            payload=payload,
        )

    # Generic mapping / unknown protocol object → persisted under the requested (or default) family.
    return EvidenceEnvelope(
        event_id=str(payload.get("event_id", "")),
        event_type=event_type or str(payload.get("event_type", cls)),
        family=family or "mission_events",
        tenant_id=tenant_id or str(payload.get("tenant_id", "")),
        mission_id=str(payload.get("mission_id", "")),
        trace_id=str(payload.get("trace_id", "")),
        parent_event_id=str(payload.get("parent_event_id", "")),
        correlation_id=str(payload.get("correlation_id", "")),
        contract_version=contract_version,
        event_time=str(payload.get("event_time", payload.get("occurred_at", ""))),
        payload=payload,
    )
