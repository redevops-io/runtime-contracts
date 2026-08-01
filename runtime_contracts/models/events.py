"""RuntimeEvent — one envelope, so a trajectory can be replayed.

Every runtime emits events. Without one envelope they cannot be ordered,
correlated across a subagent boundary, or replayed — and "what did the model
actually see, in what order?" becomes unanswerable exactly when it matters.

Ordering is **physical and explicit**: a monotonic `sequence` per stream, not a
wall-clock timestamp. Two events emitted in the same millisecond on different
hosts have no reliable order otherwise, and reconstructing a trajectory from
timestamps is how a replay silently reorders itself.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Sequence

from ..canonical import CONTRACT_VERSION, content_hash
from .visibility import AuthorizationOutcome, Visibility


class EventKind(str, Enum):
    DEREFERENCE = "DEREFERENCE"
    CONTEXT_PLANNED = "CONTEXT_PLANNED"
    CONTEXT_MATERIALIZED = "CONTEXT_MATERIALIZED"
    CAPABILITY_INVOKED = "CAPABILITY_INVOKED"
    CAPABILITY_COMPLETED = "CAPABILITY_COMPLETED"
    MISSION_TRANSITION = "MISSION_TRANSITION"
    INVESTIGATION_TRANSITION = "INVESTIGATION_TRANSITION"
    VERIFICATION = "VERIFICATION"


class Intent(str, Enum):
    """Whether an event records something done or something offered.

    A proposal that reads like a completed action is the difference between a
    system that suggested a trade and one that placed it.
    """

    PROPOSED = "PROPOSED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


@dataclass(frozen=True)
class RuntimeEvent:
    """The canonical envelope. Every runtime emits this shape."""

    event_id: str
    kind: EventKind
    intent: Intent
    stream_id: str
    sequence: int
    """Monotonic within `stream_id`. Physical ordering, not a clock reading."""

    emitted_by: str
    payload: Mapping[str, Any] = field(default_factory=dict)
    parent_event_id: Optional[str] = None
    root_stream_id: Optional[str] = None
    """Set on a subagent stream so a child trajectory reattaches to its parent."""

    visibility: Visibility = Visibility.INTERNAL
    tenant_id: Optional[str] = None
    evidence_refs: Sequence[str] = ()
    emitted_at: Optional[str] = None
    schema_version: str = CONTRACT_VERSION

    def __post_init__(self) -> None:
        if self.sequence < 0:
            raise ValueError("sequence must be monotonic and non-negative")

    def canonical_form(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "kind": self.kind.value,
            "intent": self.intent.value,
            "stream_id": self.stream_id,
            "sequence": self.sequence,
            "emitted_by": self.emitted_by,
            "parent_event_id": self.parent_event_id,
            "root_stream_id": self.root_stream_id,
            "visibility": self.visibility.value,
            "tenant_id": self.tenant_id,
            "evidence_refs": sorted(self.evidence_refs),
            "payload": dict(self.payload),
            # event_id and emitted_at are excluded: one is an identifier the
            # emitter chose, the other a clock reading. Neither changes what
            # happened, and both would make a replayed event hash differently.
        }

    @property
    def event_hash(self) -> str:
        return content_hash(self.canonical_form())

    def to_json(self) -> Dict[str, Any]:
        return {**self.canonical_form(), "event_id": self.event_id,
                "event_hash": self.event_hash, "emitted_at": self.emitted_at}


@dataclass(frozen=True)
class DereferenceEvent:
    """One handle expanded, or refused.

    Recorded whether or not it succeeded. A refusal that leaves no trace makes a
    working set look complete when something was withheld from it.
    """

    handle_hash: str
    artifact_id: str
    projection: str
    outcome: AuthorizationOutcome
    returned_content_hash: Optional[str] = None
    tokens_materialized: Optional[int] = None
    reason: str = ""

    def canonical_form(self) -> Dict[str, Any]:
        return {
            "handle_hash": self.handle_hash,
            "artifact_id": self.artifact_id,
            "projection": self.projection,
            "outcome": self.outcome.value,
            "returned_content_hash": self.returned_content_hash,
        }

    def as_event(self, *, event_id: str, stream_id: str, sequence: int,
                 emitted_by: str) -> RuntimeEvent:
        return RuntimeEvent(
            event_id=event_id, kind=EventKind.DEREFERENCE,
            intent=(Intent.COMPLETED if self.outcome.granted else Intent.FAILED),
            stream_id=stream_id, sequence=sequence, emitted_by=emitted_by,
            payload=self.canonical_form(), evidence_refs=(self.artifact_id,),
        )


def replay(events: Sequence[RuntimeEvent]) -> list:
    """Order a stream the way it happened.

    By `(stream_id, sequence)` and never by timestamp — see the module docstring.
    A gap in the sequence is returned as-is rather than closed: a replay that
    silently renumbers cannot report that an event is missing.
    """
    return sorted(events, key=lambda e: (e.stream_id, e.sequence))


def missing_sequences(events: Sequence[RuntimeEvent]) -> Dict[str, list]:
    """Gaps per stream — events that were emitted and did not arrive."""
    by_stream: Dict[str, list] = {}
    for event in events:
        by_stream.setdefault(event.stream_id, []).append(event.sequence)
    gaps = {}
    for stream, seqs in by_stream.items():
        ordered = sorted(seqs)
        expected = set(range(ordered[0], ordered[-1] + 1))
        missing = sorted(expected - set(ordered))
        if missing:
            gaps[stream] = missing
    return gaps
