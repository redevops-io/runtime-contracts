"""The open storage seam — capabilities, not a table format.

``EvidenceStore`` is the entire public contract for persistence. It expresses **what** the Historical
Evidence Plane can do, never **how** it is stored: the AGPL runtime ships a file-level reference
implementation behind this same interface, and an Enterprise plugin can implement it over Iceberg/S3,
Hudi, Delta, a managed relational database, or a warehouse — all interchangeable, none named here. This
is the concrete form of the architecture statement *"ReDevOps is not a lakehouse; it can govern one as
a storage capability."*

The six capabilities:

* ``append(envelope)``   — persist one canonical event; returns its ``event_id``.
* ``resolve(ref)``       — fetch one row by ``event_id`` or ``content_hash`` (or a ``…#hash`` pin).
* ``snapshot(as_of)``    — the plane as it was *known* at an ingest instant (bitemporal replay).
* ``changes(since)``     — the incremental feed: everything learned strictly after a cursor.
* ``scan(predicate,…)``  — filter by identity-column equality and/or a valid-time range.
* ``verify(ref)``        — recompute the payload hash and confirm the row is untampered.

A ``predicate`` is a plain mapping of ``column -> value`` equality filters over the identity columns —
storage-neutral by construction: a SQL backend turns it into ``WHERE``, the file backend filters in
memory. Nothing here assumes a query language.
"""
from __future__ import annotations

from typing import Any, Iterator, Mapping, Optional, Protocol, Tuple, runtime_checkable

from .envelope import EvidenceEnvelope

#: A storage-neutral filter: exact-match on identity columns (e.g. ``{"family": "security_events",
#: "mission_id": "m-1"}``). Every backend can honour equality; richer predicates stay backend-specific.
Predicate = Mapping[str, Any]

#: An inclusive valid-time window ``(from_iso, to_iso)``; either end may be ``""`` for open.
TimeRange = Tuple[str, str]


@runtime_checkable
class EvidenceStore(Protocol):
    """The open persistence capability. Storage-neutral; implementations are injected, never imported."""

    def append(self, envelope: EvidenceEnvelope) -> str:
        """Persist one canonical event. Returns its ``event_id``. Append-only — never mutates."""
        ...

    def resolve(self, ref: str) -> Optional[EvidenceEnvelope]:
        """Fetch one row by ``event_id``, ``content_hash``, or a ``ref@version#hash`` pin. ``None`` if absent."""
        ...

    def snapshot(self, as_of: str) -> Iterator[EvidenceEnvelope]:
        """Every row whose ``known_at`` is ``<= as_of`` — the plane as known at that ingest instant."""
        ...

    def changes(self, since: str) -> Iterator[EvidenceEnvelope]:
        """Every row whose ``known_at`` is ``> since`` — the incremental change feed."""
        ...

    def scan(self, predicate: Optional[Predicate] = None, *, time_range: Optional[TimeRange] = None) -> Iterator[EvidenceEnvelope]:
        """Rows matching every ``predicate`` equality and (optionally) with ``event_time`` in ``time_range``."""
        ...

    def verify(self, ref: str) -> bool:
        """True iff the row resolves and its payload still hashes to the stored ``content_hash``."""
        ...
