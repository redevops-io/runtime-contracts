"""The Historical Evidence Plane storage seam — open interface, reference floor, pluggable backends.

Operational truth (the Hot Ledger the runtime runs its gates/replay against) and *historical* truth
(this durable system of record) are different planes; this package is only the second, and it never
sits in a synchronous decision path. The open runtime ships the interface plus a file-level floor;
Enterprise supplies the durable, streaming, warehouse-scale backends behind the same interface.

* :class:`EvidenceStore`     — the six-capability open seam (append/resolve/snapshot/changes/scan/verify).
* :class:`EvidenceEnvelope`  — the persisted row: first-class identity columns + content-addressed payload.
* :func:`project`            — the persistence projection layer (versioned protocol object -> envelope).
* :data:`EVIDENCE_FAMILIES`  — the canonical lifecycle families the plane can persist.
* :func:`open_store` / :func:`register_backend` — the pluggable backend registry.
"""
from __future__ import annotations

from .base import EvidenceStore, Predicate, TimeRange
from .envelope import EVIDENCE_FAMILIES, EvidenceEnvelope, project
from .file import FileEvidenceStore, InMemoryEvidenceStore
from .registry import available_backends, open_store, register_backend

__all__ = [
    "EvidenceStore",
    "Predicate",
    "TimeRange",
    "EvidenceEnvelope",
    "project",
    "EVIDENCE_FAMILIES",
    "FileEvidenceStore",
    "InMemoryEvidenceStore",
    "open_store",
    "register_backend",
    "available_backends",
]
