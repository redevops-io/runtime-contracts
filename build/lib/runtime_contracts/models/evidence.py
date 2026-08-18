"""The RAG → context boundary.

    ReDevOps RAG finds candidates.  Context Runtime decides what enters.

`EvidenceCandidate` is what retrieval returns: enough for a planner to judge an
item without fetching it, and explicitly *not* a context. A consumer that treats
a ranked list as final prompt text has skipped the only step where authorization,
budget and provenance are applied.

**Retrieval score is not part of handle identity.** Re-ranking changes which
evidence is chosen; it does not change what a piece of evidence *is*. Putting the
score in the handle would make every ranker change look like the corpus changed,
and would make a ContextView irreproducible across ranker versions for no reason
that concerns the reader.

The same split runs through `ContextView`: the **declaration** is canonical and
hashed, the **materialization record** is what one fetch happened to cost. Two
runs that assembled the same working set are the same view even if one was
served from cache and the other took four seconds.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Sequence

from ..canonical import content_hash
from .handle import ArtifactHandle, Freshness
from .visibility import AuthorizationOutcome, Tenancy, Visibility


class CandidateRejected(ValueError):
    """A retrieval candidate cannot become a handle.

    Raised rather than degraded. A "best effort" anonymous handle is one that
    cannot be re-resolved, which makes the working set unreproducible — and an
    unreproducible working set is indistinguishable from a fabricated one.
    """


@dataclass(frozen=True)
class EvidenceCandidate:
    """One retrieval result, judgeable before it is fetched."""

    candidate_id: str
    source_artifact_id: str
    """Version-pinned. An unpinned id resolves to whatever is latest at fetch
    time, and replay would then return a different working set."""

    artifact_kind: str
    artifact_content_hash: str
    projection: str
    authority: str
    visibility: Visibility
    tenant_id: Optional[str] = None
    freshness: Freshness = Freshness.UNKNOWN
    retrieval_score: Optional[str] = None
    """A decimal string, and deliberately outside handle identity."""

    retrieval_reason: str = ""
    estimated_tokens: Optional[int] = None

    def to_json(self) -> Dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "source_artifact_id": self.source_artifact_id,
            "artifact_kind": self.artifact_kind,
            "artifact_content_hash": self.artifact_content_hash,
            "projection": self.projection,
            "authority": self.authority,
            "visibility": self.visibility.value,
            "tenant_id": self.tenant_id,
            "freshness": self.freshness.value,
            "retrieval_score": self.retrieval_score,
            "retrieval_reason": self.retrieval_reason,
            "estimated_tokens": self.estimated_tokens,
        }


#: Everything a candidate must carry to become a resolvable handle. Missing any
#: of these means the artifact could not be fetched again later, so the
#: candidate is refused at the boundary rather than producing a handle that
#: fails at materialization.
REQUIRED_CANDIDATE_FIELDS = (
    "source_artifact_id", "artifact_kind", "artifact_content_hash",
    "projection", "authority",
)


def candidate_to_handle(candidate: EvidenceCandidate) -> ArtifactHandle:
    """Map a retrieval candidate onto a canonical handle, or refuse it."""
    missing = [
        name for name in REQUIRED_CANDIDATE_FIELDS
        if not getattr(candidate, name, None)
    ]
    if missing:
        raise CandidateRejected(
            f"candidate {candidate.candidate_id!r} is missing {missing}. A "
            "handle without these cannot be resolved again, and a working set "
            "that cannot be re-resolved cannot be replayed"
        )
    if "@" not in candidate.source_artifact_id:
        raise CandidateRejected(
            f"candidate {candidate.candidate_id!r} names an unpinned artifact "
            f"{candidate.source_artifact_id!r}; replay would resolve it to "
            "whatever is latest at the time"
        )

    _, _, version = candidate.source_artifact_id.partition("@")
    return ArtifactHandle(
        artifact_id=candidate.source_artifact_id,
        artifact_type=candidate.artifact_kind,
        version=version,
        artifact_content_hash=candidate.artifact_content_hash,
        tenancy=Tenancy(candidate.visibility, candidate.tenant_id),
        authority=candidate.authority,
        freshness=candidate.freshness,
        projections=(candidate.projection,),
        estimated_expansion_tokens=candidate.estimated_tokens,
        # retrieval_score is deliberately absent: re-ranking changes what is
        # chosen, never what a piece of evidence is.
    )


class MaterializationOutcome(str, Enum):
    MATERIALIZED = "MATERIALIZED"
    DENIED = "DENIED"
    STALE_PIN = "STALE_PIN"
    """The backing artifact changed after retrieval. Refused, never refreshed:
    silently serving new bytes under an old pin is how a replay stops being a
    replay."""

    UNRESOLVABLE = "UNRESOLVABLE"


@dataclass(frozen=True)
class MaterializedItem:
    """What one dereference actually did. Volatile; outside canonical identity."""

    handle_hash: str
    artifact_id: str
    projection: str
    outcome: MaterializationOutcome
    returned_content_hash: Optional[str] = None
    tokens: Optional[int] = None
    bytes_read: Optional[int] = None
    from_cache: bool = False
    detail: str = ""

    @property
    def succeeded(self) -> bool:
        return self.outcome is MaterializationOutcome.MATERIALIZED

    def to_json(self) -> Dict[str, Any]:
        return {"handle_hash": self.handle_hash, "artifact_id": self.artifact_id,
                "projection": self.projection, "outcome": self.outcome.value,
                "returned_content_hash": self.returned_content_hash,
                "tokens": self.tokens, "bytes_read": self.bytes_read,
                "from_cache": self.from_cache, "detail": self.detail}


@dataclass(frozen=True)
class MaterializationRecord:
    """One assembly of one declaration. Not part of the view's identity.

    Two runs that assembled the same working set are the same view even if one
    was cached and the other was slow, so none of this reaches the hash.
    """

    view_hash: str
    started_at: Optional[str] = None
    latency_ms: Optional[int] = None
    items: Sequence[MaterializedItem] = ()

    @property
    def dereference_count(self) -> int:
        return len(self.items)

    @property
    def failures(self) -> List[MaterializedItem]:
        return [i for i in self.items if not i.succeeded]

    def metrics(self, *, candidate_count: int, plan) -> Dict[str, Any]:
        """Raw counts. The inputs to context precision and expansion recall
        later; for now simply recorded rather than derived into a ratio nobody
        has agreed the denominator for."""
        from .context import Necessity

        by_necessity: Dict[str, int] = {}
        denied = 0
        for item in plan.items:
            by_necessity[item.necessity.value] = \
                by_necessity.get(item.necessity.value, 0) + 1
            if not item.authorization.granted:
                denied += 1

        return {
            "candidate_count": candidate_count,
            "selected_handles": len(plan.items),
            "by_necessity": by_necessity,
            "denied": denied,
            "omitted": plan.omitted_count,
            "estimated_tokens": plan.estimated_tokens,
            "actual_tokens": sum(i.tokens or 0 for i in self.items),
            "dereference_count": self.dereference_count,
            "cache_hits": sum(1 for i in self.items if i.from_cache),
            "stale_pin_failures": sum(
                1 for i in self.items
                if i.outcome is MaterializationOutcome.STALE_PIN),
            "materialization_latency_ms": self.latency_ms,
            "view_hash": self.view_hash,
        }

    def to_json(self) -> Dict[str, Any]:
        return {"view_hash": self.view_hash, "started_at": self.started_at,
                "latency_ms": self.latency_ms,
                "items": [i.to_json() for i in self.items],
                "dereference_count": self.dereference_count}
