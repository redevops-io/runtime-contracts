"""ArtifactHandle — a reference that can be judged before it is dereferenced.

The point of a handle is that a planner can decide whether expanding it is worth
the budget *without* expanding it. That requires it to carry enough to judge:
what it is, which version, whose it is, how fresh, how expensive, and what
projections exist.

Possessing a handle grants nothing. Authorization is applied at every
dereference, not once at retrieval — a handle that travelled from a permitted
context into a different one must be re-checked there.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from enum import Enum
from typing import Any, Dict, Optional, Sequence

from ..canonical import content_hash
from .visibility import Tenancy, Visibility


class Freshness(str, Enum):
    CURRENT = "CURRENT"
    SUPERSEDED = "SUPERSEDED"
    """A later version exists. Reported, never silently upgraded — resolving a
    pinned version must return that version or fail."""

    EXPIRED = "EXPIRED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class ArtifactHandle:
    """A resolvable, judgeable reference to one artifact version."""

    artifact_id: str
    """Canonical and version-pinned, e.g. `methodology/hrp@3`."""

    artifact_type: str
    version: str
    artifact_content_hash: str
    """The referent's hash. A handle whose backing object changed under it is a
    different handle, and comparing these is how that is detected."""

    tenancy: Tenancy
    authority: str = ""
    """Who asserts this — the source of record."""

    observed_at: Optional[str] = None
    """When the referent was last observed. Excluded from the handle hash: it
    describes the observation, not the thing observed."""

    freshness: Freshness = Freshness.UNKNOWN
    projections: Sequence[str] = ()
    """What views can be materialized — `summary`, `full`, `diagnostics`. Sorted
    in canonical form so declaration order cannot change a hash."""

    estimated_expansion_tokens: Optional[int] = None
    estimated_expansion_cost: Optional[str] = None
    """A decimal *string*. Never a float — see `canonical.py`."""

    def __post_init__(self) -> None:
        if "@" not in self.artifact_id:
            raise ValueError(
                f"{self.artifact_id!r} is not version-pinned. An unpinned handle "
                "resolves to whatever is latest at dereference time, which makes "
                "replay return a different working set than the one recorded"
            )
        if isinstance(self.estimated_expansion_cost, float):
            raise ValueError(
                "estimated_expansion_cost must be a decimal string, not a float"
            )

    @property
    def concept_id(self) -> str:
        return self.artifact_id.split("@")[0]

    def canonical_form(self) -> Dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "artifact_type": self.artifact_type,
            "version": self.version,
            "artifact_content_hash": self.artifact_content_hash,
            "tenancy": self.tenancy.canonical_form(),
            "authority": self.authority or None,
            "projections": sorted(self.projections),
            # observed_at, freshness and the estimates are deliberately absent:
            # they describe the observation and the cost of acting on it, not
            # the referent. Two runs that observed the same artifact at
            # different moments must produce the same handle hash.
        }

    @property
    def handle_hash(self) -> str:
        return content_hash(self.canonical_form())

    def to_json(self) -> Dict[str, Any]:
        return {
            **self.canonical_form(),
            "handle_hash": self.handle_hash,
            "observed_at": self.observed_at,
            "freshness": self.freshness.value,
            "estimated_expansion_tokens": self.estimated_expansion_tokens,
            "estimated_expansion_cost": self.estimated_expansion_cost,
        }
