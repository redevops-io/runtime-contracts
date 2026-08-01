"""ContextPreviewPlan and ContextView — deciding, then materializing.

The boundary this package exists to hold:

    RAG finds candidates.  Context Runtime decides what enters the model.

A retrieval top-k is not a context. Between them sits a plan that states what is
required, what is optional, what was excluded and why, and what it will cost —
so the decision is reviewable before any bytes are fetched.

**A plan that cannot fit its required set returns infeasible.** It must never
silently drop a required item to satisfy a budget: a working set that quietly
lost the one refuting document is worse than no answer, because it looks like an
answer.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Sequence

from ..canonical import CONTRACT_VERSION, content_hash, sorted_unique
from .handle import ArtifactHandle
from .visibility import AuthorizationOutcome


class Necessity(str, Enum):
    REQUIRED = "REQUIRED"
    """Its absence invalidates the answer. Dropping it is never a budget option."""

    OPTIONAL = "OPTIONAL"
    EXCLUDED = "EXCLUDED"


class PlanFeasibility(str, Enum):
    FEASIBLE = "FEASIBLE"
    INFEASIBLE_BUDGET = "INFEASIBLE_BUDGET"
    INFEASIBLE_AUTHORIZATION = "INFEASIBLE_AUTHORIZATION"
    INFEASIBLE_MISSING = "INFEASIBLE_MISSING"


@dataclass(frozen=True)
class PlannedItem:
    """One handle and the decision made about it."""

    handle: ArtifactHandle
    necessity: Necessity
    projection: str = "summary"
    authorization: AuthorizationOutcome = AuthorizationOutcome.GRANTED
    reason: str = ""
    """Why it was excluded or denied. Free text, and outside the hash — the
    decision participates, the wording does not."""

    def canonical_form(self) -> Dict[str, Any]:
        return {
            "handle": self.handle.canonical_form(),
            "necessity": self.necessity.value,
            "projection": self.projection,
            "authorization": self.authorization.value,
        }

    @property
    def sort_key(self) -> tuple:
        return (self.handle.artifact_id, self.projection, self.necessity.value)


@dataclass(frozen=True)
class ContextPreviewPlan:
    """What would enter the model, decided before anything is fetched.

    Persisted and replayable rather than planner logging. If this only ever
    existed in a log line, "why did the model not see the contradicting
    evidence?" would be unanswerable after the fact.
    """

    plan_id: str
    items: Sequence[PlannedItem]
    budget_tokens: Optional[int] = None
    estimated_tokens: int = 0
    estimated_latency_ms: Optional[int] = None
    cache_reuse: Sequence[str] = ()
    omitted_count: int = 0
    """Candidates never planned at all. Disclosed, because a view showing a
    subset without saying so claims a completeness it does not have."""

    findings: Sequence[str] = ()
    contract_version: str = CONTRACT_VERSION

    @property
    def required(self) -> List[PlannedItem]:
        return [i for i in self.items if i.necessity is Necessity.REQUIRED]

    @property
    def feasibility(self) -> PlanFeasibility:
        denied = [i for i in self.required if not i.authorization.granted]
        if denied:
            return PlanFeasibility.INFEASIBLE_AUTHORIZATION
        if self.budget_tokens is not None:
            required_tokens = sum(
                i.handle.estimated_expansion_tokens or 0 for i in self.required)
            if required_tokens > self.budget_tokens:
                return PlanFeasibility.INFEASIBLE_BUDGET
        return PlanFeasibility.FEASIBLE

    @property
    def is_feasible(self) -> bool:
        return self.feasibility is PlanFeasibility.FEASIBLE

    def canonical_form(self) -> Dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "items": [
                i.canonical_form()
                for i in sorted_unique(self.items, key=lambda i: i.sort_key)
            ],
            "budget_tokens": self.budget_tokens,
            "omitted_count": self.omitted_count,
            # plan_id, estimates, latency and cache reuse are excluded: they
            # describe this planning run, not the decision it reached. Two
            # planners reaching the same decision must agree.
        }

    @property
    def plan_hash(self) -> str:
        return content_hash(self.canonical_form())

    def to_json(self) -> Dict[str, Any]:
        return {
            **self.canonical_form(),
            "plan_id": self.plan_id,
            "plan_hash": self.plan_hash,
            "feasibility": self.feasibility.value,
            "estimated_tokens": self.estimated_tokens,
            "estimated_latency_ms": self.estimated_latency_ms,
            "cache_reuse": sorted(self.cache_reuse),
            "findings": list(self.findings),
        }


@dataclass(frozen=True)
class ContextView:
    """The materialized working set. The reproducibility unit.

        same handles + same plan + same version pins + same contract version
            = same view_hash

    Materialized content participates through its *pinned content hash*, never
    its bytes, so the canonical form stays small and stays comparable.
    """

    view_id: str
    plan: ContextPreviewPlan
    version_pins: Mapping[str, str]
    """artifact_id -> content hash, at materialization. The pin is what makes
    replay honest: resolving `@3` must return the same bytes it returned then,
    or the view is reported as unreproducible rather than silently refreshed."""

    materialized_at: Optional[str] = None
    contract_version: str = CONTRACT_VERSION

    def canonical_form(self) -> Dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "plan": self.plan.canonical_form(),
            "version_pins": dict(sorted(self.version_pins.items())),
            # view_id and materialized_at are excluded. Two materializations of
            # one plan over unchanged artifacts are the same view, and a clock
            # reading is not part of what the model saw.
        }

    @property
    def view_hash(self) -> str:
        return content_hash(self.canonical_form())

    def divergence_from(self, other: "ContextView") -> List[str]:
        """Which pins moved. The answer to "why did replay differ?"."""
        out = []
        for artifact_id in sorted(set(self.version_pins) | set(other.version_pins)):
            mine = self.version_pins.get(artifact_id)
            theirs = other.version_pins.get(artifact_id)
            if mine != theirs:
                out.append(artifact_id)
        return out

    def to_json(self) -> Dict[str, Any]:
        return {
            **self.canonical_form(),
            "view_id": self.view_id,
            "view_hash": self.view_hash,
            "materialized_at": self.materialized_at,
            "plan_hash": self.plan.plan_hash,
        }
