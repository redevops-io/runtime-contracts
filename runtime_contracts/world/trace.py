"""Visual-trace schema — one mission trace that streams to the animated execution canvas.

The canvas shows a business event (left) → the Runtime spine (center) → the four business blocks (right),
with app nodes lighting up as the mission crosses them and a **capsule** carrying identity / evidence /
policy / authority / context moving *with* the mission rather than being copied between apps. This module
fixes the shape of that stream so any runtime can emit it and any canvas can render it. It is a presentation
projection of the real Mission trace — not a second source of truth.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class BusinessBlock(str, Enum):
    RUNTIME = "runtime"                 # the spine (Discovery/Planner/Mission/Context/Verification)
    CUSTOMER_SUCCESS = "customer_success"
    REVENUE = "revenue_intelligence"
    FINANCE = "finance"
    SECURITY = "security_compliance"
    PLATFORM_OPS = "platform_operations"


class MilestoneKind(str, Enum):
    EVENT = "event"; DISCOVERY = "discovery"; PLAN = "plan"; POLICY = "policy"
    APPROVAL = "approval"; NEEDS_YOU = "needs_you"; ACTION = "action"; VERIFY = "verify"; OUTCOME = "outcome"


#: NeedsYou reasons — a human-resolvable interruption is never a generic "mission failed" (v2 §26).
class NeedsYouReason(str, Enum):
    AMBIGUOUS_INTENT = "AMBIGUOUS_INTENT"; MISSING_EVIDENCE = "MISSING_EVIDENCE"
    AUTHORITY_REQUIRED = "AUTHORITY_REQUIRED"; POLICY_APPROVAL = "POLICY_APPROVAL"
    CONFLICTING_EVIDENCE = "CONFLICTING_EVIDENCE"; CAPABILITY_UNAVAILABLE = "CAPABILITY_UNAVAILABLE"
    OUT_OF_DISTRIBUTION = "OUT_OF_DISTRIBUTION"; HIGH_RISK = "HIGH_RISK"; BUDGET_EXCEEDED = "BUDGET_EXCEEDED"


@dataclass(frozen=True)
class Capsule:
    """The identity/evidence/policy context that moves with the mission along canvas edges — references
    only, never copies (the anti-pattern the whole design replaces is copying data between apps)."""
    mission_id: str = ""
    entity_id: str = ""
    evidence_hash: str = ""
    policy_ref: str = ""
    authority_ref: str = ""
    context_epoch: str = ""

    def canonical_form(self) -> Dict[str, Any]:
        return {k: v for k, v in {
            "mission_id": self.mission_id, "entity_id": self.entity_id, "evidence_hash": self.evidence_hash,
            "policy_ref": self.policy_ref, "authority_ref": self.authority_ref,
            "context_epoch": self.context_epoch}.items() if v}


@dataclass(frozen=True)
class TraceMilestone:
    """One visible step on the canvas — its offset, what happened, which app/runtime node and block, and the
    capsule state at that moment. ``needs_you`` names a human-resolvable interruption reason."""
    t_offset_s: float
    label: str
    kind: str = MilestoneKind.EVENT.value
    node: str = ""                                  # app/runtime node id the edge enters (e.g. "crm", "finance")
    block: str = BusinessBlock.RUNTIME.value
    capsule: Optional[Capsule] = None
    needs_you: str = ""                             # a NeedsYouReason value, when kind == needs_you
    realism: str = ""                               # RealismClass label to badge this step's data

    def canonical_form(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"t_offset_s": self.t_offset_s, "label": self.label, "kind": self.kind,
                             "block": self.block}
        if self.node:
            d["node"] = self.node
        if self.capsule is not None:
            d["capsule"] = self.capsule.canonical_form()
        if self.needs_you:
            d["needs_you"] = self.needs_you
        if self.realism:
            d["realism"] = self.realism
        return d


@dataclass
class VisualTrace:
    """The ordered milestone stream for one mission over one world — what the canvas animates."""
    mission_id: str
    world_id: str = ""
    milestones: List[TraceMilestone] = field(default_factory=list)

    def add(self, milestone: TraceMilestone) -> "VisualTrace":
        self.milestones.append(milestone)
        return self

    def canonical_form(self) -> Dict[str, Any]:
        return {"mission_id": self.mission_id, "world_id": self.world_id,
                "milestones": [m.canonical_form() for m in sorted(self.milestones, key=lambda x: x.t_offset_s)]}
