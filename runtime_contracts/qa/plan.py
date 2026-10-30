"""``QAPlan``: a fully resolved, declarative plan.

Planning decides order, lanes, budgets and evidence level and nothing else. The runner follows the plan: it does no
work stealing, no re-planning and no dependency resolution, so this object has no field through which any of those
could be requested, and ``from_json`` refuses a key it does not define.

``coverage_contract`` is ``FULL`` (every declared assertion of every planned spec is scheduled). ``SUBSET`` is a
reserved enum value so the schema need not break if it is ever enabled; every validator rejects it today.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .base import (SCHEMA_ID_PREFIX, AnyDigest, Code, Ident, NonNeg, Pos, QAContractError, QARecord,
                   QAValue, Rcv1, SpecRefStr)
from .enums import CoverageContract, EvidenceLevel
from .spec import Budget, ComponentRef, SmallCount


@dataclass(frozen=True)
class PlanItem(QAValue):
    """One spec in the plan, in a lane, at a position, under a budget."""

    spec_ref: SpecRefStr
    lane: Ident
    order: NonNeg
    budget: Budget
    recovery_ceiling: SmallCount
    """Cap on recovery attempts for this item. The budget may not exceed it, and the plan may not exceed the arm cap."""

    evidence_level: EvidenceLevel = EvidenceLevel.STANDARD

    def validate(self) -> None:
        if self.budget.max_recovery_attempts > self.recovery_ceiling:
            raise QAContractError(Code.PLAN_INVALID, f"{self.spec_ref}: budget allows "
                                  f"{self.budget.max_recovery_attempts} recovery attempts, above the ceiling "
                                  f"{self.recovery_ceiling}")


@dataclass(frozen=True)
class PlanGate(QAValue):
    """A start condition the runner checks, not a decision it makes: ``item`` starts after every ``after``."""

    SET_FIELDS = {"after": None}

    item: SpecRefStr
    after: Tuple[SpecRefStr, ...]

    def validate(self) -> None:
        if not self.after:
            raise QAContractError(Code.PLAN_INVALID, f"gate on {self.item} waits for nothing")
        if self.item in self.after:
            raise QAContractError(Code.PLAN_INVALID, f"gate on {self.item} waits for itself")


@dataclass(frozen=True)
class ResourceClaim(QAValue):
    """A resource the plan was built under, for example ``browser_slots``. Declarative; the runner reserves nothing."""

    resource: Ident
    amount: Pos


def _guard_full_coverage(plan: "QAPlan") -> None:
    if plan.coverage_contract is not CoverageContract.FULL:
        raise QAContractError(Code.UNSUPPORTED_COVERAGE_CONTRACT,
                              f"coverage_contract {plan.coverage_contract.value} is not supported; only FULL is "
                              "accepted, and no partial coverage is certified anywhere")


def _guard_lanes(plan: "QAPlan") -> None:
    lanes = set(plan.lanes)
    seen = set()
    for item in plan.items:
        if item.lane not in lanes:
            raise QAContractError(Code.PLAN_INVALID, f"{item.spec_ref} is in lane {item.lane}, which the plan "
                                  "does not declare")
        slot = (item.lane, item.order)
        if slot in seen:
            raise QAContractError(Code.PLAN_INVALID, f"lane {item.lane} has two items at order {item.order}")
        seen.add(slot)
    if not 1 <= plan.max_parallel <= len(plan.lanes):
        raise QAContractError(Code.PLAN_INVALID, f"max_parallel {plan.max_parallel} must be between 1 and the "
                              f"number of lanes ({len(plan.lanes)})")


def _guard_gates(plan: "QAPlan") -> None:
    known = {i.spec_ref for i in plan.items}
    for gate in plan.gates:
        for ref in (gate.item, *gate.after):
            if ref not in known:
                raise QAContractError(Code.PLAN_INVALID, f"gate refers to {ref}, which is not an item of the plan")
    # With static lanes a gate that points at a later item of its own lane (or any cycle through lane order and
    # gates) can never start. That is a deadlock the runner has no power to resolve, so the plan is refused.
    edges: Dict[str, List[str]] = {ref: [] for ref in known}
    by_lane: Dict[str, List[PlanItem]] = {}
    for item in plan.items:
        by_lane.setdefault(item.lane, []).append(item)
    for items in by_lane.values():
        items.sort(key=lambda i: i.order)
        for a, b in zip(items, items[1:]):
            edges[a.spec_ref].append(b.spec_ref)
    for gate in plan.gates:
        for dep in gate.after:
            edges[dep].append(gate.item)
    state: Dict[str, int] = {}

    def visit(node: str) -> None:
        state[node] = 1
        for nxt in edges[node]:
            if state.get(nxt) == 1:
                raise QAContractError(Code.PLAN_INVALID, f"the plan can never start {nxt}: lane order and gates "
                                      "form a cycle")
            if nxt not in state:
                visit(nxt)
        state[node] = 2

    for node in sorted(known):
        if node not in state:
            visit(node)


@dataclass(frozen=True)
class QAPlan(QARecord):
    SCHEMA_ID = SCHEMA_ID_PREFIX + "qa-plan"
    CUSTODY = frozenset({"rationale_ref"})
    SET_FIELDS = {"items": "spec_ref", "lanes": None, "gates": "item", "resource_claims": "resource"}

    items: Tuple[PlanItem, ...]
    lanes: Tuple[Ident, ...]
    """Static worker slots. Each is executed in order, by position of its items."""

    max_parallel: Pos
    coverage_contract: CoverageContract
    planner: ComponentRef
    gates: Tuple[PlanGate, ...] = ()
    resource_claims: Tuple[ResourceClaim, ...] = ()
    action_policy_ref: Optional[Rcv1] = None
    """The default QA action policy the harness enforces at run time. A reference, not the policy."""

    rationale_ref: Optional[AnyDigest] = None
    """Explanation of why the planner chose this plan. Custody: not hashed."""

    def validate(self) -> None:
        _guard_full_coverage(self)
        if not self.items:
            raise QAContractError(Code.PLAN_INVALID, "a plan schedules at least one spec")
        _guard_lanes(self)
        _guard_gates(self)

    @property
    def plan_hash(self) -> str:
        return self.content_hash
