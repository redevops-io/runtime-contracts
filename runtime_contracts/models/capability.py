"""CapabilityDescriptor — what a capability does, needs and guarantees.

The largest gap against `context_runtime.registry.Capability`, and not a rename:
that type is a **selection token** telling a planner what to pick, where this is
an **invocation descriptor** telling it what happens if it does. Overlapping
names, different objects.

Three forms are kept apart, because conflating them is how a planner ends up
maintaining a parallel table:

    identity            what this capability *is* — id and version
    comparable form     what a planner reasons over — semantics, not providers
    implementation binding  who runs it — outside the descriptor

A provider does not belong in the abstract descriptor. Two providers of one
capability with identical semantics are one capability; if their semantics
differ, they are two capabilities and should say so rather than hiding the
difference behind a provider field.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Sequence

from ..canonical import content_hash, decimal_string
from .visibility import Visibility


class Idempotency(str, Enum):
    IDEMPOTENT = "IDEMPOTENT"
    """Repeating it changes nothing further. Safe to retry blindly."""

    AT_MOST_ONCE = "AT_MOST_ONCE"
    """Repeating it is harmful. A retry needs a completion check first."""

    UNKNOWN = "UNKNOWN"
    """Refuses to claim either. The honest default — an unmarked capability
    treated as idempotent is a duplicate side effect waiting to happen."""


class RetrySafety(str, Enum):
    SAFE = "SAFE"
    UNSAFE = "UNSAFE"
    SAFE_WITH_IDEMPOTENCY_KEY = "SAFE_WITH_IDEMPOTENCY_KEY"


class SideEffect(str, Enum):
    NONE = "NONE"
    READS_EXTERNAL = "READS_EXTERNAL"
    WRITES_INTERNAL = "WRITES_INTERNAL"
    WRITES_EXTERNAL = "WRITES_EXTERNAL"
    NOTIFIES_HUMAN = "NOTIFIES_HUMAN"
    SPENDS_MONEY = "SPENDS_MONEY"


@dataclass(frozen=True)
class Estimate:
    """A bounded estimate. Never a point float.

    Bounds rather than a single number because a planner budgeting against a
    mean will exceed it half the time, and because a decimal string is the only
    fractional form this contract accepts.
    """

    low: str
    high: str
    unit: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "low", decimal_string(self.low))
        object.__setattr__(self, "high", decimal_string(self.high))
        if float(self.low) > float(self.high):   # comparison only, never stored
            raise ValueError(f"estimate low {self.low} exceeds high {self.high}")

    def canonical_form(self) -> Dict[str, Any]:
        return {"low": self.low, "high": self.high, "unit": self.unit}


@dataclass(frozen=True)
class TypedPort:
    """One typed input or output."""

    name: str
    schema_id: str
    required: bool = True

    def canonical_form(self) -> Dict[str, Any]:
        return {"name": self.name, "schema_id": self.schema_id,
                "required": self.required}


@dataclass(frozen=True)
class SecurityProfile:
    visibility: Visibility = Visibility.INTERNAL
    requires_human_approval: bool = False
    handles_tenant_data: bool = False
    may_egress: bool = False
    """Whether it can send data outside the trust boundary. Separate from
    `may_write` because reading-and-sending is the exfiltration shape."""

    def canonical_form(self) -> Dict[str, Any]:
        return {"visibility": self.visibility.value,
                "requires_human_approval": self.requires_human_approval,
                "handles_tenant_data": self.handles_tenant_data,
                "may_egress": self.may_egress}


@dataclass(frozen=True)
class CapabilityDescriptor:
    """Everything a planner needs before invoking something."""

    SCHEMA_ID: str = field(default="runtime-contracts/capability-descriptor",
                           init=False, repr=False)
    SCHEMA_VERSION: str = field(default="0.1", init=False, repr=False)

    capability_id: str
    version: str
    kind: str
    typed_inputs: Sequence[TypedPort] = ()
    typed_outputs: Sequence[TypedPort] = ()
    preconditions: Sequence[str] = ()
    postconditions: Sequence[str] = ()
    failure_modes: Sequence[str] = ()
    side_effects: Sequence[SideEffect] = (SideEffect.NONE,)
    required_runtimes: Sequence[str] = ()
    security_profile: SecurityProfile = field(default_factory=SecurityProfile)
    verification_method: Optional[str] = None
    """The check that establishes the postconditions held. A capability with
    postconditions and no verification method is asserting an outcome nobody
    confirms."""

    idempotency: Idempotency = Idempotency.UNKNOWN
    retry_safety: RetrySafety = RetrySafety.UNSAFE
    cost_estimate: Optional[Estimate] = None
    latency_estimate: Optional[Estimate] = None
    context_estimate: Optional[Estimate] = None
    locality: str = "remote"

    def __post_init__(self) -> None:
        if self.postconditions and not self.verification_method:
            raise ValueError(
                f"{self.capability_id} declares postconditions with no "
                "verification_method. An outcome nobody checks is the "
                "declaration-without-realization defect, in the one place a "
                "planner would trust it most"
            )
        if (self.retry_safety is RetrySafety.SAFE
                and self.idempotency is Idempotency.AT_MOST_ONCE):
            raise ValueError(
                f"{self.capability_id} is at-most-once and claims retries are "
                "safe. One of the two is wrong, and guessing which would make "
                "a duplicate side effect a planner decision"
            )

    @property
    def artifact_id(self) -> str:
        return f"capability/{self.capability_id}@{self.version}"

    @property
    def writes(self) -> bool:
        return any(e in {SideEffect.WRITES_EXTERNAL, SideEffect.WRITES_INTERNAL,
                         SideEffect.SPENDS_MONEY, SideEffect.NOTIFIES_HUMAN}
                   for e in self.side_effects)

    def canonical_form(self) -> Dict[str, Any]:
        """Exact identity — everything declared."""
        return {
            "schema_id": self.SCHEMA_ID,
            "schema_version": self.SCHEMA_VERSION,
            "capability_id": self.capability_id,
            "version": self.version,
            "kind": self.kind,
            "typed_inputs": [p.canonical_form() for p in self.typed_inputs],
            "typed_outputs": [p.canonical_form() for p in self.typed_outputs],
            "preconditions": sorted(self.preconditions),
            "postconditions": sorted(self.postconditions),
            "failure_modes": sorted(self.failure_modes),
            "side_effects": sorted(e.value for e in self.side_effects),
            "required_runtimes": sorted(self.required_runtimes),
            "security_profile": self.security_profile.canonical_form(),
            "verification_method": self.verification_method,
            "idempotency": self.idempotency.value,
            "retry_safety": self.retry_safety.value,
            "locality": self.locality,
            "cost_estimate": (self.cost_estimate.canonical_form()
                              if self.cost_estimate else None),
            "latency_estimate": (self.latency_estimate.canonical_form()
                                 if self.latency_estimate else None),
            "context_estimate": (self.context_estimate.canonical_form()
                                 if self.context_estimate else None),
        }

    def comparable_form(self) -> Dict[str, Any]:
        """What a planner reasons over.

        Estimates and locality are excluded: a capability that got cheaper is
        the same capability, and a planner comparing two descriptors is asking
        whether they do the same thing, not whether they cost the same.
        """
        declared = self.canonical_form()
        for planning_only in ("cost_estimate", "latency_estimate",
                              "context_estimate", "locality", "version"):
            declared.pop(planning_only, None)
        return declared

    @property
    def content_hash(self) -> str:
        return content_hash(self.canonical_form())

    @property
    def semantic_hash(self) -> str:
        """Two descriptors sharing this do the same thing."""
        return content_hash(self.comparable_form())

    def to_json(self) -> Dict[str, Any]:
        return {**self.canonical_form(), "artifact_id": self.artifact_id,
                "content_hash": self.content_hash,
                "semantic_hash": self.semantic_hash, "writes": self.writes}
