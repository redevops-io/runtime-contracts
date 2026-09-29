"""Execution-locality contract — where a governed step physically runs (server / browser-local / device-local).

From the edge browser-native execution plan. Edge is an execution/resource *class* inside ReDevOps, not a separate
architecture: this adds the LOCALITY axis (where execution happens) and its policy, and a deterministic, fail-closed
target selection. It is orthogonal to two existing axes and composes with them:

  * isolation/privilege — the device-posture ``ExecutionClass`` (local_container < host_process < …) in agentic-os;
  * enforcement strength — ``EnforcementProfile`` + ``BackendCapabilities`` (models/execution_backend).

Nothing here names Chrome or any device SDK: Chrome built-in AI, Jetson/PAIR, TensorRT etc. are adapters that
*advertise* a ``LocalCapabilityDescriptor``. The load-bearing product capability is **governed execution locality**:
the Runtime chooses among targets by measured capability, privacy, locality, availability and policy, and it never
silently sends raw sensitive data to a remote target.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from .seal import content_hash

EDGE_EXECUTION_CONTRACT_VERSION = "1"


class ExecutionLocality(str, Enum):
    """Where a step physically executes. SERVER is remote; the others keep data on the user's device."""
    SERVER = "server"
    BROWSER_LOCAL = "browser_local"
    DEVICE_LOCAL = "device_local"       # PAIR / Jetson / a local node

    @property
    def is_local(self) -> bool:
        return self is not ExecutionLocality.SERVER

    @property
    def is_remote(self) -> bool:
        return self is ExecutionLocality.SERVER


class Availability(str, Enum):
    """Whether a local capability can run *now*. Only AVAILABLE is selectable; the rest are honest not-yet states."""
    AVAILABLE = "available"
    DOWNLOADABLE = "downloadable"
    DOWNLOADING = "downloading"
    UNAVAILABLE = "unavailable"


class LocalityPolicy(str, Enum):
    """A step's declared fallback behavior across localities. There is never a silent local→remote fallback for
    data a step marks as prohibited-from-leaving-device (that is enforced by selection, below)."""
    LOCAL_ONLY = "local_only"                               # never remote; defer if no local target
    LOCAL_PREFERRED = "local_preferred"                     # local if available, else remote when permitted
    REMOTE_ALLOWED = "remote_allowed"                       # any target
    REMOTE_REQUIRES_APPROVAL = "remote_requires_approval"   # remote is a candidate only behind human approval
    DEFER_IF_LOCAL_UNAVAILABLE = "defer_if_local_unavailable"


@dataclass(frozen=True)
class LocalCapabilityDescriptor:
    """The stable, policy-relevant identity of a locality-bearing capability (fast-changing state stays telemetry).
    A provider advertises one of these; the Runtime selects over them."""
    capability_id: str
    locality: ExecutionLocality
    device_class: str = ""              # "browser" | "jetson" | "server" | … (opaque)
    runtime: str = ""                  # "chrome" | "tensorrt" | … (opaque; never required by the Runtime)
    offline_capable: bool = False
    availability: Availability = Availability.UNAVAILABLE
    #: True if executing HERE sends raw input off the device (SERVER ⇒ True; on-device ⇒ False). The privacy gate
    #: reads this: a step that prohibits raw data leaving the device excludes any candidate where this is True.
    raw_data_may_leave_device: bool = True

    def canonical_form(self) -> dict[str, Any]:
        return {
            "capability_id": self.capability_id, "locality": self.locality.value,
            "device_class": self.device_class, "runtime": self.runtime, "offline_capable": self.offline_capable,
            "availability": self.availability.value, "raw_data_may_leave_device": self.raw_data_may_leave_device,
        }

    def identity(self) -> str:
        return content_hash(self.canonical_form())

    @property
    def selectable(self) -> bool:
        return self.availability is Availability.AVAILABLE


# Selection outcomes.
SELECTED = "selected"
REQUIRES_APPROVAL = "requires_approval"   # a remote target is the only option under REMOTE_REQUIRES_APPROVAL
DEFERRED = "deferred"                     # no permitted target now — never a silent remote fallback


@dataclass(frozen=True)
class LocalityDecision:
    """The EXPLAIN-able result of target selection: what ran (or why not), and what was considered."""
    outcome: str                       # SELECTED | REQUIRES_APPROVAL | DEFERRED
    reason: str
    selected: Optional[LocalCapabilityDescriptor] = None
    considered: tuple[str, ...] = ()   # capability_ids weighed, for EXPLAIN

    def canonical_form(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome, "reason": self.reason,
            "selected": self.selected.capability_id if self.selected else None,
            "selected_locality": self.selected.locality.value if self.selected else None,
            "considered": list(self.considered),
        }


def select_execution_target(candidates: list[LocalCapabilityDescriptor], policy: LocalityPolicy, *,
                            prohibit_raw_remote: bool = False,
                            require_offline: bool = False) -> LocalityDecision:
    """Deterministically choose where a step runs, fail-closed.

    Rules (from the plan §5/§10):
      * only ``AVAILABLE`` candidates are selectable;
      * ``require_offline`` keeps only offline-capable candidates;
      * ``prohibit_raw_remote`` drops any candidate that would send raw data off the device — so there is **no
        silent local→remote fallback for sensitive data**;
      * the ``LocalityPolicy`` then decides local-vs-remote, preferring local; a remote-only situation under
        ``REMOTE_REQUIRES_APPROVAL`` returns ``REQUIRES_APPROVAL`` (never auto-executes remote), and any policy with
        no permitted target returns ``DEFERRED``.
    """
    considered = tuple(c.capability_id for c in candidates)
    avail = [c for c in candidates if c.selectable]
    if require_offline:
        avail = [c for c in avail if c.offline_capable]
    permitted = [c for c in avail if not (prohibit_raw_remote and c.raw_data_may_leave_device)]

    locals_ = [c for c in permitted if c.locality.is_local]
    remotes = [c for c in permitted if c.locality.is_remote]

    def defer(reason: str) -> LocalityDecision:
        return LocalityDecision(DEFERRED, reason, None, considered)

    # Local is always preferred when a permitted local target exists.
    if locals_:
        return LocalityDecision(SELECTED, "permitted local target available", locals_[0], considered)

    # No permitted local target. Behavior now depends on the policy.
    if policy in (LocalityPolicy.LOCAL_ONLY, LocalityPolicy.DEFER_IF_LOCAL_UNAVAILABLE):
        return defer("no permitted local target; policy forbids remote")
    if not remotes:
        # LOCAL_PREFERRED / REMOTE_ALLOWED / REMOTE_REQUIRES_APPROVAL but nothing remote is permitted either
        reason = ("remote prohibited for raw sensitive data" if prohibit_raw_remote
                  else "no permitted target available")
        return defer(reason)
    if policy == LocalityPolicy.REMOTE_REQUIRES_APPROVAL:
        return LocalityDecision(REQUIRES_APPROVAL, "only a remote target is available; requires human approval",
                                remotes[0], considered)
    # LOCAL_PREFERRED / REMOTE_ALLOWED with a permitted remote target
    return LocalityDecision(SELECTED, "no local target; remote permitted by policy", remotes[0], considered)
