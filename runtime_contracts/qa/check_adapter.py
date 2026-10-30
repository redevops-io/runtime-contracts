"""``CheckAdapter`` (``qa-check-adapter/1``): the seam for resource targets (infrastructure checks).

``executor = PLAYWRIGHT`` runs through ``QAAdapter``; ``executor = SCRIPT`` runs through ``CheckAdapter``. Both
produce an ``ObservedValue``; only the verifier produces a verdict. This protocol never receives an expected value
and never returns a verdict.

Boundary: no persistent writes outside a disposable, isolated Tier K cluster. Offline, an adapter reads the case
workspace and local image metadata and appends evidence. In Tier K, and only when the disposable-cluster guard has
passed (``CheckProfile.disposable_proof_ref``), it may use server-side dry-run admission and fixed probe workloads
defined by the individually hashed check registry. Anything else is ``ActionBlockedByPolicy``. Closed-world
properties that cannot be established are ``UnsupportedOperation``: reported as not expressible, never a pass.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol, Sequence, Tuple, runtime_checkable

from ..protocol.evidence import EvidenceRef
from .base import Code, AnyDigest, Ident, QAContractError, QAValue, Sha256
from .enums import CaptureKind, CheckTier, ResetScope
from .adapter import ResetResult
from .records import CleanupReport, ObservedValue
from .spec import CheckProgramRef, ResourceRef

CHECK_ADAPTER_API_VERSION = "qa-check-adapter/1"
MAX_CHECK_INPUTS = 16


def _guard_disposable_proof(p: "CheckProfile") -> None:
    if p.tier is CheckTier.K and p.disposable_proof_ref is None:
        raise QAContractError(Code.INVALID_FIELD, "tier K requires disposable_proof_ref: Tier K work happens only "
                              "in a disposable, isolated cluster that has passed the guard")
    if p.tier is CheckTier.OFFLINE and p.disposable_proof_ref is not None:
        raise QAContractError(Code.INVALID_FIELD, "an offline profile carries no disposable_proof_ref")


@dataclass(frozen=True)
class CheckProfile(QAValue):
    tier: CheckTier
    case_root_digest: Sha256
    disposable_proof_ref: Optional[AnyDigest] = None

    def validate(self) -> None:
        _guard_disposable_proof(self)


@dataclass(frozen=True)
class WorkspaceHandle(QAValue):
    workspace_id: Ident


@dataclass(frozen=True)
class ResolvedResource(QAValue):
    """A resource reference and the content digest it resolved to."""

    ref: ResourceRef
    content_digest: Sha256


@dataclass(frozen=True)
class CheckSubject(QAValue):
    """One registered, hashed check program, its inputs and the tier it runs in."""

    check_program_ref: CheckProgramRef
    inputs: Tuple[ResourceRef, ...]
    tier: CheckTier

    def validate(self) -> None:
        if not 1 <= len(self.inputs) <= MAX_CHECK_INPUTS:
            raise QAContractError(Code.INVALID_FIELD, f"a check takes 1 to {MAX_CHECK_INPUTS} inputs")


@runtime_checkable
class CheckAdapter(Protocol):
    adapter_id: str
    adapter_version: str
    api_version: str
    """``"qa-check-adapter/1"``."""

    def open_workspace(self, profile: CheckProfile) -> WorkspaceHandle:
        """A read-only case tree. Tier OFFLINE or K."""
        ...

    def resolve(self, w: WorkspaceHandle, ref: ResourceRef) -> ResolvedResource:
        """The content digest of the resolved resource. No side effects."""
        ...

    def run_check(self, w: WorkspaceHandle, subject: CheckSubject) -> ObservedValue:
        """Executes one registered, hashed check program and returns the actual value only."""
        ...

    def capture(self, w: WorkspaceHandle, kinds: Sequence[CaptureKind]) -> Sequence[EvidenceRef]: ...

    def reset(self, w: WorkspaceHandle, scope: ResetScope) -> ResetResult:
        """Disposable Tier K only."""
        ...

    def close_workspace(self, w: WorkspaceHandle) -> CleanupReport: ...
