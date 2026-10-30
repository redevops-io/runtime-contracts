"""``QAAdapter`` (``qa-adapter/1``): the browser-facing seam.

A Python ``Protocol`` in contracts, mirrored structurally by the harness, so an adapter satisfies both without
either library importing the other (``ExecutionBackend`` is the precedent). Rules, enforced by what the signatures
can and cannot carry:

* ``assert_`` takes a subject and returns an ``ObservedValue``. It has no ``expected`` parameter and its return
  type has no verdict. The verifier compares, from assertions loaded by hash. (``assert`` is a Python keyword, so
  the schema operation ``assert`` is the method ``assert_``.)
* ``locate`` returns every candidate with role, accessible name, visibility, enabled state and a uniqueness flag.
  The runner, not the adapter, decides whether a candidate is acceptable. It has no side effects.
* ``act`` takes a ``ResolvedTarget`` and an ``ActionRequest`` that carries a policy decision reference. An adapter
  refuses an action without one (``ActionBlockedByPolicy``).
* ``capture`` returns redacted artifacts only; a failed redaction is ``RedactionFailed``, never a raw artifact.
* ``close_session`` returns a ``CleanupReport`` that feeds the verified-cleanup gate.

Adapters also enforce the egress allow-list at the browser level, as defence in depth; the runner remains the
policy authority. No adapter computes a verdict.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol, Sequence, Tuple, runtime_checkable

from ..protocol.evidence import EvidenceRef
from .base import Code, AnyDigest, Ident, QAContractError, QAValue, Rcv1, ShortText
from .enums import (CaptureKind, LocateMode, LocatorStrategy, Phase, ResetScope, ResultCode)
from .records import CleanupReport, Observation, ObservedValue
from .spec import Action, AssertionSubject, LocatorDescriptor

QA_ADAPTER_API_VERSION = "qa-adapter/1"


@dataclass(frozen=True)
class SessionProfile(QAValue):
    """A fresh, isolated context. Downloads, popups and file choosers are denied unless the spec permits them."""

    egress_profile: Ident
    redaction_policy_id: AnyDigest
    allow_downloads: bool = False
    allow_popups: bool = False
    allow_file_choosers: bool = False


@dataclass(frozen=True)
class SessionHandle(QAValue):
    session_id: Ident


@dataclass(frozen=True)
class ObserveRequest(QAValue):
    SET_FIELDS = {"capture": None}

    step_id: Ident
    phase: Phase
    capture: Tuple[CaptureKind, ...] = ()


@dataclass(frozen=True)
class LocateCandidate(QAValue):
    """One element a locator could mean. ``unique`` is true only for the sole candidate."""

    candidate_ref: Ident
    visible: bool
    enabled: bool
    unique: bool
    role: Optional[ShortText] = None
    name: Optional[ShortText] = None


@dataclass(frozen=True)
class LocateResult(QAValue):
    candidates: Tuple[LocateCandidate, ...] = ()

    def validate(self) -> None:
        if any(c.unique != (len(self.candidates) == 1) for c in self.candidates):
            raise QAContractError(Code.RECORD_INCONSISTENT, "unique is true exactly for the sole candidate")
        refs = [c.candidate_ref for c in self.candidates]
        if len(set(refs)) != len(refs):
            raise QAContractError(Code.DUPLICATE_ENTRY, "a candidate_ref appears twice")


@dataclass(frozen=True)
class ResolvedTarget(QAValue):
    """What ``locate`` produced and the runner accepted: the element, the locator that found it and how."""

    candidate_ref: Ident
    locator: LocatorDescriptor
    strategy: LocatorStrategy


@dataclass(frozen=True)
class ActionRequest(QAValue):
    """An action plus the policy decision that allowed it. There is no way to build one without the reference."""

    step_id: Ident
    action: Action
    idempotency_key: Ident
    policy_decision_ref: Rcv1


@dataclass(frozen=True)
class ActionOutcome(QAValue):
    """The raw result of an action. No verdict: whether the step's postcondition held is the runner's to check."""

    result: ResultCode
    detail: Optional[ShortText] = None


@dataclass(frozen=True)
class ResetResult(QAValue):
    scope: ResetScope
    ok: bool


@runtime_checkable
class QAAdapter(Protocol):
    adapter_id: str
    adapter_version: str
    api_version: str
    """``"qa-adapter/1"``."""

    def open_session(self, profile: SessionProfile) -> SessionHandle:
        """A fresh isolated context with the egress profile applied."""
        ...

    def observe(self, s: SessionHandle, req: ObserveRequest) -> Observation: ...

    def locate(self, s: SessionHandle, target: LocatorDescriptor, *, mode: LocateMode) -> LocateResult:
        """Every candidate. No side effects."""
        ...

    def act(self, s: SessionHandle, action: ActionRequest, target: ResolvedTarget) -> ActionOutcome:
        """Raw result, no verdict. Refused with ``ActionBlockedByPolicy`` without a policy decision reference."""
        ...

    def assert_(self, s: SessionHandle, subject: AssertionSubject) -> ObservedValue:
        """Reads the actual value. No expected value in, no verdict out."""
        ...

    def capture(self, s: SessionHandle, kinds: Sequence[CaptureKind]) -> Sequence[EvidenceRef]:
        """Redacted artifacts only. ``RedactionFailed`` on failure."""
        ...

    def reset(self, s: SessionHandle, scope: ResetScope) -> ResetResult: ...

    def close_session(self, s: SessionHandle) -> CleanupReport:
        """Verifiable cleanup."""
        ...
