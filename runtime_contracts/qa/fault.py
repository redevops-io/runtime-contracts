"""``FaultEvent``: detection and recovery as two separate records, recorded in that order.

A step that meets a fault produces a ``FaultDetection`` first. It is hashed on its own, before any recovery action
starts, so recovery cannot rewrite what was detected. The ``FaultRecovery`` that follows names the detection it
responds to by that hash (``detection_ref``), and its ``result`` is judged by the step's own postcondition
(``postcondition_verified``), never inferred from how the run ended. The run outcome is a third, separate field.

Because each field stands alone, all of these are representable: a false alarm (``detected`` with no fault), a miss
(a fault with ``detected = false``), a mis-recovery (``RECOVERED`` onto the wrong target) and a suppressed recovery.
The contract records them; deciding which one happened is not its job.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

from ..protocol.evidence import EvidenceRef
from .base import SCHEMA_ID_PREFIX, Code, CodeToken, Ident, NonNeg, QAContractError, QARecord, QAValue, Rcv1
from .enums import (ClaimedClass, FaultSignal, RecoveryReason, RecoveryResult, RecoveryStrategy, SuppressedReason)
from .records import _guard_evidence_refs
from .spec import ComponentRef


def _guard_detection_shape(d: "FaultDetection") -> None:
    if d.detected and d.signal is FaultSignal.NONE:
        raise QAContractError(Code.RECORD_INCONSISTENT, "a detection names its signal")
    if not d.detected and (d.signal is not FaultSignal.NONE or d.claimed_class is not ClaimedClass.UNKNOWN):
        raise QAContractError(Code.RECORD_INCONSISTENT, "no detection means signal NONE and claimed_class UNKNOWN")


@dataclass(frozen=True)
class FaultDetection(QARecord):
    """Written and hashed first."""

    SCHEMA_ID = SCHEMA_ID_PREFIX + "fault-detection"
    CUSTODY = frozenset({"detected_at_ms_into_step"})
    SET_FIELDS = {"evidence_refs": "@json"}

    detected: bool
    signal: FaultSignal
    claimed_class: ClaimedClass
    detector: ComponentRef
    evidence_refs: Tuple[EvidenceRef, ...] = ()
    detected_at_ms_into_step: Optional[NonNeg] = None

    def validate(self) -> None:
        _guard_detection_shape(self)
        _guard_evidence_refs("evidence_refs", self.evidence_refs)


@dataclass(frozen=True)
class RecoveryCost(QAValue):
    tokens: NonNeg = 0
    model_calls: NonNeg = 0
    ms: NonNeg = 0


def _guard_recovery_shape(r: "FaultRecovery") -> None:
    if r.attempted:
        if (r.strategy is RecoveryStrategy.NONE or r.attempts < 1 or r.result is RecoveryResult.NOT_ATTEMPTED
                or r.suppressed_reason is not SuppressedReason.NONE):
            raise QAContractError(Code.RECORD_INCONSISTENT, "an attempted recovery names its strategy, counts at "
                                  "least one attempt, has a result and is not suppressed")
    else:
        if (r.attempts != 0 or r.result is not RecoveryResult.NOT_ATTEMPTED or r.postcondition_verified):
            raise QAContractError(Code.RECORD_INCONSISTENT, "a recovery that was not attempted has zero attempts, "
                                  "result NOT_ATTEMPTED and no verified postcondition")
    if len(r.candidates_rejected_reasons) > r.candidates_considered:
        raise QAContractError(Code.RECORD_INCONSISTENT, "more rejection reasons than candidates considered")


def _guard_result_is_judged_by_the_postcondition(r: "FaultRecovery") -> None:
    if (r.result is RecoveryResult.RECOVERED) != r.postcondition_verified:
        raise QAContractError(Code.RECORD_INCONSISTENT, "RECOVERED exactly when the step's own postcondition was "
                              "verified; recovery is never inferred from the run's final outcome")


def _guard_reason_code(r: "FaultRecovery") -> None:
    if r.reason_code is not None and r.result is RecoveryResult.RECOVERED:
        raise QAContractError(Code.RECORD_INCONSISTENT, "a recovery that RECOVERED carries no reason_code; the "
                              "reason says why it did not")


@dataclass(frozen=True)
class FaultRecovery(QARecord):
    """Written second. Binds to the detection it responds to by hash.

    ``candidates_rejected_reasons`` is per candidate: one code for each candidate that was considered and rejected,
    in the order they were considered (a list, not a set, so order and repeats are identity), and never more of them
    than ``candidates_considered``. A recovery that stopped before it considered any candidate has nowhere to say
    why in that field; ``reason_code`` is where the recovery as a whole says why it did not recover.
    """

    SCHEMA_ID = SCHEMA_ID_PREFIX + "fault-recovery"
    CUSTODY = frozenset({"cost"})

    detection_ref: Rcv1
    attempted: bool
    strategy: RecoveryStrategy
    result: RecoveryResult
    postcondition_verified: bool
    suppressed_reason: SuppressedReason = SuppressedReason.NONE
    attempts: NonNeg = 0
    candidates_considered: NonNeg = 0
    candidates_rejected_reasons: Tuple[CodeToken, ...] = ()
    cost: Optional[RecoveryCost] = None
    reason_code: Optional[RecoveryReason] = None
    """Why the recovery as a whole did not recover. Optional, identity, closed vocabulary (``RecoveryReason``);
    absent equals null, so a recovery that omits it hashes exactly as it did before the field existed. Never set
    when ``result`` is ``RECOVERED``."""

    def validate(self) -> None:
        _guard_recovery_shape(self)
        _guard_result_is_judged_by_the_postcondition(self)
        _guard_reason_code(self)

    def responds_to(self, detection: FaultDetection) -> bool:
        return self.detection_ref == detection.content_hash


def _guard_fault_binding(e: "FaultEvent") -> None:
    if not e.recovery.responds_to(e.detection):
        raise QAContractError(Code.FAULT_BINDING_MISMATCH, f"fault event {e.fault_event_id}: recovery.detection_ref "
                              f"is {e.recovery.detection_ref}, not the hash of the detection "
                              f"({e.detection.content_hash}); recovery cannot rewrite what was detected")
    if not e.detection.detected and e.recovery.attempted:
        raise QAContractError(Code.RECORD_INCONSISTENT, f"fault event {e.fault_event_id}: recovery was attempted "
                              "though nothing was detected")


@dataclass(frozen=True)
class FaultEvent(QARecord):
    SCHEMA_ID = SCHEMA_ID_PREFIX + "fault-event"

    fault_event_id: Ident
    step_id: Ident
    sequence: NonNeg
    detection: FaultDetection
    recovery: FaultRecovery

    def validate(self) -> None:
        _guard_fault_binding(self)
