"""``RunManifest``: the pins a run started under and the outcome it ended with.

The assertion coverage lists are hashed, order-independent sets: ``assertions_declared`` (the spec's frozen set),
``assertions_executed`` (a result was produced, any verdict) and ``assertions_skipped`` (each with a reason). The
invariants are ``declared == executed | skipped`` and ``executed & skipped == {}``. A manifest that breaks them can
still be recorded, because the record of a violation must exist, but only as ``INCONCLUSIVE(ASSERTION_INTEGRITY)``;
claiming anything else is refused. A ``PASS`` requires every declared assertion executed and passed, nothing
skipped and every detected fault recovered by its own postcondition.

No ground truth and no scoring field is carried here. A manifest cannot tell a run what it is being tested against.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Optional, Tuple

from ..models.verification import Determinism, Verdict
from .base import (SCHEMA_ID_PREFIX, AnyDigest, BoundedJson, Code, CodeToken, Ident, NonNeg, Pos,
                   QAContractError, QARecord, QAValue, Rcv1, Revision, Rule, Sha256, ShortText, SpecRefStr,
                   Version, AssertionIntegrityError)
from .enums import Outcome, PostconditionResult, ResultCode, SkipReason
from .fault import FaultEvent
from .integrity import integrity_violations
from .records import AssertionResult
from .spec import ComponentRef

TraceId = Annotated[str, Rule(pattern=r"[0-9a-f]{32}")]
Decimal = Annotated[str, Rule(pattern=r"-?(0|[1-9][0-9]*)(\.[0-9]*[1-9])?")]


@dataclass(frozen=True)
class SkippedAssertion(QAValue):
    assertion_id: Ident
    reason_code: SkipReason


@dataclass(frozen=True)
class VersionPin(QAValue):
    """A component the run depended on, pinned by version and, where known, revision."""

    component: Ident
    version: Version
    revision: Optional[Revision] = None


@dataclass(frozen=True)
class ModelRef(QAValue):
    provider: Ident
    model_id: ShortText
    parameters: Optional[BoundedJson] = None


@dataclass(frozen=True)
class StepResult(QAValue):
    """How one attempted step ended. ``receipts`` are the ``content_hash`` of each attempt's ``ActionReceipt``."""

    step_id: Ident
    result: ResultCode
    postcondition: PostconditionResult
    receipts: Tuple[Rcv1, ...]

    def validate(self) -> None:
        if not self.receipts:
            raise QAContractError(Code.RECORD_INCONSISTENT, f"step {self.step_id} was attempted, so it has at "
                                  "least one receipt")

    @property
    def attempts(self) -> int:
        return len(self.receipts)


@dataclass(frozen=True)
class Counters(QAValue):
    """Cost counters. Custody: they describe the run and are not part of what it was."""

    tokens: NonNeg = 0
    model_calls: NonNeg = 0
    infrastructure_ms: NonNeg = 0
    cost: Optional[Decimal] = None
    """Money as a decimal string, never a float."""


def _guard_manifest_integrity(m: "RunManifest") -> None:
    violations = integrity_violations(
        declared=m.assertions_declared, executed=m.assertions_executed,
        skipped=[s.assertion_id for s in m.assertions_skipped],
        results=[(r.assertion_id, r.assertion_set_hash) for r in m.assertion_results],
        assertion_set_hash=m.assertion_set_hash)
    if violations and (m.outcome is not Outcome.INCONCLUSIVE or m.outcome_reason != Code.ASSERTION_INTEGRITY):
        raise AssertionIntegrityError(
            Code.COVERAGE_VIOLATION,
            f"run {m.run_id} breaks the assertion accounting ({', '.join(violations)}); the only outcome it can "
            "carry is INCONCLUSIVE with outcome_reason ASSERTION_INTEGRITY")
    if not violations and m.outcome_reason == Code.ASSERTION_INTEGRITY:
        raise QAContractError(Code.RECORD_INCONSISTENT, "ASSERTION_INTEGRITY is claimed but the assertion "
                              "accounting is consistent")


def _guard_pass_is_earned(m: "RunManifest") -> None:
    if m.outcome is not Outcome.PASS:
        return
    why = []
    if not m.assertions_declared:
        why.append("no assertion declared")
    if m.assertions_skipped:
        why.append("an assertion was skipped")
    if set(m.assertions_executed) != set(m.assertions_declared):
        why.append("not every declared assertion was executed")
    if any(r.verdict is not Verdict.PASS or r.determinism is not Determinism.DETERMINISTIC for r in m.assertion_results):
        why.append("an assertion did not pass deterministically")
    if any(s.result is not ResultCode.OK or s.postcondition is not PostconditionResult.SATISFIED
           for s in m.step_results):
        why.append("a step did not end OK with its postcondition satisfied")
    if any(e.detection.detected and not e.recovery.postcondition_verified for e in m.fault_events):
        why.append("a detected fault was not recovered by its own postcondition")
    if why:
        raise QAContractError(Code.RECORD_INCONSISTENT, f"run {m.run_id} cannot be PASS: " + "; ".join(why))


def _guard_product_fail_has_a_failure(m: "RunManifest") -> None:
    if m.outcome is Outcome.PRODUCT_FAIL and not any(r.verdict is Verdict.FAIL for r in m.assertion_results):
        raise QAContractError(Code.RECORD_INCONSISTENT, f"run {m.run_id} is PRODUCT_FAIL but no deterministic "
                              "assertion evaluated FAIL")


def _guard_recovery_flags(m: "RunManifest") -> None:
    if m.model_recovery_enabled and not (m.recovery_enabled and m.model is not None):
        raise QAContractError(Code.RECORD_INCONSISTENT, "model recovery needs recovery enabled and a model "
                              "recorded in the manifest")
    if (m.planner is None) != (m.plan_hash is None):
        raise QAContractError(Code.RECORD_INCONSISTENT, "planner and plan_hash are recorded together or not at all")


@dataclass(frozen=True)
class RunManifest(QARecord):
    SCHEMA_ID = SCHEMA_ID_PREFIX + "run-manifest"
    CUSTODY = frozenset({"counters", "started_at", "finished_at"})
    SET_FIELDS = {"versions": "component", "assertions_declared": None, "assertions_executed": None,
                  "assertions_skipped": "assertion_id", "step_results": "step_id",
                  "assertion_results": "assertion_id"}

    run_id: Ident
    spec_ref: SpecRefStr
    assertion_set_hash: Rcv1
    adapter: ComponentRef
    egress_policy_id: AnyDigest
    redaction_policy_id: AnyDigest
    trace_id: TraceId
    recovery_enabled: bool
    model_recovery_enabled: bool
    assertions_declared: Tuple[Ident, ...]
    assertions_executed: Tuple[Ident, ...]
    assertions_skipped: Tuple[SkippedAssertion, ...]
    outcome: Outcome
    versions: Tuple[VersionPin, ...] = ()
    plan_hash: Optional[Rcv1] = None
    planner: Optional[ComponentRef] = None
    browser: Optional[ShortText] = None
    model: Optional[ModelRef] = None
    seeds: Tuple[int, ...] = ()
    sandbox_image_digest: Optional[Sha256] = None
    resource_limits: Optional[BoundedJson] = None
    step_results: Tuple[StepResult, ...] = ()
    assertion_results: Tuple[AssertionResult, ...] = ()
    fault_events: Tuple[FaultEvent, ...] = ()
    outcome_reason: Optional[CodeToken] = None
    counters: Optional[Counters] = None
    started_at: Optional[ShortText] = None
    finished_at: Optional[ShortText] = None

    def validate(self) -> None:
        _guard_recovery_flags(self)
        ids = [e.fault_event_id for e in self.fault_events]
        if len(set(ids)) != len(ids):
            raise QAContractError(Code.DUPLICATE_ENTRY, "a fault event id appears twice")
        _guard_manifest_integrity(self)
        _guard_pass_is_earned(self)
        _guard_product_fail_has_a_failure(self)

    @property
    def manifest_hash(self) -> str:
        return self.content_hash
