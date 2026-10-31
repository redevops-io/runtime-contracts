"""Run-side records: what was observed, what was done, what each assertion read and what was decided.

Identity versus custody follows the repository rule (``canonical.py``): what a record says enters the ``rcv1``
hash; who, when and how long (timestamps, durations, free-text rationale) do not. Durations are integer
milliseconds and money is a decimal string; floats are refused.

Only the verifier produces an ``AssertionResult``, from assertions loaded by content hash. An adapter reports raw
facts (``ObservedValue``, ``ActionOutcome``) and never a verdict; nothing here has a field through which an
adapter or a recovery module could express one.

These records say what happened. Nothing in them says how a run is judged from outside.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Annotated, Optional, Sequence, Tuple

from ..models.verification import Check, Determinism, Verdict
from ..models.capability import SideEffect
from ..protocol.evidence import EvidenceRef
from .base import (SCHEMA_ID_PREFIX, AnyDigest, BoundedJson, Code, CodeToken, Ident, Json, NonNeg, Pos,
                   QAContractError, QARecord, QAValue, Rcv1, Rule, ShortText, Text, Version, value_digest)
from .enums import (VALUE_ACTIONS, ActionKind, Executor, LocatorStrategy, Phase, PolicyDecisionKind,
                    PostconditionResult, Resolution, ResultCode, ReviewDecision)
from .spec import Action, ComponentRef, LocatorDescriptor, ResourceRef

Url = Annotated[str, Rule(min_length=1, max_length=2048)]
_BLOB_OR_RECORD = re.compile(r"(rcv1|sha256):[0-9a-f]{64}")
_PIN = re.compile(r".+@.*#(rcv1|sha256):[0-9a-f]{64}")


def _guard_evidence_ref(name: str, ref: EvidenceRef) -> None:
    """An evidence reference carries the full-width digest of what it names. A truncated or absent digest is not
    evidence, so it is refused rather than stored."""
    if not _BLOB_OR_RECORD.fullmatch(ref.content_hash or ""):
        raise QAContractError(Code.INVALID_FIELD, f"{name}: evidence {ref.ref!r} has no full-width "
                              "rcv1 or sha256 digest")


def _guard_evidence_refs(name: str, refs: Sequence[EvidenceRef]) -> None:
    for ref in refs:
        _guard_evidence_ref(name, ref)


# ── observation ────────────────────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ObservationSource(QAValue):
    adapter: Ident
    adapter_version: Version
    browser: Optional[ShortText] = None
    browser_version: Optional[ShortText] = None


def _guard_url_has_no_credentials(url: str) -> None:
    authority = url.split("://", 1)[-1].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in authority:
        raise QAContractError(Code.INVALID_FIELD, "a recorded url carries no userinfo (credentials in a url are "
                              "never stored)")


def _guard_raw_artifacts_are_redacted(o: "Observation") -> None:
    captured = (o.a11y_snapshot_ref, o.screenshot_ref, o.network_excerpt_ref, o.console_excerpt_ref)
    if any(r is not None for r in captured) and not o.redaction_applied:
        raise QAContractError(Code.RECORD_INCONSISTENT, f"observation {o.observation_id} references a captured "
                              "artifact but redaction_applied is false; an unredacted artifact is never recorded")


@dataclass(frozen=True)
class Observation(QARecord):
    """A bounded view of the page or resource at one moment of one step."""

    SCHEMA_ID = SCHEMA_ID_PREFIX + "observation"
    CUSTODY = frozenset({"observed_at", "duration_ms"})

    observation_id: Ident
    step_id: Ident
    phase: Phase
    source: ObservationSource
    redaction_policy_id: AnyDigest
    redaction_applied: bool
    url: Optional[Url] = None
    frame: Optional[ShortText] = None
    a11y_snapshot_ref: Optional[EvidenceRef] = None
    dom_meta: Optional[BoundedJson] = None
    screenshot_ref: Optional[EvidenceRef] = None
    network_excerpt_ref: Optional[EvidenceRef] = None
    console_excerpt_ref: Optional[EvidenceRef] = None
    observed_at: Optional[ShortText] = None
    duration_ms: Optional[NonNeg] = None

    def validate(self) -> None:
        for name in ("a11y_snapshot_ref", "screenshot_ref", "network_excerpt_ref", "console_excerpt_ref"):
            ref = getattr(self, name)
            if ref is not None:
                _guard_evidence_ref(name, ref)
        if self.url is not None:
            _guard_url_has_no_credentials(self.url)
        _guard_raw_artifacts_are_redacted(self)


# ── action receipt ─────────────────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ToolRef(QAValue):
    name: Ident
    version: Version


@dataclass(frozen=True)
class LocatorUsed(QAValue):
    """Which locator the action actually used. The authored descriptor is frozen in the spec; this is the fact."""

    descriptor: LocatorDescriptor
    strategy: LocatorStrategy


@dataclass(frozen=True)
class ActionRecord(QAValue):
    """The action taken. A value is never recorded, only its digest."""

    kind: ActionKind
    value_digest: Optional[Rcv1] = None

    def validate(self) -> None:
        if (self.kind in VALUE_ACTIONS) != (self.value_digest is not None):
            raise QAContractError(Code.RECORD_INCONSISTENT, f"{self.kind.value} "
                                  f"{'needs' if self.kind in VALUE_ACTIONS else 'takes no'} value_digest")


def action_value_digest(action: Action) -> Optional[str]:
    """``ActionRecord.value_digest`` for an action: the ``value_digest`` of its literal value, or the fingerprint of
    its ``SecretRef`` (the ``rcv1`` hash of the reference, never of the secret it resolves to), or ``None`` for an
    action that carries neither. Nothing about the action's kind enters the digest."""
    if action.value is not None:
        return value_digest(action.value)
    if action.secret_ref is not None:
        return action.secret_ref.fingerprint()
    return None


@dataclass(frozen=True)
class Postcondition(QAValue):
    declared: Annotated[str, Rule(min_length=1, max_length=1024)]
    result: PostconditionResult
    observed: Optional[ShortText] = None


def _guard_postcondition_follows_result(r: "ActionReceipt") -> None:
    if r.postcondition.result is PostconditionResult.SATISFIED and r.result is not ResultCode.OK:
        raise QAContractError(Code.RECORD_INCONSISTENT, f"receipt {r.receipt_id}: the action ended "
                              f"{r.result.value} but its postcondition is recorded as satisfied")
    if r.postcondition.result is not PostconditionResult.NOT_EVALUATED and r.postcondition.observed is None:
        raise QAContractError(Code.RECORD_INCONSISTENT, f"receipt {r.receipt_id}: an evaluated postcondition "
                              "records what was observed")


def _guard_one_target_used(r: "ActionReceipt") -> None:
    if (r.locator_used is None) == (r.resource_used is None):
        raise QAContractError(Code.RECORD_INCONSISTENT, f"receipt {r.receipt_id} names exactly one of "
                              "locator_used (ui) and resource_used (resource)")


def _guard_blocked_action_changed_nothing(r: "ActionReceipt") -> None:
    if r.result is ResultCode.ACTION_BLOCKED_BY_POLICY and r.state_after_hash != r.state_before_hash:
        raise QAContractError(Code.RECORD_INCONSISTENT, f"receipt {r.receipt_id}: an action blocked by policy "
                              "left the state unchanged")


@dataclass(frozen=True)
class ActionReceipt(QARecord):
    """What one attempt of one step did. Written by the harness runner; the adapter reports the raw outcome.

    ``policy_decision_ref`` is required, including for a blocked action: every ``ui_action`` decision, allow or
    deny, is recorded and referenced here, and an action without a reference is refused by the adapter.
    """

    SCHEMA_ID = SCHEMA_ID_PREFIX + "action-receipt"
    CUSTODY = frozenset({"duration_ms", "recovery_rationale"})

    receipt_id: Ident
    run_id: Ident
    step_id: Ident
    attempt: Pos
    tool: ToolRef
    action: ActionRecord
    state_before_hash: Rcv1
    state_after_hash: Rcv1
    policy_decision_ref: Rcv1
    idempotency_key: Ident
    postcondition: Postcondition
    result: ResultCode
    locator_used: Optional[LocatorUsed] = None
    resource_used: Optional[ResourceRef] = None
    execution_binding: Optional[Rcv1] = None
    """The ``ExecutionEnvelope`` binding or ``ExecutionReceipt`` id when the step ran under an envelope. No third
    receipt shape: this is a reference to the existing one."""

    duration_ms: Optional[NonNeg] = None
    recovery_rationale: Optional[Text] = None

    def validate(self) -> None:
        _guard_one_target_used(self)
        _guard_postcondition_follows_result(self)
        _guard_blocked_action_changed_nothing(self)


# ── policy decision ────────────────────────────────────────────────────────────────────────────────────────

UI_ACTION_PHASE = "ui_action"


def _guard_phase(d: "QAPolicyDecision") -> None:
    if d.phase != UI_ACTION_PHASE:
        raise QAContractError(Code.INVALID_FIELD, f"policy decision phase is {d.phase!r}; qa/v1 records "
                              f"{UI_ACTION_PHASE!r} decisions")


@dataclass(frozen=True)
class QAPolicyDecision(QARecord):
    """One ``ui_action`` policy decision. Every decision, allow or deny, is recorded; the receipt cites its hash.

    ``rule_id`` is absent when no rule matched and the default (deny) applied.
    """

    SCHEMA_ID = SCHEMA_ID_PREFIX + "policy-decision"
    CUSTODY = frozenset({"reason", "decided_at"})
    SET_FIELDS = {"scope": None}

    policy_decision_id: Ident
    run_id: Ident
    step_id: Ident
    principal: ShortText
    app: Ident
    decision: PolicyDecisionKind
    provider: Ident
    action_kind: ActionKind
    side_effect: SideEffect
    scope: Tuple[ShortText, ...] = ()
    rule_id: Optional[Ident] = None
    phase: Annotated[str, Rule(max_length=32)] = UI_ACTION_PHASE
    reason: Optional[Text] = None
    decided_at: Optional[ShortText] = None

    def validate(self) -> None:
        _guard_phase(self)


# ── recovery candidates ────────────────────────────────────────────────────────────────────────────────────

def _guard_candidate_strategy(c: "LocatorCandidate") -> None:
    if c.strategy is LocatorStrategy.AUTHORED:
        raise QAContractError(Code.INVALID_FIELD, "a recovery candidate is never the authored locator")


@dataclass(frozen=True)
class LocatorCandidate(QARecord):
    """The only thing recovery may express: "try this locator". Strict by construction: no free-form field, no
    assertion field, and ``from_json`` refuses any key it does not define."""

    SCHEMA_ID = SCHEMA_ID_PREFIX + "locator-candidate"

    strategy: LocatorStrategy
    role: Optional[ShortText] = None
    name: Optional[ShortText] = None
    test_id: Optional[ShortText] = None
    label: Optional[ShortText] = None

    def validate(self) -> None:
        _guard_candidate_strategy(self)
        if not any((self.role, self.name, self.test_id, self.label)):
            raise QAContractError(Code.INVALID_FIELD, "a locator candidate needs at least one of role, name, "
                                  "test_id or label")

    def as_descriptor(self) -> LocatorDescriptor:
        return LocatorDescriptor(role=self.role, name=self.name, test_id=self.test_id, label=self.label)


# ── what an adapter read, and the verdict-free report of it ─────────────────────────────────────────────────

def _guard_resolution_shape(v: "ObservedValue") -> None:
    ok = {Resolution.RESOLVED: v.match_count == 1,
          Resolution.UNRESOLVED: v.match_count == 0 and v.value is None and v.value_digest is None,
          Resolution.AMBIGUOUS: v.match_count >= 2 and v.value is None and v.value_digest is None}[v.resolution]
    if not ok or (v.value is not None and v.value_digest is not None):
        raise QAContractError(Code.RECORD_INCONSISTENT, f"observed value does not fit resolution "
                              f"{v.resolution.value} with {v.match_count} match(es)")


@dataclass(frozen=True)
class ObservedValue(QARecord):
    """What ``assert_`` or ``run_check`` read. There is no expected value and no verdict in this type: the
    verifier compares, and only the verifier."""

    SCHEMA_ID = SCHEMA_ID_PREFIX + "observed-value"

    resolution: Resolution
    match_count: NonNeg
    value: Optional[Json] = None
    value_digest: Optional[Rcv1] = None
    """Carried instead of ``value`` when the value is sensitive."""

    observation_id: Optional[Ident] = None

    def validate(self) -> None:
        _guard_resolution_shape(self)


# ── assertion result ───────────────────────────────────────────────────────────────────────────────────────

def _guard_result_shape(r: "AssertionResult") -> None:
    c = r.check
    if c.check_id != r.assertion_id:
        raise QAContractError(Code.RECORD_INCONSISTENT, f"the embedded check is {c.check_id!r}, not "
                              f"{r.assertion_id!r}")
    if c.verdict is Verdict.NOT_APPLICABLE:
        raise QAContractError(Code.RECORD_INCONSISTENT, "a gating assertion is never NOT_APPLICABLE; one that "
                              "does not arise is skipped, with a reason, in the manifest")
    for pin in c.evidence_refs:
        if not _PIN.fullmatch(pin):
            raise QAContractError(Code.INVALID_FIELD, f"evidence ref {pin!r} is not a ref@version#digest pin "
                                  "with a full-width digest")
    if r.actual is not None and r.actual_digest is not None:
        raise QAContractError(Code.RECORD_INCONSISTENT, "carry actual or actual_digest, not both")
    if c.verdict.is_conclusive:
        if c.determinism is not Determinism.DETERMINISTIC:
            raise QAContractError(Code.RECORD_INCONSISTENT, "a PASS or FAIL verdict is deterministic; a "
                                  "non-deterministic judgement is INDETERMINATE evidence, never a gate")
        if r.reason_code is not None:
            raise QAContractError(Code.RECORD_INCONSISTENT, "a conclusive verdict carries no reason_code")
        if r.actual is None and r.actual_digest is None:
            raise QAContractError(Code.RECORD_INCONSISTENT, "a conclusive verdict records what was read "
                                  "(actual or actual_digest)")
    elif r.reason_code is None:
        raise QAContractError(Code.RECORD_INCONSISTENT, "an INDETERMINATE result states why (reason_code, for "
                              "example SUBJECT_UNRESOLVED)")


@dataclass(frozen=True)
class AssertionResult(QARecord):
    """What the verifier concluded for one frozen assertion. Embeds the contract ``Check``.

    Repeats the hashes the verifier loaded under (``assertion_set_hash``, ``expected_hash``) and mirrors the
    ``executor``: a result whose executor differs from the frozen assertion's is refused
    (``integrity.check_result_matches_assertion``).
    """

    SCHEMA_ID = SCHEMA_ID_PREFIX + "assertion-result"
    CUSTODY = frozenset({"evaluated_at"})

    assertion_id: Ident
    assertion_set_hash: Rcv1
    expected_hash: Rcv1
    executor: Executor
    verifier: ComponentRef
    check: Check
    reason_code: Optional[CodeToken] = None
    observation_id: Optional[Ident] = None
    actual: Optional[Json] = None
    actual_digest: Optional[Rcv1] = None
    evaluated_at: Optional[ShortText] = None

    def validate(self) -> None:
        _guard_result_shape(self)

    @property
    def verdict(self) -> Verdict:
        return self.check.verdict

    @property
    def determinism(self) -> Determinism:
        return self.check.determinism

    @property
    def evidence_refs(self) -> Tuple[str, ...]:
        return tuple(self.check.evidence_refs)


# ── checkpoint, review, cleanup ────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Checkpoint(QARecord):
    """An in-run resume point. Carries a state hash and a fixture snapshot id; never browser storage state."""

    SCHEMA_ID = SCHEMA_ID_PREFIX + "checkpoint"
    CUSTODY = frozenset({"taken_at"})

    checkpoint_id: Ident
    run_id: Ident
    step_index: NonNeg
    state_hash: Rcv1
    fixture_snapshot_id: Optional[Ident] = None
    taken_at: Optional[ShortText] = None


@dataclass(frozen=True)
class ReviewItem(QARecord):
    """A request for a human to look. An INCONCLUSIVE run always creates one; it is never counted as a pass."""

    SCHEMA_ID = SCHEMA_ID_PREFIX + "review-item"
    CUSTODY = frozenset({"created_at"})
    SET_FIELDS = {"evidence_refs": "@json"}

    review_item_id: Ident
    run_id: Ident
    reason: CodeToken
    evidence_refs: Tuple[EvidenceRef, ...] = ()
    suggested_change_ref: Optional[Rcv1] = None
    created_at: Optional[ShortText] = None

    def validate(self) -> None:
        _guard_evidence_refs("evidence_refs", self.evidence_refs)


@dataclass(frozen=True)
class ReviewRecord(QARecord):
    """A later, appended decision about a review item. Separate from the run manifest, so the manifest is
    immutable once recorded. Reviewer identity and time spent are custody."""

    SCHEMA_ID = SCHEMA_ID_PREFIX + "review-record"
    CUSTODY = frozenset({"reviewer_id", "review_minutes", "decided_at"})

    review_item_ref: Rcv1
    decision: ReviewDecision
    reviewer_id: Optional[ShortText] = None
    review_minutes: Optional[NonNeg] = None
    decided_at: Optional[ShortText] = None


def _guard_cleanup(c: "CleanupReport") -> None:
    if c.verified and c.leaked:
        raise QAContractError(Code.RECORD_INCONSISTENT, "cleanup cannot be verified while resources leaked")


@dataclass(frozen=True)
class CleanupReport(QARecord):
    """What ``close_session`` or ``close_workspace`` left behind. Feeds the verified-cleanup gate."""

    SCHEMA_ID = SCHEMA_ID_PREFIX + "cleanup-report"
    CUSTODY = frozenset({"closed_at"})
    SET_FIELDS = {"released": None, "leaked": None}

    handle_id: Ident
    verified: bool
    released: Tuple[Ident, ...] = ()
    leaked: Tuple[Ident, ...] = ()
    closed_at: Optional[ShortText] = None

    def validate(self) -> None:
        _guard_cleanup(self)

