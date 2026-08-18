"""Submission semantics and replay — the contract a transition ledger implements.

Two things every real consumer needs and would otherwise each invent:

**Idempotent submission.** The moment retries, queues or Discovery delivery
exist, the same transition arrives twice. Resubmitting an identical event must
be a no-op, and resubmitting the *same id with a different body* must be a hard
conflict — silently accepting the second would let a redelivery quietly rewrite
history, which is the one thing an append-only ledger promises it cannot.

**Replay as the source of truth.** Current state is derived from the initial
state, the pinned program and the ordered events. Persisting `current_state` as
an independent fact means two answers to one question, and the stored one wins
exactly when it is wrong.

`permitted_then` and `current_program_would_permit` are kept apart. The first is
history and cannot change. The second is an audit question, and answering it must
never rewrite the first.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Sequence

from .investigation import InvestigationTransitionEvent
from .mission import MissionProgram, TransitionRefused
from .verification import Verdict


class SubmissionOutcome(str, Enum):
    ACCEPTED = "ACCEPTED"
    DUPLICATE = "DUPLICATE"
    """Same id, identical body. A no-op, and the correct answer to a retry."""

    CONFLICT = "CONFLICT"
    """Same id, different body. Refused: a redelivery must not rewrite history."""

    REFUSED = "REFUSED"
    """The pinned program does not permit it."""


@dataclass(frozen=True)
class SubmissionResult:
    outcome: SubmissionOutcome
    event_id: str
    reason: str = ""

    @property
    def stored(self) -> bool:
        return self.outcome is SubmissionOutcome.ACCEPTED

    @property
    def is_error(self) -> bool:
        return self.outcome in {SubmissionOutcome.CONFLICT,
                                SubmissionOutcome.REFUSED}

    def to_json(self) -> Dict[str, Any]:
        return {"outcome": self.outcome.value, "event_id": self.event_id,
                "reason": self.reason, "stored": self.stored}


def submit(
    event: InvestigationTransitionEvent,
    *,
    event_id: str,
    existing: Mapping[str, str],
    program: MissionProgram,
) -> SubmissionResult:
    """Decide what to do with an arriving transition.

    `existing` maps already-stored event ids to their canonical event hashes —
    the hash, not the body, because the comparison is about whether the same
    fact arrived twice and prose is not part of the fact.
    """
    previous = existing.get(event_id)
    if previous is not None:
        if previous == event.event_hash:
            return SubmissionResult(
                SubmissionOutcome.DUPLICATE, event_id,
                "identical body already stored; retry absorbed")
        return SubmissionResult(
            SubmissionOutcome.CONFLICT, event_id,
            f"event {event_id} is already stored with a different body. A "
            "redelivery that changed content is not a retry, and accepting it "
            "would rewrite an append-only history")

    try:
        event.permitted_by(program)
    except TransitionRefused as exc:
        return SubmissionResult(SubmissionOutcome.REFUSED, event_id, str(exc))

    return SubmissionResult(SubmissionOutcome.ACCEPTED, event_id, "")


@dataclass(frozen=True)
class ReplayResult:
    """Everything derived from a history. Nothing here is stored."""

    current_state: str
    terminal_outcome: Optional[str] = None
    active_assignment: Optional[str] = None
    history: Sequence[InvestigationTransitionEvent] = ()
    invalid_events: Sequence[Dict[str, str]] = ()
    program_mismatches: Sequence[str] = ()
    verification_history: Sequence[Dict[str, Any]] = ()
    is_terminal: bool = False

    @property
    def can_transition(self) -> bool:
        """Whether the inquiry can move again. False once it has concluded."""
        return not self.is_terminal

    @property
    def is_consistent(self) -> bool:
        return not self.invalid_events and not self.program_mismatches

    def to_json(self) -> Dict[str, Any]:
        return {
            "current_state": self.current_state,
            "terminal_outcome": self.terminal_outcome,
            "active_assignment": self.active_assignment,
            "transition_count": len(self.history),
            "invalid_events": list(self.invalid_events),
            "program_mismatches": list(self.program_mismatches),
            "verification_history": list(self.verification_history),
            "is_terminal": self.is_terminal,
            "can_transition": self.can_transition,
            "is_consistent": self.is_consistent,
        }


def replay_ledger(
    events: Sequence[InvestigationTransitionEvent],
    program: MissionProgram,
    *,
    strict: bool = True,
) -> ReplayResult:
    """Derive current state from history and the pinned program.

    `strict` raises on the first invalid event. Non-strict collects them and
    keeps going, which is what an audit view needs — a single bad event should
    not make the rest of a history unreadable.
    """
    ordered = sorted(events, key=lambda e: e.sequence)
    seen_sequences = set()
    invalid: List[Dict[str, str]] = []
    mismatches: List[str] = []
    verifications: List[Dict[str, Any]] = []
    accepted: List[InvestigationTransitionEvent] = []

    state = program.initial_state
    assignment: Optional[str] = None
    outcome: Optional[str] = None
    terminal = False

    for event in ordered:
        def reject(reason: str) -> None:
            invalid.append({"sequence": str(event.sequence),
                            "transition_id": event.transition_id,
                            "reason": reason})
            if strict:
                raise TransitionRefused(reason)

        if event.sequence in seen_sequences:
            reject(f"duplicate sequence {event.sequence}; ordering is not "
                   "reconstructible")
            continue
        seen_sequences.add(event.sequence)

        if event.program_hash != program.content_hash:
            mismatches.append(
                f"sequence {event.sequence} pinned program "
                f"{event.program_hash[:16]}…")
            if strict:
                raise TransitionRefused(
                    f"sequence {event.sequence} pinned a different program")
            continue

        if terminal:
            reject("a transition follows one that already ended the inquiry")
            continue

        if event.from_state != state:
            reject(f"history is not contiguous: at {state}, next event moves "
                   f"from {event.from_state}")
            continue

        try:
            event.permitted_by(program)
        except TransitionRefused as exc:
            reject(str(exc))
            continue

        if event.verification is not None:
            verifications.append({
                "sequence": event.sequence,
                "transition_id": event.transition_id,
                "verdict": event.verification.verdict.value,
                "verifier": event.verification.verifier_id,
            })

        if event.ownership_change is not None:
            assignment = event.ownership_change.to_actor

        accepted.append(event)
        state = event.to_state
        outcome = event.terminal_outcome or outcome
        terminal = program.state(state).terminal

    return ReplayResult(
        current_state=state,
        terminal_outcome=outcome if terminal else None,
        active_assignment=assignment,
        history=tuple(accepted),
        invalid_events=tuple(invalid),
        program_mismatches=tuple(mismatches),
        verification_history=tuple(verifications),
        is_terminal=terminal,
    )


def permitted_then(event: InvestigationTransitionEvent,
                   pinned: MissionProgram) -> bool:
    """Was it allowed by the program in force at the time? History; immutable."""
    try:
        event.permitted_by(pinned)
        return True
    except TransitionRefused:
        return False


def current_program_would_permit(event: InvestigationTransitionEvent,
                                 current: MissionProgram) -> bool:
    """Would today's program allow it? An audit comparison only.

    Never rewrites history. A `False` here means the rules changed, not that the
    recorded transition was wrong when it was made.
    """
    return current.permits(from_state=event.from_state,
                           to_state=event.to_state,
                           transition_id=event.transition_id) is not None


#: Outcomes and what they may emit. The routing rule the first Phase B slice
#: enforces: the absence path is proven before anything generates a Finding.
def finding_requirement(program: MissionProgram, outcome_id: str) -> str:
    """`FORBIDDEN`, `REQUIRED` — derived from the program, never hardcoded."""
    outcome = program.outcome(outcome_id)
    return "REQUIRED" if outcome.emits_artifact_kinds else "FORBIDDEN"


def check_finding_routing(program: MissionProgram, outcome_id: str,
                          finding_refs: Sequence[str]) -> Optional[str]:
    """Whether the findings attached to an outcome are what it permits."""
    requirement = finding_requirement(program, outcome_id)
    if requirement == "FORBIDDEN" and finding_refs:
        return (f"{outcome_id} emits nothing, but {len(finding_refs)} finding(s) "
                "were attached. A null result that produced a finding has "
                "mislabelled its own outcome")
    if requirement == "REQUIRED" and not finding_refs:
        return (f"{outcome_id} requires at least one finding and none was "
                "referenced. An uncited conclusion cannot be reviewed")
    return None
