"""InvestigationTransitionEvent — a historical fact about one move.

It records what happened. It does **not** record whether it was allowed: that is
derived from the pinned `MissionProgram`, so an event cannot assert its own
legitimacy. An event carrying `permitted: true` would be checkable only against
itself.

What it does persist is the `VerificationResult` received *at the time*. The
program says which check was required; the event says what that check returned
when it ran. A year later the program may have changed, and the question "what
did the gate say then?" must still be answerable.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from ..canonical import CONTRACT_VERSION, content_hash
from .events import EventKind, Intent, RuntimeEvent
from .mission import MissionProgram, Transition, TransitionRefused
from .verification import VerificationResult, Verdict
from .visibility import Visibility


@dataclass(frozen=True)
class OwnershipChange:
    """Who held it before and after. Absent when ownership did not move."""

    from_actor: Optional[str]
    to_actor: Optional[str]

    def canonical_form(self) -> Dict[str, Any]:
        return {"from_actor": self.from_actor, "to_actor": self.to_actor}


@dataclass(frozen=True)
class InvestigationTransitionEvent:
    """One state change, as it happened."""

    SCHEMA_ID: str = field(
        default="runtime-contracts/investigation-transition-event",
        init=False, repr=False)

    investigation_id: str
    program_id: str
    program_version: str
    program_hash: str
    """The exact program pinned when this ran. Permission is re-derivable only
    against the program that was in force, not against today's."""

    transition_id: str
    from_state: str
    to_state: str
    actor: str
    sequence: int
    mission_id: Optional[str] = None
    terminal_outcome: Optional[str] = None
    """Required entering a terminal state, forbidden otherwise. Where an inquiry
    ended does not say what it ended with."""

    reason: str = ""
    evidence_refs: Sequence[str] = ()
    verification: Optional[VerificationResult] = None
    ownership_change: Optional[OwnershipChange] = None
    verification_result_ref: Optional[str] = None
    parent_event_id: Optional[str] = None
    parents: Sequence[str] = ()
    """Partial-order causal parents (transition_ids this event follows). Empty = the classic total order
    by ``sequence``. Concurrent branches record multiple parents so a fan-out/join history is
    reconstructible without a single global sequence — see ``causal_order``. Additive: an event with no
    parents serialises and hashes exactly as before."""
    visibility: Visibility = Visibility.INTERNAL
    tenant_id: Optional[str] = None
    occurred_at: Optional[str] = None
    schema_version: str = CONTRACT_VERSION

    def __post_init__(self) -> None:
        if self.sequence < 0:
            raise ValueError(
                f"{self.investigation_id}: sequence {self.sequence} is negative; "
                "ordering would not be reconstructible")
        if self.ownership_change is not None:
            change = self.ownership_change
            if change.from_actor is None and change.to_actor is None:
                raise ValueError(
                    f"{self.investigation_id}: an ownership change naming neither "
                    "a prior nor a new owner records nothing")
        if self.verification is not None:
            target = self.verification.target_handle_hash
            if self.verification_result_ref and \
                    self.verification_result_ref != self.verification.result_hash:
                raise ValueError(
                    f"{self.investigation_id}: verification_result_ref does not "
                    "match the embedded result; a reference pointing at a "
                    "different verification than the one carried is worse than "
                    "no reference")
            del target

    def public_leak(self) -> List[str]:
        """Private evidence references on a public event.

        A public event citing a private artifact is the boundary violation the
        whole visibility model exists to prevent, and an event is the easiest
        place for one to travel unnoticed.
        """
        if self.visibility is not Visibility.PUBLIC:
            return []
        return [ref for ref in self.evidence_refs
                if ref.split("/")[0] in {"mission", "intent", "plan-run",
                                          "scenario", "observation"}]

    def permitted_by(self, program: MissionProgram) -> Transition:
        """Re-derive permission from the pinned program.

        Raises when the program does not allow the move, or when the pinned
        hash does not match the program supplied — checking a transition against
        a *different* program than the one in force is a silent lie about what
        the rules were.
        """
        if program.content_hash != self.program_hash:
            raise TransitionRefused(
                f"{self.investigation_id}: this event pinned program "
                f"{self.program_hash[:16]}… and was checked against "
                f"{program.content_hash[:16]}…. Permission derived from the "
                "wrong program is not permission"
            )
        transition = program.require(from_state=self.from_state,
                                     to_state=self.to_state,
                                     transition_id=self.transition_id)

        if self.from_state == self.to_state and not transition.permits_self_transition():
            raise TransitionRefused(
                f"{self.investigation_id}: {self.from_state} -> {self.to_state} "
                "is a self-transition the program does not declare")

        is_terminal = program.state(self.to_state).terminal
        if is_terminal and not self.terminal_outcome:
            raise TransitionRefused(
                f"{self.investigation_id}: entered terminal state "
                f"{self.to_state!r} with no outcome recorded")
        if self.terminal_outcome and not is_terminal:
            raise TransitionRefused(
                f"{self.investigation_id}: recorded outcome "
                f"{self.terminal_outcome!r} on a non-terminal move")
        if self.terminal_outcome and transition.outcome != self.terminal_outcome:
            raise TransitionRefused(
                f"{self.investigation_id}: recorded outcome "
                f"{self.terminal_outcome!r} but {transition.transition_id!r} "
                f"produces {transition.outcome!r}")

        leaked = self.public_leak()
        if leaked:
            raise TransitionRefused(
                f"{self.investigation_id}: a public event cites private "
                f"artifacts {leaked}")

        return transition

    def satisfied_its_gate(self, program: MissionProgram) -> bool:
        """Whether the verification the program required actually passed.

        A required check with no recorded result is not satisfied. An absent
        result reads as "nobody ran it", which is the honest reading.
        """
        transition = self.permitted_by(program)
        if transition.verification_method is None:
            return True
        if self.verification is None:
            return False
        return self.verification.verdict is Verdict.PASS

    def canonical_form(self) -> Dict[str, Any]:
        d = {
            "schema_id": self.SCHEMA_ID,
            "schema_version": self.schema_version,
            "investigation_id": self.investigation_id,
            "program_id": self.program_id,
            "program_version": self.program_version,
            "program_hash": self.program_hash,
            "mission_id": self.mission_id,
            "transition_id": self.transition_id,
            "from_state": self.from_state,
            "to_state": self.to_state,
            "terminal_outcome": self.terminal_outcome,
            "actor": self.actor,
            "sequence": self.sequence,
            "evidence_refs": sorted(self.evidence_refs),
            "verification": (self.verification.canonical_form()
                             if self.verification else None),
            "verification_result_ref": self.verification_result_ref,
            "ownership_change": (self.ownership_change.canonical_form()
                                 if self.ownership_change else None),
            "parent_event_id": self.parent_event_id,
            "visibility": self.visibility.value,
            "tenant_id": self.tenant_id,
            # `reason` and `occurred_at` are excluded: prose and a clock reading.
            # The same transition, reworded, is the same transition.
        }
        # Only serialise partial-order parents when present, so an event with none hashes exactly as it
        # did before this field existed (backward-compatible event_hash).
        if self.parents:
            d["parents"] = list(self.parents)
        return d

    @property
    def event_hash(self) -> str:
        return content_hash(self.canonical_form())

    def as_runtime_event(self, *, event_id: str, stream_id: str,
                         emitted_by: str) -> RuntimeEvent:
        """Wrap in the common envelope so it joins one replayable stream."""
        return RuntimeEvent(
            event_id=event_id,
            kind=EventKind.INVESTIGATION_TRANSITION,
            intent=Intent.COMPLETED,
            stream_id=stream_id,
            sequence=self.sequence,
            emitted_by=emitted_by,
            payload=self.canonical_form(),
            parent_event_id=self.parent_event_id,
            visibility=self.visibility,
            tenant_id=self.tenant_id,
            evidence_refs=self.evidence_refs,
        )

    def to_json(self) -> Dict[str, Any]:
        return {**self.canonical_form(), "event_hash": self.event_hash,
                "reason": self.reason, "occurred_at": self.occurred_at}


def causal_order(events: Sequence[InvestigationTransitionEvent]) -> list:
    """A linearization that respects partial-order ``parents`` (each event follows all of its declared
    parents), tie-broken by ``sequence``. When no event declares parents this is exactly the sequence
    order — so a concurrent fan-out/join history and a classic total-order history both replay
    deterministically through the same function. Raises on a cycle or a dangling parent reference.
    """
    import heapq
    from collections import defaultdict

    by_id = {e.transition_id: e for e in events}
    indeg = {e.transition_id: 0 for e in events}
    children: dict = defaultdict(list)
    for e in events:
        for p in e.parents:
            if p in by_id:                     # only edges among this event set constrain the order
                indeg[e.transition_id] += 1
                children[p].append(e.transition_id)
    ready = [(by_id[i].sequence, i) for i, deg in indeg.items() if deg == 0]
    heapq.heapify(ready)
    out: list = []
    while ready:
        _, i = heapq.heappop(ready)
        out.append(by_id[i])
        for c in children[i]:
            indeg[c] -= 1
            if indeg[c] == 0:
                heapq.heappush(ready, (by_id[c].sequence, c))
    if len(out) != len(events):
        raise TransitionRefused("causal_order: parents form a cycle or reference a missing event")
    return out


def replay_states(events: Sequence[InvestigationTransitionEvent],
                  program: MissionProgram) -> str:
    """Walk a transition history and return the state it ends in.

    Every step is re-derived against the pinned program, so a history containing
    a move the program never permitted fails here rather than producing a state
    nobody could have reached.
    """
    ordered = sorted(events, key=lambda e: e.sequence)
    seen = set()
    for event in ordered:
        if event.sequence in seen:
            raise TransitionRefused(
                f"two events share sequence {event.sequence}; ordering is not "
                "reconstructible")
        seen.add(event.sequence)

    state = program.initial_state
    terminated = False
    for event in ordered:
        if terminated:
            raise TransitionRefused(
                "a second terminal transition follows one that already ended the "
                "inquiry")
        if event.from_state != state:
            raise TransitionRefused(
                f"history is not contiguous: at {state}, next event moves from "
                f"{event.from_state}"
            )
        event.permitted_by(program)
        state = event.to_state
        terminated = program.state(state).terminal
    return state
