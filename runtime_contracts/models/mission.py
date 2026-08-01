"""MissionProgram — the canonical lifecycle declaration.

    The program declares the lifecycle.  The running Mission records history.

Keeping those apart is what makes "was that transition allowed?" answerable a
year later, when the code that ran it is gone. The program is pinned by version
and hash; permission is *derived* from the pinned program rather than trusted
from the event claiming it.

**State and outcome are different things.** `CONCLUDED` is where an inquiry
ended; `INCONCLUSIVE` versus `FINDING_PRODUCED` is what it ended *with*. Folding
the second into the first would either multiply terminal states or lose the
distinction — and the distinction is the whole reason a null result is
recordable.

Capability is declared, never assumed: a program states whether it supports
pausing, cancellation, retries and compensation. Requiring every program to
support all four would put fictional semantics in the ones that do not.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set

from ..canonical import CONTRACT_VERSION, content_hash


class Disposition(str, Enum):
    """What a terminal outcome means, so a reader is not left inferring it."""

    PRODUCED_RESULT = "PRODUCED_RESULT"
    PRODUCED_NOTHING = "PRODUCED_NOTHING"
    """Concluded, carefully, with nothing to show. A finding of absence, not an
    absence of finding."""

    STOPPED = "STOPPED"
    """Ended without concluding."""


class ApproverType(str, Enum):
    NONE = "NONE"
    HUMAN = "HUMAN"
    DETERMINISTIC_VERIFIER = "DETERMINISTIC_VERIFIER"
    HUMAN_AND_VERIFIER = "HUMAN_AND_VERIFIER"

    @property
    def needs_verifier(self) -> bool:
        return self in {ApproverType.DETERMINISTIC_VERIFIER,
                        ApproverType.HUMAN_AND_VERIFIER}


@dataclass(frozen=True)
class ApprovalGate:
    approver: ApproverType
    policy: str = ""

    def __post_init__(self) -> None:
        if self.approver is not ApproverType.NONE and not self.policy:
            raise ValueError(
                f"an {self.approver.value} gate with no policy names who must "
                "approve without saying against what — unreviewable by design"
            )

    def canonical_form(self) -> Dict[str, Any]:
        return {"approver": self.approver.value, "policy": self.policy or None}


NO_APPROVAL = ApprovalGate(ApproverType.NONE)


@dataclass(frozen=True)
class TerminalOutcome:
    outcome_id: str
    disposition: Disposition
    emits_artifact_kinds: Sequence[str] = ()
    description: str = ""

    def canonical_form(self) -> Dict[str, Any]:
        return {"outcome_id": self.outcome_id,
                "disposition": self.disposition.value,
                "emits_artifact_kinds": sorted(self.emits_artifact_kinds),
                "description": self.description or None}

    def semantic_form(self) -> Dict[str, Any]:
        return {"outcome_id": self.outcome_id,
                "disposition": self.disposition.value,
                "emits_artifact_kinds": sorted(self.emits_artifact_kinds)}


@dataclass(frozen=True)
class State:
    state_id: str
    terminal: bool = False
    description: str = ""

    def canonical_form(self) -> Dict[str, Any]:
        return {"state_id": self.state_id, "terminal": self.terminal,
                "description": self.description or None}

    def semantic_form(self) -> Dict[str, Any]:
        return {"state_id": self.state_id, "terminal": self.terminal}


@dataclass(frozen=True)
class Transition:
    """One permitted move. `from_states` is a list — several origins, one move."""

    transition_id: str
    from_states: Sequence[str]
    to_state: str
    outcome: Optional[str] = None
    """Required when `to_state` is terminal, forbidden otherwise."""

    approval: ApprovalGate = NO_APPROVAL
    verification_method: Optional[str] = None
    capability_id: Optional[str] = None
    retry_limit: int = 0
    compensation: Optional[str] = None
    timeout_seconds: Optional[int] = None
    emits_event_schema: str = "runtime-contracts/investigation-transition-event"
    description: str = ""

    def __post_init__(self) -> None:
        if not self.from_states:
            raise ValueError(f"{self.transition_id} has no origin state")
        if self.approval.approver.needs_verifier and not self.verification_method:
            raise ValueError(
                f"{self.transition_id} requires a verifier and names no "
                "verification_method — a gate nothing performs"
            )

    def permits_self_transition(self) -> bool:
        return self.to_state in self.from_states

    def canonical_form(self) -> Dict[str, Any]:
        return {
            "transition_id": self.transition_id,
            "from_states": sorted(self.from_states),
            "to_state": self.to_state,
            "outcome": self.outcome,
            "approval": self.approval.canonical_form(),
            "verification_method": self.verification_method,
            "capability_id": self.capability_id,
            "retry_limit": self.retry_limit,
            "compensation": self.compensation,
            "timeout_seconds": self.timeout_seconds,
            "emits_event_schema": self.emits_event_schema,
            "description": self.description or None,
        }

    def semantic_form(self) -> Dict[str, Any]:
        """What execution depends on. Prose and advisory hints excluded."""
        declared = self.canonical_form()
        for advisory in ("timeout_seconds", "emits_event_schema", "description"):
            declared.pop(advisory, None)
        return declared


@dataclass(frozen=True)
class Supports:
    """What the lifecycle can do — declared, not assumed."""

    pause: bool = False
    cancellation: bool = False
    retries: bool = False
    compensation: bool = False

    def canonical_form(self) -> Dict[str, Any]:
        return {"pause": self.pause, "cancellation": self.cancellation,
                "retries": self.retries, "compensation": self.compensation}


class TransitionRefused(ValueError):
    """A move the pinned program does not permit."""


@dataclass(frozen=True)
class MissionProgram:
    """A versioned lifecycle. Pinned by a running Mission, never mutated."""

    SCHEMA_ID: str = field(default="runtime-contracts/mission-program",
                           init=False, repr=False)

    program_id: str
    program_version: str
    states: Sequence[State]
    transitions: Sequence[Transition]
    terminal_outcomes: Sequence[TerminalOutcome]
    initial_state: str
    accepted_inputs: Sequence[str] = ()
    emitted_outputs: Sequence[str] = ()
    supports: Supports = field(default_factory=Supports)
    schema_version: str = CONTRACT_VERSION

    def __post_init__(self) -> None:
        state_ids = {s.state_id for s in self.states}
        outcome_ids = {o.outcome_id for o in self.terminal_outcomes}
        terminal_ids = {s.state_id for s in self.states if s.terminal}

        if self.initial_state not in state_ids:
            raise ValueError(
                f"initial state {self.initial_state!r} is not declared")

        seen: Set[str] = set()
        for t in self.transitions:
            if t.transition_id in seen:
                raise ValueError(
                    f"duplicate transition id {t.transition_id!r}; two rules with "
                    "one name cannot be told apart in a recorded history")
            seen.add(t.transition_id)

            for origin in t.from_states:
                if origin not in state_ids:
                    raise ValueError(
                        f"{t.transition_id} leaves undeclared state {origin!r}")
            if t.to_state not in state_ids:
                raise ValueError(
                    f"{t.transition_id} enters undeclared state {t.to_state!r}")

            if t.to_state in terminal_ids and not t.outcome:
                raise ValueError(
                    f"{t.transition_id} enters terminal state {t.to_state!r} with "
                    "no outcome. Where an inquiry ended does not say what it "
                    "ended with, and that difference is the whole point")
            if t.outcome and t.to_state not in terminal_ids:
                raise ValueError(
                    f"{t.transition_id} declares outcome {t.outcome!r} on a "
                    f"non-terminal move into {t.to_state!r}")
            if t.outcome and t.outcome not in outcome_ids:
                raise ValueError(
                    f"{t.transition_id} names undeclared outcome {t.outcome!r}")

            if any(origin in terminal_ids for origin in t.from_states):
                raise ValueError(
                    f"{t.transition_id} leaves a terminal state; terminal means "
                    "terminal, and a history could otherwise continue past its end")

            if t.retry_limit and not self.supports.retries:
                raise ValueError(
                    f"{t.transition_id} declares retries in a program that does "
                    "not support them")
            if t.compensation and not self.supports.compensation:
                raise ValueError(
                    f"{t.transition_id} declares compensation in a program that "
                    "does not support it")

        if not self.terminal_outcomes:
            raise ValueError(
                f"{self.program_id} declares no terminal outcome; a lifecycle "
                "that cannot end is not a lifecycle")
        if not any(o.disposition is Disposition.PRODUCED_NOTHING
                   for o in self.terminal_outcomes):
            raise ValueError(
                f"{self.program_id} has no outcome meaning 'concluded with "
                "nothing to show'. That is the outcome most likely to go "
                "unrecorded, and a lifecycle without it guarantees it will")

        reached = {t.to_state for t in self.transitions}
        unreachable = state_ids - reached - {self.initial_state}
        if unreachable:
            raise ValueError(
                f"{self.program_id}: states {sorted(unreachable)} have no inbound "
                "transition and are not initial")

        declared_outcomes = {t.outcome for t in self.transitions if t.outcome}
        orphan_outcomes = outcome_ids - declared_outcomes
        if orphan_outcomes:
            raise ValueError(
                f"{self.program_id}: outcomes {sorted(orphan_outcomes)} are "
                "declared and unreachable")

        if self.supports.pause:
            paused = {t.to_state for t in self.transitions
                      if t.transition_id.startswith("pause")}
            resumable = {o for t in self.transitions for o in t.from_states}
            stranded = paused - resumable
            if stranded:
                raise ValueError(
                    f"{self.program_id}: {sorted(stranded)} can be paused and "
                    "never resumed or cancelled")

        emitted = {kind for o in self.terminal_outcomes
                   for kind in o.emits_artifact_kinds}
        undeclared = emitted - set(self.emitted_outputs)
        if undeclared:
            raise ValueError(
                f"{self.program_id}: outcomes emit {sorted(undeclared)}, which "
                "the program does not declare as an output")

    # ---- identity ---------------------------------------------------------

    @property
    def artifact_id(self) -> str:
        return f"mission-program/{self.program_id}@{self.program_version}"

    def canonical_form(self) -> Dict[str, Any]:
        return {
            "schema_id": self.SCHEMA_ID,
            "schema_version": self.schema_version,
            "program_id": self.program_id,
            "program_version": self.program_version,
            "initial_state": self.initial_state,
            "states": sorted((s.canonical_form() for s in self.states),
                             key=lambda s: s["state_id"]),
            "transitions": sorted((t.canonical_form() for t in self.transitions),
                                  key=lambda t: t["transition_id"]),
            "terminal_outcomes": sorted(
                (o.canonical_form() for o in self.terminal_outcomes),
                key=lambda o: o["outcome_id"]),
            "accepted_inputs": sorted(self.accepted_inputs),
            "emitted_outputs": sorted(self.emitted_outputs),
            "supports": self.supports.canonical_form(),
        }

    def semantic_form(self) -> Dict[str, Any]:
        """Lifecycle semantics that affect execution.

        A documentation change must not sever compatibility; a changed allowed
        transition must. Descriptions never reach either hash; timing hints and
        event-schema references reach only `content_hash`.
        """
        return {
            "program_id": self.program_id,
            "initial_state": self.initial_state,
            "states": sorted((s.semantic_form() for s in self.states),
                             key=lambda s: s["state_id"]),
            "transitions": sorted((t.semantic_form() for t in self.transitions),
                                  key=lambda t: t["transition_id"]),
            "terminal_outcomes": sorted(
                (o.semantic_form() for o in self.terminal_outcomes),
                key=lambda o: o["outcome_id"]),
            "supports": self.supports.canonical_form(),
        }

    @property
    def content_hash(self) -> str:
        return content_hash(self.canonical_form())

    @property
    def semantic_hash(self) -> str:
        return content_hash(self.semantic_form())

    def is_compatible_with(self, other: "MissionProgram") -> bool:
        return self.semantic_hash == other.semantic_hash

    # ---- lookup and permission -------------------------------------------

    def state(self, state_id: str) -> State:
        for s in self.states:
            if s.state_id == state_id:
                return s
        raise KeyError(f"{self.artifact_id} has no state {state_id!r}")

    def outcome(self, outcome_id: str) -> TerminalOutcome:
        for o in self.terminal_outcomes:
            if o.outcome_id == outcome_id:
                return o
        raise KeyError(f"{self.artifact_id} has no outcome {outcome_id!r}")

    def transition(self, transition_id: str) -> Transition:
        for t in self.transitions:
            if t.transition_id == transition_id:
                return t
        raise KeyError(f"{self.artifact_id} has no transition {transition_id!r}")

    def permits(self, *, from_state: str, to_state: str,
                transition_id: Optional[str] = None) -> Optional[Transition]:
        for t in self.transitions:
            if from_state in t.from_states and t.to_state == to_state:
                if transition_id is None or t.transition_id == transition_id:
                    return t
        return None

    def require(self, *, from_state: str, to_state: str,
                transition_id: Optional[str] = None) -> Transition:
        found = self.permits(from_state=from_state, to_state=to_state,
                             transition_id=transition_id)
        if found is None:
            named = f" as {transition_id!r}" if transition_id else ""
            raise TransitionRefused(
                f"{self.artifact_id} does not permit {from_state} -> {to_state}{named}")
        return found

    def validate_against_capabilities(
            self, capabilities: Mapping[str, Any]) -> List[str]:
        """Retries declared against capabilities that are not retry-safe.

        Checked here rather than at construction because a program should not
        have to import capability instances to be valid on its own.
        """
        problems = []
        for t in self.transitions:
            if not t.retry_limit or not t.capability_id:
                continue
            capability = capabilities.get(t.capability_id)
            if capability is None:
                problems.append(
                    f"{t.transition_id} retries unknown capability "
                    f"{t.capability_id!r}")
            elif getattr(capability, "retry_safety", None) is not None and \
                    capability.retry_safety.value == "UNSAFE":
                problems.append(
                    f"{t.transition_id} retries {t.capability_id!r}, which "
                    "declares retries unsafe")
        return problems

    def to_json(self) -> Dict[str, Any]:
        return {**self.canonical_form(), "artifact_id": self.artifact_id,
                "content_hash": self.content_hash,
                "semantic_hash": self.semantic_hash}


# --- the Investigation lifecycle Phase B needs -----------------------------

INVESTIGATION_PROGRAM = MissionProgram(
    program_id="investigation/default",
    program_version="1",
    initial_state="PROPOSED",
    accepted_inputs=("investigation", "artifact_handle", "verification_result"),
    emitted_outputs=("evidence", "finding", "investigation_transition_event"),
    supports=Supports(pause=True, cancellation=True, retries=False,
                      compensation=True),
    states=(
        State("PROPOSED", description="Discovery or a person opened a question"),
        State("ASSIGNED", description="Owned, not yet started"),
        State("ACTIVE", description="Evidence is being gathered"),
        State("PAUSED", description="Suspended, resumable, retaining state"),
        State("BLOCKED", description="Waiting on something outside the inquiry"),
        State("CONCLUDED", terminal=True, description="Ended"),
    ),
    terminal_outcomes=(
        TerminalOutcome("FINDING_PRODUCED", Disposition.PRODUCED_RESULT,
                        emits_artifact_kinds=("finding",),
                        description="Concluded with one or more findings"),
        TerminalOutcome("INCONCLUSIVE", Disposition.PRODUCED_NOTHING,
                        description="The evidence could not settle the question"),
        TerminalOutcome("NO_MATERIAL_IMPACT", Disposition.PRODUCED_NOTHING,
                        description="Settled, and nothing downstream changes"),
        TerminalOutcome("CANCELLED", Disposition.STOPPED,
                        description="Stopped before concluding"),
    ),
    transitions=(
        Transition("assign", ("PROPOSED",), "ASSIGNED",
                   approval=ApprovalGate(ApproverType.HUMAN, "an owner accepts it")),
        Transition("start", ("ASSIGNED", "PAUSED"), "ACTIVE"),
        Transition("pause", ("ACTIVE",), "PAUSED", compensation="start"),
        Transition("block", ("ACTIVE",), "BLOCKED"),
        Transition("unblock", ("BLOCKED",), "ACTIVE"),
        # The only transition creating a public artifact, so the only one gated
        # on both a human and a deterministic check.
        Transition("conclude_with_finding", ("ACTIVE",), "CONCLUDED",
                   outcome="FINDING_PRODUCED",
                   approval=ApprovalGate(ApproverType.HUMAN_AND_VERIFIER,
                                         "a reviewer accepts the finding and it "
                                         "cites evidence"),
                   verification_method="finding_is_evidenced"),
        # The null outcomes are ordinary transitions, deliberately. Making them
        # harder to record than a positive conclusion is how a research record
        # acquires survivorship bias.
        Transition("conclude_inconclusive", ("ACTIVE",), "CONCLUDED",
                   outcome="INCONCLUSIVE",
                   approval=ApprovalGate(ApproverType.HUMAN,
                                         "a reviewer accepts that it could not "
                                         "be settled"),
                   verification_method="examined_something"),
        Transition("conclude_no_impact", ("ACTIVE",), "CONCLUDED",
                   outcome="NO_MATERIAL_IMPACT",
                   approval=ApprovalGate(ApproverType.HUMAN,
                                         "a reviewer accepts that nothing changes"),
                   verification_method="examined_something"),
        Transition("cancel", ("PROPOSED", "ASSIGNED", "ACTIVE", "PAUSED",
                              "BLOCKED"), "CONCLUDED", outcome="CANCELLED"),
    ),
)
