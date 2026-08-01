"""The program declares the lifecycle; the Mission records history."""
from __future__ import annotations

import dataclasses

import pytest

from runtime_contracts import (
    INVESTIGATION_PROGRAM,
    ApprovalGate,
    ApproverType,
    Disposition,
    MissionProgram,
    State,
    Supports,
    TerminalOutcome,
    Transition,
    TransitionRefused,
)

P = INVESTIGATION_PROGRAM


def minimal(**overrides):
    spec = dict(
        program_id="p", program_version="1", initial_state="A",
        states=(State("A"), State("Z", terminal=True)),
        terminal_outcomes=(
            TerminalOutcome("NOTHING", Disposition.PRODUCED_NOTHING),),
        transitions=(Transition("finish", ("A",), "Z", outcome="NOTHING"),),
    )
    spec.update(overrides)
    return MissionProgram(**spec)


class TestStateAndOutcomeAreDifferentThings:
    def test_one_terminal_state_carries_four_outcomes(self):
        assert {s.state_id for s in P.states if s.terminal} == {"CONCLUDED"}
        assert {o.outcome_id for o in P.terminal_outcomes} == {
            "FINDING_PRODUCED", "INCONCLUSIVE", "NO_MATERIAL_IMPACT", "CANCELLED"}

    def test_only_one_outcome_emits_a_public_artifact(self):
        emitting = {o.outcome_id for o in P.terminal_outcomes
                    if o.emits_artifact_kinds}
        assert emitting == {"FINDING_PRODUCED"}

    def test_entering_a_terminal_state_requires_an_outcome(self):
        with pytest.raises(ValueError, match="no outcome"):
            minimal(transitions=(Transition("finish", ("A",), "Z"),))

    def test_an_outcome_on_a_non_terminal_move_is_refused(self):
        with pytest.raises(ValueError, match="non-terminal move"):
            minimal(
                states=(State("A"), State("B"), State("Z", terminal=True)),
                transitions=(Transition("step", ("A",), "B", outcome="NOTHING"),
                             Transition("finish", ("B",), "Z", outcome="NOTHING")))


class TestAProgramMustBeAbleToConcludeNothing:
    def test_the_investigation_program_has_two_null_outcomes(self):
        nulls = {o.outcome_id for o in P.terminal_outcomes
                 if o.disposition is Disposition.PRODUCED_NOTHING}
        assert nulls == {"INCONCLUSIVE", "NO_MATERIAL_IMPACT"}

    def test_a_program_without_one_is_refused(self):
        with pytest.raises(ValueError, match="concluded with nothing to show"):
            minimal(terminal_outcomes=(
                TerminalOutcome("DONE", Disposition.PRODUCED_RESULT),),
                transitions=(Transition("finish", ("A",), "Z", outcome="DONE"),))

    def test_a_null_outcome_is_no_harder_to_record_than_a_finding(self):
        """Making it harder is how a record acquires survivorship bias."""
        assert P.transition("conclude_with_finding").approval.approver is \
            ApproverType.HUMAN_AND_VERIFIER
        assert P.transition("conclude_inconclusive").approval.approver is \
            ApproverType.HUMAN


class TestConstructionInvariants:
    def test_a_duplicate_transition_id_is_refused(self):
        with pytest.raises(ValueError, match="duplicate transition id"):
            minimal(transitions=(Transition("finish", ("A",), "Z", outcome="NOTHING"),
                                 Transition("finish", ("A",), "Z", outcome="NOTHING")))

    def test_leaving_a_terminal_state_is_refused(self):
        with pytest.raises(ValueError, match="leaves a terminal state"):
            minimal(transitions=(Transition("finish", ("A",), "Z", outcome="NOTHING"),
                                 Transition("undo", ("Z",), "A")))

    def test_an_unreachable_state_is_refused(self):
        with pytest.raises(ValueError, match="no inbound transition"):
            minimal(states=(State("A"), State("ORPHAN"), State("Z", terminal=True)))

    def test_an_unreachable_outcome_is_refused(self):
        with pytest.raises(ValueError, match="declared and unreachable"):
            minimal(terminal_outcomes=(
                TerminalOutcome("NOTHING", Disposition.PRODUCED_NOTHING),
                TerminalOutcome("NEVER", Disposition.STOPPED)))

    def test_an_undeclared_state_is_refused(self):
        with pytest.raises(ValueError, match="undeclared state"):
            minimal(transitions=(Transition("finish", ("NOWHERE",), "Z",
                                            outcome="NOTHING"),))

    def test_a_gate_with_no_policy_is_refused(self):
        with pytest.raises(ValueError, match="unreviewable by design"):
            ApprovalGate(ApproverType.HUMAN)

    def test_a_verifier_gate_with_nothing_to_perform_it_is_refused(self):
        with pytest.raises(ValueError, match="a gate nothing performs"):
            Transition("t", ("A",), "B",
                       approval=ApprovalGate(ApproverType.DETERMINISTIC_VERIFIER,
                                             "some policy"))

    def test_retries_in_a_program_that_does_not_support_them(self):
        with pytest.raises(ValueError, match="does not support them"):
            minimal(transitions=(Transition("finish", ("A",), "Z",
                                            outcome="NOTHING", retry_limit=3),))

    def test_a_paused_state_with_no_way_out_is_refused(self):
        with pytest.raises(ValueError, match="never resumed or cancelled"):
            MissionProgram(
                program_id="p", program_version="1", initial_state="A",
                supports=Supports(pause=True),
                states=(State("A"), State("STUCK"), State("Z", terminal=True)),
                terminal_outcomes=(
                    TerminalOutcome("NOTHING", Disposition.PRODUCED_NOTHING),),
                transitions=(Transition("pause_it", ("A",), "STUCK"),
                             Transition("finish", ("A",), "Z", outcome="NOTHING")))

    def test_an_undeclared_emitted_artifact_is_refused(self):
        with pytest.raises(ValueError, match="does not declare as an output"):
            minimal(terminal_outcomes=(
                TerminalOutcome("NOTHING", Disposition.PRODUCED_NOTHING,
                                emits_artifact_kinds=("finding",)),))

    def test_a_program_may_decline_to_support_pausing(self):
        """Declared, not required. Requiring it would put fictional semantics
        in programs that do not pause."""
        assert minimal().supports.pause is False


class TestTheTwoHashes:
    def test_a_documentation_change_does_not_sever_compatibility(self):
        reworded = dataclasses.replace(
            P, states=tuple(dataclasses.replace(s, description="reworded")
                            for s in P.states))

        assert P.content_hash != reworded.content_hash
        assert P.is_compatible_with(reworded)

    def test_a_changed_allowed_transition_does(self):
        widened = dataclasses.replace(
            P, transitions=tuple(t for t in P.transitions
                                 if t.transition_id != "block")
            + (Transition("block", ("ACTIVE", "ASSIGNED"), "BLOCKED"),))

        assert not P.is_compatible_with(widened)


class TestPermissionIsDerived:
    def test_a_transition_may_have_several_origins(self):
        assert set(P.transition("start").from_states) == {"ASSIGNED", "PAUSED"}
        assert P.permits(from_state="PAUSED", to_state="ACTIVE") is not None

    def test_cancel_reaches_from_every_live_state(self):
        assert set(P.transition("cancel").from_states) == {
            "PROPOSED", "ASSIGNED", "ACTIVE", "PAUSED", "BLOCKED"}

    def test_a_forbidden_move_is_refused(self):
        with pytest.raises(TransitionRefused, match="does not permit"):
            P.require(from_state="PROPOSED", to_state="BLOCKED")

    def test_retry_against_an_unsafe_capability_is_reported(self):
        from runtime_contracts import CapabilityDescriptor, RetrySafety

        program = MissionProgram(
            program_id="p", program_version="1", initial_state="A",
            supports=Supports(retries=True),
            states=(State("A"), State("Z", terminal=True)),
            terminal_outcomes=(
                TerminalOutcome("NOTHING", Disposition.PRODUCED_NOTHING),),
            transitions=(Transition("finish", ("A",), "Z", outcome="NOTHING",
                                    capability_id="writer", retry_limit=2),))
        unsafe = CapabilityDescriptor("writer", "1", "tool",
                                      retry_safety=RetrySafety.UNSAFE)

        assert program.validate_against_capabilities({"writer": unsafe})
