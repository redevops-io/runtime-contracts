"""InvestigationTransitionEvent — a historical fact that cannot vouch for itself."""
from __future__ import annotations

import json
import pathlib

import pytest

from golden.lifecycle import event, inconclusive_journey, passing
from runtime_contracts import (
    INVESTIGATION_PROGRAM as P,
    InvestigationTransitionEvent,
    OwnershipChange,
    TransitionRefused,
    Visibility,
    replay_states,
)

GOLDEN = json.loads(
    (pathlib.Path(__file__).parent.parent / "golden"
     / "investigation_lifecycle.json").read_text())["cases"]


class TestTheInconclusiveJourney:
    """Phase C's gate: work that concludes without a positive finding."""

    def test_it_replays_to_a_terminal_state(self):
        assert replay_states(inconclusive_journey(), P) == "CONCLUDED"

    def test_it_produced_nothing_and_emits_no_finding(self):
        outcome = P.outcome(inconclusive_journey()[-1].terminal_outcome)
        assert outcome.disposition.value == "PRODUCED_NOTHING"
        assert not outcome.emits_artifact_kinds

    def test_it_reproduces_the_golden_hashes(self):
        assert [e.event_hash for e in inconclusive_journey()] == \
            GOLDEN["inconclusive_journey"]["event_hashes"]

    def test_order_variation_replays_identically(self):
        assert replay_states(list(reversed(inconclusive_journey())), P) == \
            GOLDEN["order_variation_replays_identically"]["final_state"]

    def test_the_pause_and_resume_survive_in_the_history(self):
        states = [(e.from_state, e.to_state) for e in inconclusive_journey()]
        assert ("ACTIVE", "PAUSED") in states and ("PAUSED", "ACTIVE") in states

    def test_ownership_is_recorded_where_it_moved(self):
        [assigned] = [e for e in inconclusive_journey()
                      if e.transition_id == "assign"]
        assert assigned.ownership_change == OwnershipChange(None, "pilot")


class TestOutcomeChangesIdentity:
    def test_a_finding_outcome_is_a_different_history(self):
        case = GOLDEN["outcome_changes_identity"]
        assert case["differs_from_inconclusive"]
        assert case["emits_finding"] is True

    def test_prose_and_time_do_not(self):
        original = inconclusive_journey()[0]
        reworded = InvestigationTransitionEvent(
            **{**original.__dict__, "reason": "reworded after review",
               "occurred_at": "2026-07-31T09:00:00Z"})
        assert original.event_hash == reworded.event_hash
        assert reworded.event_hash == GOLDEN["prose_and_time_excluded"]["event_hash"]


class TestInvalidWorkflowsFailWithTypedReasons:
    """A rejection must name what was wrong, not just that something was."""

    CASES = GOLDEN["invalid_workflows"]["cases"]

    @pytest.mark.parametrize("case", sorted(CASES))
    def test_each_is_refused(self, case):
        assert self.CASES[case]["refused"], f"{case} was accepted"

    @pytest.mark.parametrize("case,phrase", [
        ("conclude_from_proposed", "does not permit"),
        ("resume_without_pause", "not contiguous"),
        ("finding_outcome_on_inconclusive_transition", "produces"),
        ("wrong_program_version", "wrong program"),
        ("two_terminal_transitions", "already ended"),
        ("terminal_state_without_outcome", "no outcome recorded"),
        ("private_evidence_on_public_event", "cites private artifacts"),
        ("duplicate_sequence", "not\n reconstructible".replace("\n ", " ")),
    ])
    def test_the_reason_names_the_defect(self, case, phrase):
        assert phrase in self.CASES[case]["reason"]


class TestAnEventCannotVouchForItself:
    def test_permitted_is_nowhere_in_the_payload(self):
        assert "permitted" not in inconclusive_journey()[0].to_json()

    def test_a_negative_sequence_is_refused(self):
        with pytest.raises(ValueError, match="not be reconstructible"):
            event("assign", "PROPOSED", "ASSIGNED", -1)

    def test_an_empty_ownership_change_is_refused(self):
        with pytest.raises(ValueError, match="records nothing"):
            event("assign", "PROPOSED", "ASSIGNED", 0,
                  ownership=OwnershipChange(None, None))

    def test_a_mismatched_verification_ref_is_refused(self):
        with pytest.raises(ValueError, match="different verification"):
            InvestigationTransitionEvent(
                investigation_id="i", program_id=P.program_id,
                program_version=P.program_version, program_hash=P.content_hash,
                transition_id="assign", from_state="PROPOSED",
                to_state="ASSIGNED", actor="pilot", sequence=0,
                verification=passing("x"), verification_result_ref="rcv1:other")

    def test_a_required_gate_with_no_result_is_not_satisfied(self):
        assert not event("conclude_inconclusive", "ACTIVE", "CONCLUDED", 0,
                         outcome="INCONCLUSIVE").satisfied_its_gate(P)

    def test_it_joins_the_common_event_stream(self):
        from runtime_contracts import EventKind

        wrapped = inconclusive_journey()[0].as_runtime_event(
            event_id="e1", stream_id="inv-1", emitted_by="control-plane")
        assert wrapped.kind is EventKind.INVESTIGATION_TRANSITION
