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


class TestIdempotentSubmission:
    """Essential the moment retries, queues or Discovery delivery exist."""

    CASES = GOLDEN["idempotent_submission"]["cases"]

    def test_a_first_submission_is_accepted(self):
        assert self.CASES["first_submission"]["outcome"] == "ACCEPTED"
        assert self.CASES["first_submission"]["stored"] is True

    def test_an_identical_retry_is_a_no_op(self):
        assert self.CASES["identical_retry"]["outcome"] == "DUPLICATE"
        assert self.CASES["identical_retry"]["stored"] is False

    def test_the_same_id_with_a_different_body_is_a_hard_conflict(self):
        """Accepting it would let a redelivery rewrite an append-only history."""
        case = self.CASES["same_id_different_body"]
        assert case["outcome"] == "CONFLICT"
        assert "rewrite an append-only history" in case["reason"]

    def test_rewording_alone_is_still_a_retry(self):
        """Prose is not part of the fact, so it does not make a new event."""
        assert self.CASES["same_id_reworded_only"]["outcome"] == "DUPLICATE"

    def test_a_forbidden_transition_is_refused_not_conflicted(self):
        """Different failure, different answer — the caller acts on each
        differently."""
        assert self.CASES["forbidden_transition"]["outcome"] == "REFUSED"


class TestReplayIsTheSourceOfTruth:
    def test_it_derives_state_outcome_and_assignment(self):
        from runtime_contracts import INVESTIGATION_PROGRAM, replay_ledger

        result = replay_ledger(inconclusive_journey(), INVESTIGATION_PROGRAM)

        assert result.current_state == "CONCLUDED"
        assert result.terminal_outcome == "INCONCLUSIVE"
        assert result.active_assignment == "pilot"
        assert result.is_consistent

    def test_a_concluded_inquiry_cannot_transition_again(self):
        from runtime_contracts import INVESTIGATION_PROGRAM, replay_ledger

        assert not replay_ledger(inconclusive_journey(),
                                 INVESTIGATION_PROGRAM).can_transition

    def test_verification_history_survives(self):
        from runtime_contracts import INVESTIGATION_PROGRAM, replay_ledger

        [check] = replay_ledger(inconclusive_journey(),
                                INVESTIGATION_PROGRAM).verification_history
        assert check["verdict"] == "PASS"
        assert check["transition_id"] == "conclude_inconclusive"

    def test_non_strict_replay_collects_rather_than_stops(self):
        """One bad event must not make the rest of a history unreadable."""
        from runtime_contracts import INVESTIGATION_PROGRAM, replay_ledger

        broken = inconclusive_journey() + [
            event("start", "PAUSED", "ACTIVE", 9)]
        result = replay_ledger(broken, INVESTIGATION_PROGRAM, strict=False)

        assert result.invalid_events
        assert result.current_state == "CONCLUDED"
        assert not result.is_consistent

    def test_a_program_mismatch_is_reported_separately(self):
        import dataclasses

        from runtime_contracts import INVESTIGATION_PROGRAM, replay_ledger

        wrong = [dataclasses.replace(e, program_hash="rcv1:" + "0" * 64)
                 for e in inconclusive_journey()]
        result = replay_ledger(wrong, INVESTIGATION_PROGRAM, strict=False)

        assert result.program_mismatches
        assert result.current_state == INVESTIGATION_PROGRAM.initial_state


class TestHistoryAndAuditAreDifferentQuestions:
    def test_permitted_then_uses_the_pinned_program(self):
        from runtime_contracts import INVESTIGATION_PROGRAM, permitted_then

        assert permitted_then(inconclusive_journey()[0], INVESTIGATION_PROGRAM)

    def test_a_narrowed_current_program_does_not_rewrite_history(self):
        """A False here means the rules changed, not that the transition was
        wrong when it was made."""
        import dataclasses

        from runtime_contracts import (
            INVESTIGATION_PROGRAM, current_program_would_permit, permitted_then)

        from runtime_contracts import Transition

        # `start` no longer resumes from PAUSED. Dropping `pause` outright would
        # have left PAUSED unreachable, which the program validator refuses —
        # a narrowing has to remain a valid lifecycle.
        narrowed = dataclasses.replace(
            INVESTIGATION_PROGRAM,
            program_version="2",
            transitions=tuple(
                t for t in INVESTIGATION_PROGRAM.transitions
                if t.transition_id != "start")
            + (Transition("start", ("ASSIGNED",), "ACTIVE"),))
        [resumed] = [e for e in inconclusive_journey()
                     if e.from_state == "PAUSED"]

        assert permitted_then(resumed, INVESTIGATION_PROGRAM)
        assert not current_program_would_permit(resumed, narrowed)


class TestFindingRoutingIsDerivedFromTheProgram:
    def test_a_null_outcome_forbids_findings(self):
        from runtime_contracts import INVESTIGATION_PROGRAM, check_finding_routing

        for outcome in ("INCONCLUSIVE", "NO_MATERIAL_IMPACT"):
            assert check_finding_routing(INVESTIGATION_PROGRAM, outcome, []) is None
            assert "mislabelled its own outcome" in check_finding_routing(
                INVESTIGATION_PROGRAM, outcome, ["finding/x@1"])

    def test_a_finding_outcome_requires_at_least_one(self):
        from runtime_contracts import INVESTIGATION_PROGRAM, check_finding_routing

        assert "cannot be reviewed" in check_finding_routing(
            INVESTIGATION_PROGRAM, "FINDING_PRODUCED", [])
        assert check_finding_routing(
            INVESTIGATION_PROGRAM, "FINDING_PRODUCED", ["finding/x@1"]) is None

    def test_the_rule_is_read_from_the_program_not_hardcoded(self):
        from runtime_contracts import INVESTIGATION_PROGRAM, finding_requirement

        assert finding_requirement(INVESTIGATION_PROGRAM, "INCONCLUSIVE") == "FORBIDDEN"
        assert finding_requirement(
            INVESTIGATION_PROGRAM, "FINDING_PRODUCED") == "REQUIRED"
