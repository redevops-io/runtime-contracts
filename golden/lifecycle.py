"""The first executable workflow fixture — and the invalid one beside it.

The inconclusive journey is Phase C's gate: work that concludes without a
positive finding, replayable, with the full history intact. The invalid cases
exist so a rejection is a *typed reason* rather than a generic schema error —
"conclude directly from PROPOSED" and "malformed payload" must not look alike.
"""
from __future__ import annotations

import json
import pathlib

from runtime_contracts import (
    INVESTIGATION_PROGRAM as P,
    InvestigationTransitionEvent,
    OwnershipChange,
    TransitionRefused,
    VerificationResult,
    Visibility,
    replay_states,
)
from runtime_contracts.models.verification import Check, Verdict

HERE = pathlib.Path(__file__).parent
INVESTIGATION = "investigation/regime-features-leak-future-state@1"


def event(transition_id, a, b, sequence, *, outcome=None, verification=None,
          ownership=None, program=P, visibility=Visibility.INTERNAL,
          evidence_refs=()):
    return InvestigationTransitionEvent(
        investigation_id=INVESTIGATION,
        program_id=program.program_id,
        program_version=program.program_version,
        program_hash=program.content_hash,
        transition_id=transition_id, from_state=a, to_state=b,
        actor="pilot", sequence=sequence, terminal_outcome=outcome,
        verification=verification, ownership_change=ownership,
        visibility=visibility, evidence_refs=evidence_refs,
    )


def passing(check_id):
    return VerificationResult("realization-verifier", "1", "rcv1:target",
                              [Check(check_id, Verdict.PASS)])


def inconclusive_journey():
    """PROPOSED → ASSIGNED → ACTIVE → PAUSED → ACTIVE → CONCLUDED/INCONCLUSIVE."""
    return [
        event("assign", "PROPOSED", "ASSIGNED", 0,
              ownership=OwnershipChange(None, "pilot")),
        event("start", "ASSIGNED", "ACTIVE", 1),
        event("pause", "ACTIVE", "PAUSED", 2),
        event("start", "PAUSED", "ACTIVE", 3),
        event("conclude_inconclusive", "ACTIVE", "CONCLUDED", 4,
              outcome="INCONCLUSIVE",
              verification=passing("examined_something"),
              evidence_refs=("evidence/vendor-notice-2026@1",)),
    ]


def invalid_cases():
    """Each must fail with a reason naming what was wrong."""
    other_program_hash = "rcv1:" + "0" * 64

    def refusal(build):
        try:
            build()
        except (TransitionRefused, ValueError) as exc:
            return {"refused": True, "reason": str(exc)}
        return {"refused": False, "reason": None}

    return {
        "conclude_from_proposed": refusal(
            lambda: event("conclude_inconclusive", "PROPOSED", "CONCLUDED", 0,
                          outcome="INCONCLUSIVE").permitted_by(P)),
        "resume_without_pause": refusal(
            lambda: replay_states([event("assign", "PROPOSED", "ASSIGNED", 0),
                                   event("start", "PAUSED", "ACTIVE", 1)], P)),
        "finding_outcome_on_inconclusive_transition": refusal(
            lambda: event("conclude_inconclusive", "ACTIVE", "CONCLUDED", 0,
                          outcome="FINDING_PRODUCED").permitted_by(P)),
        "wrong_program_version": refusal(
            lambda: InvestigationTransitionEvent(
                investigation_id=INVESTIGATION, program_id=P.program_id,
                program_version="99", program_hash=other_program_hash,
                transition_id="assign", from_state="PROPOSED",
                to_state="ASSIGNED", actor="pilot", sequence=0
            ).permitted_by(P)),
        "two_terminal_transitions": refusal(
            lambda: replay_states(
                inconclusive_journey()
                + [event("conclude_no_impact", "ACTIVE", "CONCLUDED", 5,
                         outcome="NO_MATERIAL_IMPACT")], P)),
        "terminal_state_without_outcome": refusal(
            lambda: event("conclude_inconclusive", "ACTIVE", "CONCLUDED",
                          0).permitted_by(P)),
        "private_evidence_on_public_event": refusal(
            lambda: event("assign", "PROPOSED", "ASSIGNED", 0,
                          visibility=Visibility.PUBLIC,
                          evidence_refs=("mission/my-plan@1",)).permitted_by(P)),
        "duplicate_sequence": refusal(
            lambda: replay_states([event("assign", "PROPOSED", "ASSIGNED", 0),
                                   event("start", "ASSIGNED", "ACTIVE", 0)], P)),
    }


def idempotency_cases() -> dict:
    """The fixture retries, queues and Discovery delivery all depend on."""
    import dataclasses

    from runtime_contracts import submit

    first = inconclusive_journey()[0]
    stored = {}

    accepted = submit(first, event_id="evt-0", existing=stored, program=P)
    stored["evt-0"] = first.event_hash

    retried = submit(first, event_id="evt-0", existing=stored, program=P)

    # Same id, different body. A redelivery that changed content is not a retry.
    tampered = dataclasses.replace(first, actor="someone-else")
    conflicted = submit(tampered, event_id="evt-0", existing=stored, program=P)

    # Same id, reworded only. Prose is not part of the fact, so it is a retry.
    reworded = dataclasses.replace(first, reason="reworded after review")
    absorbed = submit(reworded, event_id="evt-0", existing=stored, program=P)

    forbidden = submit(
        event("conclude_inconclusive", "PROPOSED", "CONCLUDED", 0,
              outcome="INCONCLUSIVE"),
        event_id="evt-9", existing=stored, program=P)

    return {
        "first_submission": accepted.to_json(),
        "identical_retry": retried.to_json(),
        "same_id_different_body": conflicted.to_json(),
        "same_id_reworded_only": absorbed.to_json(),
        "forbidden_transition": forbidden.to_json(),
    }


def cases() -> dict:
    journey = inconclusive_journey()
    reversed_journey = list(reversed(journey))

    with_finding = journey[:-1] + [
        event("conclude_with_finding", "ACTIVE", "CONCLUDED", 4,
              outcome="FINDING_PRODUCED",
              verification=passing("finding_is_evidenced"))]

    return {
        "program": {
            "why": "the pinned lifecycle every transition is checked against",
            "artifact_id": P.artifact_id,
            "content_hash": P.content_hash,
            "semantic_hash": P.semantic_hash,
        },
        "inconclusive_journey": {
            "why": ("work that concludes without a positive finding, replayable "
                    "with its history intact — Phase C's gate"),
            "final_state": replay_states(journey, P),
            "terminal_outcome": journey[-1].terminal_outcome,
            "emits_finding": bool(
                P.outcome(journey[-1].terminal_outcome).emits_artifact_kinds),
            "event_hashes": [e.event_hash for e in journey],
            "sequence": [e.sequence for e in journey],
        },
        "order_variation_replays_identically": {
            "why": "insertion order is a property of the caller, not the history",
            "final_state": replay_states(reversed_journey, P),
            "event_hashes": [e.event_hash for e in reversed(reversed_journey)],
        },
        "outcome_changes_identity": {
            "why": ("replacing INCONCLUSIVE with FINDING_PRODUCED is a different "
                    "history, and one of them emits a public artifact"),
            "final_state": replay_states(with_finding, P),
            "terminal_outcome": with_finding[-1].terminal_outcome,
            "emits_finding": bool(
                P.outcome(with_finding[-1].terminal_outcome).emits_artifact_kinds),
            "event_hash": with_finding[-1].event_hash,
            "differs_from_inconclusive":
                with_finding[-1].event_hash != journey[-1].event_hash,
        },
        "prose_and_time_excluded": {
            "why": "the same transition, reworded or re-clocked, is the same fact",
            "event_hash": InvestigationTransitionEvent(
                **{**journey[0].__dict__, "reason": "reworded after review",
                   "occurred_at": "2026-07-31T09:00:00Z"}).event_hash,
        },
        "idempotent_submission": {
            "why": ("the same transition arrives twice the moment retries, "
                    "queues or Discovery delivery exist. An identical body is a "
                    "no-op; the same id with a different body is a hard conflict, "
                    "because a redelivery must not rewrite an append-only history"),
            "cases": idempotency_cases(),
        },
        "invalid_workflows": {
            "why": ("a rejection must be a typed reason, not a generic schema "
                    "error — 'conclude from PROPOSED' and 'malformed payload' "
                    "must not look alike"),
            "cases": invalid_cases(),
        },
    }


if __name__ == "__main__":
    payload = {"contract_version": "0.1", "cases": cases()}
    (HERE / "investigation_lifecycle.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    print(json.dumps(payload["cases"]["inconclusive_journey"], indent=2))
