"""Concurrency topology vocabulary + partial-order event causal ordering (additive, backward-compatible)."""
from __future__ import annotations

import pytest

from runtime_contracts import ConcurrencyGroup, JoinPolicy, TopologyKind, causal_order
from runtime_contracts.models.investigation import InvestigationTransitionEvent


def _ev(tid, seq, parents=()):
    return InvestigationTransitionEvent(
        investigation_id="i", program_id="p", program_version="1", program_hash="h",
        transition_id=tid, from_state="A", to_state="B", actor="u", sequence=seq, parents=parents)


# ── topology vocabulary ──

def test_concurrency_group_basics():
    g = ConcurrencyGroup(kind=TopologyKind.PARALLEL_ALL, members=("b", "c", "d"),
                         join_policy=JoinPolicy.ALL, max_concurrency=2)
    assert g.kind is TopologyKind.PARALLEL_ALL and g.join_policy is JoinPolicy.ALL and g.max_concurrency == 2


def test_quorum_requires_min_successes():
    with pytest.raises(ValueError):
        ConcurrencyGroup(kind=TopologyKind.PARALLEL_ALL, members=("b", "c"), join_policy=JoinPolicy.QUORUM)
    ok = ConcurrencyGroup(kind=TopologyKind.PARALLEL_ALL, members=("b", "c"),
                          join_policy=JoinPolicy.QUORUM, min_successes=2)
    assert ok.min_successes == 2


def test_negative_concurrency_rejected():
    with pytest.raises(ValueError):
        ConcurrencyGroup(kind=TopologyKind.SEQUENCE, members=("b",), max_concurrency=-1)


# ── partial-order events ──

def test_no_parents_serialises_as_before():
    """Backward-compat: an event with no parents omits the key entirely → identical canonical_form/hash."""
    e = _ev("t1", 1)
    assert "parents" not in e.canonical_form()
    e2 = _ev("t2", 2, parents=("t1",))
    assert e2.canonical_form()["parents"] == ["t1"]


def test_causal_order_is_sequence_order_without_parents():
    events = [_ev("t3", 3), _ev("t1", 1), _ev("t2", 2)]
    assert [e.transition_id for e in causal_order(events)] == ["t1", "t2", "t3"]


def test_causal_order_respects_fan_out_join():
    # root → {b, c} → join ; b and c are concurrent (same parent), join follows both
    root = _ev("root", 1)
    b = _ev("b", 5, parents=("root",))          # sequence deliberately out of causal order
    c = _ev("c", 2, parents=("root",))
    join = _ev("join", 3, parents=("b", "c"))
    order = [e.transition_id for e in causal_order([join, b, c, root])]
    assert order[0] == "root" and order[-1] == "join"
    assert order.index("c") < order.index("join") and order.index("b") < order.index("join")
    assert order.index("c") < order.index("b")   # tie-break by sequence among the concurrent siblings


def test_causal_order_detects_cycle():
    from runtime_contracts.models import TransitionRefused
    a = _ev("a", 1, parents=("b",))
    b = _ev("b", 2, parents=("a",))
    with pytest.raises(TransitionRefused):
        causal_order([a, b])


def test_a_history_that_repeats_a_transition_is_ordered_not_refused():
    """transition_id is the program's transition, so a paused-and-resumed inquiry has two ``start`` events. Keyed by
    transition_id alone, the second replaced the first and the whole history was refused as a cycle."""
    h = [_ev("assign", 1), _ev("start", 2), _ev("pause", 3), _ev("start", 4), _ev("pause", 5), _ev("start", 6)]
    assert [(e.transition_id, e.sequence) for e in causal_order(list(reversed(h)))] == [(e.transition_id, e.sequence) for e in h]


def test_a_parent_reference_means_the_nearest_preceding_event_of_that_name():
    first, pause, second = _ev("start", 2), _ev("pause", 3, parents=("start",)), _ev("start", 4, parents=("pause",))
    late = _ev("note", 1, parents=("start",))            # sequence says first; its parent says after a start
    exact = _ev("audit", 0, parents=("start@4",))         # names the second start exactly
    order = [(e.transition_id, e.sequence) for e in causal_order([exact, late, second, pause, first])]
    assert order.index(("start", 2)) < order.index(("note", 1)) < order.index(("pause", 3)) < order.index(("start", 4)) < order.index(("audit", 0))


def test_a_parent_outside_the_given_events_does_not_constrain_the_order():
    assert [e.transition_id for e in causal_order([_ev("b", 2, parents=("not-here",)), _ev("a", 1)])] == ["a", "b"]
