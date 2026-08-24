"""Security Telemetry Protocol — canonical RuntimeSecurityEvent, causal ordering, and the trajectory
correlation where individually-permissible events compose into an unacceptable disposition."""
from __future__ import annotations

from decimal import Decimal

import pytest

from runtime_contracts import (
    CausalCycle,
    GovernanceDisposition,
    RuntimeSecurityEvent,
    SecurityEventType,
    SecurityTrajectory,
    TelemetryKind,
    correlate,
)
from runtime_contracts.protocol.telemetry import causal_order


def _ev(eid, etype=SecurityEventType.CAPABILITY_INVOKED, **kw):
    return RuntimeSecurityEvent(event_id=eid, kind=TelemetryKind.SECURITY, event_type=etype.value, **kw)


# ── envelope identity ──

def test_event_hash_is_canonical_and_omits_empty_fields():
    a = _ev("e1", mission_id="m", capability="read", data_classifications=("pii",), sequence=1)
    b = _ev("e1", mission_id="m", capability="read", data_classifications=("pii",), sequence=1, model="")
    assert a.event_hash == b.event_hash and a.event_hash.startswith("rcv1:")   # empty model omitted
    assert _ev("e1", mission_id="m", capability="read", data_classifications=("phi",)).event_hash != a.event_hash


def test_hashes_not_raw_payloads():
    e = _ev("e1", input_hash="rcv1:aa", output_hash="rcv1:bb", capability="export")
    cf = e.canonical_form()
    assert cf["input_hash"] == "rcv1:aa" and cf["output_hash"] == "rcv1:bb"   # only hashes are carried


# ── causal ordering of the append-only stream ──

def test_causal_order_is_topological_then_sequence():
    root = _ev("root", sequence=1)
    a = _ev("a", parent_event_id="root", sequence=5)     # sequence deliberately out of causal order
    b = _ev("b", parent_event_id="root", sequence=2)
    leaf = _ev("leaf", parent_event_id="a", sequence=3)
    order = [e.event_id for e in causal_order([leaf, a, b, root])]
    assert order[0] == "root"
    assert order.index("b") < order.index("a")           # tie-break by sequence among siblings
    assert order.index("a") < order.index("leaf")        # parent before child


def test_causal_cycle_is_refused():
    x = _ev("x", parent_event_id="y")
    y = _ev("y", parent_event_id="x")
    with pytest.raises(CausalCycle):
        causal_order([x, y])


# ── the trajectory IS the signal (τ-bench) ──

def test_three_allows_compose_into_a_deny():
    # each event alone is permissible; the SERIES is exfiltration
    traj = SecurityTrajectory()
    traj.add(_ev("1", capability="crm.read", data_classifications=("pii",),
                 side_effects=("records_read=2000",)))
    traj.add(_ev("2", capability="report.generate"))
    traj.add(_ev("3", capability="storage.upload", network=("s3.external.com",),
                etype=SecurityEventType.DATA_MOVEMENT))
    disp, reasons = correlate(traj, max_external_records=100)
    assert disp is GovernanceDisposition.DENY
    assert any("exfiltration" in r for r in reasons)


def test_benign_trajectory_allows():
    traj = SecurityTrajectory().add(_ev("1", capability="crm.read", data_classifications=("pii",),
                                        side_effects=("records_read=3",)))
    disp, reasons = correlate(traj, planned_capabilities=("crm.read",))
    assert disp is GovernanceDisposition.ALLOW and reasons == []


def test_plan_vs_observed_divergence_requires_review():
    # planned: read → summarize → respond; observed adds a subprocess + network it never planned
    traj = SecurityTrajectory()
    traj.add(_ev("1", capability="crm.read"))
    traj.add(_ev("2", capability="subprocess.exec", network=("attacker.net",),
                etype=SecurityEventType.NETWORK_ACCESS))
    disp, reasons = correlate(traj, planned_capabilities=("crm.read", "summarize", "respond"))
    assert disp is GovernanceDisposition.REQUIRE_REVIEW
    assert any("divergence" in r and "subprocess.exec" in r for r in reasons)


def test_hard_transitions_are_no_override():
    for t in (SecurityEventType.PRIVILEGE_ESCALATION, SecurityEventType.SANDBOX_VIOLATION):
        traj = SecurityTrajectory().add(_ev("1", capability="c", etype=t))
        disp, _ = correlate(traj)
        assert disp is GovernanceDisposition.NO_OVERRIDE


def test_deny_wins_over_review():
    # divergence (review) AND exfiltration (deny) → deny governs
    traj = SecurityTrajectory()
    traj.add(_ev("1", capability="crm.read", data_classifications=("pii",), side_effects=("records_read=5000",)))
    traj.add(_ev("2", capability="unplanned.upload", network=("x.com",)))
    disp, reasons = correlate(traj, planned_capabilities=("crm.read",), max_external_records=100)
    assert disp is GovernanceDisposition.DENY and len(reasons) >= 2
