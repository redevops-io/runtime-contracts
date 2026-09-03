"""Conformance for the execution boundary contracts.

These encode the properties the audit's benchmarks depend on: an envelope's identity is
its content, tampering is intrinsically detectable, containment denies by default, and a
receipt is bound to the envelope it discharges.
"""
import pytest

from runtime_contracts.models import (
    ExecutionConstraint,
    ExecutionEnvelope,
    ExecutionReceipt,
)
from runtime_contracts.models.capability import Idempotency


def _envelope(**over):
    base = dict(
        mission_id="m-1",
        plan_fingerprint="rcv1:plan",
        capability_id="broker.place_order",
        authority="grant-7",
        target="node-local",
        parameters={"account": "A1", "instrument": "AAPL", "quantity": "10"},
        credential_refs=("secret://broker/key",),
        constraint=ExecutionConstraint(allow_egress=("broker.example:443",),
                                       max_memory_mb=256, max_duration_seconds=30),
        idempotency=Idempotency.AT_MOST_ONCE,
        idempotency_key="idem-abc",
        not_after="2026-09-03T00:00:00Z",
    )
    base.update(over)
    return ExecutionEnvelope(**base)


def test_binding_is_stable_and_content_addressed():
    e1 = _envelope()
    e2 = _envelope()
    assert e1.binding == e2.binding
    assert e1.binding.startswith("rcv1:")


def test_signature_is_not_part_of_the_binding():
    # A detached signature signs the binding, so it must not change it.
    assert _envelope(signature="sig-A").binding == _envelope(signature="sig-B").binding


@pytest.mark.parametrize("field,value", [
    ("parameters", {"account": "A1", "instrument": "AAPL", "quantity": "9999"}),
    ("capability_id", "broker.cancel_all"),
    ("authority", "grant-forged"),
    ("mission_id", "m-2"),
    ("target", "node-somewhere-else"),
    ("not_after", "2099-01-01T00:00:00Z"),
    ("idempotency_key", "idem-replay"),
])
def test_tampering_any_bound_field_changes_the_binding(field, value):
    # Benchmark D: every modified envelope is a different envelope no authority issued.
    assert _envelope(**{field: value}).binding != _envelope().binding


def test_containment_denies_by_default():
    c = ExecutionConstraint()
    assert c.read_paths == () and c.write_paths == ()
    assert c.allow_egress == ()          # no ambient network
    assert c.max_processes == 1 and c.max_concurrency == 1


def test_constraint_is_part_of_the_binding():
    tight = _envelope(constraint=ExecutionConstraint())
    loose = _envelope(constraint=ExecutionConstraint(allow_egress=("0.0.0.0/0",)))
    assert tight.binding != loose.binding


def test_floats_have_no_canonical_form():
    # The discipline that makes envelopes reproduce across languages: a bare float in
    # parameters is refused at binding time (use decimal strings instead).
    with pytest.raises(Exception):
        _envelope(parameters={"quantity": 10.5}).binding


def test_receipt_binds_to_the_envelope():
    e = _envelope()
    r = ExecutionReceipt(
        envelope_binding=e.binding,
        mission_id=e.mission_id,
        capability_id=e.capability_id,
        idempotency_key=e.idempotency_key,
        outcome="executed",
        side_effect_digest="rcv1:effect",
    )
    assert r.envelope_binding == e.binding
    assert r.receipt_id.startswith("rcv1:")


def test_refusal_is_a_first_class_receipt():
    e = _envelope()
    r = ExecutionReceipt(
        envelope_binding=e.binding, mission_id=e.mission_id,
        capability_id=e.capability_id, idempotency_key=e.idempotency_key,
        outcome="refused", reason="envelope_expired",
    )
    assert r.outcome == "refused" and r.reason == "envelope_expired"
    assert r.side_effect_digest == ""    # nothing happened, and the receipt says so
