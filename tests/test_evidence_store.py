"""Tests for the Historical Evidence Plane storage seam (runtime_contracts.store)."""
from __future__ import annotations

from dataclasses import replace

import pytest

from runtime_contracts.protocol.telemetry import RuntimeSecurityEvent, TelemetryKind
from runtime_contracts.store import (
    EVIDENCE_FAMILIES,
    EvidenceEnvelope,
    EvidenceStore,
    FileEvidenceStore,
    InMemoryEvidenceStore,
    available_backends,
    open_store,
    project,
    register_backend,
)


def _clock():
    """A deterministic ISO clock that advances one second per call."""
    n = {"t": 0}

    def tick() -> str:
        n["t"] += 1
        return f"2026-01-01T00:00:{n['t']:02d}+00:00"

    return tick


def _env(event_id="e1", family="security_events", event_time="2026-01-01", **kw):
    return EvidenceEnvelope(event_id=event_id, event_type="x", family=family,
                            event_time=event_time, payload={"event_id": event_id, **kw})


def test_families_are_the_thirteen():
    assert len(EVIDENCE_FAMILIES) == 13
    assert "security_events" in EVIDENCE_FAMILIES
    assert "governance_dispositions" in EVIDENCE_FAMILIES


def test_envelope_is_self_pinning_and_content_addressed():
    a = _env(payload_kw="v")
    assert a.content_hash.startswith("rcv1:")
    # payload_ref defaults to the content hash
    assert a.payload_ref == a.content_hash
    # identity excludes known_at (chain-of-custody)
    assert a.identity() == replace(a, known_at="2030-01-01").identity()
    # a different payload => a different content hash
    b = EvidenceEnvelope(event_id="e2", event_type="x", payload={"k": "other"})
    assert b.content_hash != a.content_hash


def test_stores_satisfy_the_protocol():
    assert isinstance(InMemoryEvidenceStore(), EvidenceStore)
    assert isinstance(FileEvidenceStore, type)


def test_append_resolve_by_id_and_hash():
    s = InMemoryEvidenceStore(clock=_clock())
    e = _env("m1")
    s.append(e)
    assert s.resolve("m1").event_id == "m1"
    assert s.resolve(e.content_hash).content_hash == e.content_hash
    # pin form ref@ver#hash resolves on the hash tail
    assert s.resolve(f"whatever@1#{e.content_hash}").content_hash == e.content_hash
    assert s.resolve("nope") is None


def test_snapshot_and_changes_are_bitemporal():
    s = InMemoryEvidenceStore(clock=_clock())      # stamps :01, :02, :03 …
    s.append(_env("a"))
    s.append(_env("b"))
    s.append(_env("c"))
    cutoff = "2026-01-01T00:00:02+00:00"
    # snapshot(as_of) = known at or before the instant
    assert [e.event_id for e in s.snapshot(cutoff)] == ["a", "b"]
    # changes(since) = strictly after
    assert [e.event_id for e in s.changes(cutoff)] == ["c"]


def test_scan_by_predicate_and_time_range():
    s = InMemoryEvidenceStore(clock=_clock())
    s.append(_env("a", family="security_events", event_time="2026-03-01"))
    s.append(_env("b", family="governance_dispositions", event_time="2026-03-05"))
    s.append(_env("c", family="security_events", event_time="2026-04-01"))
    got = [e.event_id for e in s.scan({"family": "security_events"})]
    assert got == ["a", "c"]
    ranged = [e.event_id for e in s.scan(time_range=("2026-03-01", "2026-03-31"))]
    assert ranged == ["a", "b"]


def test_verify_detects_tampering():
    s = InMemoryEvidenceStore(clock=_clock())
    e = _env("t1", secret="keep")
    s.append(e)
    assert s.verify("t1") is True
    # forge a row whose stored hash no longer matches its payload
    forged = replace(e, payload={"secret": "changed"})
    assert forged.verify_payload() is False


def test_project_runtime_security_event():
    ev = RuntimeSecurityEvent(
        event_id="se-1", kind=TelemetryKind.SECURITY, event_type="capability.invoked",
        mission_id="m-9", capability="storage.upload", occurred_at="2026-05-01T00:00:00Z",
        parent_event_id="se-0", causal_id="c-1", decision="DENY",
        data_classifications=("pii",), network=("s3.external.com",),
    )
    env = project(ev, tenant_id="acme", contract_version="rcv1")
    assert env.family == "security_events"
    assert env.event_id == "se-1"
    assert env.mission_id == "m-9"
    assert env.parent_event_id == "se-0"
    assert env.causation_id == "c-1"
    assert env.event_time == "2026-05-01T00:00:00Z"
    assert env.tenant_id == "acme"
    assert env.content_hash.startswith("rcv1:")
    # the projected row is persistable and verifiable
    s = InMemoryEvidenceStore(clock=_clock())
    s.append(env)
    assert s.verify("se-1") is True


def test_project_generic_mapping():
    env = project({"event_id": "x1", "event_type": "MissionCreated", "mission_id": "m-1"},
                  family="mission_events")
    assert env.family == "mission_events"
    assert env.event_type == "MissionCreated"
    assert env.mission_id == "m-1"


def test_file_store_round_trips_and_reloads(tmp_path):
    path = str(tmp_path / "evidence.jsonl")
    s1 = FileEvidenceStore(path, clock=_clock())
    s1.append(_env("f1", family="approvals"))
    s1.append(_env("f2", family="trace_spans"))
    assert len(s1) == 2
    # a fresh store over the same file sees the persisted rows, intact and verifiable
    s2 = FileEvidenceStore(path, clock=_clock())
    assert len(s2) == 2
    assert s2.resolve("f1").family == "approvals"
    assert s2.verify("f2") is True


def test_registry_and_pluggable_backend(tmp_path):
    assert "file" in available_backends()
    assert "memory" in available_backends()
    mem = open_store("memory")
    assert isinstance(mem, EvidenceStore)
    fs = open_store("file", path=str(tmp_path / "e.jsonl"))
    assert isinstance(fs, FileEvidenceStore)
    with pytest.raises(LookupError):
        open_store("iceberg")           # not registered in the open runtime
    # an enterprise plugin registers its own backend behind the same interface
    register_backend("custom", lambda **cfg: InMemoryEvidenceStore())
    assert isinstance(open_store("custom"), EvidenceStore)
