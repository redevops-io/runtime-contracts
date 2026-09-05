"""ControlEvidence — the canonical, content-addressed compliance-evidence contract (AGPL base)."""
from runtime_contracts import ControlEvidence, ControlEvidenceCollector, ControlStatus, RuntimeStream


def test_evidence_is_content_addressed():
    e = ControlEvidence(control_id="RDO-AI-004", subject="tenant:acme",
                        status=ControlStatus.ENFORCED, mission_id="m1",
                        event_ids=("e2", "e1"), collector="governance", observed_at="2026-09-05T00:00:00Z")
    assert e.evidence_id.startswith("rcv1:")
    # deterministic + order-independent on the tuple fields
    e2 = ControlEvidence(control_id="RDO-AI-004", subject="tenant:acme",
                         status=ControlStatus.ENFORCED, mission_id="m1",
                         event_ids=("e1", "e2"), collector="governance", observed_at="2026-09-05T00:00:00Z")
    assert e.evidence_id == e2.evidence_id
    # any material change ⇒ new id
    assert ControlEvidence(control_id="RDO-AI-004", subject="tenant:acme",
                           status=ControlStatus.EVIDENCED).evidence_id != e.evidence_id


def test_status_vocabulary_is_explicit():
    vals = {s.value for s in ControlStatus}
    assert vals == {"enforced", "evidenced", "external_evidence_required",
                    "not_applicable", "unverified"}


def test_runtime_stream_vocabulary_is_the_shared_seam():
    # the ten runtime-truth streams a base producer projects into ControlEvidence
    vals = {s.value for s in RuntimeStream}
    assert vals == {
        "durable_event_ledger", "hitl_approval", "authority_grant", "execution_envelope",
        "verification_receipt", "capability_manifest", "evidence_lineage",
        "model_version_lock", "data_flow_classification", "risk_assessment",
    }
    # a producer tags evidence.control_id with the stream key; it's a plain str for the mapping side
    e = ControlEvidence(control_id=RuntimeStream.DURABLE_EVENT_LEDGER.value, subject="sys",
                        status=ControlStatus.ENFORCED)
    assert e.control_id == "durable_event_ledger"
    assert RuntimeStream.DURABLE_EVENT_LEDGER == "durable_event_ledger"  # StrEnum equality


def test_canonical_form_serializes_status_and_sorts_refs():
    e = ControlEvidence(control_id="c", subject="s", status=ControlStatus.EVIDENCED,
                        event_ids=("b", "a"), artifact_refs=("y", "x"))
    cf = e.canonical_form()
    assert cf["status"] == "evidenced"
    assert cf["event_ids"] == ["a", "b"] and cf["artifact_refs"] == ["x", "y"]
    assert cf["contract_version"] == "control-evidence/v1"


def test_defaults_are_conservative():
    e = ControlEvidence(control_id="c", subject="s")
    assert e.status is ControlStatus.UNVERIFIED and e.valid_until == ""


def test_collector_is_a_duck_typed_seam():
    class GovCollector:
        control_id = "RDO-AI-004"
        def collect(self, *, subject):
            return [ControlEvidence(control_id=self.control_id, subject=subject,
                                    status=ControlStatus.ENFORCED, collector="governance")]
    c: ControlEvidenceCollector = GovCollector()   # conforms by shape
    (ev,) = c.collect(subject="tenant:acme")
    assert ev.control_id == "RDO-AI-004" and ev.status is ControlStatus.ENFORCED
