"""Evidence-native protocol primitives folded onto the Decimal canonical (0.3.x consolidation, #5).

EvidenceRef / EvidenceChange (versioned, content-addressed evidence identity + typed delta), the
canonical lineage edge vocabulary, and the STALE/INVALIDATED conclusion states — all computing identity
through the strict `rcv1:` canonical, all additive (existing intent/seal identity unchanged).
"""
from __future__ import annotations

import json
from pathlib import Path

import runtime_contracts as rc
from runtime_contracts import (
    EvidenceRef, EvidenceChange, CREATED, UPDATED, DELETED, KNOWN_REF_TYPES,
    RelationKind, MemberRole, LineageMember, derived_from, supersedes, relation,
    VerifiedIntent, IntentState, IntentField, Author, intent_from_json,
)


# ── EvidenceRef ──

def test_evidence_ref_identity_is_rcv1_and_content_addressed():
    r = EvidenceRef("crm/acct/42", content_hash="rcv1:deadbeef", version="7", ref_type="chunk")
    assert r.identity().startswith("rcv1:")
    assert r.pin() == "crm/acct/42@7#rcv1:deadbeef"
    # same descriptive content ⇒ same identity regardless of construction
    assert r.identity() == EvidenceRef("crm/acct/42", content_hash="rcv1:deadbeef",
                                       version="7", ref_type="chunk").identity()
    # a different revision (content_hash) is different evidence
    assert r.identity() != EvidenceRef("crm/acct/42", content_hash="rcv1:cafe",
                                       version="8", ref_type="chunk").identity()
    assert "chunk" in KNOWN_REF_TYPES and "embedding" in KNOWN_REF_TYPES


# ── EvidenceChange ──

def test_evidence_change_types_and_basis_removal():
    prior = EvidenceRef("crm/acct/42", content_hash="rcv1:a", version="1")
    new = EvidenceRef("crm/acct/42", content_hash="rcv1:b", version="2")
    upd = EvidenceChange("crm/acct/42", UPDATED, prior=prior, new=new)
    assert upd.change_type == UPDATED and not upd.removes_basis
    dele = EvidenceChange("crm/acct/42", DELETED, prior=prior)
    assert dele.removes_basis and dele.new is None
    assert EvidenceChange("x", CREATED).change_type == "CREATED"


def test_evidence_change_identity_excludes_who_and_when():
    prior = EvidenceRef("crm/acct/42", content_hash="rcv1:a")
    base = EvidenceChange("crm/acct/42", UPDATED, prior=prior,
                          new=EvidenceRef("crm/acct/42", content_hash="rcv1:b"))
    # observed_at / provenance are chain-of-custody — two changes that differ only there are the same
    other = EvidenceChange("crm/acct/42", UPDATED, prior=prior,
                           new=EvidenceRef("crm/acct/42", content_hash="rcv1:b"),
                           observed_at="2026-08-21T00:00:00Z", provenance="crm-connector")
    assert base.identity() == other.identity()


# ── lineage edge vocabulary ──

def test_derived_from_is_the_canonical_lineage_edge():
    edge = derived_from("emb::beef", "chunk::c0ffee", subject_type="embedding", source_type="chunk",
                        asserted_by="redevops-rag")
    assert edge.kind is RelationKind.DERIVED_FROM
    subj, obj = edge.members
    assert (subj.role, subj.ref, subj.ref_type) == (MemberRole.SUBJECT, "emb::beef", "embedding")
    assert (obj.role, obj.ref, obj.ref_type) == (MemberRole.OBJECT, "chunk::c0ffee", "chunk")


def test_relation_identity_excludes_asserter_and_confidence():
    a = derived_from("a", "b", asserted_by="reader-1", confidence="1")
    b = derived_from("a", "b", asserted_by="reader-2", confidence="0.7")
    assert a.identity() == b.identity()          # who asserted / how confidently is not identity
    assert supersedes("v2", "v1").kind is RelationKind.SUPERSEDES


def test_relation_normalizes_roles():
    m = LineageMember("x", role=MemberRole.OBJECT, ref_type="evidence")
    edge = relation(RelationKind.REFINES, m, "y")
    assert edge.members[0].role is MemberRole.SUBJECT and edge.members[0].ref == "x"
    assert edge.members[1].role is MemberRole.OBJECT


# ── STALE / INVALIDATED + capability/policy version on VerifiedIntent ──

def _sealed_intent(**kw) -> VerifiedIntent:
    vi = VerifiedIntent(objective="rebalance",
                        fields={"target": IntentField(value="growth", author=Author.USER)}, **kw)
    return vi.seal()


def test_stale_and_invalidated_states_round_trip():
    for state in (IntentState.STALE, IntentState.INVALIDATED):
        from dataclasses import replace
        vi = replace(_sealed_intent(), state=state)
        back = intent_from_json(vi.to_json())
        assert back.state is state                          # the transitioned state survives the round-trip
        assert back.intent_hash == vi.intent_hash           # identity unchanged by the transition


def test_capability_and_policy_version_are_recorded_not_hashed():
    plain = _sealed_intent()
    versioned = _sealed_intent(capability_version="readers@3", policy_version="pol@9")
    # provenance, not identity — neither the request hash nor the artifact hash moves
    assert versioned.intent_hash == plain.intent_hash
    assert versioned.artifact_digest == plain.artifact_digest
    # but they round-trip through the serialized artifact
    back = intent_from_json(versioned.to_json())
    assert back.capability_version == "readers@3" and back.policy_version == "pol@9"


# ── golden vectors (cross-language conformance) ──

_GOLDEN = json.loads((Path(__file__).parent / "golden_evidence_native.json").read_text())


def test_golden_evidence_native_vectors_reproduce():
    """The pinned rcv1 identities must be reproducible byte-for-byte — the cross-language contract.
    A Go/Kotlin port loads the same file and must reproduce every ``expected_identity``."""
    assert _GOLDEN["canonicalization_version"] == rc.CANONICALIZATION_VERSION

    refs = {
        "chunk-ref": EvidenceRef("crm/acct/42", content_hash="rcv1:deadbeef", version="7",
                                 ref_type="chunk", modality="text"),
        "embedding-ref": EvidenceRef("doc.md::0", content_hash="rcv1:c0ffee", ref_type="embedding",
                                     media_type="application/json"),
    }
    for case in _GOLDEN["evidence_ref_cases"]:
        assert refs[case["name"]].identity() == case["expected_identity"], case["name"]

    changes = {
        "updated": EvidenceChange("crm/acct/42", UPDATED,
                                  prior=EvidenceRef("crm/acct/42", content_hash="rcv1:a", version="1"),
                                  new=EvidenceRef("crm/acct/42", content_hash="rcv1:b", version="2")),
        "deleted": EvidenceChange("crm/acct/42", DELETED,
                                  prior=EvidenceRef("crm/acct/42", content_hash="rcv1:a")),
    }
    for case in _GOLDEN["evidence_change_cases"]:
        assert changes[case["name"]].identity() == case["expected_identity"], case["name"]

    edges = {
        "derived_from": derived_from("emb::beef", "chunk::c0ffee",
                                     subject_type="embedding", source_type="chunk"),
        "supersedes": supersedes("cut:v2", "cut:v1",
                                 subject_type="context_view", prior_type="context_view"),
    }
    for case in _GOLDEN["lineage_cases"]:
        assert edges[case["name"]].identity() == case["expected_identity"], case["name"]
