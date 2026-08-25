"""P0 dataset-world contract — WorldEvent, IdentityGraph, WorldRegistry, VisualTrace.

Exit criterion (docx Phase 0): one source record retains identity + provenance through
Discovery → Mission → Context → app capability, and the same canonical entity resolves to every app.
"""
from __future__ import annotations

from runtime_contracts import (
    BusinessBlock,
    Capsule,
    EntityKind,
    EntityRef,
    GroundTruth,
    IdentityGraph,
    NeedsYouReason,
    RealismClass,
    TraceMilestone,
    VisualTrace,
    WorldEvent,
    default_registry,
)
from runtime_contracts.protocol.evidence import EvidenceRef
from runtime_contracts.world.event import LEAD_RECEIVED


def _lead_event():
    return WorldEvent(
        world_id="after-hours-lead", dataset_id="home-services", source_record_id="call-8842",
        event_type=LEAD_RECEIVED,
        entity_ids=(EntityRef("cust-acme", EntityKind.CUSTOMER.value, "Acme Roofing"),
                    EntityRef("prop-114-elm", EntityKind.PROPERTY.value, "114 Elm St")),
        observed_at="2026-08-25T21:47:00Z", effective_at="2026-08-25T21:47:00Z",
        evidence_refs=(EvidenceRef(ref="transcript-8842", content_hash="rcv1:aa", source="voice"),),
        classification=RealismClass.SYNTHETIC.value, data_classifications=("pii",),
        permissions=("crm.read",), tenant="world:after-hours-lead",
        ground_truth=GroundTruth(situation="qualified after-hours lead",
                                 target_outcome="governed quote during the interaction"),
        capability_requirements=("crm.read", "geo.resolve", "pricing.quote"),
        scenario_seed="seed-42",
        payload={"caller": "Acme", "service": "roof repair", "property": "114 Elm St"})


def test_world_event_is_content_addressed_and_stable():
    e = _lead_event()
    assert e.content_hash.startswith("rcv1:")
    assert e.identity().startswith("rcv1:")
    # identity excludes ingest-time + optimizer hints: same event learned later / with hints has same id
    from dataclasses import replace
    assert e.identity() == replace(e, known_at="2030-01-01", latency_ms_hint=999, freshness_s=5).identity()
    # a different source payload => a different content hash
    assert e.content_hash != replace(e, content_hash="", payload={"caller": "Other"}).content_hash


def test_carried_entities_and_realism():
    e = _lead_event()
    assert e.entity(EntityKind.CUSTOMER.value).entity_id == "cust-acme"
    assert e.entity(EntityKind.PROPERTY.value).label == "114 Elm St"
    assert e.realism() is RealismClass.SYNTHETIC


def test_identity_preserved_across_the_stack_and_every_app():
    """The exit criterion: the canonical entity keeps identity from the event through to each app node."""
    e = _lead_event()
    cust = e.entity(EntityKind.CUSTOMER.value)
    g = IdentityGraph()
    # a projection seeder created a real Twenty record; ERPNext is derived (no seeded record)
    g.register(cust.entity_id, "twenty", "twenty-company-991")
    twenty_id = g.resolve(cust.entity_id, "twenty")
    erpnext_id = g.resolve(cust.entity_id, "erpnext")
    chatwoot_id = g.resolve(cust.entity_id, "chatwoot")
    assert twenty_id == "twenty-company-991"                 # registered wins
    assert erpnext_id.startswith("erpnext-") and chatwoot_id.startswith("chatwoot-")
    # deterministic: same entity+app always derives the same id (replay-stable)
    assert erpnext_id == g.resolve(cust.entity_id, "erpnext")
    # reverse: an app-native id maps back to the canonical entity, never a new object
    assert g.reverse("twenty", "twenty-company-991") == cust.entity_id
    assert g.reverse("twenty", "unknown") is None
    # provenance holds: the event identity is unchanged regardless of which app projection we resolved
    assert e.identity() == _lead_event().identity()


def test_world_registry_catalogs_real_sources_with_realism():
    r = default_registry()
    ids = {w.world_id for w in r.list()}
    assert {"kyc-ownership", "security-telemetry", "geo-zoning", "finance-evidence"} <= ids
    kyc = r.get("kyc-ownership")
    assert kyc.realism == RealismClass.REAL_SNAPSHOT.value and kyc.ground_truth_available
    assert "GLEIF LEI" in kyc.datasources
    assert r.get("finance-evidence").realism == RealismClass.REAL_LIVE.value


def test_visual_trace_carries_the_capsule_and_needs_you():
    cap = Capsule(mission_id="M-1", entity_id="cust-acme", evidence_hash="rcv1:aa",
                  policy_ref="pol:quote/v1", authority_ref="chain:ctx1")
    vt = VisualTrace(mission_id="M-1", world_id="after-hours-lead")
    vt.add(TraceMilestone(0.0, "lead arrives", node="intake", block=BusinessBlock.REVENUE.value,
                          realism=RealismClass.SYNTHETIC.value))
    vt.add(TraceMilestone(10.0, "roof attribute missing — ask caller", kind="needs_you",
                          needs_you=NeedsYouReason.MISSING_EVIDENCE.value, capsule=cap,
                          block=BusinessBlock.RUNTIME.value))
    vt.add(TraceMilestone(13.0, "quote created", kind="action", node="pricing",
                          block=BusinessBlock.FINANCE.value, capsule=cap))
    cf = vt.canonical_form()
    assert [m["t_offset_s"] for m in cf["milestones"]] == [0.0, 10.0, 13.0]     # ordered
    ny = cf["milestones"][1]
    assert ny["needs_you"] == "MISSING_EVIDENCE" and ny["capsule"]["entity_id"] == "cust-acme"
    assert ny["capsule"]["evidence_hash"] == "rcv1:aa"                          # references, not copies
