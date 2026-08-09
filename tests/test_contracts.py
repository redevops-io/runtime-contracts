"""The contract types themselves."""
from __future__ import annotations

import pytest

from runtime_contracts import (
    ArtifactHandle,
    AuthorizationOutcome,
    ContextPreviewPlan,
    ContextView,
    DereferenceEvent,
    EventKind,
    Intent,
    Necessity,
    PlanFeasibility,
    PlannedItem,
    RuntimeEvent,
    Tenancy,
    Visibility,
    missing_sequences,
    replay,
)


def handle(n=1, *, tenant=None, visibility=Visibility.PUBLIC, tokens=100):
    return ArtifactHandle(f"evidence/e{n}@1", "evidence", "1", f"rcv1:{n}",
                          Tenancy(visibility, tenant),
                          estimated_expansion_tokens=tokens)


class TestHandlesAreJudgeableBeforeExpansion:
    def test_an_unpinned_id_is_refused(self):
        with pytest.raises(ValueError, match="not version-pinned"):
            ArtifactHandle("evidence/e1", "evidence", "1", "h",
                           Tenancy(Visibility.PUBLIC))

    def test_a_float_cost_is_refused(self):
        with pytest.raises(ValueError, match="decimal string"):
            ArtifactHandle("e/x@1", "evidence", "1", "h",
                           Tenancy(Visibility.PUBLIC),
                           estimated_expansion_cost=1.5)

    def test_observation_time_does_not_change_identity(self):
        a = handle()
        b = ArtifactHandle("evidence/e1@1", "evidence", "1", "rcv1:1",
                           Tenancy(Visibility.PUBLIC),
                           observed_at="2026-07-31T00:00:00Z")
        assert a.handle_hash == b.handle_hash


class TestVisibilityRunsOneWay:
    def test_a_private_artifact_must_name_its_tenant(self):
        with pytest.raises(ValueError, match="must name its tenant"):
            Tenancy(Visibility.PRIVATE)

    def test_a_public_artifact_may_not_name_one(self):
        with pytest.raises(ValueError, match="private data that has escaped"):
            Tenancy(Visibility.PUBLIC, "acme")

    def test_private_may_cite_public(self):
        assert Tenancy(Visibility.PUBLIC).may_be_cited_by(
            Tenancy(Visibility.PRIVATE, "acme"))

    def test_public_may_never_cite_private(self):
        assert not Tenancy(Visibility.PRIVATE, "acme").may_be_cited_by(
            Tenancy(Visibility.PUBLIC))

    def test_tenants_are_separated(self):
        assert not Tenancy(Visibility.PRIVATE, "a").may_be_cited_by(
            Tenancy(Visibility.PRIVATE, "b"))


class TestARequiredItemIsNeverDropped:
    def test_an_unaffordable_required_set_is_infeasible(self):
        plan = ContextPreviewPlan(
            "p", [PlannedItem(handle(tokens=900), Necessity.REQUIRED)],
            budget_tokens=100)
        assert plan.feasibility is PlanFeasibility.INFEASIBLE_BUDGET
        assert not plan.is_feasible

    def test_a_denied_required_item_is_infeasible(self):
        plan = ContextPreviewPlan(
            "p", [PlannedItem(handle(), Necessity.REQUIRED,
                              authorization=AuthorizationOutcome.DENIED_TENANT)])
        assert plan.feasibility is PlanFeasibility.INFEASIBLE_AUTHORIZATION

    def test_an_unaffordable_optional_item_is_still_feasible(self):
        plan = ContextPreviewPlan(
            "p", [PlannedItem(handle(tokens=900), Necessity.OPTIONAL)],
            budget_tokens=100)
        assert plan.is_feasible


class TestViewsReplay:
    def test_a_moved_pin_is_reported_not_refreshed(self):
        plan = ContextPreviewPlan("p", [PlannedItem(handle(), Necessity.REQUIRED)])
        first = ContextView("v1", plan, {"evidence/e1@1": "rcv1:1"})
        later = ContextView("v2", plan, {"evidence/e1@1": "rcv1:CHANGED"})

        assert first.view_hash != later.view_hash
        assert first.divergence_from(later) == ["evidence/e1@1"]


class TestEventsOrderPhysically:
    def _events(self, seqs):
        return [RuntimeEvent(f"e{s}", EventKind.DEREFERENCE, Intent.COMPLETED,
                             "s1", s, "cr") for s in seqs]

    def test_replay_uses_sequence_not_time(self):
        assert [e.sequence for e in replay(self._events([2, 0, 1]))] == [0, 1, 2]

    def test_a_gap_is_reported_rather_than_closed(self):
        """A replay that renumbers cannot report a missing event."""
        assert missing_sequences(self._events([0, 1, 3])) == {"s1": [2]}

    def test_the_event_id_does_not_change_the_hash(self):
        a = RuntimeEvent("a", EventKind.DEREFERENCE, Intent.COMPLETED, "s", 0, "cr")
        b = RuntimeEvent("b", EventKind.DEREFERENCE, Intent.COMPLETED, "s", 0, "cr")
        assert a.event_hash == b.event_hash

    def test_proposed_and_completed_are_distinguishable(self):
        """The difference between suggesting an action and taking one."""
        proposed = RuntimeEvent("a", EventKind.CAPABILITY_INVOKED, Intent.PROPOSED,
                                "s", 0, "cr")
        completed = RuntimeEvent("a", EventKind.CAPABILITY_INVOKED,
                                 Intent.COMPLETED, "s", 0, "cr")
        assert proposed.event_hash != completed.event_hash

    def test_a_refused_dereference_is_still_recorded(self):
        event = DereferenceEvent("rcv1:h", "evidence/e1@1", "full",
                                 AuthorizationOutcome.DENIED_TENANT).as_event(
            event_id="e", stream_id="s", sequence=0, emitted_by="cr")
        assert event.intent is Intent.FAILED


class TestTheEvidenceCandidateBoundary:
    """RAG finds candidates; Context Runtime decides what enters."""

    def _candidate(self, **kw):
        from runtime_contracts import EvidenceCandidate, Freshness

        spec = dict(candidate_id="c1", source_artifact_id="evidence/e1@1",
                    artifact_kind="evidence", artifact_content_hash="rcv1:aaa",
                    projection="summary", authority="redevops-rag",
                    visibility=Visibility.PUBLIC, freshness=Freshness.CURRENT,
                    retrieval_score="0.87", estimated_tokens=120)
        spec.update(kw)
        return EvidenceCandidate(**spec)

    def test_retrieval_score_is_not_part_of_handle_identity(self):
        """Re-ranking changes what is chosen, never what evidence is."""
        from runtime_contracts import candidate_to_handle

        high = candidate_to_handle(self._candidate(retrieval_score="0.99"))
        low = candidate_to_handle(self._candidate(retrieval_score="0.01"))
        assert high.handle_hash == low.handle_hash

    def test_the_retrieval_reason_is_not_either(self):
        from runtime_contracts import candidate_to_handle

        a = candidate_to_handle(self._candidate(retrieval_reason="semantic"))
        b = candidate_to_handle(self._candidate(retrieval_reason="exact id"))
        assert a.handle_hash == b.handle_hash

    def test_projection_is(self):
        from runtime_contracts import candidate_to_handle

        summary = candidate_to_handle(self._candidate(projection="summary"))
        full = candidate_to_handle(self._candidate(projection="full"))
        assert summary.handle_hash != full.handle_hash

    @pytest.mark.parametrize("field", [
        "artifact_content_hash", "artifact_kind", "authority", "projection"])
    def test_a_candidate_missing_a_required_field_is_refused(self, field):
        from runtime_contracts import CandidateRejected, candidate_to_handle

        with pytest.raises(CandidateRejected, match="cannot be replayed"):
            candidate_to_handle(self._candidate(**{field: ""}))

    def test_an_unpinned_artifact_is_refused(self):
        from runtime_contracts import CandidateRejected, candidate_to_handle

        with pytest.raises(CandidateRejected, match="latest at the time"):
            candidate_to_handle(self._candidate(source_artifact_id="evidence/e1"))

    def test_a_private_candidate_carries_its_tenant(self):
        from runtime_contracts import candidate_to_handle

        handle = candidate_to_handle(self._candidate(
            visibility=Visibility.PRIVATE, tenant_id="acme"))
        assert handle.tenancy.tenant_id == "acme"


class TestDeclarationAndMaterializationAreSeparate:
    def test_cost_and_cache_do_not_reach_identity(self):
        """Two runs that assembled the same working set are the same view."""
        from runtime_contracts import (
            MaterializationOutcome, MaterializationRecord, MaterializedItem)

        slow = MaterializationRecord(
            view_hash="rcv1:same", latency_ms=4000,
            items=(MaterializedItem("h", "evidence/e1@1", "summary",
                                    MaterializationOutcome.MATERIALIZED,
                                    from_cache=False),))
        cached = MaterializationRecord(
            view_hash="rcv1:same", latency_ms=12,
            items=(MaterializedItem("h", "evidence/e1@1", "summary",
                                    MaterializationOutcome.MATERIALIZED,
                                    from_cache=True),))

        assert slow.view_hash == cached.view_hash

    def test_failures_are_enumerated_not_summarised(self):
        from runtime_contracts import (
            MaterializationOutcome, MaterializationRecord, MaterializedItem)

        record = MaterializationRecord(view_hash="rcv1:x", items=(
            MaterializedItem("h1", "a@1", "summary",
                             MaterializationOutcome.MATERIALIZED),
            MaterializedItem("h2", "b@1", "summary",
                             MaterializationOutcome.STALE_PIN),
            MaterializedItem("h3", "c@1", "summary",
                             MaterializationOutcome.DENIED)))

        assert record.dereference_count == 3
        assert {f.outcome for f in record.failures} == {
            MaterializationOutcome.STALE_PIN, MaterializationOutcome.DENIED}


def test_the_module_version_matches_the_package_version():
    """v0.2.0 shipped a module reporting 0.1.0. Anyone pinning the tag and
    asking the package what it was got the wrong answer — and a version string
    that lies is worse than none, because it is checked."""
    import re
    from pathlib import Path

    import runtime_contracts

    declared = re.search(
        r'^version = "([^"]+)"',
        (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text(),
        re.M).group(1)
    assert runtime_contracts.__version__ == declared
