"""The Quantify adapter — the first contact between contract and real artifacts.

Quantify is not installed here, so its boundary function is injected. That is
also the point: the adapter must not require the application, and the
application must not require the contracts.
"""
from __future__ import annotations

import json
import pathlib

import pytest

from adapters.quantify.adapter import plan_from, to_handle, view_from, visibility_of
from runtime_contracts import (
    AuthorizationOutcome,
    Necessity,
    Tenancy,
    Visibility,
    content_hash,
)

GOLDEN = json.loads(
    (pathlib.Path(__file__).parent.parent / "golden" / "context_view.json").read_text()
)["cases"]


class _QuantifyVisibility:
    """Stands in for Quantify's own `Visibility` enum."""

    def __init__(self, value):
        self.value = value


def quantify_boundary(reference: str):
    """Stands in for `src.mission.boundary.visibility_of`."""
    kind = reference.split("/")[0]
    private = {"mission", "intent", "plan-run"}
    return _QuantifyVisibility(
        "PRIVATE_WORKSPACE" if kind in private else "PUBLIC_LIBRARY")


class TestVisibilityMapsWithoutLoss:
    @pytest.mark.parametrize("reference,expected", [
        ("methodology/hrp@3", Visibility.PUBLIC),
        ("calendar/nyse@1", Visibility.PUBLIC),
        ("finding/hrp-degenerates-to-cash-proxy@1", Visibility.PUBLIC),
        ("claim/hrp-diversifies@1", Visibility.PUBLIC),
        ("mission/my-plan@1", Visibility.PRIVATE),
        ("intent/retire@1", Visibility.PRIVATE),
    ])
    def test_each_kind_maps(self, reference, expected):
        assert visibility_of(reference, quantify_boundary=quantify_boundary) is expected

    def test_the_directional_rule_survives_translation(self):
        public = Tenancy(Visibility.PUBLIC)
        private = Tenancy(Visibility.PRIVATE, "pilot")

        assert public.may_be_cited_by(private)
        assert not private.may_be_cited_by(public)


class TestHandlesCarryIdentityNotContent:
    def test_a_handle_holds_only_the_referent_hash(self):
        handle = to_handle("methodology/hrp@3", artifact_type="methodology",
                           content_hash="rcv1:aaa", visibility=Visibility.PUBLIC)
        payload = handle.canonical_form()

        assert payload["artifact_content_hash"] == "rcv1:aaa"
        assert "content" not in payload and "body" not in payload

    def test_an_unpinned_reference_is_refused(self):
        with pytest.raises(ValueError, match="not version-pinned"):
            to_handle("methodology/hrp", artifact_type="methodology",
                      content_hash="rcv1:aaa", visibility=Visibility.PUBLIC)

    def test_a_quantify_hash_is_not_a_view_hash(self):
        """Different things. If they could collide, one could be passed for the
        other and a working set would be indistinguishable from an artifact."""
        handle = to_handle("methodology/hrp@3", artifact_type="methodology",
                           content_hash="rcv1:aaa", visibility=Visibility.PUBLIC)
        plan = plan_from(
            [(handle, Necessity.REQUIRED, "full", AuthorizationOutcome.GRANTED)],
            plan_id="p")
        view = view_from(plan, view_id="v",
                         version_pins={"methodology/hrp@3": "rcv1:aaa"})

        assert view.view_hash != "rcv1:aaa"
        assert view.view_hash != handle.handle_hash

    def test_projections_are_explicit_not_implied_by_type(self):
        handle = to_handle("run/1487@1", artifact_type="run",
                           content_hash="rcv1:r", visibility=Visibility.PUBLIC,
                           projections=("summary", "diagnostics"))
        assert handle.canonical_form()["projections"] == ["diagnostics", "summary"]


class TestDeniedAndOmittedChangeTheView:
    def _view(self, *, authorization=AuthorizationOutcome.GRANTED, omitted=0):
        handle = to_handle("methodology/hrp@3", artifact_type="methodology",
                           content_hash="rcv1:aaa", visibility=Visibility.PUBLIC)
        plan = plan_from([(handle, Necessity.OPTIONAL, "full", authorization)],
                         plan_id="p", omitted_count=omitted)
        return view_from(plan, view_id="v",
                         version_pins={"methodology/hrp@3": "rcv1:aaa"})

    def test_a_denial_changes_identity(self):
        assert self._view().view_hash != self._view(
            authorization=AuthorizationOutcome.DENIED_TENANT).view_hash

    def test_an_omission_changes_identity(self):
        assert self._view().view_hash != self._view(omitted=3).view_hash


class TestReplayReproducesTheGoldenDigest:
    """The reason the adapter exists: real artifacts, golden hash."""

    def _pins(self):
        return {f"evidence/e{n}@1": f"rcv1:{n:064d}" for n in (1, 2)}

    def _handles(self):
        return [
            to_handle(f"evidence/e{n}@1", artifact_type="evidence",
                      content_hash=f"rcv1:{n:064d}", visibility=Visibility.PUBLIC,
                      authority="redevops-rag", estimated_expansion_tokens=120)
            for n in (1, 2)
        ]

    def test_the_adapter_reproduces_the_baseline_view_hash(self):
        first, second = self._handles()
        plan = plan_from(
            [(first, Necessity.REQUIRED, "full", AuthorizationOutcome.GRANTED),
             (second, Necessity.OPTIONAL, "summary", AuthorizationOutcome.GRANTED)],
            plan_id="plan-1", budget_tokens=1000)
        view = view_from(plan, view_id="v-a", version_pins=self._pins())

        assert view.view_hash == GOLDEN["reproducible_working_set"]["view_hash"]

    def test_declaration_order_does_not_change_it(self):
        first, second = self._handles()
        plan = plan_from(
            [(second, Necessity.OPTIONAL, "summary", AuthorizationOutcome.GRANTED),
             (first, Necessity.REQUIRED, "full", AuthorizationOutcome.GRANTED)],
            plan_id="plan-2", budget_tokens=1000)
        view = view_from(plan, view_id="v-b",
                         version_pins=dict(reversed(list(self._pins().items()))))

        assert view.view_hash == GOLDEN["order_variation"]["view_hash"]

    def test_a_moved_pin_is_reported(self):
        first, second = self._handles()
        plan = plan_from(
            [(first, Necessity.REQUIRED, "full", AuthorizationOutcome.GRANTED),
             (second, Necessity.OPTIONAL, "summary", AuthorizationOutcome.GRANTED)],
            plan_id="plan-1", budget_tokens=1000)
        original = view_from(plan, view_id="v", version_pins=self._pins())
        restated = view_from(plan, view_id="v",
                             version_pins={**self._pins(),
                                           "evidence/e1@1": f"rcv1:{99:064d}"})

        assert restated.view_hash == GOLDEN["stale_version_pin"]["view_hash"]
        assert original.divergence_from(restated) == ["evidence/e1@1"]
