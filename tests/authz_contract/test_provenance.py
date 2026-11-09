"""#45 — the suite has to be able to say *which* implementation answered, and about *what*.

A matrix cell claims that an edition enforced something. That claim is only worth reading if the receipt it
was scored on came out of that edition and concerns the request that was made. Three dishonest adapters, each
handing the suite a receipt it did not earn: if any of them can score a pass, the matrix is crediting
enforcement to an edition that did not perform it.

These adapters are harness fictions, not product mutants — the defect under test is in the harness's own
bookkeeping, so it lives here rather than beside the real implementations.
"""
from __future__ import annotations

import pytest

from runtime_contracts.authz.decision import (DECISION_EVENT, AuthorizationDecision, PolicyReason, roles_hash)
from runtime_contracts.authz.qualification import Invariant, Qualification
from runtime_contracts.authz.suite import AuthzAdapter, Receipt, run_invariant


def _envelope(*, principal: str, resource_name: str, action: str = "read",
              plane: str = "acme-edition") -> AuthorizationDecision:
    return AuthorizationDecision(
        allowed=False, policy_reason=PolicyReason.TENANT_ISOLATION, principal=principal, principal_kind="user",
        roles_digest=roles_hash(("operator",)), resource_kind="table", resource_name=resource_name,
        requested_action=action, grant_ids=(), tenant="acme", decision_epoch=0, break_glass=False,
        plane=plane, version=1, event=DECISION_EVENT)


class _Edition(AuthzAdapter):
    """A small edition that refuses everything, attributed and bound to the request like a real receipt."""

    implementation = "acme-edition"
    edition = "kernel"
    variant = "honest-deny"

    def grant(self, principal, *, resource="", actions=(), permissions=(), tenant=None) -> str:
        return "grant-1"

    def _receipt(self, principal, target: str, action: str = "read") -> Receipt:
        return Receipt(allowed=False, reason="denied: outside the boundary",
                       decision=_envelope(principal=principal.subject, resource_name=target, action=action),
                       seam=f"{self.implementation}.decide")

    def decide_resource(self, principal, *, resource, action="read", request_tenant=None) -> Receipt:
        return self._receipt(principal, resource, action)

    def decide_capability(self, principal, *, capability, permissions=(), request_tenant=None) -> Receipt:
        return self._receipt(principal, capability)

    def decide_tenant_scoped_resource(self, principal, *, grant_tenant, request_tenant, resource,
                                      action="read") -> Receipt:
        return self._receipt(principal, resource, action)

    def decide_resource_tenancy(self, principal, *, owner_tenant, resource_tenant, capability,
                                delegated=False) -> Receipt:
        return self._receipt(principal, capability)


class _BorrowedPlane(_Edition):
    """Returns a decision another implementation emitted — the edition under test gets no such credit."""

    variant = "cross_talk_borrowed_plane"

    def _receipt(self, principal, target: str, action: str = "read") -> Receipt:
        return Receipt(allowed=False, reason="denied by somebody else's plane",
                       decision=_envelope(principal=principal.subject, resource_name=target, action=action,
                                          plane="some-other-edition"),
                       seam=f"{self.implementation}.decide")


class _WrongQuestion(_Edition):
    """Decides a different principal and resource than the ones requested."""

    variant = "cross_talk_wrong_question"

    def _receipt(self, principal, target: str, action: str = "read") -> Receipt:
        return Receipt(allowed=False, reason="denied, but not for you",
                       decision=_envelope(principal="user:eve", resource_name="erp.invoice", action=action),
                       seam=f"{self.implementation}.decide")


class _ReplayedAnswer(_Edition):
    """Answers every later question with the first envelope it produced, the way a decision cache would."""

    variant = "cross_talk_replayed"

    def __init__(self) -> None:
        self._served: Receipt | None = None

    def _receipt(self, principal, target: str, action: str = "read") -> Receipt:
        if self._served is None:
            self._served = super()._receipt(principal, target, action)
        return self._served


DISHONEST = pytest.mark.parametrize("dishonest", [_BorrowedPlane, _WrongQuestion, _ReplayedAnswer],
                                    ids=lambda c: c.variant)


@DISHONEST
def test_a_receipt_from_elsewhere_cannot_score_a_pass(dishonest) -> None:
    result = run_invariant(Invariant.CROSS_TENANT_DENIED, dishonest())
    assert result.verdict is Qualification.FAIL, (
        f"a {dishonest.variant} adapter scored {result.verdict_value}: the suite accepted an answer it cannot "
        "attribute to the request and the implementation under test")
    assert "cross-talk" in result.detail, f"failed, but not for the reason that matters: {result.detail}"
    assert result.evidence.get("variant") == dishonest.variant, "the matrix must still say which variant ran"


@DISHONEST
def test_cross_talk_is_reported_per_sub_criterion_not_swallowed(dishonest) -> None:
    """A provenance failure must surface as the cell's own detail, not as a scenario crashing on a bad shape."""
    result = run_invariant(Invariant.CROSS_TENANT_DENIED, dishonest())
    assert result.implementation == "acme-edition"
    assert result.detail, "a silent FAIL is as unreadable as a false PASS"


def test_an_honest_denial_is_never_reported_as_cross_talk() -> None:
    """The check must not be trigger-happy: correct attribution and binding pass it on every invariant.

    What the honest edition scores elsewhere (unsupported seams, unmet criteria) is a separate question; what
    matters here is that nothing is rejected for provenance when the receipt is truthful.
    """
    for invariant in Invariant:
        result = run_invariant(invariant, _Edition())
        assert "cross-talk" not in result.detail, (
            f"{invariant.value}: an honestly attributed, correctly bound receipt was rejected as cross-talk "
            f"({result.detail})")