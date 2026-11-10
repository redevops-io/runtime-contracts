"""#45 — the suite has to be able to say *which* implementation answered, and about *what*.

A matrix cell claims that an edition enforced something. That claim is only worth reading if the receipt it
was scored on came out of that edition and concerns the request that was made. Three dishonest adapters, each
handing the suite a receipt it did not earn: if any of them can score a pass, the matrix is crediting
enforcement to an edition that did not perform it.

These adapters are harness fictions, not product mutants — the defect under test is in the harness's own
bookkeeping, so it lives here rather than beside the real implementations.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from adapters._implementations import ROOT_ENV, imported_root
from runtime_contracts.authz.decision import (DECISION_EVENT, AuthorizationDecision, PolicyReason, roles_hash)
from runtime_contracts.authz.qualification import Invariant, Qualification
from runtime_contracts.authz.suite import AuthzAdapter, Receipt, run_invariant

REPO = Path(__file__).resolve().parents[2]
EXPECTATIONS = REPO / "tests" / "authz_contract" / "qualification.json"

#: Which package each adapter's verdict is measured against, for the commit binding below.
_PACKAGE_BY_IMPLEMENTATION = {"agentic-os": "agentic_os.permissions",
                              "agentic-os-enterprise": "agentic_os_enterprise.identity"}


def _git(root: Path, *args: str) -> str:
    """One git question, or ``''`` when this machine cannot answer it (no git, no history)."""
    try:
        out = subprocess.run(("git", "-C", str(root), *args), capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return ""
    return out.stdout.strip() if out.returncode == 0 else ""


def _git_ok(root: Path, *args: str) -> bool:
    """Whether a git question succeeds, for questions whose answer is the exit status itself."""
    try:
        return subprocess.run(("git", "-C", str(root), *args), capture_output=True, text=True,
                              timeout=30).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


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


# ── the other half of provenance: the checkout a verdict is credited to ─────────────────────────────


@pytest.mark.parametrize("reference", sorted(json.loads(EXPECTATIONS.read_text())["implementations"]),
                         ids=lambda r: r.split(".")[-2])
def test_a_recorded_commit_is_the_code_that_answered(reference: str) -> None:
    """``qualification.json`` names a commit per implementation. Nothing in the suite checked that the
    module which produced the verdict came from that commit — so a machine with a different checkout (or a
    stale installed copy) could keep printing SHAs it never measured.

    The binding is resolved from the import system: the file the plane was imported from, walked up to its
    git working tree, compared with what is recorded. An environment variable is not evidence, because a
    variable nobody reads still looks correct in a report.
    """
    recorded = json.loads(EXPECTATIONS.read_text())["implementations"][reference]
    implementation = recorded["implementation"]
    module = _PACKAGE_BY_IMPLEMENTATION.get(implementation)
    if module is None:
        pytest.skip(f"{implementation}: no package is named for it, so no commit can be bound to it")
    module_name, _, _cls = reference.partition(":")
    try:
        root = imported_root(implementation, module)
    except Exception as exc:  # noqa: BLE001 — a missing checkout is a statement about this run
        pytest.skip(f"BLOCKED — {exc}")

    configured = os.environ.get(ROOT_ENV.get(implementation, ""), "").strip()
    if configured:
        assert root == Path(configured).expanduser().resolve(), (
            f"{ROOT_ENV[implementation]} names {configured} but the code answering came from {root}; the "
            "verdicts in the matrix describe the imported copy, not the one on the command line")

    head = _git(root, "rev-parse", "HEAD")
    if not head:
        pytest.skip(f"{implementation}: {root} has no readable git HEAD, so its commit cannot be bound")
    assert head == recorded["checkout_commit"], (
        f"{implementation}: the matrix records {recorded['checkout_commit']} but the plane imported from "
        f"{root} at {head}. Re-measure the matrix against this checkout, or point {ROOT_ENV.get(implementation)}"
        " at the recorded one — do not edit the recorded SHA to make this pass.")
    base = recorded.get("base_commit", "")
    if base:
        assert _git_ok(root, "cat-file", "-e", base), (
            f"{implementation}: recorded base {base} does not exist in the measured checkout at {root}")
        assert _git_ok(root, "merge-base", "--is-ancestor", base, head), (
            f"{implementation}: recorded base {base} is not an ancestor of the measured {head}; the "
            "qualification would describe a lineage the checkout does not have")