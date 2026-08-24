"""Canonical security contracts — identity, decision, and verifiable delegation."""
from __future__ import annotations

import json
import pathlib
from decimal import Decimal

import pytest

from runtime_contracts import (
    AuthorityContext,
    DelegationRefused,
    PrincipalRef,
    SecurityDecision,
    SecurityVerdict,
    verify_chain,
)
from golden.security import cases


# ── principal ──

def test_principal_canonical_and_role_order_independent():
    a = PrincipalRef("u1", "user", tenant="t", roles=("b", "a"), auth_level="mfa")
    b = PrincipalRef("u1", "user", tenant="t", roles=("a", "b"), auth_level="mfa")
    assert a.content_hash == b.content_hash and a.content_hash.startswith("rcv1:")
    assert PrincipalRef("u1", "user").content_hash != a.content_hash    # tenant/roles are identity


# ── security decision ──

def test_decision_deny_wins_and_unions_obligations():
    d = SecurityDecision.combine([
        SecurityDecision(SecurityVerdict.ALLOW),
        SecurityDecision(SecurityVerdict.REQUIRE_REVIEW, obligations=("review",)),
        SecurityDecision(SecurityVerdict.DENY, obligations=("audit",)),
        SecurityDecision(SecurityVerdict.ISOLATION, obligations=("sandbox:strict",)),
    ])
    assert d.verdict is SecurityVerdict.DENY                       # most severe governs
    assert set(d.obligations) == {"review", "audit", "sandbox:strict"}   # obligations carried forward
    assert not d.allowed


def test_all_six_verdicts_exist_and_rank():
    names = {v.value for v in SecurityVerdict}
    assert names == {"ALLOW", "DENY", "REQUIRE_REVIEW", "STRONGER_AUTH", "ISOLATION", "ATTESTATION"}
    assert SecurityVerdict.DENY.rank > SecurityVerdict.REQUIRE_REVIEW.rank > SecurityVerdict.ALLOW.rank


def test_empty_combine_is_allow():
    assert SecurityDecision.combine([]).verdict is SecurityVerdict.ALLOW


# ── authority + delegation ──

def _root() -> AuthorityContext:
    return AuthorityContext(
        authority_id="root", principal=PrincipalRef("alice", "user", tenant="acme"),
        purpose="deploy", scope=("deploy:read", "deploy:write", "logs:read"),
        constraints=("no_egress",), max_cost=Decimal("20.00"), expires_at="2026-09-01T00:00:00Z")


def test_narrow_produces_subset_child_and_records_parent():
    root = _root()
    child = root.narrow(authority_id="child", scope=("deploy:read", "logs:read"),
                        constraints=("read_only",), max_cost=Decimal("5.00"))
    assert set(child.scope) <= set(root.scope)                    # child ⊆ parent
    assert set(child.constraints) >= set(root.constraints)        # constraints only grow
    assert child.max_cost <= root.max_cost
    assert child.parent_digest == root.digest() and child.depth == 1
    assert child.permits("deploy:read") and not child.permits("deploy:write")


def test_narrow_refuses_to_widen_scope_budget_or_lifetime():
    root = _root()
    with pytest.raises(DelegationRefused):                        # new permission
        root.narrow(authority_id="c", scope=("deploy:read", "secrets:read"))
    with pytest.raises(DelegationRefused):                        # bigger budget
        root.narrow(authority_id="c", max_cost=Decimal("50.00"))
    with pytest.raises(DelegationRefused):                        # longer lifetime
        root.narrow(authority_id="c", expires_at="2027-01-01T00:00:00Z")
    with pytest.raises(DelegationRefused):                        # remove the expiry entirely
        root.narrow(authority_id="c", expires_at="")


def test_wildcard_scope_can_be_narrowed_to_anything():
    root = AuthorityContext("root", PrincipalRef("svc", "service"), scope=("*",))
    child = root.narrow(authority_id="c", scope=("deploy:read",))
    assert child.permits("deploy:read") and set(child.scope) == {"deploy:read"}


def test_verify_chain_accepts_valid_and_rejects_tampered():
    root = _root()
    child = root.narrow(authority_id="child", scope=("deploy:read",), max_cost=Decimal("5.00"))
    grand = child.narrow(authority_id="grand", scope=("deploy:read",))
    verify_chain([root, child, grand])                            # valid, no raise

    forged = AuthorityContext("forged", root.principal, scope=("deploy:read",),
                              parent_digest="rcv1:" + "0" * 64)   # wrong parent link
    with pytest.raises(DelegationRefused):
        verify_chain([root, forged])
    with pytest.raises(DelegationRefused):                        # root must have no parent
        verify_chain([child])


def test_chain_ref_is_authority_id_at_digest():
    root = _root()
    assert root.chain_ref == f"root@{root.digest()}"


# ── golden reproduction (Python↔Go conformance hook) ──

GOLDEN = json.loads((pathlib.Path(__file__).parent.parent / "golden" / "security.json").read_text())


def test_committed_security_vectors_reproduce():
    assert cases() == GOLDEN["cases"]


def test_child_records_parent_vector_is_consistent():
    c = GOLDEN["cases"]["child_records_parent"]
    assert c["parent_digest"] == c["root_digest"]
    assert GOLDEN["cases"]["decision_combine_deny_wins"]["verdict"] == "DENY"
