"""Canonical security contracts — identity, decision, and verifiable delegation."""
from __future__ import annotations

import json
import pathlib
from decimal import Decimal

import pytest

from decimal import Decimal

from runtime_contracts import (
    AuthorityContext,
    ContextIdentity,
    DelegationRefused,
    PrincipalRef,
    SecurityDecision,
    SecurityVerdict,
    verify_chain,
)
from runtime_contracts.models.capability import CapabilityDescriptor
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


# ── context identity (security-keyed cache key) ──

def _ctx(**kw) -> ContextIdentity:
    base = dict(tenant="acme", permissions=("read:a", "read:b"), data_classification="pii",
                model_revision="m@1", tokenizer_revision="t@1", prompt_prefix_hash="pfx")
    base.update(kw)
    return ContextIdentity(**base)


def test_context_id_is_security_keyed_and_prompt_order_independent():
    base = _ctx().context_id()
    assert _ctx(permissions=("read:b", "read:a")).context_id() == base   # perms order-independent
    for boundary in (dict(tenant="other"), dict(permissions=("read:a",)),
                     dict(data_classification="public"), dict(model_revision="m@2"),
                     dict(tokenizer_revision="t@2"), dict(prompt_prefix_hash="other")):
        assert _ctx(**boundary).context_id() != base                    # every boundary changes the key


def test_within_tier_model_swap_changes_context_id():
    # the fabric gap: same tenant/perms but a new model revision must NOT reuse the cache
    assert _ctx(model_revision="m@1").context_id() != _ctx(model_revision="m@1-hotfix").context_id()


# ── capability descriptor security surface ──

def test_capability_security_fields_are_canonical_and_change_identity():
    base = CapabilityDescriptor(capability_id="c", version="1", kind="tool")
    hardened = CapabilityDescriptor(capability_id="c", version="1", kind="tool",
                                    required_authority=("deploy:write",), isolation_class="strict",
                                    network=("api.acme.com",), secrets=("db_password",),
                                    provenance="attested", content_digest="sha256:abc",
                                    trust=Decimal("0.9"))
    assert hardened.content_hash != base.content_hash                   # security surface is identity
    assert hardened.requires_isolation and not base.requires_isolation
    assert hardened.authority_satisfied_by(("deploy:write", "logs:read"))
    assert not hardened.authority_satisfied_by(("logs:read",))          # deny-by-default
    assert hardened.authority_satisfied_by(("*",))                      # wildcard grant


# ── golden reproduction (Python↔Go conformance hook) ──

GOLDEN = json.loads((pathlib.Path(__file__).parent.parent / "golden" / "security.json").read_text())


def test_committed_security_vectors_reproduce():
    assert cases() == GOLDEN["cases"]


def test_child_records_parent_vector_is_consistent():
    c = GOLDEN["cases"]["child_records_parent"]
    assert c["parent_digest"] == c["root_digest"]
    assert GOLDEN["cases"]["decision_combine_deny_wins"]["verdict"] == "DENY"


# ── supply-chain admission gate (Slice 4) ──

def test_admit_denies_a_substituted_digest():
    from runtime_contracts import SecurityVerdict
    d = CapabilityDescriptor(capability_id="render", version="1", kind="tool", content_digest="sha256:aaa")
    good = d.admit(pinned_digests={"render": "sha256:aaa"})
    bad = d.admit(pinned_digests={"render": "sha256:bbb"})     # what runs ≠ what was admitted
    assert good.verdict is SecurityVerdict.ALLOW
    assert bad.verdict is SecurityVerdict.DENY and "quarantine_capability" in bad.obligations


def test_admit_enforces_provenance_and_trust_floor():
    from runtime_contracts import SecurityVerdict
    unsigned = CapabilityDescriptor(capability_id="c", version="1", kind="tool", provenance="unknown")
    assert unsigned.admit(trusted_publishers=("attested",)).verdict is SecurityVerdict.DENY
    low = CapabilityDescriptor(capability_id="c", version="1", kind="tool", provenance="attested",
                               trust=Decimal("0.2"))
    assert low.admit(trusted_publishers=("attested",),
                     min_trust=Decimal("0.8")).verdict is SecurityVerdict.REQUIRE_REVIEW
    assert low.admit().verdict is SecurityVerdict.ALLOW      # admission is opt-in; no constraints → allow
