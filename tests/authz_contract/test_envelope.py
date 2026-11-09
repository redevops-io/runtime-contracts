"""The `authz/v1` decision envelope: what both planes emit, and what agreement between them does not mean.

The point of a shared receipt is correlation: one grant, one role set, one digest in both audit trails. What
it is *not* is evidence of a data boundary. A plane can emit a perfectly formed ``tenant_isolation`` denial
next to a code path that leaks content, so this module pins the receipt contract and, in
``test_a_receipt_is_not_a_data_boundary``, pins the difference the receipt cannot resolve — the kernel's
envelope carries no tenant at all, which is precisely why it may not be cited as tenant-bound.
"""
from __future__ import annotations

import pytest

from runtime_contracts.authz.decision import (AUTHZ_CONTRACT_VERSION, DECISION_EVENT, ENVELOPE_FIELDS,
                                              AuthorizationDecision, EnvelopeError, PolicyReason,
                                              parse_envelope, roles_hash, validate_envelope)

ROLE_SETS = [("admin",), ("admin", "finance"), ("finance", "admin"), (), ("clerk",),
             ("a", "", None, 7, "b"), ("dup", "dup")]


def _envelope(**overrides) -> dict:
    base = {"version": 1, "event": DECISION_EVENT, "principal_kind": "user", "principal": "user:al",
            "roles_hash": roles_hash(["operator"]), "resource_kind": "capability",
            "resource_name": "reports.read", "requested_action": "invoke", "allowed": True,
            "policy_reason": "explicit_grant", "grant_ids": ["r-1"], "tenant": "acme"}
    base.update(overrides)
    return base


# ── the digest is one definition, not two ──────────────────────────────────────

def test_the_digest_is_a_property_of_the_role_set_not_its_order_or_spelling() -> None:
    assert roles_hash(["admin", "finance"]) == roles_hash(["finance", "admin", "admin"])
    assert roles_hash(["a", "", None, 7]) == roles_hash(["a"])
    assert roles_hash(ROLE_SETS[0]) != roles_hash(ROLE_SETS[1])
    assert len(roles_hash([])) == 16 and roles_hash([]) == roles_hash(None)


def test_the_kernel_computes_the_same_digest_as_the_contract() -> None:
    kernel = pytest.importorskip("agentic_os.permissions", reason="BLOCKED — AGENTIC_OS_ROOT not set")
    if not hasattr(kernel, "canonical_roles_hash"):
        pytest.skip("BLOCKED — the kernel predates the exported canonical_roles_hash (pre-E-2 checkout)")
    for roles in ROLE_SETS:
        assert roles_hash(roles) == kernel.canonical_roles_hash([r for r in roles if isinstance(r, str)])


def test_the_enterprise_computes_the_same_digest_as_the_contract() -> None:
    enterprise = pytest.importorskip("agentic_os_enterprise.identity",
                                     reason="BLOCKED — AGENTIC_OS_ENTERPRISE_ROOT not set")
    kernel = pytest.importorskip("agentic_os.permissions", reason="BLOCKED — AGENTIC_OS_ROOT not set")
    for roles in ROLE_SETS:
        clean = [r for r in roles if isinstance(r, str) and r]
        assert roles_hash(clean) == enterprise._roles_hash(list(roles)) == kernel.canonical_roles_hash(clean)


# ── the receipt contract ──────────────────────────────────────────────────────

def test_a_well_formed_receipt_validates_and_survives_a_round_trip() -> None:
    decision = parse_envelope(_envelope())
    assert validate_envelope(decision, request_tenant="acme") == []
    assert parse_envelope(decision.to_envelope()) == decision
    assert decision.content_hash == parse_envelope(decision.to_envelope()).content_hash


def test_the_envelope_never_carries_role_names() -> None:
    decision = parse_envelope(_envelope(roles_hash=roles_hash(["admin", "finance"])))
    assert "admin" not in str(decision.canonical_form())
    assert decision.canonical_form()["roles_hash"] == roles_hash(["admin", "finance"])


@pytest.mark.parametrize("field", ENVELOPE_FIELDS)
def test_a_receipt_missing_a_required_field_is_refused(field: str) -> None:
    raw = _envelope()
    del raw[field]
    with pytest.raises(EnvelopeError):
        parse_envelope(raw)


@pytest.mark.parametrize("mutation,code", [
    ({"allowed": True, "grant_ids": [], "break_glass": False}, "allow_without_grant_or_elevation"),
    ({"allowed": True, "grant_ids": [], "break_glass": True}, None),
    ({"policy_reason": "because_i_said_so"}, "policy_reason_unclassified"),
    ({"roles_hash": "admin-finance"}, "roles_hash_malformed"),
    ({"grant_ids": ["g-2", "g-1"]}, "grant_ids_not_canonical"),
    ({"policy_reason": ""}, "policy_reason_unclassified"),
])
def test_validation_reports_the_reason_a_receipt_is_unauditable(mutation: dict, code: str | None) -> None:
    codes = validate_envelope(parse_envelope(_envelope(**mutation)))
    if code is None:
        assert codes == [], f"an elevated allow with no grant should be attributable to the elevation: {codes}"
    else:
        assert code in codes


@pytest.mark.parametrize("grant_ids", [["g-1", ""], ["g-1", None], "g-1", {"a": 1}])
def test_a_malformed_grant_id_list_is_refused_at_parse_time(grant_ids) -> None:
    """Nothing downstream has to be defensive about a receipt that never entered the system."""
    with pytest.raises(EnvelopeError):
        parse_envelope(_envelope(grant_ids=grant_ids))


def test_an_unclassified_reason_is_a_defect_in_the_emitter_not_a_reason() -> None:
    decision = parse_envelope(_envelope(allowed=False, policy_reason="denied for policy reasons",
                                       grant_ids=[]))
    assert decision.policy_reason is PolicyReason.UNCLASSIFIED
    assert "policy_reason_unclassified" in validate_envelope(decision)


@pytest.mark.parametrize("request_tenant,tenant,expected", [
    ("acme", "acme", []),
    ("acme", "globex", ["tenant_mismatch"]),
    ("acme", "", ["envelope_tenant_unset"]),
    (None, "", []),
])
def test_a_receipt_must_name_the_tenant_the_request_was_made_for(request_tenant, tenant, expected) -> None:
    assert validate_envelope(parse_envelope(_envelope(tenant=tenant)), request_tenant=request_tenant) == expected


def test_the_contract_version_participates_in_identity() -> None:
    """A receipt's version is part of its meaning: an unreadable version is refused, not guessed."""
    assert parse_envelope(_envelope()).canonical_form()["contract"] == AUTHZ_CONTRACT_VERSION
    assert parse_envelope(_envelope(version=2)).version == 2
    assert "envelope_version_unsupported" in validate_envelope(parse_envelope(_envelope(version=2)))


# ── what agreement between the two planes does not establish ───────────────────

def test_a_receipt_is_not_a_data_boundary() -> None:
    """The kernel emits well-formed receipts that name no tenant. Matching shapes are not tenant binding."""
    kernel_receipt = AuthorizationDecision(allowed=True, policy_reason=PolicyReason.EXPLICIT_GRANT,
                                           principal="app:crm", principal_kind="app",
                                           roles_digest=roles_hash(["operator"]), resource_kind="table",
                                           resource_name="crm.customers", requested_action="read",
                                           grant_ids=("g-1",), tenant="", plane="agentic-os")
    assert validate_envelope(kernel_receipt) == []                       # well-formed…
    assert "envelope_tenant_unset" in validate_envelope(kernel_receipt, request_tenant="acme")
    # …so it cannot be cited as a tenant-bound decision, however tidy the JSON looks.
    assert kernel_receipt.canonical_form()["grant_ids"] == ["g-1"]