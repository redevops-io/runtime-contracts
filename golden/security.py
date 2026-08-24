"""Language-neutral golden vectors for the canonical security contracts.

A Go (or any) port reproduces these hashes from the same inputs, or it does not conform. Deterministic:
no clocks, no randomness — every value is content-addressed. Regenerate with `python -m golden.security`.
"""
from __future__ import annotations

import json
import pathlib
from decimal import Decimal

from runtime_contracts.protocol.security import (
    AuthorityContext,
    PrincipalRef,
    SecurityDecision,
    SecurityVerdict,
)

HERE = pathlib.Path(__file__).parent

# Deterministic fixtures shared across cases.
_ALICE = PrincipalRef(id="alice", kind="user", tenant="acme", roles=("engineer", "oncall"), auth_level="mfa")
_ROOT = AuthorityContext(
    authority_id="auth-root", principal=_ALICE, purpose="deploy",
    scope=("deploy:read", "deploy:write", "logs:read"),
    constraints=("no_egress",), max_cost=Decimal("20.00"), expires_at="2026-09-01T00:00:00Z",
)
_CHILD = _ROOT.narrow(authority_id="auth-child", scope=("deploy:read", "logs:read"),
                      purpose="inspect", constraints=("read_only",), max_cost=Decimal("5.00"))


def cases() -> dict:
    out: dict = {}

    # 1. Principal identity is canonical and role-order-independent.
    out["principal_hash"] = {
        "why": "id·kind·tenant·roles·auth_level, roles sorted, canonical",
        "hash": _ALICE.content_hash,
    }
    out["principal_role_order_invariant"] = {
        "why": "reordered roles hash identically (sets sorted into lists)",
        "hash": PrincipalRef(id="alice", kind="user", tenant="acme",
                             roles=("oncall", "engineer"), auth_level="mfa").content_hash,
    }

    # 2. Security decision identity + deny-wins combination.
    out["decision_deny_hash"] = {
        "why": "a DENY decision with obligations+evidence, canonical",
        "hash": SecurityDecision(SecurityVerdict.DENY, subject="alice", resource="deploy:write",
                                 reason="policy", obligations=("audit",), evidence=("policy:p1",),
                                 decided_by="policy-plane").content_hash,
    }
    combined = SecurityDecision.combine([
        SecurityDecision(SecurityVerdict.ALLOW, resource="r"),
        SecurityDecision(SecurityVerdict.ISOLATION, resource="r", obligations=("sandbox:strict",)),
        SecurityDecision(SecurityVerdict.DENY, resource="r", reason="denied", obligations=("audit",)),
    ])
    out["decision_combine_deny_wins"] = {
        "why": "most-severe verdict governs; obligations unioned",
        "verdict": combined.verdict.value,
        "hash": combined.content_hash,
    }

    # 3. Authority digests + verifiable delegation (child ⊆ parent).
    out["authority_root_digest"] = {"why": "root authority content-addressed", "hash": _ROOT.digest()}
    out["authority_child_digest"] = {"why": "narrowed child content-addressed", "hash": _CHILD.digest()}
    out["child_records_parent"] = {
        "why": "the child's parent_digest is exactly the parent's digest",
        "parent_digest": _CHILD.parent_digest,
        "root_digest": _ROOT.digest(),
    }
    out["child_chain_ref"] = {"why": "the id a side effect resolves to", "chain_ref": _CHILD.chain_ref}
    return out


if __name__ == "__main__":
    payload = {"contract_version": "0.3.x", "cases": cases()}
    (HERE / "security.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    print(json.dumps(payload["cases"], indent=2)[:600])
