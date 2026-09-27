"""Canonical cross-runtime security contracts (0.3.x).

The security primitives already exist across the ReDevOps codebase — identity planes, a governed policy
engine, Context Fabric, mission policy — but under different names per repo, with no single canonical,
hashable, cross-runtime contract set and no Python↔Go conformance vectors. This module is that set for the
three primitives the branch-correct audit found genuinely missing everywhere:

  * ``SecurityVerdict`` / ``SecurityDecision`` — one typed, deny-wins security verdict (the six verdicts:
    ALLOW · DENY · REQUIRE_REVIEW · STRONGER_AUTH · ISOLATION · ATTESTATION), unifying the disjoint
    ``GateResult`` (governance) and ``AccessDecision`` (identity) decisions.
  * ``PrincipalRef`` — a canonical principal reference (id · kind · tenant · roles · auth level).
  * ``AuthorityContext`` — a mission authority envelope with **verifiable delegation**: a child is derived
    only by *narrowing* a parent (``child_authority ⊆ parent_authority``), records the parent's digest,
    and every consequential side effect resolves to exactly one authority chain (``chain_ref``).

Each type exposes ``canonical_form()`` — a plain dict over the repo's canonical rules (sorted keys, sets
sorted into lists, floats refused, empties omitted) — so ``content_hash`` produces a byte-identical digest
in any language. New security golden vectors plug into ``golden/generate.py`` exactly like the existing
contracts, giving Python↔Go conformance the moment the Go port reproduces the hashes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from enum import Enum

from ..canonical import content_hash, decimal_string


class DelegationRefused(ValueError):
    """A delegation tried to *widen* authority (scope, budget, or lifetime) instead of narrowing it, or a
    chain's parent link did not verify. Raised rather than silently granting more than the parent held."""


# ──────────────────────────── security verdict ────────────────────────────


class SecurityVerdict(str, Enum):
    """The six security verdicts. Ordered by severity so a set of decisions combines **deny-wins**: the
    most severe verdict governs (DENY beats REQUIRE_REVIEW beats a conditional allow beats ALLOW)."""
    ALLOW = "ALLOW"                     # permit as requested
    ATTESTATION = "ATTESTATION"         # permit once provenance/attestation is verified
    ISOLATION = "ISOLATION"             # permit only inside a stronger isolation class
    STRONGER_AUTH = "STRONGER_AUTH"     # permit only after step-up authentication
    REQUIRE_REVIEW = "REQUIRE_REVIEW"   # hold for human review
    DENY = "DENY"                       # refuse; no override

    @property
    def rank(self) -> int:
        return _VERDICT_RANK[self]


_VERDICT_RANK = {
    SecurityVerdict.ALLOW: 0,
    SecurityVerdict.ATTESTATION: 1,
    SecurityVerdict.ISOLATION: 2,
    SecurityVerdict.STRONGER_AUTH: 3,
    SecurityVerdict.REQUIRE_REVIEW: 4,
    SecurityVerdict.DENY: 5,
}


@dataclass(frozen=True)
class SecurityDecision:
    """A typed security verdict on a (subject → resource) request, with the obligations that make a
    conditional verdict (ISOLATION/STRONGER_AUTH/ATTESTATION) concrete and the evidence that justifies it."""
    verdict: SecurityVerdict
    subject: str = ""                            # principal id the decision is about
    resource: str = ""                           # capability / resource / node id
    reason: str = ""
    obligations: tuple[str, ...] = ()            # e.g. "sandbox:strict", "redact:pii", "attest:sbom"
    evidence: tuple[str, ...] = ()               # policy/evidence refs that produced the verdict
    decided_by: str = ""                         # the plane/policy that decided

    @property
    def allowed(self) -> bool:
        return self.verdict is SecurityVerdict.ALLOW

    def canonical_form(self) -> dict:
        d: dict = {"verdict": self.verdict.value}
        if self.subject:
            d["subject"] = self.subject
        if self.resource:
            d["resource"] = self.resource
        if self.reason:
            d["reason"] = self.reason
        if self.obligations:
            d["obligations"] = sorted(set(self.obligations))
        if self.evidence:
            d["evidence"] = sorted(set(self.evidence))
        if self.decided_by:
            d["decided_by"] = self.decided_by
        return d

    @property
    def content_hash(self) -> str:
        return content_hash(self.canonical_form())

    @staticmethod
    def combine(decisions: "list[SecurityDecision] | tuple[SecurityDecision, ...]") -> "SecurityDecision":
        """Deny-wins reduction: the most severe verdict governs, obligations are unioned so every
        conditional requirement from any input is carried forward. Empty input = ALLOW (nothing objected)."""
        if not decisions:
            return SecurityDecision(SecurityVerdict.ALLOW)
        worst = max(decisions, key=lambda x: x.verdict.rank)
        obligations = sorted({o for d in decisions for o in d.obligations})
        evidence = sorted({e for d in decisions for e in d.evidence})
        return SecurityDecision(verdict=worst.verdict, subject=worst.subject, resource=worst.resource,
                                reason=worst.reason, obligations=tuple(obligations),
                                evidence=tuple(evidence), decided_by=worst.decided_by)


# ──────────────────────────── principal ────────────────────────────


@dataclass(frozen=True)
class PrincipalRef:
    """A canonical, cross-runtime principal reference — the *identity* an authority chain is rooted in.
    Not the full identity record (keys, sessions), just the stable reference every runtime agrees on."""
    id: str
    kind: str = "user"                           # "user" | "service" | "agent"
    tenant: str = ""
    roles: tuple[str, ...] = ()
    auth_level: str = ""                         # "", "mfa", "sso", "break_glass", …

    def canonical_form(self) -> dict:
        d: dict = {"id": self.id, "kind": self.kind}
        if self.tenant:
            d["tenant"] = self.tenant
        if self.roles:
            d["roles"] = sorted(set(self.roles))
        if self.auth_level:
            d["auth_level"] = self.auth_level
        return d

    @property
    def content_hash(self) -> str:
        return content_hash(self.canonical_form())


# ──────────────────────────── authority + delegation ────────────────────────────

WILDCARD = "*"


@dataclass(frozen=True)
class AuthorityContext:
    """A mission authority envelope: which principal, for what purpose, may exercise which scope, under
    what constraints, within what budget, until when — plus the parent it was delegated from.

    Delegation is *narrowing only*. `narrow()` is the sole way to derive a child, and it refuses to widen
    scope, budget or lifetime (``DelegationRefused``), so the invariant ``child_authority ⊆ parent_authority``
    is enforced by construction. ``chain_ref`` is the single identity a side effect is attributed to.
    """
    authority_id: str
    principal: PrincipalRef
    purpose: str = ""
    scope: tuple[str, ...] = ()                   # permissions granted (order-independent set)
    constraints: tuple[str, ...] = ()            # a child is at least as constrained: constraints only grow
    max_cost: Decimal | None = None              # budget ceiling; a child may only lower it
    expires_at: str = ""                         # ISO instant; "" = no expiry. A child may only shorten it.
    parent_digest: str = ""                      # "" = root authority
    depth: int = 0

    def canonical_form(self) -> dict:
        d: dict = {"authority_id": self.authority_id, "principal": self.principal.canonical_form(),
                   "depth": self.depth}
        if self.purpose:
            d["purpose"] = self.purpose
        if self.scope:
            d["scope"] = sorted(set(self.scope))
        if self.constraints:
            d["constraints"] = sorted(set(self.constraints))
        if self.max_cost is not None:
            d["max_cost"] = decimal_string(self.max_cost)
        if self.expires_at:
            d["expires_at"] = self.expires_at
        if self.parent_digest:
            d["parent_digest"] = self.parent_digest
        return d

    def digest(self) -> str:
        """Content-addressed identity — the value a child records as ``parent_digest`` and the fingerprint
        binds the plan to. Same canonical discipline as every other runtime digest."""
        return content_hash(self.canonical_form())

    @property
    def chain_ref(self) -> str:
        """The one identity a consequential side effect resolves to: ``authority_id@digest``."""
        return f"{self.authority_id}@{self.digest()}"

    def permits(self, permission: str) -> bool:
        return WILDCARD in self.scope or permission in self.scope

    def _covers_scope(self, child_scope: tuple[str, ...]) -> bool:
        return all(self.permits(p) for p in child_scope)

    def narrow(self, *, authority_id: str, scope: tuple[str, ...] | None = None, purpose: str | None = None,
               constraints: tuple[str, ...] = (), max_cost: Decimal | None = None,
               expires_at: str | None = None, principal: PrincipalRef | None = None) -> "AuthorityContext":
        """Derive a delegated child. Refuses to widen: the child's scope must be a subset of this scope, its
        budget may only be lower, its expiry only earlier, and its constraints are the union (never fewer)."""
        child_scope = self.scope if scope is None else tuple(scope)
        if not self._covers_scope(child_scope):
            extra = sorted(set(child_scope) - set(self.scope)) if WILDCARD not in self.scope else []
            raise DelegationRefused(f"child scope not ⊆ parent scope; would grant new permissions {extra}")

        child_cost = self.max_cost if max_cost is None else max_cost
        if self.max_cost is not None and (child_cost is None or child_cost > self.max_cost):
            raise DelegationRefused(f"child budget {child_cost} would exceed parent budget {self.max_cost}")

        child_expiry = self.expires_at if expires_at is None else expires_at
        if self.expires_at and (not child_expiry or child_expiry > self.expires_at):
            raise DelegationRefused(f"child expiry {child_expiry!r} would outlast parent {self.expires_at!r}")

        child_constraints = tuple(sorted(set(self.constraints) | set(constraints)))   # constraints only grow
        return AuthorityContext(
            authority_id=authority_id,
            principal=self.principal if principal is None else principal,
            purpose=self.purpose if purpose is None else purpose,
            scope=child_scope, constraints=child_constraints, max_cost=child_cost,
            expires_at=child_expiry, parent_digest=self.digest(), depth=self.depth + 1,
        )


# ──────────────────────────── context identity (security-keyed cache key) ────────────────────────────


@dataclass(frozen=True)
class ContextIdentity:
    """The canonical security identity of an assembled context — the key a cache MUST use so a computed
    context is never reused across a tenant, permission, data-classification, or model boundary. This is
    Context Fabric's composition lifted into one cross-runtime contract: two requests with the same prompt
    prefix but a different tenant / permissions / sensitivity / model produce a different ``context_id``,
    so cross-tenant or cross-permission cache reuse cannot collide.
    """
    tenant: str = ""
    permissions: tuple[str, ...] = ()
    data_classification: str = ""
    model_revision: str = ""
    tokenizer_revision: str = ""
    prompt_prefix_hash: str = ""

    def policy_fingerprint(self) -> str:
        """The security posture (everything but the prompt) — tenant, permissions, classification, model."""
        return content_hash({"kind": "policy", "tenant": self.tenant,
                             "permissions": sorted(set(self.permissions)),
                             "data_classification": self.data_classification,
                             "model_revision": self.model_revision,
                             "tokenizer_revision": self.tokenizer_revision})

    def context_id(self) -> str:
        """The full cache key: the prompt prefix bound to the model/tokenizer and the security posture."""
        return content_hash({"kind": "ctx", "prompt_prefix_hash": self.prompt_prefix_hash,
                             "model_tokenizer": f"{self.model_revision}/{self.tokenizer_revision}",
                             "policy_fingerprint": self.policy_fingerprint()})

    def canonical_form(self) -> dict:
        d: dict = {"policy_fingerprint": self.policy_fingerprint(), "context_id": self.context_id()}
        return d


def verify_chain(chain: "list[AuthorityContext]") -> None:
    """Verify a delegation chain root→leaf: each link records the previous link's digest, and authority
    only narrows (scope ⊆, constraints ⊇, budget ≤, expiry ≤). Raises ``DelegationRefused`` on any break.
    The root must have no parent."""
    if not chain:
        raise DelegationRefused("empty authority chain")
    if chain[0].parent_digest:
        raise DelegationRefused("root authority must have no parent_digest")
    for parent, child in zip(chain, chain[1:]):
        if child.parent_digest != parent.digest():
            raise DelegationRefused(f"broken link: {child.authority_id} does not descend from {parent.authority_id}")
        if not parent._covers_scope(child.scope):
            raise DelegationRefused(f"{child.authority_id} widens scope beyond {parent.authority_id}")
        if not set(parent.constraints) <= set(child.constraints):
            raise DelegationRefused(f"{child.authority_id} drops a parent constraint")
        if parent.max_cost is not None and (child.max_cost is None or child.max_cost > parent.max_cost):
            raise DelegationRefused(f"{child.authority_id} widens budget beyond {parent.authority_id}")
        if parent.expires_at and (not child.expires_at or child.expires_at > parent.expires_at):
            raise DelegationRefused(f"{child.authority_id} outlasts {parent.authority_id}")
