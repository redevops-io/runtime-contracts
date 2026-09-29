"""Agent identity seam — the external-IAM boundary, as a VIEW over the existing security primitives.

This is the Phase-0/1 slice from the NVIDIA/IBM deployment-security audit. It adds abstraction *seams* around
identity infrastructure the Runtime already has; it does not introduce a second identity hierarchy and it does not
encode any vendor (IBM Agent Identity / Entra / Okta / SPIFFE) concept into the contract.

  * ``ExecutionIdentity`` — a composition/view over ``PrincipalRef`` + ``AuthorityContext`` that names, for one
    consequential action, the *human subject* (on whose behalf), the *agent actor* (what is executing), the
    *agent owner*, and the mission/delegation context. It carries no new authority: scope/lifetime/budget stay in
    the AuthorityContext it is built from.
  * ``AgentIdentityProvider`` — the provider-neutral boundary an enterprise IAM plugs into. IBM Agent Identity,
    Entra, Okta and SPIFFE/SPIRE are prospective *adapters*, not architectural dependencies; nothing here names them.
  * ``IdentityRiskSignal`` — an external risk observation carried as **evidence**. Deployment policy decides what to
    do with it; the Runtime never hardcodes severity→action, so no vendor risk taxonomy leaks into Runtime behavior.

Business authorization stays in the Runtime: this layer establishes *who/what* is acting and *under whose delegated
authority*, never *what business action is allowed* (that remains Runtime capabilities/policy/approval).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Optional, Protocol, runtime_checkable

from .seal import content_hash
from .security import AuthorityContext, PrincipalRef

AGENT_IDENTITY_CONTRACT_VERSION = "1"


# ── external risk, carried as evidence (never as hardcoded Runtime behavior) ─────────────────────────────
class RiskSeverity(IntEnum):
    """A normalized, vendor-neutral severity scale. Ordinal so deployment policy can threshold on it — but the
    response (approve / reduce capability / revoke / terminate) is deployment policy, NOT part of this contract."""
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass(frozen=True)
class IdentityRiskSignal:
    """An external identity/risk observation (e.g. from an identity-protection product), normalized to neutral
    fields and consumed by deployment policy as evidence. The Runtime attaches it to the evidence spine; it does
    not embed the provider's risk taxonomy or any severity→action mapping."""
    provider: str                       # opaque source name; never interpreted structurally
    actor_id: str                       # the PrincipalRef.id this is about
    risk_type: str                      # provider-defined label, treated as opaque
    severity: RiskSeverity = RiskSeverity.NONE
    confidence: float = 0.0             # 0..1
    observed_at: str = ""
    evidence_ref: str = ""              # pointer into the evidence store, not the raw payload
    recommended_response: str = ""      # advisory from the provider; NOT binding on the Runtime

    def canonical_form(self) -> dict[str, Any]:
        return {
            "provider": self.provider, "actor_id": self.actor_id, "risk_type": self.risk_type,
            "severity": int(self.severity), "confidence": self.confidence, "observed_at": self.observed_at,
            "evidence_ref": self.evidence_ref, "recommended_response": self.recommended_response,
        }

    def identity(self) -> str:
        return content_hash(self.canonical_form())


# ── execution identity: a view over PrincipalRef + AuthorityContext ──────────────────────────────────────
@dataclass(frozen=True)
class ExecutionIdentity:
    """Who/what is acting on one consequential action, and under whose delegated authority — a *view* composed
    from the existing primitives, not a competing identity type.

    ``agent_actor`` is the executing principal (``PrincipalRef.kind == "agent"`` in the common case). ``human_subject``
    is the person on whose behalf it runs (``None`` for fully autonomous service missions). ``agent_owner`` is the
    principal accountable for the agent. Scope, budget and lifetime are NOT here — they remain in the
    ``AuthorityContext`` referenced by ``authority_ref``.
    """
    agent_actor: PrincipalRef
    human_subject: Optional[PrincipalRef] = None
    agent_owner: Optional[PrincipalRef] = None
    tenant: str = ""
    mission_id: str = ""
    authority_ref: str = ""             # AuthorityContext.chain_ref() — the delegation this action binds to
    delegation_depth: int = 0
    assurance_level: str = ""           # "", "mfa", "sso", "attested", … (from the IAM boundary)

    @classmethod
    def of(cls, authority: AuthorityContext, *, mission_id: str = "",
           human_subject: Optional[PrincipalRef] = None, agent_owner: Optional[PrincipalRef] = None,
           assurance_level: str = "") -> "ExecutionIdentity":
        """Derive the view from an AuthorityContext (the single source of the acting principal + delegation)."""
        return cls(
            agent_actor=authority.principal, human_subject=human_subject, agent_owner=agent_owner,
            tenant=authority.principal.tenant, mission_id=mission_id, authority_ref=authority.chain_ref,
            delegation_depth=authority.depth, assurance_level=assurance_level)

    def canonical_form(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "agent_actor": self.agent_actor.canonical_form(),
            "tenant": self.tenant, "mission_id": self.mission_id, "authority_ref": self.authority_ref,
            "delegation_depth": self.delegation_depth, "assurance_level": self.assurance_level,
        }
        if self.human_subject is not None:
            d["human_subject"] = self.human_subject.canonical_form()
        if self.agent_owner is not None:
            d["agent_owner"] = self.agent_owner.canonical_form()
        return d

    def digest(self) -> str:
        return content_hash(self.canonical_form())


# ── the external-IAM boundary (provider-neutral) ─────────────────────────────────────────────────────────
@runtime_checkable
class AgentIdentityProvider(Protocol):
    """The seam an enterprise IAM plugs into. Every method speaks the neutral primitives above — a conforming
    adapter (IBM Agent Identity, Microsoft Entra, Okta, SPIFFE/SPIRE, or a Runtime-local default) maps its own
    concepts to these. The Runtime depends on this Protocol, never on any adapter."""
    def register_agent(self, agent: PrincipalRef, owner: PrincipalRef) -> str: ...
    def authenticate_agent(self, assertion: str) -> PrincipalRef: ...
    def resolve_owner(self, agent: PrincipalRef) -> Optional[PrincipalRef]: ...
    def get_delegation(self, agent: PrincipalRef, mission_id: str) -> AuthorityContext: ...
    def verify_authority(self, authority: AuthorityContext) -> bool: ...
    def issue_token(self, identity: ExecutionIdentity, ttl_seconds: int) -> str: ...
    def revoke_agent(self, agent: PrincipalRef) -> None: ...
    def get_risk_state(self, agent: PrincipalRef) -> Optional[IdentityRiskSignal]: ...
