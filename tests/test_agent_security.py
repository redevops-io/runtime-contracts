"""Phase-0/1 agent-security seam (NVIDIA/IBM deployment audit): agent identity as a view over the existing
primitives, capability-negotiated execution backends, fail-closed enforcement, risk-as-evidence, and deterministic
identity↔receipt linkage. No vendor concepts appear in the contract.
"""
from __future__ import annotations

import pytest

from runtime_contracts.protocol import (
    AgentIdentityProvider, AuthorityContext, DelegationRefused, ExecutionIdentity, IdentityRiskSignal,
    PrincipalRef, RiskSeverity,
)
from runtime_contracts.models import (
    BackendCapabilities, EnforcementDowngrade, EnforcementProfile, ExecutionAdmission, ExecutionBackend,
    ExecutionConstraint, ExecutionEnvelope, ExecutionReceipt, admit_backend, profile_requirements,
)


# ── helpers ──────────────────────────────────────────────────────────────────────────────────────────────
def _agent(id="agent:planner", tenant="t1"):
    return PrincipalRef(id=id, kind="agent", tenant=tenant, roles=("planner",))


def _root_authority(scope=("read", "write")):
    return AuthorityContext(authority_id="a0", principal=_agent(), purpose="mission", scope=scope)


def _envelope(authority: AuthorityContext, constraint=None):
    return ExecutionEnvelope(mission_id="m1", plan_fingerprint="pf", capability_id="cap.deploy",
                             authority=authority.chain_ref, target="k8s:prod",
                             constraint=constraint or ExecutionConstraint())


class FakeBackend:
    """A membrane-like backend advertising a fixed capability set."""
    def __init__(self, backend_id="membrane.local", caps=None):
        self.backend_id = backend_id
        self._caps = caps or BackendCapabilities(
            filesystem_isolation=True, network_egress_control=True, resource_limits=True, process_isolation=True)

    def capabilities(self) -> BackendCapabilities:
        return self._caps

    def execute(self, envelope, identity, profile) -> ExecutionReceipt:
        return ExecutionReceipt(envelope_binding=envelope.binding, mission_id=envelope.mission_id,
                                capability_id=envelope.capability_id, idempotency_key=envelope.idempotency_key,
                                outcome="executed", attestation=f"{self.backend_id}:ok")

    def terminate(self, execution_id): ...
    def status(self, execution_id): return "done"
    def attest(self, execution_id): return "att"


# ── delegation containment ───────────────────────────────────────────────────────────────────────────────
def test_delegation_narrows_and_refuses_widening():
    root = _root_authority(scope=("read", "write"))
    child = root.narrow(authority_id="a1", scope=("read",))
    assert child.depth == root.depth + 1 and set(child.scope) <= set(root.scope)
    with pytest.raises(DelegationRefused):
        root.narrow(authority_id="a2", scope=("read", "write", "admin"))   # widening is refused


def test_execution_identity_is_a_view_over_authority():
    root = _root_authority()
    child = root.narrow(authority_id="a1", scope=("read",))
    ident = ExecutionIdentity.of(child, mission_id="m1",
                                 human_subject=PrincipalRef(id="user:jane", kind="user", tenant="t1"),
                                 agent_owner=PrincipalRef(id="team:platform", kind="service", tenant="t1"))
    # carries the tri-distinction, and inherits delegation from the AuthorityContext (no new authority)
    assert ident.agent_actor.id == "agent:planner" and ident.human_subject.id == "user:jane"
    assert ident.agent_owner.id == "team:platform"
    assert ident.authority_ref == child.chain_ref and ident.delegation_depth == child.depth
    assert ident.tenant == "t1"


# ── identity attribution + deterministic receipt linkage ─────────────────────────────────────────────────
def test_identity_digest_stable_and_optional_fields_conditional():
    a = _root_authority()
    autonomous = ExecutionIdentity.of(a, mission_id="m1")                       # no human subject
    on_behalf = ExecutionIdentity.of(a, mission_id="m1", human_subject=PrincipalRef(id="user:jane", kind="user"))
    assert autonomous.digest() == ExecutionIdentity.of(a, mission_id="m1").digest()   # deterministic
    assert autonomous.digest() != on_behalf.digest()                                  # subject changes identity
    assert "human_subject" not in autonomous.canonical_form()                         # omitted when None


def test_receipt_links_to_identity_via_envelope_authority():
    a = _root_authority()
    env = _envelope(a)
    ident = ExecutionIdentity.of(a, mission_id=env.mission_id)
    receipt = FakeBackend().execute(env, ident, EnforcementProfile.ISOLATED)
    # deterministic chain: receipt → envelope.binding → envelope.authority == identity.authority_ref
    assert receipt.envelope_binding == env.binding
    assert env.authority == ident.authority_ref
    assert receipt.receipt_id == ExecutionReceipt(**{**receipt.__dict__}).receipt_id   # stable


# ── capability negotiation + fail-closed enforcement ─────────────────────────────────────────────────────
def test_capabilities_satisfies_is_subset_semantics():
    caps = BackendCapabilities(filesystem_isolation=True, network_egress_control=True, resource_limits=True,
                               process_isolation=True)
    assert caps.satisfies(profile_requirements(EnforcementProfile.ISOLATED))
    assert not caps.satisfies(profile_requirements(EnforcementProfile.HARDENED))     # lacks quarantine/attestation
    assert "quarantine" in caps.missing(profile_requirements(EnforcementProfile.HARDENED))


def test_profile_requirements_are_monotonic():
    std = profile_requirements(EnforcementProfile.STANDARD)
    iso = profile_requirements(EnforcementProfile.ISOLATED)
    hard = profile_requirements(EnforcementProfile.HARDENED)
    hw = profile_requirements(EnforcementProfile.HARDWARE_ATTESTED)
    assert iso.satisfies(std) and hard.satisfies(iso) and hw.satisfies(hard)         # each tier ⊇ the last
    assert not std.satisfies(iso) and not iso.satisfies(hard) and not hard.satisfies(hw)


def test_admission_grants_when_profile_met():
    a = _root_authority(); env = _envelope(a); ident = ExecutionIdentity.of(a, mission_id="m1")
    adm = admit_backend(EnforcementProfile.ISOLATED, FakeBackend(), env, ident)
    assert adm.granted and adm.enforcement_profile == "isolated" and adm.backend_id == "membrane.local"
    assert adm.envelope_binding == env.binding and adm.execution_identity == ident.digest()


def test_enforcement_downgrade_fails_closed():
    a = _root_authority(); env = _envelope(a); ident = ExecutionIdentity.of(a, mission_id="m1")
    membrane = FakeBackend()   # ISOLATED-class caps, no hardware attestation
    # a HARDWARE_ATTESTED mission must NOT silently run on the local membrane
    with pytest.raises(EnforcementDowngrade):
        admit_backend(EnforcementProfile.HARDWARE_ATTESTED, membrane, env, ident)
    # only an explicit, audited downgrade is allowed
    adm = admit_backend(EnforcementProfile.HARDWARE_ATTESTED, membrane, env, ident, allow_downgrade=True)
    assert adm.granted and "explicit_downgrade" in adm.reason and "hardware_attestation" in adm.reason


def test_admission_id_is_deterministic():
    a = _root_authority(); env = _envelope(a); ident = ExecutionIdentity.of(a, mission_id="m1")
    a1 = admit_backend(EnforcementProfile.ISOLATED, FakeBackend(), env, ident)
    a2 = admit_backend(EnforcementProfile.ISOLATED, FakeBackend(), env, ident)
    assert a1.admission_id() == a2.admission_id()


def test_backend_satisfies_protocol():
    assert isinstance(FakeBackend(), ExecutionBackend)


# ── risk as evidence — the contract never encodes severity→action ────────────────────────────────────────
def test_risk_signal_is_evidence_not_behavior():
    sig = IdentityRiskSignal(provider="acme-idp", actor_id="agent:planner", risk_type="anomalous_delegation",
                             severity=RiskSeverity.HIGH, confidence=0.8, evidence_ref="ev:123")
    assert sig.identity() == IdentityRiskSignal(
        provider="acme-idp", actor_id="agent:planner", risk_type="anomalous_delegation",
        severity=RiskSeverity.HIGH, confidence=0.8, evidence_ref="ev:123").identity()   # content-addressed evidence
    # the contract carries NO action mapping — response is deployment policy, defined by the caller:
    assert not any(hasattr(sig, m) for m in ("response", "action", "decide", "apply"))

    # a *deployment* policy (here, in the test — not the contract) maps severity → action
    def deployment_policy(s: IdentityRiskSignal) -> str:
        return {RiskSeverity.NONE: "continue", RiskSeverity.LOW: "continue",
                RiskSeverity.MEDIUM: "require_approval", RiskSeverity.HIGH: "reduce_capability",
                RiskSeverity.CRITICAL: "terminate"}[s.severity]
    assert deployment_policy(sig) == "reduce_capability"


# ── the provider seam is neutral (structural conformance, no vendor names) ────────────────────────────────
def test_identity_provider_protocol_is_structural():
    class LocalIdP:
        def register_agent(self, agent, owner): return agent.id
        def authenticate_agent(self, assertion): return _agent()
        def resolve_owner(self, agent): return None
        def get_delegation(self, agent, mission_id): return _root_authority()
        def verify_authority(self, authority): return True
        def issue_token(self, identity, ttl_seconds): return "tok"
        def revoke_agent(self, agent): ...
        def get_risk_state(self, agent): return None
    assert isinstance(LocalIdP(), AgentIdentityProvider)
