"""agentic-os-enterprise → the shared authorization contract.

The overlay is where the enterprise-only claims live, so it is where they are tested. Nothing in this file
decides anything: each request is answered by the overlay's own enforcement code.

============================================================  ============================================
Contract request                                              Enterprise code that answers it
============================================================  ============================================
Capability decision                                           ``IdentityPlane.authorize`` (deny-by-default ``GrantRule`` check)
Resource decision                                             ``IdentityPlane.authorize_resource`` (tenant isolation, then the
                                                              kernel's ``PermissionsPlane`` through the composed plane)
Tenant-scoped grant                                           ``GrantRule`` + ``identity.Condition(tenant=…)``
Resource-tenancy decision                                     ``tenant_plane.DelegationAuthority`` + ``execution_context.resolve_for_node``
Queued work, revoked mid-flight                               ``mission.runtime.MissionRuntime.run`` → ``_pre_exec_ok`` → ``_authorize_node``
Policy-scoped candidates                                      ``mission.runtime.MissionRuntime._scoped`` → ``PolicyScopedRegistry.discover``
============================================================  ============================================

The envelope is read from ``agentic_os_enterprise.identity``'s log lines, because that is what an audit
reader sees. Where the plane also attached the envelope to its ``AccessDecision``, both are recorded and a
mismatch between them would show up in the evidence rather than being smoothed over here.
"""
from __future__ import annotations

import tempfile
from typing import Any, Sequence

from adapters._implementations import capture_audit, import_module
from runtime_contracts.authz.decision import parse_envelope
from runtime_contracts.authz.suite import (AuthzAdapter, CacheOutcome, CandidateSet, ExecutionOutcome,
                                           PrincipalSpec, Receipt, Unsupported)

ENT_LOGGER = "agentic_os_enterprise.identity"


def _split(subject: str) -> tuple[str, str]:
    kind, _, name = subject.partition(":")
    if kind in ("user", "service", "workload"):
        return kind, name
    return "user", (name or subject)


def _permission_for(capability: str) -> str:
    """Same rule as the kernel adapter: a capability demands its family's read permission, so a scenario can
    name capabilities and grants in one vocabulary across both editions."""
    head = capability.split(".", 1)[0] or capability
    return f"{head}.read"


class _RankEmbedder:
    """Declared similarity, so candidate ordering is a fixture fact rather than a spelling accident."""

    NEED = "\u0000need"

    def __init__(self, scores: dict[str, float]) -> None:
        self._scores = dict(scores)

    def embed(self, text: str) -> list[float]:
        import math
        if text == self.NEED:
            return [1.0, 0.0]
        score = self._scores.get(text.split(" ", 1)[0], 0.0)
        return [score, math.sqrt(max(0.0, 1.0 - score * score))]


class EnterpriseAuthzAdapter(AuthzAdapter):
    """The capability plane, the resource bridge, and the governed runtime behind one adapter."""

    implementation = "agentic-os-enterprise"
    edition = "enterprise"
    _seams = {
        "decide_capability": "agentic_os_enterprise.identity.IdentityPlane.authorize",
        "decide_resource": "agentic_os_enterprise.identity.IdentityPlane.authorize_resource",
        "decide_tenant_scoped_resource": "agentic_os_enterprise.identity.IdentityPlane.authorize + Condition(tenant=…)",
        "decide_resource_tenancy": "agentic_os_enterprise.tenant_plane.DelegationAuthority (via resolve_for_node)",
        "execute_queued": "agentic_os_enterprise.mission.runtime.MissionRuntime.run → _pre_exec_ok → _authorize_node",
        "candidates": "agentic_os_enterprise.mission.runtime.MissionRuntime._scoped → PolicyScopedRegistry.discover",
        "run_plan": "agentic_os_enterprise.mission.runtime.MissionRuntime.run → _pre_exec_ok",
        "stage1_grants": "agentic_os_enterprise.identity.IdentityPlane.scoped_permissions",
    }

    def __init__(self) -> None:
        self._identity_mod = import_module(self.implementation, "agentic_os_enterprise.identity")
        self._permissions_mod = import_module("agentic-os", "agentic_os.permissions")
        self._tenant_plane = import_module(self.implementation, "agentic_os_enterprise.tenant_plane")
        self._exec_ctx = import_module("agentic-os", "agentic_os.execution_context")
        self._runtime_mod = import_module(self.implementation, "agentic_os_enterprise.mission.runtime")
        self._registry_mod = import_module(self.implementation, "agentic_os_enterprise.mission.registry")
        self._executor_mod = import_module("agentic-os", "agentic_os.mission.executor")
        self._store_mod = import_module("agentic-os", "agentic_os.mission.store")
        self._sdk = import_module("agentic-os", "agentic_os.mission.operator_sdk")
        self._types = import_module("agentic-os", "agentic_os.mission.types")

        self._tmp = tempfile.TemporaryDirectory(prefix="rc-authz-ent-")
        self._restore: dict[str, Any] = {"registry": self._exec_ctx.resource_registry(),
                                         "gate": self._exec_ctx.authority_gate()}
        self._rules: list[str] = []
        self._grant_ids: list[str] = []
        self._handles: dict[str, dict[str, list[str]]] = {}
        self._handle_seq = 0
        self.build()

    def build(self) -> None:
        # Its own fixture store, with the kernel store's explicit development key opt-in: a contract run
        # never touches an operator's real grants or key.
        self.store = self._permissions_mod.GrantStore(self._tmp.name, allow_generated_key_dev=True)
        self.permissions = self._permissions_mod.PermissionsPlane(self.store)
        self.ledger = self._identity_mod.AccessLedger()
        self.plane = self._identity_mod.IdentityPlane(permissions_plane=self.permissions, ledger=self.ledger)

    def close(self) -> None:
        try:
            self._exec_ctx.set_resource_registry(self._restore["registry"])
            self._exec_ctx.set_authority_gate(self._restore["gate"])
        finally:
            self._tmp.cleanup()

    # -- fixture helpers -------------------------------------------------------
    def _principal(self, spec: PrincipalSpec):
        kind, name = _split(spec.subject)
        return self._identity_mod.Principal(kind=kind, id=name, roles=list(spec.roles), tenant=spec.tenant)

    def _receipt(self, decision, *, seam: str, extra: dict[str, Any] | None = None) -> Receipt:
        audit = getattr(decision, "audit", None)
        decision_obj = parse_envelope(audit, plane=self.implementation) if isinstance(audit, dict) else None
        return Receipt(allowed=bool(decision.allowed), reason=str(getattr(decision, "reason", "")),
                       decision=decision_obj, seam=seam,
                       raw={**(audit if isinstance(audit, dict) else {}),
                            "reason": str(getattr(decision, "reason", "")), **(extra or {})})

    def _prefer_logged(self, receipt: Receipt, audit) -> Receipt:
        """The emitted line wins: it is what an audit reader has. The in-object envelope stays for compare."""
        logged = audit.last()
        if logged is None:
            return receipt
        consistent = (receipt.decision is None) or (receipt.decision.to_envelope() == logged.to_envelope())
        return Receipt(allowed=logged.allowed, reason=receipt.reason, decision=logged, seam=receipt.seam,
                       raw={**receipt.raw, "logged": audit.lines, "envelope_matches_decision_object": consistent,
                            "malformed_audit_lines": audit.malformed})

    def _scoped_view(self, spec: PrincipalSpec, registry):
        """The overlay's own stage-1 scoping: ``MissionRuntime._scoped`` for this mission's principal."""
        runtime = self._runtime_mod.MissionRuntime(registry,
                                                   self._executor_mod.Executor(self._sdk.LocalOperatorClient({})),
                                                   store=self._store_mod.EventStore(),
                                                   identity_plane=self.plane)
        mission = self._types.Mission(goal="authz/v1 scoping", principal=self._principal(spec),
                                      tenant=spec.tenant or "acme")
        return runtime._scoped(mission)

    # -- authority administration ---------------------------------------------
    def grant(self, principal: PrincipalSpec, *, resource: str = "", actions: Sequence[str] = (),
              permissions: Sequence[str] = (), tenant: str | None = None) -> str:
        kind, name = _split(principal.subject)
        rule_ids: list[str] = []
        grant_ids: list[str] = []
        if permissions:
            condition = self._identity_mod.Condition(tenant=tenant) if tenant else None
            rule = self.plane.add_rule(f"{kind}:{name}", list(permissions), condition=condition)
            rule_ids.append(rule.id)
            self._rules.append(rule.id)
        if resource:
            grant = self.store.add("user" if kind == "user" else "app", name, "table", resource,
                                   actions=list(actions) or ["read"])
            grant_ids.append(grant.id)
            self._grant_ids.append(grant.id)
        self._handle_seq += 1
        handle = f"ent-grant-{self._handle_seq}"
        self._handles[handle] = {"rules": rule_ids, "grants": grant_ids}
        return handle

    def revoke(self, grant_id: str) -> bool:
        parts = self._handles.get(grant_id, {"rules": [], "grants": []})
        removed = 0
        for rid in list(parts["rules"]):
            if self.plane.revoke_rule(rid):
                removed += 1
        for gid in list(parts["grants"]):
            if self.store.remove(gid):
                removed += 1
        self._handles[grant_id] = {"rules": [], "grants": []}
        return bool(removed)

    # -- decisions -------------------------------------------------------------
    def decide_capability(self, principal: PrincipalSpec, *, capability: str,
                          permissions: Sequence[str] = (), request_tenant: str | None = None) -> Receipt:
        context = {"tenant": request_tenant} if request_tenant else {}
        with capture_audit(ENT_LOGGER, plane=self.implementation) as audit:
            try:
                decision = self.plane.authorize(self._principal(principal), capability,
                                                list(permissions) or [capability], action="invoke",
                                                context=context)
            except Exception as exc:  # noqa: BLE001 — how the plane fails on a broken backend is the result
                return Receipt(allowed=False, reason=f"{type(exc).__name__}: {exc}", decision=None,
                               seam=self.seam("decide_capability"),
                               raw={"error": f"{type(exc).__name__}: {exc}", "logged": audit.lines})
        return self._prefer_logged(self._receipt(decision, seam=self.seam("decide_capability")), audit)

    def decide_resource(self, principal: PrincipalSpec, *, resource: str, action: str = "read",
                        request_tenant: str | None = None) -> Receipt:
        context = {"tenant": request_tenant} if request_tenant else {}
        with capture_audit(ENT_LOGGER, plane=self.implementation) as audit:
            try:
                decision = self.plane.authorize_resource(self._principal(principal), "table", resource,
                                                        action, context=context)
            except Exception as exc:  # noqa: BLE001
                return Receipt(allowed=False, reason=f"{type(exc).__name__}: {exc}", decision=None,
                               seam=self.seam("decide_resource"),
                               raw={"error": f"{type(exc).__name__}: {exc}", "logged": audit.lines})
        return self._prefer_logged(self._receipt(decision, seam=self.seam("decide_resource")), audit)

    def decide_tenant_scoped_resource(self, principal: PrincipalSpec, *, grant_tenant: str,
                                      request_tenant: str, resource: str, action: str = "read") -> Receipt:
        kind, name = _split(principal.subject)
        permission = f"{resource}.{action}"
        self.plane.add_rule(f"{kind}:{name}", [permission],
                            condition=self._identity_mod.Condition(tenant=grant_tenant))
        asking = PrincipalSpec(subject=principal.subject, roles=principal.roles, tenant=request_tenant)
        return self.decide_capability(asking, capability=permission, permissions=(permission,),
                                      request_tenant=request_tenant)

    def decide_resource_tenancy(self, principal: PrincipalSpec, *, owner_tenant: str, resource_tenant: str,
                                capability: str, delegated: bool = False) -> Receipt:
        ec = self._exec_ctx
        resource_id = f"erp.{capability}"
        delegations = ([self._tenant_plane.Delegation(from_tenant=owner_tenant, to_tenant=resource_tenant,
                                                     capabilities=frozenset({capability}))]
                       if delegated else [])
        ec.set_resource_registry(self._tenant_plane.EnterpriseResourceRegistry(
            {resource_id: ec.ResourceRef(resource_id, "erp", owning_tenant=resource_tenant)}))
        ec.set_authority_gate(self._tenant_plane.DelegationAuthority(delegations=delegations))
        ctx = ec.ExecutionContext(owner_tenant=owner_tenant, actor_principal=principal.subject)
        node_ctx, _resource, decision = ec.resolve_for_node(ctx, resource_id, capability)
        return Receipt(allowed=bool(decision.allowed), reason=str(decision.reason), decision=None,
                       seam=self.seam("decide_resource_tenancy"),
                       raw={"reason": str(decision.reason), "authority": node_ctx.authority,
                            "resource_tenant": node_ctx.resource_tenant,
                            "lease_ref": getattr(decision, "lease_ref", None), "envelope": "not emitted"})

    # -- queued execution and plan runs ----------------------------------------
    def _held_permissions(self, principal: PrincipalSpec) -> list[str]:
        """What the overlay's own scoping says this principal holds — the input the planner is shown."""
        return sorted(self.plane.scoped_permissions(self._principal(principal),
                                                   {"tenant": principal.tenant or "acme"}))

    def _build_runtime(self, principal: PrincipalSpec, steps, ran: list[str]):
        """A governed runtime over a provider graph the scenario declares, ranked so an unauthorized
        provider is the one an unfiltered planner would take."""
        sdk = self._sdk
        providers = [(name, outcome) for outcome, names in steps for name in names]
        held = set(self._held_permissions(principal))
        permitted = [name for name, _o in providers if _permission_for(name) in held]
        forbidden = [name for name, _o in providers if _permission_for(name) not in held]
        scores = {name: 0.99 - 0.001 * i for i, name in enumerate(forbidden)}
        scores.update({name: 0.05 + 0.001 * i for i, name in enumerate(permitted)})

        operator = sdk.Operator("authz_contract", [
            sdk.capability(name, self._recorder(ran, name), provides=[outcome],
                           permissions=[_permission_for(name)])
            for name, outcome in providers
        ])
        registry = self._registry_mod.CapabilityRegistry(embedder=_RankEmbedder(scores))
        registry.register(operator.manifest)
        client = sdk.LocalOperatorClient({"authz_contract": operator})
        types = self._types

        class _Planner:
            def plan(self, mission_id, goal, ctx):
                planned = [types.IntentStep(outcome=outcome, need=outcome.replace("_", " "), value_hint="high")
                           for outcome, _names in steps]
                return types.ExecutionIntent(mission_id=mission_id, rationale="authz/v1 scenario",
                                             steps=planned)

        runtime = self._runtime_mod.MissionRuntime(registry, self._executor_mod.Executor(client),
                                                   store=self._store_mod.EventStore(), planner=_Planner(),
                                                   identity_plane=self.plane)
        # How the overlay is really wired (see discovery/mission_bridge): the caller resolves the principal's
        # grants and hands them to the mission, because the compiler's stage-2 check reads
        # ``Mission.policy_refs`` — NOT the identity plane, which only feeds stage-1 scoping.
        mission = runtime.create_mission("authz/v1 scenario plan", policy_refs=sorted(held),
                                         principal=self._principal(principal),
                                         tenant=principal.tenant or "acme")
        return runtime, mission, {
            "held": sorted(held), "unauthorized_providers": forbidden,
            "stage1_authority": "IdentityPlane.scoped_permissions(principal) → MissionRuntime._scoped",
            "stage2_authority": "Mission.policy_refs (caller-resolved) → compiler grant check",
            "dispatch_authority": "MissionRuntime._pre_exec_ok → IdentityPlane.authorize",
        }

    @staticmethod
    def _recorder(ran: list[str], name: str):
        def run(inputs: dict) -> dict:
            ran.append(name)
            return {"ran": name}
        return run

    def _drive(self, runtime, mission, audit) -> tuple[str, list[str], list[dict]]:
        """Run the mission, keeping whatever envelopes the plane logged while nodes were admitted."""
        runtime.run(mission.id)
        state = getattr(mission.state, "value", str(mission.state))
        timeline = [t for t in (e.get("type") for e in runtime.repo.timeline(mission.id)) if t]
        ledger = [e.to_dict() for e in self.ledger.entries()][-8:]
        return str(state), timeline, ledger

    def _receipts(self, audit, ledger: Sequence[dict[str, Any]], *, seam: str) -> tuple[Receipt, ...]:
        """Receipts are the envelopes the identity plane logged during the run — an auditor's view, not this
        adapter's reconstruction. The ledger entries ride along as corroborating evidence."""
        out = [Receipt(allowed=r.allowed, reason=r.policy_reason, decision=r, seam=seam,
                       raw=dict(r.to_envelope())) for r in audit.receipts]
        if not out:
            out = [Receipt(allowed=bool(entry.get("allowed")), reason=str(entry.get("reason", "")),
                           decision=None, seam=seam, raw={"ledger": entry})
                   for entry in ledger]
        return tuple(out)

    def execute_queued(self, principal: PrincipalSpec, *, capability: str,
                       revoke_before_dispatch: str | None = None) -> ExecutionOutcome:
        ran: list[str] = []
        runtime, mission, fixture = self._build_runtime(principal, ((f"out::{capability}", (capability,)),),
                                                       ran)
        if revoke_before_dispatch:      # revoked AFTER the mission was queued, BEFORE the node dispatches
            self.revoke(revoke_before_dispatch)
        with capture_audit(ENT_LOGGER, plane=self.implementation) as audit:
            state, timeline, ledger = self._drive(runtime, mission, audit)
        receipts = self._receipts(audit, ledger, seam=self.seam("execute_queued"))
        return ExecutionOutcome(dispatched=tuple(ran), denied=tuple(() if ran else (capability,)),
                                state=state, receipts=receipts,
                                raw={"timeline": timeline, "ledger": ledger, "fixture": fixture,
                                     "logged_envelopes": audit.lines,
                                     "gate": "MissionRuntime._pre_exec_ok → IdentityPlane.authorize"})

    def run_plan(self, principal: PrincipalSpec, *, steps) -> ExecutionOutcome:
        ran: list[str] = []
        runtime, mission, fixture = self._build_runtime(principal, steps, ran)
        with capture_audit(ENT_LOGGER, plane=self.implementation) as audit:
            state, timeline, ledger = self._drive(runtime, mission, audit)
        denied = sorted({name for outcome, names in steps for name in names} - set(ran))
        return ExecutionOutcome(dispatched=tuple(ran), denied=tuple(denied), state=state,
                                receipts=self._receipts(audit, ledger, seam=self.seam("run_plan")),
                                raw={"timeline": timeline, "logged_envelopes": audit.lines, **fixture})

    # -- epoch -----------------------------------------------------------------
    def freshness_predicate(self, *, write_epoch: int, read_epoch: int) -> bool:
        raise Unsupported(f"{self.implementation}: the overlay has no authorization epoch at all — "
                          "GrantRule/AccessDecision carry no revocation epoch and nothing imports the "
                          "kernel's authz_contract helpers, so there is no freshness rule to consult")

    def serve_cached(self, principal: PrincipalSpec, *, resource: str, action: str = "read",
                     write_epoch: int, read_epoch: int) -> CacheOutcome:
        raise Unsupported(f"{self.implementation}: no authorization decision cache exists — "
                          "IdentityPlane re-evaluates its rules on every call and nothing keys a cached "
                          "decision by tenant/epoch, so the epoch-staleness criterion has no seam")

    # -- candidate graph -------------------------------------------------------
    def candidates(self, principal: PrincipalSpec, *, need: str, limit: int,
                   authorized: Sequence[str], unauthorized: Sequence[str]) -> CandidateSet:
        scores = {name: 0.90 + 0.005 * i for i, name in enumerate(unauthorized)}
        for i, name in enumerate(authorized):
            scores[name] = 0.01 + 0.001 * i
        registry = self._registry_mod.CapabilityRegistry(embedder=_RankEmbedder(scores))
        caps = [self._types.CapabilitySpec(name=name, operator="authz_contract", provides=[f"out::{name}"],
                                           permissions=[f"{name.split('.', 1)[0]}.read"])
                for name in list(unauthorized) + list(authorized)]
        registry.register(self._types.CapabilityManifest(operator="authz_contract", capabilities=caps))
        scoped = self._scoped_view(principal, registry)
        found = scoped.discover(_RankEmbedder.NEED, limit)
        names = tuple(c.name for c, _ in found)
        grants = sorted(self.plane.scoped_permissions(self._principal(principal),
                                                      {"tenant": principal.tenant or "acme"}))
        return CandidateSet(names=names, limit=limit, expected_present=tuple(authorized),
                           forbidden=tuple(unauthorized), seam=self.seam("candidates"),
                           raw={"grants": grants, "ranked_ahead": list(unauthorized)})

    # -- fault injection -------------------------------------------------------
    def break_authority_backend(self) -> None:
        """The composed resource plane loses its store — the same failure an operator would call an outage."""
        def _boom() -> tuple:
            raise RuntimeError("grant store unavailable (injected authority failure)")
        self.store.snapshot = _boom     # type: ignore[method-assign]