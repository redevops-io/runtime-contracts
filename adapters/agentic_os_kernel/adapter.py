"""agentic-os (AGPL kernel) → the shared authorization contract.

Every answer comes out of the kernel's own enforcement code. What this file adds is translation, never a
decision:

============================================================  ============================================
Contract request                                              Kernel code that answers it
============================================================  ============================================
Resource decision                                             ``agentic_os.permissions.PermissionsPlane.authorize``
Capability decision                                           ``agentic_os.permissions.make_authorizer`` (the tool gate:
                                                              a capability is a tool mapped to a resource with a
                                                              registered action — the kernel's own shape for
                                                              "this capability needs this authority")
Resource-tenancy decision                                     ``agentic_os.execution_context.resolve_for_node`` + ``OwnerOnlyAuthority``
Authorization-epoch freshness                                 ``agentic_os.authz_contract.cache_entry_is_fresh``
Policy-scoped candidates                                      ``agentic_os.mission.registry.PolicyScopedRegistry.discover``
Plan execution                                                ``agentic_os.mission.runtime.MissionRuntime.run``
Queued work                                                   ``agentic_os.mission.reconcile_jobs.ReconcileJobs`` (durable queue),
                                                              authorized at dispatch by the tool gate
============================================================  ============================================

Two translation rules are worth naming because they decide what the results mean:

**A capability needs its family's read permission.** ``reports.monthly`` is checked as a tool mapped to
resource ``reports.monthly`` requiring action ``read``, so holding ``reports.read`` covers it and nothing
else. That is the kernel's own resource-prefix rule, not a convenience of this adapter.

**Receipts come from what the kernel logged.** ``PermissionsPlane`` writes one ``authorization_decision``
line per decision. The adapter reads those lines through the logger rather than rebuilding a dict, so a
plane that decides without emitting is reported as emitting nothing — which is what an auditor would see.
"""
from __future__ import annotations

import math
import tempfile
from typing import Any, Iterable, Sequence

from adapters._implementations import capture_audit, import_module
from runtime_contracts.authz.decision import parse_envelope
from runtime_contracts.authz.suite import (AuthzAdapter, AdapterBlocked, BackendOutcome, CacheOutcome,
                                           CandidateSet, ExecutionOutcome, PrincipalSpec, Receipt, Unsupported)

KERNEL_LOGGER = "agentic_os.permissions"


class _Principal:
    """The principal shape the kernel's tool gate reads (``app`` / ``user`` / ``roles``)."""

    def __init__(self, app: str = "", user: str = "", roles: Sequence[str] = ()) -> None:
        self.app, self.user, self.roles = app, user, list(roles)


class _Tool:
    def __init__(self, name: str) -> None:
        self.name = name


class _RankEmbedder:
    """Deterministic ranking for candidate scenarios: similarity is declared, not guessed from names.

    Stage-1 scoping is about *which* candidates survive authorization and *when* the limit is applied. An
    embedding learned from token overlap would make the ordering an accident of the fixture's spelling, so
    each capability's similarity to the need is declared here and the kernel's own cosine/discover code
    does the ranking.
    """

    NEED = "\u0000need"

    def __init__(self, scores: dict[str, float]) -> None:
        self._scores = dict(scores)

    def embed(self, text: str) -> list[float]:
        if text == self.NEED:
            return [1.0, 0.0]
        name = text.split(" ", 1)[0]
        score = self._scores.get(name, 0.0)
        return [score, math.sqrt(max(0.0, 1.0 - score * score))]


def _permission_for(capability: str) -> str:
    """The permission a capability demands: its resource family's ``read`` (``reports.monthly`` →
    ``reports.read``), which is the kernel's dotted-prefix grant rule rather than a new mapping."""
    head = capability.split(".", 1)[0] or capability
    return f"{head}.read"


def _split(subject: str) -> tuple[str, str]:
    kind, _, name = subject.partition(":")
    if kind in ("app", "service", "workload"):
        return "app", (name or kind)
    if kind == "user":
        return "user", name
    return "user", (name or subject)


class KernelAuthzAdapter(AuthzAdapter):
    """The kernel plane, as an ``authz/v1`` adapter."""

    implementation = "agentic-os"
    edition = "kernel"
    _seams = {
        "decide_resource": "agentic_os.permissions.PermissionsPlane.authorize",
        "decide_capability": "agentic_os.permissions.make_authorizer",
        "decide_tenant_scoped_resource": "agentic_os.permissions.PermissionsPlane.authorize (tenant-tagged grant)",
        "decide_resource_tenancy": "agentic_os.execution_context.resolve_for_node + OwnerOnlyAuthority",
        "execute_queued": "agentic_os.mission.reconcile_jobs.ReconcileJobs.claim_due + make_authorizer",
        "freshness_predicate": "agentic_os.authz_contract.cache_entry_is_fresh",
        "candidates": "agentic_os.mission.registry.PolicyScopedRegistry.discover",
        "run_plan": "agentic_os.mission.runtime.MissionRuntime.run",
    }

    def __init__(self) -> None:
        self._permissions = import_module(self.implementation, "agentic_os.permissions")
        self._exec_ctx = import_module(self.implementation, "agentic_os.execution_context")
        self._authzc = import_module(self.implementation, "agentic_os.authz_contract")
        self._registry_mod = import_module(self.implementation, "agentic_os.mission.registry")
        self._jobs_mod = import_module(self.implementation, "agentic_os.mission.reconcile_jobs")
        self._runtime_mod = import_module(self.implementation, "agentic_os.mission.runtime")
        self._sdk = import_module(self.implementation, "agentic_os.mission.operator_sdk")
        self._types = import_module(self.implementation, "agentic_os.mission.types")
        self._tmp = tempfile.TemporaryDirectory(prefix="rc-authz-kernel-")
        self._grants: list[Any] = []
        self._handles: dict[str, list[str]] = {}
        self._handle_seq = 0
        self._broken = False
        self._restore: dict[str, Any] = {}
        self.build()

    # -- fixture ---------------------------------------------------------------
    def build(self) -> None:
        # A fixture store of its own, with the store's explicit development key-generation opt-in: a contract
        # run must not read, write or depend on an operator's real grant store or key.
        store = self._permissions.GrantStore(self._tmp.name, allow_generated_key_dev=True)
        self.store = store
        self.plane = self._permissions.PermissionsPlane(store)
        # Remember what the tenancy globals held, so a suite run cannot leak a registry into the next cell.
        self._restore = {"registry": self._exec_ctx.resource_registry(),
                         "gate": self._exec_ctx.authority_gate()}

    def close(self) -> None:
        try:
            self._exec_ctx.set_resource_registry(self._restore["registry"])
            self._exec_ctx.set_authority_gate(self._restore["gate"])
        finally:
            self._tmp.cleanup()

    def _identity(self, spec: PrincipalSpec):
        kind, name = _split(spec.subject)
        if kind == "app":
            return self._permissions.Identity(app=name, user="", roles=list(spec.roles))
        return self._permissions.Identity(app="", user=name, roles=list(spec.roles))

    def _principal(self, spec: PrincipalSpec) -> _Principal:
        kind, name = _split(spec.subject)
        if kind == "app":
            return _Principal(app=name, user="", roles=spec.roles)
        return _Principal(app="", user=name, roles=spec.roles)

    def _receipt(self, decision, *, seam: str, raw_extra: dict[str, Any] | None = None) -> Receipt:
        """A kernel AccessDecision plus the audit line the plane wrote about it."""
        audit = getattr(decision, "audit", None)
        return Receipt(allowed=bool(decision.allowed), reason=str(getattr(decision, "reason", "")),
                       decision=parse_envelope(audit, plane=self.implementation) if audit else None,
                       seam=seam, raw={**(audit if isinstance(audit, dict) else {}),
                                       "reason": str(getattr(decision, "reason", "")),
                                       **(raw_extra or {})})

    # -- authority administration ---------------------------------------------
    def grant(self, principal: PrincipalSpec, *, resource: str = "", actions: Sequence[str] = (),
              permissions: Sequence[str] = (), tenant: str | None = None) -> str:
        kind, name = _split(principal.subject)
        created: list[str] = []
        targets: list[tuple[str, list[str]]] = []
        if resource:
            targets.append((resource, list(actions) or ["read"]))
        for permission in permissions:
            targets.append((permission, ["read"]))
        for res_name, acts in targets:
            grant = self.store.add(kind, name, "table", res_name, actions=list(acts))
            if tenant:      # contract-v1 tag: settable only on the object, since add()/update() expose no tenant API
                grant.tenant = tenant
            created.append(grant.id)
            self._grants.append(grant)
        self._handle_seq += 1
        handle = f"kernel-grant-{self._handle_seq}"
        self._handles[handle] = created
        return handle

    def revoke(self, grant_id: str) -> bool:
        ids = self._handles.get(grant_id, [grant_id])
        removed = 0
        for gid in ids:
            grant = next((g for g in self._grants if g.id == gid), None)
            if grant is not None and self.store.remove(gid):
                self._grants.remove(grant)
                removed += 1
        if ids:
            self._handles[grant_id] = []
        return bool(removed)

    # -- decisions -------------------------------------------------------------
    def decide_resource(self, principal: PrincipalSpec, *, resource: str, action: str = "read",
                        request_tenant: str | None = None) -> Receipt:
        if request_tenant:
            raise Unsupported(f"{self.implementation}: PermissionsPlane.authorize takes no request tenant, "
                              "so no kernel seam can bind a resource decision to a tenant")
        with capture_audit(KERNEL_LOGGER, plane=self.implementation) as audit:
            try:
                decision = self.plane.authorize(self._identity(principal), "table", resource, action)
            except Exception as exc:  # noqa: BLE001 — what the plane does on a failing backend IS the result
                return Receipt(allowed=False, reason=f"{type(exc).__name__}: {exc}", decision=None,
                               seam=self.seam("decide_resource"),
                               raw={"error": f"{type(exc).__name__}: {exc}", "logged": audit.lines})
        receipt = self._receipt(decision, seam=self.seam("decide_resource"))
        return self._prefer_logged(receipt, audit)

    def _prefer_logged(self, receipt: Receipt, audit) -> Receipt:
        """Prefer the envelope the plane actually emitted; keep the in-memory one only as a fallback."""
        logged = audit.last()
        if logged is None:
            return receipt
        return Receipt(allowed=logged.allowed, reason=receipt.reason, decision=logged, seam=receipt.seam,
                       raw={**receipt.raw, "logged": audit.lines, "malformed_audit_lines": audit.malformed})

    def _tool_gate(self, tool: str, resource: str, action: str):
        return self._permissions.make_authorizer(self.store, tool_resources={tool: ("table", resource)},
                                                 tool_actions={tool: action})

    def decide_capability(self, principal: PrincipalSpec, *, capability: str,
                          permissions: Sequence[str] = (), request_tenant: str | None = None) -> Receipt:
        if request_tenant:
            raise Unsupported(f"{self.implementation}: the tool gate resolves no request tenant; the kernel "
                              "has no tenant-bound capability decision")
        resource = next(iter(permissions), capability)
        authorizer = self._tool_gate(capability, resource, "read")
        with capture_audit(KERNEL_LOGGER, plane=self.implementation) as audit:
            try:
                denial = authorizer(self._principal(principal), _Tool(capability), {})
            except Exception as exc:  # noqa: BLE001
                return Receipt(allowed=False, reason=f"{type(exc).__name__}: {exc}", decision=None,
                               seam=self.seam("decide_capability"),
                               raw={"error": f"{type(exc).__name__}: {exc}", "logged": audit.lines})
        reason = denial or "allow · tool gate"
        logged = audit.last()
        return Receipt(allowed=denial is None, reason=reason, decision=logged,
                       seam=self.seam("decide_capability"),
                       raw={"gate_reason": reason, "logged": audit.lines, "malformed_audit_lines": audit.malformed})

    def decide_tenant_scoped_resource(self, principal: PrincipalSpec, *, grant_tenant: str,
                                      request_tenant: str, resource: str, action: str = "read") -> Receipt:
        kind, name = _split(principal.subject)
        grant = self._permissions.Grant(id=self._permissions.new_grant_id(), subject_kind=kind, subject=name,
                                        resource_kind="table", resource_name=resource, actions=[action],
                                        tenant=grant_tenant)
        plane = self._permissions.PermissionsPlane(_ListView([grant]))
        with capture_audit(KERNEL_LOGGER, plane=self.implementation) as audit:
            decision = plane.authorize(self._identity(principal), "table", resource, action)
        receipt = self._receipt(decision, seam=self.seam("decide_tenant_scoped_resource"),
                                raw_extra={"grant_tenant": grant_tenant, "request_tenant": request_tenant})
        return self._prefer_logged(receipt, audit)

    def decide_resource_tenancy(self, principal: PrincipalSpec, *, owner_tenant: str, resource_tenant: str,
                                capability: str, delegated: bool = False) -> Receipt:
        ec = self._exec_ctx
        resource_id = f"erp.{capability}"
        self._exec_ctx.set_resource_registry(
            ec.SingleTenantResourceRegistry({resource_id: ec.ResourceRef(resource_id, "erp",
                                                                        owning_tenant=resource_tenant)}))
        ec.set_authority_gate(ec.OwnerOnlyAuthority())
        if delegated:
            raise Unsupported(f"{self.implementation}: the Community authority gate is OwnerOnlyAuthority; "
                              "an authorized cross-tenant exception needs the enterprise delegation plane")
        ctx = ec.ExecutionContext(owner_tenant=owner_tenant, actor_principal=principal.subject)
        _node_ctx, _resource, decision = ec.resolve_for_node(ctx, resource_id, capability)
        return Receipt(allowed=bool(decision.allowed), reason=str(decision.reason), decision=None,
                       seam=self.seam("decide_resource_tenancy"),
                       raw={"reason": str(decision.reason), "authority": _node_ctx.authority,
                            "resource_tenant": _node_ctx.resource_tenant, "envelope": "not emitted"})

    # -- queued execution ------------------------------------------------------
    def execute_queued(self, principal: PrincipalSpec, *, capability: str,
                       revoke_before_dispatch: str | None = None) -> ExecutionOutcome:
        ran: list[str] = []
        operator = self._sdk.Operator("authz_contract", [
            self._sdk.capability(capability, lambda inputs: {"ran": capability},
                                 provides=[f"out::{capability}"], permissions=[_permission_for(capability)]),
        ])
        client = self._sdk.LocalOperatorClient({"authz_contract": operator})
        jobs = self._jobs_mod.ReconcileJobs(f"{self._tmp.name}/reconcile.db")
        jobs.enqueue("job-1", mission_id="m-1", node_id="n-1", capability=capability,
                     tenant=principal.tenant, dispatched_at=1.0, first_at=1.0, max_attempts=3, now=1.0)
        if revoke_before_dispatch:
            self.revoke(revoke_before_dispatch)
        claimed = jobs.claim_due("worker-1", now=2.0, limit=10)
        # The tool is checked against the resource its capability demands — the same family-read rule the
        # suite uses everywhere, so a revocation is measured rather than a mapping mismatch.
        authorizer = self._tool_gate(capability, _permission_for(capability), "read")
        receipts: list[Receipt] = []
        with capture_audit(KERNEL_LOGGER, plane=self.implementation) as audit:
            denial = authorizer(self._principal(principal), _Tool(capability), {}) if claimed else "not claimed"
        receipts.extend(Receipt(allowed=r.allowed, reason=r.policy_reason, decision=r, seam=self.seam("execute_queued"),
                                raw=dict(r.to_envelope())) for r in audit.receipts)
        if denial is None:
            client.invoke("authz_contract", capability, {}, "idem-1")
            ran.append(capability)
        else:
            receipts.append(Receipt(allowed=False, reason=str(denial), decision=None,
                                    seam=self.seam("execute_queued"), raw={"gate_reason": str(denial)}))
        return ExecutionOutcome(dispatched=tuple(ran), denied=() if ran else (capability,),
                                state=f"queued:{len(claimed)} claimed", receipts=tuple(receipts),
                                raw={"queue": "agentic_os.mission.reconcile_jobs.ReconcileJobs",
                                     "denied_reason": denial if isinstance(denial, str) else ""})

    # -- epoch -----------------------------------------------------------------
    def freshness_predicate(self, *, write_epoch: int, read_epoch: int) -> bool:
        return bool(self._authzc.cache_entry_is_fresh({"epoch": write_epoch}, current_epoch=read_epoch))

    def serve_cached(self, principal: PrincipalSpec, *, resource: str, action: str = "read",
                     write_epoch: int, read_epoch: int) -> CacheOutcome:
        raise Unsupported(f"{self.implementation}: no authorization decision cache exists to serve from — "
                          "authz_contract.decision_digest and cache_entry_is_fresh are defined but have no "
                          "caller in the kernel, so a stale decision has nothing to be refused by")

    # -- candidate graph -------------------------------------------------------
    def _stage1_grants(self, principal: PrincipalSpec) -> list[str]:
        """The kernel's own stage-1 input (``Mission.policy_refs``), read back out of the grant store: the
        resources this principal holds a read grant on. No scenario hands the kernel a permission list — it
        holds grants, exactly as an operator would have given them."""
        if self._broken:
            return []
        grants, _sealed = self.store.snapshot()
        identity = self._identity(principal)
        return sorted({g.resource_name for g in grants
                       if g.matches(identity) and "read" in (g.actions or [])})

    def _registry(self, scores: dict[str, float], providers: Iterable[tuple[str, str]],
                  grants: Sequence[str]) -> Any:
        """A registry of ``(capability, outcome)`` providers and the kernel's scoped view of it."""
        registry = self._registry_mod.CapabilityRegistry(embedder=_RankEmbedder(scores))
        specs = [self._types.CapabilitySpec(name=name, operator="authz_contract", provides=[outcome],
                                           permissions=[_permission_for(name)])
                 for name, outcome in providers]
        registry.register(self._types.CapabilityManifest(operator="authz_contract", capabilities=specs))
        return registry, self._registry_mod.PolicyScopedRegistry(registry, list(grants))

    def candidates(self, principal: PrincipalSpec, *, need: str, limit: int,
                   authorized: Sequence[str], unauthorized: Sequence[str]) -> CandidateSet:
        scores = {name: 0.90 + 0.005 * i for i, name in enumerate(unauthorized)}
        for i, name in enumerate(authorized):
            scores[name] = 0.01 + 0.001 * i          # every permitted candidate ranks behind every forbidden one
        _base, scoped = self._registry(scores, [(name, f"out::{name}") for name in
                                               list(unauthorized) + list(authorized)],
                                       self._stage1_grants(principal))
        found = scoped.discover(_RankEmbedder.NEED, limit)
        names = tuple(c.name for c, _ in found)
        return CandidateSet(names=names, limit=limit, expected_present=tuple(authorized),
                           forbidden=tuple(unauthorized), seam=self.seam("candidates"),
                           raw={"stage1_grants": self._stage1_grants(principal),
                                "ranked_ahead": list(unauthorized)})

    def run_plan(self, principal: PrincipalSpec, *, steps) -> ExecutionOutcome:
        """Drive a real mission. ``steps`` is ``(outcome, providers)`` per step, providers listed in the
        order an unfiltered planner prefers them — the unauthorized one first, so a plane that does not
        filter is caught executing it."""
        ran: list[str] = []
        grants = self._stage1_grants(principal)
        providers = [(name, outcome) for outcome, names in steps for name in names]
        permitted = [name for name, _o in providers if _permission_for(name) in grants]
        forbidden = [name for name, _o in providers if _permission_for(name) not in grants]
        scores = {name: 0.99 - 0.001 * i for i, name in enumerate(forbidden)}
        scores.update({name: 0.05 + 0.001 * i for i, name in enumerate(permitted)})

        def _handler(name: str):
            def run(inputs: dict) -> dict:
                ran.append(name)
                return {"ran": name}
            return run

        operator = self._sdk.Operator("authz_contract", [
            self._sdk.capability(name, _handler(name), provides=[outcome],
                                 permissions=[_permission_for(name)])
            for name, outcome in providers
        ])
        registry = self._registry_mod.CapabilityRegistry(embedder=_RankEmbedder(scores))
        registry.register(operator.manifest)
        types = self._types

        class _Planner:
            def plan(self, mission_id, goal, ctx):
                planned = [types.IntentStep(outcome=outcome, need=outcome.replace("_", " "), value_hint="high")
                           for outcome, _names in steps]
                return types.ExecutionIntent(mission_id=mission_id, rationale="authz/v1 scenario",
                                             steps=planned)

        executor_mod = import_module(self.implementation, "agentic_os.mission.executor")
        store_mod = import_module(self.implementation, "agentic_os.mission.store")
        client = self._sdk.LocalOperatorClient({"authz_contract": operator})
        runtime = self._runtime_mod.MissionRuntime(registry, executor_mod.Executor(client),
                                                   store=store_mod.EventStore(), planner=_Planner())
        mission = runtime.create_mission("authz/v1 scenario plan", policy_refs=list(grants),
                                         tenant=principal.tenant)
        runtime.run(mission.id)
        state = getattr(mission.state, "value", str(mission.state))
        denied = sorted({name for name, _o in providers} - set(ran))
        timeline = [e.get("type") for e in runtime.repo.timeline(mission.id)]
        receipts = tuple(Receipt(allowed=False, reason=str(e), decision=None, seam=self.seam("run_plan"),
                                 raw={"event": str(e)}) for e in timeline if e and "Denied" in str(e))
        return ExecutionOutcome(dispatched=tuple(ran), denied=tuple(denied), state=str(state),
                                receipts=receipts,
                                raw={"timeline": timeline, "stage1_grants": grants,
                                     "unauthorized_providers": forbidden,
                                     "scoping": "Mission.policy_refs → PolicyScopedRegistry"})

    # -- fault injection -------------------------------------------------------
    def break_authority_backend(self) -> None:
        """Make the grant store unreadable — the real fail-closed trigger, not a stubbed check."""
        self._broken = True

        def _boom() -> tuple:
            raise RuntimeError("grants store backend is unavailable (injected authority failure)")

        self.store.snapshot = _boom     # type: ignore[method-assign]


class _ListView:
    """A store-shaped view of hand-built grants (``PermissionsPlane`` reads any object with ``snapshot()``)."""

    def __init__(self, grants: Sequence[Any]) -> None:
        self._grants = list(grants)
        self.sealed = False

    def snapshot(self) -> tuple:
        return list(self._grants), self.sealed