"""Deliberately-broken kernel variants. Nothing here is a product claim.

A green invariant test proves nothing unless something can make it red. Each mutant below re-introduces one
specific defect into the real kernel code path — usually by restoring behaviour the kernel used to have — and
the negative-control suite requires that its named invariant fails against it. Two directions are covered:

``bad_*``
    a known-bad implementation that MUST fail its invariant.
``reference_*``
    a corrected implementation the current product does not have, used only to show the criterion is
    satisfiable and the assertion is not vacuous. A reference passing is never reported as product progress;
    the qualification matrix keeps it in a separate column.
"""
from __future__ import annotations

from typing import Any, Sequence

from adapters._reference import error_denial_receipt
from runtime_contracts.authz.suite import (CacheOutcome, CandidateSet, ExecutionOutcome, PrincipalSpec,
                                           Receipt, Unsupported)

from .adapter import KernelAuthzAdapter, _ListView, _RankEmbedder, _Tool, _permission_for


def _pre_e2_plane(permissions_mod, store):
    """The kernel's pre-E-2 ``PermissionsPlane``: a role name in the identity short-circuits to full access."""

    class _RoleBypassPlane(permissions_mod.PermissionsPlane):
        def authorize(self, identity, resource_kind, resource_name, action="read"):
            if any(r in {"admin"} for r in (identity.roles or [])):
                return permissions_mod.AccessDecision(True, "privileged role — full access (bypass)")
            return super().authorize(identity, resource_kind, resource_name, action)

    return _RoleBypassPlane(store)


class KernelRoleBypassMutant(KernelAuthzAdapter):
    """Restores the implicit privileged-role bypass the kernel removed in E-2."""

    variant = "bad_role_bypass"
    breaks = "no_privilege_laundering"

    def build(self) -> None:
        super().build()
        self.plane = _pre_e2_plane(self._permissions, self.store)

    def decide_capability(self, principal: PrincipalSpec, *, capability: str,
                          permissions: Sequence[str] = (), request_tenant: str | None = None) -> Receipt:
        if any(r == "admin" for r in principal.roles):
            decision = self._permissions.AccessDecision(True, "privileged role — full access (bypass)")
            return self._receipt(decision, seam=f"{self.seam('decide_capability')} + role bypass")
        return super().decide_capability(principal, capability=capability, permissions=permissions,
                                         request_tenant=request_tenant)


class KernelDecisionCachedAtEnqueue(KernelAuthzAdapter):
    """Authorizes when work is queued and reuses that answer at dispatch — the classic revocation hole."""

    variant = "bad_cached_decision_at_enqueue"
    breaks = "revocation_during_queue"

    def execute_queued(self, principal: PrincipalSpec, *, capability: str,
                       revoke_before_dispatch: str | None = None) -> ExecutionOutcome:
        base = super().execute_queued(principal, capability=capability, revoke_before_dispatch=None)
        cached = base.receipts                                     # the answer taken while the grant still held
        if revoke_before_dispatch:
            self.revoke(revoke_before_dispatch)
        ran: list[str] = []
        operator = self._sdk.Operator("authz_contract", [
            self._sdk.capability(capability, self._recorder(ran, capability), provides=[f"out::{capability}"],
                                 permissions=[_permission_for(capability)])])
        client = self._sdk.LocalOperatorClient({"authz_contract": operator})
        client.invoke("authz_contract", capability, {}, "idem-1")   # dispatched on the cached answer
        return ExecutionOutcome(dispatched=tuple(ran), denied=(), state="dispatched on cached decision",
                                receipts=cached, raw={"cache": "decision taken at enqueue, reused at dispatch"})

    @staticmethod
    def _recorder(ran: list[str], capability: str = ""):
        def run(inputs: dict) -> dict:
            ran.append(capability or "dispatched")
            return {}
        return run


class KernelFailOpenOnBackendError(KernelAuthzAdapter):
    """Swallows an authority-store failure and serves the request anyway — a silent degradation to a broad read."""

    variant = "bad_fail_open_on_error"
    breaks = "adapter_error_fails_closed"

    def decide_resource(self, principal: PrincipalSpec, *, resource: str, action: str = "read",
                        request_tenant: str | None = None) -> Receipt:
        # The defect sits at the call into the real plane — not above the adapter's own error handling — so
        # an outage is read as "nothing said no" and the request is served.
        try:
            decision = self.plane.authorize(self._identity(principal), "table", resource, action)
        except Exception:  # noqa: BLE001 — the defect
            return Receipt(allowed=True, reason="authority backend unavailable — proceeding", decision=None,
                           seam=f"{self.seam('decide_resource')} + fail-open")
        return self._receipt(decision, seam=self.seam("decide_resource"))

    def break_authority_backend(self) -> None:
        def _boom() -> tuple:
            raise RuntimeError("grants store backend is unavailable (injected authority failure)")
        self.store.snapshot = _boom     # type: ignore[method-assign]
        self._broken = True


class KernelEpochBlindCache(KernelAuthzAdapter):
    """An authorization cache that never consults the epoch — the shape the epoch criterion exists to catch."""

    variant = "bad_epoch_blind_cache"
    breaks = "stale_epoch_refusal"

    def __init__(self) -> None:
        super().__init__()
        self._cache: dict[str, dict[str, Any]] = {}

    def serve_cached(self, principal: PrincipalSpec, *, resource: str, action: str = "read",
                     write_epoch: int, read_epoch: int) -> CacheOutcome:
        key = f"{principal.subject}|{resource}|{action}"
        entry = self._cache.get(key)
        if entry is None:
            decision = self.plane.authorize(self._identity(principal), "table", resource, action)
            entry = {"epoch": write_epoch, "allowed": bool(decision.allowed)}
            self._cache[key] = entry
        return CacheOutcome(served=entry["allowed"], implementation_says_fresh=None,
                            seam=f"{self.implementation}.mutant.cache",
                            raw={"entry_epoch": entry["epoch"], "current_epoch": read_epoch,
                                 "consulted": "agentic_os.authz_contract.cache_entry_is_fresh (never)"})


class KernelUnscopedCandidates(KernelAuthzAdapter):
    """Stage-1 scoping that hands the planner ``*`` — every forbidden capability becomes a candidate."""

    variant = "bad_unscoped_candidates"
    breaks = "authorization_before_limit"

    def candidates(self, principal: PrincipalSpec, *, need: str, limit: int,
                   authorized: Sequence[str], unauthorized: Sequence[str]) -> CandidateSet:
        scores = {name: 0.90 + 0.005 * i for i, name in enumerate(unauthorized)}
        for i, name in enumerate(authorized):
            scores[name] = 0.01 + 0.001 * i
        registry = self._registry_mod.CapabilityRegistry(embedder=_RankEmbedder(scores))
        specs = [self._types.CapabilitySpec(name=n, operator="authz_contract", provides=[f"out::{n}"],
                                           permissions=[_permission_for(n)])
                 for n in list(unauthorized) + list(authorized)]
        registry.register(self._types.CapabilityManifest(operator="authz_contract", capabilities=specs))
        found = self._registry_mod.PolicyScopedRegistry(registry, ["*"]).discover(_RankEmbedder.NEED, limit)
        return CandidateSet(names=tuple(c.name for c, _ in found), limit=limit,
                           expected_present=tuple(authorized), forbidden=tuple(unauthorized),
                           seam=f"{self.seam('candidates')} + wildcard grants", raw={"grants": ["*"]})


class KernelReferenceTenantBoundGrants(KernelAuthzAdapter):
    """Reference: a tenant-tagged grant binds to its tenant. The shipped kernel does not do this."""

    variant = "reference_tenant_bound_grants"
    demonstrates = "cross_tenant_denied"

    def decide_tenant_scoped_resource(self, principal: PrincipalSpec, *, grant_tenant: str,
                                      request_tenant: str, resource: str, action: str = "read") -> Receipt:
        kind, name = _split_subject(principal.subject)
        grant = self._permissions.Grant(id=self._permissions.new_grant_id(), subject_kind=kind, subject=name,
                                        resource_kind="table", resource_name=resource, actions=[action],
                                        tenant=grant_tenant)
        plane = _TenantBoundPlane(self._permissions, _ListView([grant]))
        decision = plane.authorize(self._identity(principal), "table", resource, action,
                                   request_tenant=request_tenant)
        return self._receipt(decision, seam="reference: tenant-bound grant check")


class KernelReferenceFilterBeforeLimit(KernelAuthzAdapter):
    """Reference: filter to what is permitted, THEN apply the limit. Satisfies the criterion the kernel misses."""

    variant = "reference_filter_before_limit"
    demonstrates = "authorization_before_limit"

    def candidates(self, principal: PrincipalSpec, *, need: str, limit: int,
                   authorized: Sequence[str], unauthorized: Sequence[str]) -> CandidateSet:
        from .adapter import _permission_for as perm
        scores = {name: 0.90 + 0.005 * i for i, name in enumerate(unauthorized)}
        for i, name in enumerate(authorized):
            scores[name] = 0.01 + 0.001 * i
        registry = self._registry_mod.CapabilityRegistry(embedder=_RankEmbedder(scores))
        specs = [self._types.CapabilitySpec(name=n, operator="authz_contract", provides=[f"out::{n}"],
                                           permissions=[perm(n)])
                 for n in list(unauthorized) + list(authorized)]
        registry.register(self._types.CapabilityManifest(operator="authz_contract", capabilities=specs))
        grants = set(self._stage1_grants(principal))
        ranked = registry.discover(_RankEmbedder.NEED, len(scores))              # rank everything…
        permitted = [(c, s) for c, s in ranked if all(p in grants for p in c.permissions)]
        return CandidateSet(names=tuple(c.name for c, _ in permitted[:limit]), limit=limit,  # …then cut…
                           expected_present=tuple(authorized), forbidden=tuple(unauthorized),
                           seam="reference: filter before limit", raw={"grants": sorted(grants)})


class _TenantBoundPlane:
    def __init__(self, permissions_mod, view) -> None:
        self._mod = permissions_mod
        self._plane = permissions_mod.PermissionsPlane(view)

    def authorize(self, identity, resource_kind, resource_name, action="read", *, request_tenant=""):
        decision = self._plane.authorize(identity, resource_kind, resource_name, action)
        if decision.allowed and request_tenant:
            return self._mod.AccessDecision(False, f"denied: no '{action}' grant for tenant "
                                                   f"'{request_tenant}' on {resource_kind} '{resource_name}'")
        return decision


def _split_subject(subject: str) -> tuple[str, str]:
    kind, _, name = subject.partition(":")
    return ("app" if kind in ("app", "service", "workload") else "user"), name


class KernelReferenceEpochHonoringCache(KernelAuthzAdapter):
    """Reference: a decision cache that keys on the epoch and refuses a stale entry.

    The kernel already ships both halves — ``authz_contract.decision_digest`` and
    ``cache_entry_is_fresh`` — and calls neither. This variant supplies the missing half (the cache) and
    reads every entry through the kernel's own predicate, so the criterion is exercised through the kernel's
    code rather than the harness's. The point is narrow: E-3 is a wiring ticket, not an impossible request.
    """

    variant = "reference_epoch_honoring_cache"
    demonstrates = "stale_epoch_refusal"

    def __init__(self) -> None:
        super().__init__()
        self._cache: dict[str, dict[str, Any]] = {}

    def serve_cached(self, principal: PrincipalSpec, *, resource: str, action: str = "read",
                     write_epoch: int, read_epoch: int) -> CacheOutcome:
        key = f"{principal.subject}|{resource}|{action}"
        entry = self._cache.get(key)
        if entry is None:
            decision = self.plane.authorize(self._identity(principal), "table", resource, action)
            entry = {"epoch": write_epoch, "allowed": bool(decision.allowed)}
            self._cache[key] = entry
        fresh = bool(self._authzc.cache_entry_is_fresh({"epoch": entry["epoch"]}, current_epoch=read_epoch))
        return CacheOutcome(served=bool(entry["allowed"]) and fresh, implementation_says_fresh=fresh,
                            seam=f"{self.seam('serve_cached')} (reference)",
                            raw={"entry_epoch": entry["epoch"], "current_epoch": read_epoch,
                                 "consulted": "agentic_os.authz_contract.cache_entry_is_fresh"})


class KernelReferenceDeniedWithReceipt(KernelAuthzAdapter):
    """Reference: an authority outage that answers with a denial and an envelope, not a bare exception.

    The real plane's behaviour is unchanged up to the failure: the grant, the store break and the call all
    go through the shipped code. Only the shape of the answer differs, and it is built by the harness — see
    :mod:`adapters._reference`. This is the E-6 target, not E-2 output.
    """

    variant = "reference_error_denied_with_receipt"
    demonstrates = "adapter_error_fails_closed"

    def decide_resource(self, principal: PrincipalSpec, *, resource: str, action: str = "read",
                        request_tenant: str | None = None) -> Receipt:
        receipt = super().decide_resource(principal, resource=resource, action=action,
                                          request_tenant=request_tenant)
        if receipt.allowed or receipt.enveloped:
            return receipt                       # the shipped shape already satisfies the criterion here
        return error_denial_receipt(self.implementation, principal, resource=resource, action=action,
                                    outage=receipt.reason or "authority backend failure",
                                    seam=f"{receipt.seam} (reference)")


MUTANTS = (KernelRoleBypassMutant, KernelDecisionCachedAtEnqueue, KernelFailOpenOnBackendError,
           KernelEpochBlindCache, KernelUnscopedCandidates, KernelReferenceTenantBoundGrants,
           KernelReferenceFilterBeforeLimit, KernelReferenceEpochHonoringCache,
           KernelReferenceDeniedWithReceipt)