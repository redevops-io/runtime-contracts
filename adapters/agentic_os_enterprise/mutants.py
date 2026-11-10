"""Deliberately-broken overlay variants. Nothing here is a product claim.

Most of these restore behaviour the overlay had before E-2, which is the point: a mutation that a green
suite does not catch means the suite is measuring something other than enforcement. Each mutant names the
invariant it must break, and ``adapters/agentic_os_enterprise/test_negative_controls``-style checks in
``tests/authz_contract/`` require that it does.
"""
from __future__ import annotations

from typing import Sequence

from adapters._reference import error_denial_receipt
from runtime_contracts.authz.suite import (CacheOutcome, CandidateSet, ExecutionOutcome, PrincipalSpec,
                                           Receipt)

from .adapter import EnterpriseAuthzAdapter, _RankEmbedder, _permission_for


def _bypass_plane(identity_mod, *, scoped_all: bool):
    """The overlay's pre-E-2 ``IdentityPlane``: role membership is authority."""

    class _RoleBypassPlane(identity_mod.IdentityPlane):
        def authorize(self, principal, capability, required=(), *, action="invoke", context=None):
            if any(r in {"admin"} for r in principal.roles):
                return identity_mod.AccessDecision(True, "allow: privileged role (bypass)")
            return super().authorize(principal, capability, required, action=action, context=context)

        def scoped_permissions(self, principal, context=None):
            if scoped_all and any(r in {"admin"} for r in principal.roles):
                return {"*"}
            return super().scoped_permissions(principal, context)

    return _RoleBypassPlane


class EnterpriseRoleBypassMutant(EnterpriseAuthzAdapter):
    """Role name alone authorizes — the pre-E-2 bypass, restored at the capability plane."""

    variant = "bad_role_bypass"
    breaks = "no_privilege_laundering"

    def build(self) -> None:
        super().build()
        self.plane = _bypass_plane(self._identity_mod, scoped_all=False)(
            permissions_plane=self.permissions, ledger=self.ledger)


class EnterpriseScopedAllMutant(EnterpriseAuthzAdapter):
    """Stage-1 scoping hands an ``admin`` ``{"*"}``: every forbidden capability becomes a candidate and a
    dispatchable node. This is the pre-E-2 ``scoped_permissions`` behaviour."""

    variant = "bad_scoped_all"
    breaks = "permitted_edges_survive"

    def build(self) -> None:
        super().build()
        self.plane = _bypass_plane(self._identity_mod, scoped_all=True)(
            permissions_plane=self.permissions, ledger=self.ledger)
        # The mutant's principal carries the role, exactly as a federated token would.
        self._admin_roles = ("admin",)

    def _principal(self, spec: PrincipalSpec):
        base = super()._principal(spec)
        roles = sorted(set(base.roles) | set(self._admin_roles))
        return self._identity_mod.Principal(kind=base.kind, id=base.id, roles=roles, tenant=base.tenant,
                                           attributes=base.attributes)


class EnterpriseTenantBlindMutant(EnterpriseAuthzAdapter):
    """Drops the tenant-isolation gate. Everything else is the real plane."""

    variant = "bad_tenant_blind"
    breaks = "cross_tenant_denied"

    def build(self) -> None:
        super().build()

        class _TenantBlindPlane(self._identity_mod.IdentityPlane):
            def _tenant_ok(self, principal, context):
                return True, ""

        self.plane = _TenantBlindPlane(permissions_plane=self.permissions, ledger=self.ledger)


class EnterpriseRevokeIgnoredMutant(EnterpriseAuthzAdapter):
    """Reports a revocation as accepted while leaving the grant in place."""

    variant = "bad_revoke_ignored"
    breaks = "revocation_during_queue"

    def build(self) -> None:
        super().build()

        class _NoRevokePlane(self._identity_mod.IdentityPlane):
            def revoke_rule(self, rule_id_):
                self.ledger.append(principal="*", tenant="*", capability=f"grant:{rule_id_}", action="revoke",
                                   allowed=True, reason=f"grant {rule_id_} revoked")
                return True        # the paperwork says revoked; the rule is still in self._rules

        self.plane = _NoRevokePlane(permissions_plane=self.permissions, ledger=self.ledger)


class EnterpriseFailOpenGateMutant(EnterpriseAuthzAdapter):
    """An authority outage degrades into a broad read instead of a refusal."""

    variant = "bad_fail_open_on_error"
    breaks = "adapter_error_fails_closed"

    def decide_resource(self, principal: PrincipalSpec, *, resource: str, action: str = "read",
                        request_tenant: str | None = None) -> Receipt:
        # The defect is placed at the call into the real plane, above nothing the adapter already handles:
        # an authority outage is read as "no policy said no".
        try:
            decision = self.plane.authorize_resource(self._principal(principal), "table", resource, action,
                                                    context={"tenant": request_tenant} if request_tenant else {})
        except Exception:  # noqa: BLE001 — the defect
            return Receipt(allowed=True, reason="authority backend unavailable — proceeding", decision=None,
                           seam=f"{self.seam('decide_resource')} + fail-open")
        return self._receipt(decision, seam=self.seam("decide_resource"))


class EnterpriseEpochBlindCache(EnterpriseAuthzAdapter):
    """A decision cache with an epoch field that is written and never compared."""

    variant = "bad_epoch_blind_cache"
    breaks = "stale_epoch_refusal"

    def __init__(self) -> None:
        super().__init__()
        self._cache: dict[str, dict] = {}

    def freshness_predicate(self, *, write_epoch: int, read_epoch: int) -> bool:
        return True      # the defect: every entry is fresh, whatever its epoch

    def serve_cached(self, principal: PrincipalSpec, *, resource: str, action: str = "read",
                     write_epoch: int, read_epoch: int) -> CacheOutcome:
        key = f"{principal.subject}|{resource}|{action}"
        entry = self._cache.get(key)
        if entry is None:
            decision = self.plane.authorize_resource(self._principal(principal), "table", resource, action)
            entry = {"epoch": write_epoch, "allowed": bool(decision.allowed)}
            self._cache[key] = entry
        return CacheOutcome(served=entry["allowed"], implementation_says_fresh=True,
                            seam=f"{self.implementation}.mutant.cache",
                            raw={"entry_epoch": entry["epoch"], "current_epoch": read_epoch})


class EnterpriseReferenceEpochHonoringCache(EnterpriseAuthzAdapter):
    """Reference: an overlay cache keyed by an epoch the overlay does not currently carry.

    The overlay has no authorization epoch anywhere, so the epoch comparison is written here in the simplest
    honest form (an entry is fresh while the epoch has not moved). It shows the criterion is satisfiable at
    the overlay's own seam — the decision to re-evaluate on every call — and that E-3 for this edition is
    about carrying (tenant, epoch) on the rule and bumping it on revoke, not about inventing a mechanism.
    """

    variant = "reference_epoch_honoring_cache"
    demonstrates = "stale_epoch_refusal"

    def __init__(self) -> None:
        super().__init__()
        self._cache: dict[str, dict] = {}

    def freshness_predicate(self, *, write_epoch: int, read_epoch: int) -> bool:
        return int(write_epoch) == int(read_epoch)

    def serve_cached(self, principal: PrincipalSpec, *, resource: str, action: str = "read",
                     write_epoch: int, read_epoch: int) -> CacheOutcome:
        key = f"{principal.subject}|{resource}|{action}"
        entry = self._cache.get(key)
        if entry is None:
            decision = self.plane.authorize_resource(self._principal(principal), "table", resource, action)
            entry = {"epoch": write_epoch, "allowed": bool(decision.allowed)}
            self._cache[key] = entry
        fresh = self.freshness_predicate(write_epoch=entry["epoch"], read_epoch=read_epoch)
        return CacheOutcome(served=bool(entry["allowed"]) and fresh, implementation_says_fresh=fresh,
                            seam=f"{self.seam('serve_cached')} (reference)",
                            raw={"entry_epoch": entry["epoch"], "current_epoch": read_epoch})


class EnterpriseReferenceDeniedWithReceipt(EnterpriseAuthzAdapter):
    """Reference: the outage is returned as a denied, enveloped decision instead of raising past the ledger.

    Same caveat as the kernel's reference variant: the envelope is built in the harness (E-6 is the ticket
    that puts it inside ``IdentityPlane.authorize_resource``). The failure itself is the real one — the
    injected store outage under the shipped plane.
    """

    variant = "reference_error_denied_with_receipt"
    demonstrates = "adapter_error_fails_closed"

    def decide_resource(self, principal: PrincipalSpec, *, resource: str, action: str = "read",
                        request_tenant: str | None = None) -> Receipt:
        receipt = super().decide_resource(principal, resource=resource, action=action,
                                          request_tenant=request_tenant)
        if receipt.allowed or receipt.enveloped:
            return receipt
        return error_denial_receipt(self.implementation, principal, resource=resource, action=action,
                                    outage=receipt.reason or "authority backend failure",
                                    seam=f"{receipt.seam} (reference)")


class EnterpriseReferenceFilterBeforeLimit(EnterpriseAuthzAdapter):
    """Reference: scope the candidate set to what is permitted, then apply the limit.

    The overlay reaches the over-fetching ``PolicyScopedRegistry`` through ``MissionRuntime._scoped``, so the
    fix has to be applied at the overlay's own seam too — a kernel-side fix does not, on its own, make this
    cell true. Ranked here by the overlay's permissions, then cut.
    """

    variant = "reference_filter_before_limit"
    demonstrates = "authorization_before_limit"

    def candidates(self, principal: PrincipalSpec, *, need: str, limit: int,
                   authorized: Sequence[str], unauthorized: Sequence[str]) -> CandidateSet:
        scores = {name: 0.90 + 0.005 * i for i, name in enumerate(unauthorized)}
        for i, name in enumerate(authorized):
            scores[name] = 0.01 + 0.001 * i
        registry = self._registry_mod.CapabilityRegistry(embedder=_RankEmbedder(scores))
        caps = [self._types.CapabilitySpec(name=name, operator="authz_contract",
                                           provides=[f"out::{name}"],
                                           permissions=[f"{name.split('.', 1)[0]}.read"])
                for name in list(unauthorized) + list(authorized)]
        registry.register(self._types.CapabilityManifest(operator="authz_contract", capabilities=caps))
        grants = self.plane.scoped_permissions(self._principal(principal),
                                               {"tenant": principal.tenant or "acme"})
        ranked = registry.discover(_RankEmbedder.NEED, len(scores))            # rank everything…
        permitted = [(c, s) for c, s in ranked
                     if all(p in grants for p in c.permissions)]              # …then cut
        return CandidateSet(names=tuple(c.name for c, _ in permitted[:limit]), limit=limit,
                            expected_present=tuple(authorized), forbidden=tuple(unauthorized),
                            seam="reference: filter before limit", raw={"grants": sorted(grants)})


MUTANTS = (EnterpriseRoleBypassMutant, EnterpriseScopedAllMutant, EnterpriseTenantBlindMutant,
           EnterpriseRevokeIgnoredMutant, EnterpriseFailOpenGateMutant, EnterpriseEpochBlindCache,
           EnterpriseReferenceEpochHonoringCache, EnterpriseReferenceDeniedWithReceipt,
           EnterpriseReferenceFilterBeforeLimit)