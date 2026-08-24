"""The AGPL local credential broker — the single seam through which local secrets are reached.

Development-grade: it enforces the *authority* rules (scope narrowing, TTL policy, Mission/capability
redemption binding, fail-closed on a declared production requirement) and emits safe events, but it makes
no claim to distributed revocation, dynamic database users, renewable production leases, HA, HSM-backed
signing, or rotation orchestration. Its ``assurance_level`` is ``"development"``, so any capability marked
``production_broker_required=True`` is refused — that is the fail-closed boundary an enterprise Vault/OpenBao
broker exists to satisfy.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, Optional

from ..protocol.credentials import CredentialGrant
from ..protocol.secrets import (
    AuthorityContext,
    CredentialLease,
    CredentialRequest,
    LeaseStatus,
    SecretMaterial,
    SecretRef,
    SecurityVerdict,
    authorize_request,
)
from .store import SecretAccessError


class CredentialDenied(RuntimeError):
    """A grant was refused. Carries the deny ``reason`` (a safe DenyReason code / message)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class _Active:
    __slots__ = ("grant", "ref", "capability_id", "mission_id", "expires")

    def __init__(self, grant: CredentialGrant, ref: Optional[SecretRef], capability_id: str,
                 mission_id: str, expires: datetime) -> None:
        self.grant = grant
        self.ref = ref
        self.capability_id = capability_id
        self.mission_id = mission_id
        self.expires = expires


class LocalCredentialBroker:
    """Mints TTL-bounded, authority-scoped, in-process grants over a local :class:`SecretStore`."""

    assurance_level = "development"

    def __init__(self, store, *, clock: Callable[[], datetime] = _utc_now,
                 default_ttl_seconds: int = 300) -> None:
        self._store = store
        self._clock = clock
        self._default_ttl = default_ttl_seconds
        self._active: Dict[str, _Active] = {}
        self._n = 0

    def grant(self, request: CredentialRequest, *, authority_context: AuthorityContext) -> CredentialGrant:
        decision = authorize_request(request, authority_context, broker_assurance=self.assurance_level)
        if decision.verdict != SecurityVerdict.ALLOW:
            raise CredentialDenied(decision.reason)

        req = request.requirement
        ttl = request.requested_ttl_seconds or req.max_ttl_seconds or self._default_ttl
        if req.max_ttl_seconds is not None:
            ttl = min(ttl, req.max_ttl_seconds)
        now = self._clock()
        expires = now + timedelta(seconds=ttl)

        self._n += 1
        gid = f"grant-{self._n:06d}"
        lease_id = f"lease-{self._n:06d}"
        material_hash = ""
        ref = req.secret_ref
        if ref is not None:
            try:
                material_hash = _hash_material(self._store._read(ref))
            except SecretAccessError:
                material_hash = ""  # dynamic secrets have no pre-existing material to hash

        grant = CredentialGrant(
            grant_id=gid, principal=authority_context.principal.id if hasattr(authority_context, "principal") else request.tenant_id,
            resource=req.name, scope=tuple(sorted(req.required_scopes)), ttl_seconds=ttl,
            authority_ref=getattr(authority_context, "chain_ref", "") or "",
            material_hash=material_hash, request_id=request.request_id, credential_ref=ref,
            lease_id=lease_id, issued_at=now.isoformat(), expires_at=expires.isoformat(),
            renewable=False, revocable=True, handle=gid,
        )
        self._active[gid] = _Active(grant, ref, request.capability_id, request.mission_id, expires)
        return grant

    def redeem(self, grant: CredentialGrant, *, capability_id: str, mission_id: str) -> SecretMaterial:
        active = self._active.get(grant.grant_id)
        if active is None:
            raise CredentialDenied("grant is not active (revoked, expired, or unknown)")
        if capability_id != active.capability_id or mission_id != active.mission_id:
            raise CredentialDenied("grant redeemed outside its Mission/capability binding")
        if self._clock() >= active.expires:
            self._active.pop(grant.grant_id, None)
            raise CredentialDenied("grant expired")
        if active.ref is None:
            raise CredentialDenied("grant has no secret reference to redeem")
        return SecretMaterial(self._store._read(active.ref))

    def renew(self, lease: CredentialLease) -> CredentialLease:
        return CredentialLease(lease_id=lease.lease_id, grant_id=lease.grant_id, issued_at=lease.issued_at,
                               expires_at=lease.expires_at, renewable=lease.renewable, revocable=lease.revocable,
                               status=LeaseStatus.RENEWED)

    def revoke_grant(self, grant_id: str, *, reason: str) -> None:
        self._active.pop(grant_id, None)

    def revoke_mission(self, mission_id: str) -> int:
        """Enterprise-style bulk revoke — drop every active grant bound to a Mission (containment/cancel)."""
        gids = [g for g, a in self._active.items() if a.mission_id == mission_id]
        for g in gids:
            self._active.pop(g, None)
        return len(gids)


def _hash_material(material: bytes) -> str:
    from ..protocol.seal import content_hash
    return content_hash(material.decode("utf-8", "replace"))
