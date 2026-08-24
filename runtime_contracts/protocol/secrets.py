"""Secret references, credential requirements/requests/leases, safe material, and the broker seams.

The open contract layer for **authority-scoped credential brokerage** — the runtime-native model that keeps
the *secret itself* out of plans, context, telemetry, replay and the Evidence Lakehouse, while recording
that authority to use a credential was granted and exercised. Vault / OpenBao / cloud secret managers are
*implementations* of these seams (enterprise), never dependencies of the runtime.

Canonical rules (they mirror the existing credential/redaction contract in ``credentials.py``):

  * **A secret is never context.** What travels is a :class:`SecretRef` (a *reference*: provider + path +
    version) and a :class:`CredentialGrant` (scope + authority + a hash of the material) — never bytes.
  * **Authority only narrows.** A grant's scope must be covered by the Mission's ``AuthorityContext`` and the
    capability's declared requirement and the backend policy — the intersection, never a widening.
  * **Material is redeemed only at the capability boundary**, into :class:`SecretMaterial` that is
    deliberately hard to serialize and is destroyed after use.
  * **Fail closed where authority is declared.** A capability that declares it needs a production broker, and
    finds none wired, does not run.

Identity follows the package rule (``canonical.py``): a reference *is* its content, so its descriptive
fields participate in its hash; live redemption tokens (broker handles) never enter any canonical form.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Protocol, Tuple, runtime_checkable

from .seal import content_hash
from .security import AuthorityContext, SecurityDecision, SecurityVerdict


# ── secret reference & descriptor ────────────────────────────────────────────────────────────────────

#: Classifications that mark a secret as production-grade credential material.
SECRET_CLASSIFICATIONS = frozenset({
    "credential", "private-key", "database-password", "api-token",
    "signing-key", "tls-key", "oauth-client-secret",
})


@dataclass(frozen=True)
class SecretRef:
    """A reference to a secret's *location and version*, never its value. ``fingerprint()`` is the stable,
    non-reversible identity persisted in evidence; the raw ``path`` is redacted from broad telemetry."""

    provider: str                       # env | file | vault | openbao | aws-secretsmanager | …
    namespace: str = ""                 # tenant/namespace scope (validated against the Mission tenant)
    path: str = ""
    key: Optional[str] = None
    version: Optional[str] = None

    def canonical_form(self) -> Dict[str, Any]:
        return {
            "key": self.key or None,
            "namespace": self.namespace or None,
            "path": self.path,
            "provider": self.provider,
            "version": self.version or None,
        }

    def fingerprint(self) -> str:
        """The ``rcv1:`` hash of the reference — safe to persist and correlate; discloses no secret."""
        return content_hash(self.canonical_form())

    def redacted(self) -> Dict[str, Any]:
        """Telemetry-safe view: provider + namespace + fingerprint, with the raw path withheld."""
        return {"provider": self.provider, "namespace": self.namespace or None,
                "version": self.version or None, "fingerprint": self.fingerprint()}


@dataclass(frozen=True)
class SecretDescriptor:
    """Lifecycle metadata about a secret — classifications, scopes it may grant, renew/rotate/dynamic
    flags — returned by a store's ``describe()``. Never carries the value."""

    ref: SecretRef
    classifications: Tuple[str, ...] = ()
    scopes: Tuple[str, ...] = ()
    renewable: bool = False
    rotatable: bool = False
    dynamic: bool = False
    expires_at: Optional[str] = None
    metadata: Tuple[Tuple[str, str], ...] = ()

    def canonical_form(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"ref": self.ref.canonical_form(), "dynamic": self.dynamic,
                             "renewable": self.renewable, "rotatable": self.rotatable}
        if self.classifications:
            d["classifications"] = sorted(self.classifications)
        if self.scopes:
            d["scopes"] = sorted(self.scopes)
        if self.expires_at:
            d["expires_at"] = self.expires_at
        if self.metadata:
            d["metadata"] = sorted((k, v) for k, v in self.metadata)
        return d


# ── capability requirement / request ─────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class CredentialRequirement:
    """What a capability declares it needs. ``production_broker_required=True`` means a development broker
    must refuse it (fail closed). ``required_scopes`` must be covered by the Mission authority."""

    name: str
    required_scopes: Tuple[str, ...] = ()
    secret_ref: Optional[SecretRef] = None
    dynamic_role: Optional[str] = None
    production_broker_required: bool = False
    max_ttl_seconds: Optional[int] = None

    def canonical_form(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"name": self.name, "production_broker_required": self.production_broker_required}
        if self.required_scopes:
            d["required_scopes"] = sorted(self.required_scopes)
        if self.secret_ref is not None:
            d["secret_ref"] = self.secret_ref.canonical_form()
        if self.dynamic_role:
            d["dynamic_role"] = self.dynamic_role
        if self.max_ttl_seconds is not None:
            d["max_ttl_seconds"] = self.max_ttl_seconds
        return d

    def requirement_hash(self) -> str:
        return content_hash(self.canonical_form())


@dataclass(frozen=True)
class CredentialRequest:
    """A concrete ask, bound to the Mission/node/capability/authority that justifies it."""

    request_id: str
    mission_id: str
    node_id: str
    capability_id: str
    tenant_id: str
    authority_context_id: str
    requirement: CredentialRequirement
    requested_ttl_seconds: Optional[int] = None

    def canonical_form(self) -> Dict[str, Any]:
        d = {"authority_context_id": self.authority_context_id, "capability_id": self.capability_id,
             "mission_id": self.mission_id, "node_id": self.node_id, "request_id": self.request_id,
             "requirement": self.requirement.canonical_form(), "tenant_id": self.tenant_id}
        if self.requested_ttl_seconds is not None:
            d["requested_ttl_seconds"] = self.requested_ttl_seconds
        return d


# ── lease ────────────────────────────────────────────────────────────────────────────────────────────

class LeaseStatus:
    ACTIVE = "ACTIVE"
    RENEWED = "RENEWED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    FAILED = "FAILED"


@dataclass(frozen=True)
class CredentialLease:
    """The lease side of a grant — its renewable/revocable lifecycle and current status."""

    lease_id: str
    grant_id: str
    issued_at: str = ""
    expires_at: str = ""
    renewable: bool = False
    revocable: bool = True
    status: str = LeaseStatus.ACTIVE

    def canonical_form(self) -> Dict[str, Any]:
        return {"expires_at": self.expires_at or None, "grant_id": self.grant_id,
                "issued_at": self.issued_at or None, "lease_id": self.lease_id,
                "renewable": self.renewable, "revocable": self.revocable, "status": self.status}


# ── safe material ──────────────────────────────────────────────────────────────────────────────────────

class SecretMaterial:
    """Raw secret bytes, deliberately hard to serialize or log. Not a dataclass; has no ``canonical_form``,
    so the canonical serializer *rejects* it — a secret can never enter a fingerprint, plan, event or the
    lakehouse. Python cannot guarantee memory erasure; this shortens material lifetime and blocks the easy
    accidents (repr/str/json)."""

    __slots__ = ("_value", "_closed")

    def __init__(self, value: bytes) -> None:
        self._value = bytearray(value)
        self._closed = False

    def bytes(self) -> bytes:
        if self._closed:
            raise RuntimeError("secret material already destroyed")
        return bytes(self._value)

    def destroy(self) -> None:
        for i in range(len(self._value)):
            self._value[i] = 0
        self._closed = True

    def __repr__(self) -> str:
        return "<SecretMaterial redacted>"

    def __str__(self) -> str:
        return "<redacted>"

    def __enter__(self) -> "SecretMaterial":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.destroy()


# ── protocol seams (structural typing; implementations are injected, never imported) ───────────────────

@runtime_checkable
class SecretStore(Protocol):
    """Secret identity + lifecycle. Managing a secret's location/version/rotation — never bulk-reading it
    back into the runtime. ``describe()`` must never return the raw value."""

    def describe(self, ref: SecretRef) -> SecretDescriptor: ...
    def put(self, *, namespace: str, path: str, value: bytes,
            classifications: Tuple[str, ...] = (), metadata: Optional[Dict[str, str]] = None) -> SecretRef: ...
    def rotate(self, ref: SecretRef) -> SecretRef: ...
    def revoke(self, ref: SecretRef) -> None: ...


@runtime_checkable
class CredentialBroker(Protocol):
    """Mints the narrowest possible grant against a request+authority, and redeems it — only at the
    capability boundary, only for the exact Mission/capability binding. Enterprise brokers add dynamic
    credentials, leases, distributed revocation; the interface is the same."""

    #: "development" | "production" — capabilities requiring a production broker reject "development".
    assurance_level: str

    def grant(self, request: CredentialRequest, *, authority_context: AuthorityContext) -> "CredentialGrant": ...
    def redeem(self, grant: "CredentialGrant", *, capability_id: str, mission_id: str) -> SecretMaterial: ...
    def renew(self, lease: CredentialLease) -> CredentialLease: ...
    def revoke_grant(self, grant_id: str, *, reason: str) -> None: ...


@runtime_checkable
class KeyService(Protocol):
    """Sign / verify / HMAC / encrypt / decrypt *without extracting key material* — Vault/OpenBao Transit or
    a cloud KMS implement this so a non-exportable key never enters the runtime."""

    def sign(self, key_ref: SecretRef, payload: bytes) -> bytes: ...
    def verify(self, key_ref: SecretRef, payload: bytes, signature: bytes) -> bool: ...
    def hmac(self, key_ref: SecretRef, payload: bytes) -> bytes: ...
    def encrypt(self, key_ref: SecretRef, plaintext: bytes) -> bytes: ...
    def decrypt(self, key_ref: SecretRef, ciphertext: bytes) -> SecretMaterial: ...


# ── the authority gate the broker consults before minting ──────────────────────────────────────────────

#: Canonical deny reasons for a refused credential (safe to emit).
class DenyReason:
    INSUFFICIENT_AUTHORITY = "INSUFFICIENT_AUTHORITY"
    BROKER_UNAVAILABLE = "BROKER_UNAVAILABLE"
    PRODUCTION_BROKER_REQUIRED = "PRODUCTION_BROKER_REQUIRED"
    TTL_EXCEEDS_POLICY = "TTL_EXCEEDS_POLICY"
    SECRET_NOT_FOUND = "SECRET_NOT_FOUND"
    LEASE_REJECTED = "LEASE_REJECTED"
    BACKEND_POLICY_DENY = "BACKEND_POLICY_DENY"
    TENANT_MISMATCH = "TENANT_MISMATCH"


def authorize_request(request: CredentialRequest, authority: AuthorityContext,
                      *, broker_assurance: str = "production") -> SecurityDecision:
    """The gate a broker consults *before* minting a grant. Deny-wins:

      * a capability that declares ``production_broker_required`` against a ``development`` broker → DENY;
      * a requested scope not covered by the Mission authority → DENY (authority only narrows);
      * a requested TTL over the requirement's ``max_ttl_seconds`` → DENY.

    Returns ALLOW only when every check passes."""
    req = request.requirement
    if req.production_broker_required and broker_assurance != "production":
        return SecurityDecision(SecurityVerdict.DENY, subject=request.tenant_id, resource=request.capability_id,
                                reason=DenyReason.PRODUCTION_BROKER_REQUIRED, decided_by="credentials:authorize")
    missing = sorted(s for s in set(req.required_scopes) if not authority.permits(s))
    if missing:
        return SecurityDecision(SecurityVerdict.DENY, subject=request.tenant_id, resource=request.capability_id,
                                reason=f"{DenyReason.INSUFFICIENT_AUTHORITY}: {missing}", decided_by="credentials:authorize")
    ttl = request.requested_ttl_seconds
    if req.max_ttl_seconds is not None and ttl is not None and ttl > req.max_ttl_seconds:
        return SecurityDecision(SecurityVerdict.DENY, subject=request.tenant_id, resource=request.capability_id,
                                reason=f"{DenyReason.TTL_EXCEEDS_POLICY}: {ttl}>{req.max_ttl_seconds}",
                                decided_by="credentials:authorize")
    return SecurityDecision(SecurityVerdict.ALLOW, subject=request.tenant_id, resource=request.capability_id,
                            decided_by="credentials:authorize")


def admit_credentials(requirements: "Tuple[CredentialRequirement, ...]",
                      broker: "Optional[CredentialBroker]") -> SecurityDecision:
    """Fail-closed capability admission for declared credential requirements (§1.4). If any requirement
    declares ``production_broker_required`` and no production broker is wired, DENY — the capability does not
    run. A development broker (or none) can only satisfy non-production requirements."""
    assurance = getattr(broker, "assurance_level", None) if broker is not None else None
    for req in requirements:
        if req.production_broker_required and assurance != "production":
            reason = (DenyReason.BROKER_UNAVAILABLE if broker is None else DenyReason.PRODUCTION_BROKER_REQUIRED)
            return SecurityDecision(SecurityVerdict.DENY, resource=req.name, reason=reason,
                                    decided_by="credentials:admit")
    return SecurityDecision(SecurityVerdict.ALLOW, decided_by="credentials:admit")


# re-exported for convenience so `from ..protocol.secrets import CredentialGrant` works alongside the rest.
from .credentials import CredentialGrant  # noqa: E402,F401
