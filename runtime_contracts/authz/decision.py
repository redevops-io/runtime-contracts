"""`authz/v1` — the one decision envelope both ReDevOps editions emit, and what makes it auditable.

An authorization decision is only auditable if it says *why* and *on whose authority*. Prose alone is not
auditable: "allow · all rows" cannot be aggregated, alerted on, or compared across editions. So both planes
emit this envelope for every decision, allow or deny:

    {"allowed": true, "policy_reason": "explicit_grant", "grant_ids": ["g-…"], "roles_hash": "9f2c…",
     "principal": "app:crm", "principal_kind": "app", "resource_kind": "table",
     "resource_name": "crm.customers", "requested_action": "read", "tenant": "acme",
     "decision_epoch": 0, "event": "authorization_decision", "version": 1}

Three rules carry the weight:

**`policy_reason` is a closed vocabulary.** An open-ended reason string is how "denied for policy reasons"
ends up meaning three different things in three logs. The members below are exactly the reasons the two
planes emit; anything else is `UNCLASSIFIED`, which this module treats as a defect in the emitter, not as a
reason.

**`roles_hash` never carries role names.** A log line that lists roles invites the reader — human or
downstream — to treat the listing as a grant. The digest still correlates: the same role set produces the
same digest in both planes, so "which role set decided this" is answerable without restating a privilege.

**The receipt is not the boundary.** `allowed` and `policy_reason` record what the plane *said*. They cannot
show that no unauthorized content crossed a boundary — a document into a candidate set, a row into a cache,
a snippet into a model's context. Data-boundary claims need scenario-level evidence; see
:mod:`runtime_contracts.authz.suite`.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Mapping

from ..canonical import content_hash

#: Contract identity. It participates in :attr:`AuthorizationDecision.content_hash`, so a change to what a
#: receipt *means* (which fields, which reasons) changes every digest rather than drifting under a consumer.
AUTHZ_CONTRACT_VERSION = "authz/v1"

#: The envelope's own version, carried in every line so a reader can tell a `authz/v1` receipt from the
#: pre-contract prose-only decisions it replaces.
ENVELOPE_VERSION = 1

#: The log event name both planes write.
DECISION_EVENT = "authorization_decision"

#: `roles_hash` is a 128-bit-cut digest: long enough to correlate, short enough to sit in a log line.
ROLES_HASH_HEX_LEN = 16
_ROLES_HASH_RE = re.compile(r"^[0-9a-f]{%d}$" % ROLES_HASH_HEX_LEN)


class PolicyReason(str, Enum):
    """Why a decision was made, as a closed set.

    The values are the strings the implementations emit; renaming one is a contract change. A plane that
    cannot name its reason emits :attr:`UNCLASSIFIED`, and :func:`validate_envelope` reports that as a
    defect — an unnamed reason is unfalsifiable, so it cannot be gated on.
    """

    EXPLICIT_GRANT = "explicit_grant"                 # an explicit grant covers the request
    WILDCARD_GRANT = "wildcard_grant"                 # a grant of ``*`` covers it
    MISSING_EXPLICIT_GRANT = "missing_explicit_grant"  # nothing granted it (the deny-by-default case)
    TENANT_ISOLATION = "tenant_isolation"             # the request reached across a tenant boundary
    NO_RESOURCE_PLANE = "no_resource_plane"           # resource authority could not be consulted
    INVALID_PRINCIPAL = "invalid_principal"           # the principal itself is not well-formed
    MALFORMED_REQUEST = "malformed_request"           # resource or action is not a well-formed request
    SEALED_STORE = "sealed_store"                     # the grant store is sealed; nothing is honored
    OWN_ROWS_REQUIRES_USER = "own_rows_requires_user"  # an own-rows grant with no user to be "own" of
    PRINCIPAL_EXPIRED = "principal_expired"           # the token expired before the decision
    UNCLASSIFIED = "unclassified"                     # the emitter did not classify its own decision


def roles_hash(roles: Iterable[Any]) -> str:
    """The canonical digest of a role set — the definition both planes are required to reproduce.

    Non-string and empty members are dropped (a malformed member is not a role), the survivors are
    de-duplicated and sorted, joined with ``|``, and hashed with SHA-256 to the first
    :data:`ROLES_HASH_HEX_LEN` hex characters. Sorting first means the digest is a property of the set, not
    of the order a token happened to list it in.
    """
    try:
        members = [r for r in roles if isinstance(r, str) and r]
    except TypeError:
        members = []
    canonical = "|".join(sorted(set(members)))
    return hashlib.sha256(canonical.encode("utf-8", "surrogatepass")).hexdigest()[:ROLES_HASH_HEX_LEN]


class EnvelopeError(ValueError):
    """A mapping cannot be read as an `authz/v1` decision at all (missing or mistyped fields)."""


@dataclass(frozen=True)
class AuthorizationDecision:
    """One authorization decision, in the form an auditor and a gate can both read.

    `grant_ids` are the ids of the grants that carried the decision — for a denial, the matching-but-
    insufficient ones, or empty when nothing matched at all. An *allow* with no `grant_ids` and no
    `break_glass` marker is an unattributable allow, which is the thing this envelope exists to prevent.
    """

    allowed: bool
    policy_reason: PolicyReason = PolicyReason.UNCLASSIFIED
    principal: str = ""
    principal_kind: str = ""
    roles_digest: str = ""                # the digest, never the listing — see :func:`roles_hash`
    resource_kind: str = ""
    resource_name: str = ""
    requested_action: str = "read"
    grant_ids: tuple[str, ...] = ()
    tenant: str = ""
    decision_epoch: int = 0
    break_glass: bool = False
    plane: str = ""                       # which plane/adapter produced it (attribution, not identity)
    version: int = ENVELOPE_VERSION
    event: str = DECISION_EVENT
    undeclared: tuple[str, ...] = field(default=(), compare=False)   # extra keys the emitter sent

    def canonical_form(self) -> dict[str, Any]:
        """Plain, deterministic, hashable — and free of role names."""
        d: dict[str, Any] = {
            "contract": AUTHZ_CONTRACT_VERSION,
            "version": self.version,
            "event": self.event,
            "allowed": bool(self.allowed),
            "policy_reason": _reason_value(self.policy_reason),
            "resource_kind": self.resource_kind,
            "resource_name": self.resource_name,
            "requested_action": self.requested_action,
            "grant_ids": sorted(set(self.grant_ids)),
        }
        if self.principal:
            d["principal"] = self.principal
        if self.principal_kind:
            d["principal_kind"] = self.principal_kind
        if self.roles_digest:
            d["roles_hash"] = self.roles_digest
        if self.tenant:
            d["tenant"] = self.tenant
        if self.decision_epoch:
            d["decision_epoch"] = int(self.decision_epoch)
        if self.break_glass:
            d["break_glass"] = True
        return d

    @property
    def content_hash(self) -> str:
        return content_hash(self.canonical_form())

    def to_envelope(self) -> dict[str, Any]:
        """The wire/log form: the field names the planes write, not the dataclass's."""
        d: dict[str, Any] = {
            "version": self.version, "event": self.event,
            "principal_kind": self.principal_kind, "principal": self.principal,
            "roles_hash": self.roles_digest, "resource_kind": self.resource_kind,
            "resource_name": self.resource_name, "requested_action": self.requested_action,
            "allowed": bool(self.allowed), "policy_reason": _reason_value(self.policy_reason),
            "grant_ids": sorted(set(self.grant_ids)), "tenant": self.tenant,
        }
        if self.decision_epoch:
            d["decision_epoch"] = int(self.decision_epoch)
        if self.break_glass:
            d["break_glass"] = True
        return d


def _reason_value(reason: Any) -> str:
    if isinstance(reason, PolicyReason):
        return reason.value
    return str(reason) if isinstance(reason, str) else _reason_value(PolicyReason.UNCLASSIFIED)


#: The keys an `authz/v1` emitter MUST write. `decision_epoch` and `break_glass` are optional because the
#: resource plane has no epoch and the capability plane has no break-glass-free path to hide.
ENVELOPE_FIELDS: tuple[str, ...] = (
    "version", "event", "principal_kind", "principal", "roles_hash", "resource_kind", "resource_name",
    "requested_action", "allowed", "policy_reason", "grant_ids", "tenant",
)
OPTIONAL_ENVELOPE_FIELDS: tuple[str, ...] = ("decision_epoch", "break_glass")


def parse_envelope(raw: Mapping[str, Any], *, plane: str = "") -> AuthorizationDecision:
    """Read a plane's log/dict envelope into the contract type. Strict, and never guesses.

    Absent-and-null fields are not silently filled in for the required set: a receipt that omits
    `tenant` cannot later be claimed to be tenant-bound, so it parses with `tenant=""` and the validator
    reports the binding it lacks.
    """
    if not isinstance(raw, Mapping):
        raise EnvelopeError(f"an envelope must be a mapping, got {type(raw).__name__}")
    missing = [k for k in ENVELOPE_FIELDS if k not in raw]
    if missing:
        raise EnvelopeError(f"envelope is missing required field(s): {', '.join(missing)}")
    if not isinstance(raw["allowed"], bool):
        raise EnvelopeError("`allowed` must be a boolean, not a truthy value")
    grant_ids = raw["grant_ids"]
    if isinstance(grant_ids, str) or not isinstance(grant_ids, (list, tuple)):
        raise EnvelopeError("`grant_ids` must be a list of grant ids")
    if any(not isinstance(g, str) or not g for g in grant_ids):
        raise EnvelopeError("every grant id must be a non-empty string")
    epoch = raw.get("decision_epoch", 0) or 0
    if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 0:
        raise EnvelopeError("`decision_epoch` must be a non-negative integer")
    reason_raw = raw["policy_reason"]
    try:
        reason = PolicyReason(reason_raw)
    except ValueError:
        reason = PolicyReason.UNCLASSIFIED
    known = set(ENVELOPE_FIELDS) | set(OPTIONAL_ENVELOPE_FIELDS)
    return AuthorizationDecision(
        allowed=raw["allowed"], policy_reason=reason,
        principal=raw["principal"], principal_kind=raw["principal_kind"], roles_digest=raw["roles_hash"],
        resource_kind=raw["resource_kind"], resource_name=raw["resource_name"],
        requested_action=raw["requested_action"], grant_ids=tuple(grant_ids), tenant=raw["tenant"],
        decision_epoch=int(epoch), break_glass=bool(raw.get("break_glass", False)), plane=plane,
        version=raw["version"], event=raw["event"],
        undeclared=tuple(sorted(k for k in raw if k not in known)),
    )


def validate_envelope(decision: AuthorizationDecision, *, request_tenant: str | None = None) -> list[str]:
    """Every way this receipt fails to be auditable, as reason codes (empty list = clean).

    ``request_tenant`` is the tenant the caller asked to act for. When it is supplied, the receipt must
    name the same tenant: a decision whose tenant is empty while the request had one is not
    tenant-bound, whatever its `policy_reason` says — which is why ``envelope_tenant_unset`` is reported
    separately from ``tenant_mismatch`` (missing binding vs. wrong binding).
    """
    codes: list[str] = []
    if decision.version != ENVELOPE_VERSION:
        codes.append("envelope_version_unsupported")
    if decision.event != DECISION_EVENT:
        codes.append("event_name_unknown")
    if not isinstance(decision.allowed, bool):
        codes.append("allowed_not_boolean")
    if _reason_value(decision.policy_reason) == PolicyReason.UNCLASSIFIED.value:
        codes.append("policy_reason_unclassified")
    if not _ROLES_HASH_RE.match(decision.roles_digest or ""):
        codes.append("roles_hash_malformed")
    if decision.grant_ids != tuple(sorted(set(decision.grant_ids))):
        codes.append("grant_ids_not_canonical")
    if any(not isinstance(g, str) or not g for g in decision.grant_ids):
        codes.append("grant_id_blank")
    if decision.allowed and not decision.grant_ids and not decision.break_glass:
        codes.append("allow_without_grant_or_elevation")
    if not decision.allowed and not decision.resource_name:
        codes.append("deny_without_resource")
    if request_tenant is not None:
        if not decision.tenant:
            codes.append("envelope_tenant_unset")
        elif decision.tenant != request_tenant:
            codes.append("tenant_mismatch")
    return codes