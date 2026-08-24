"""Just-in-time credentials + redaction (0.3.x) — keeping secrets out of context.

Two canonical rules:

  1. **A credential is leased at the capability boundary, scoped to the authority, and short-lived.**
     It is never embedded in the plan, the context, or the fingerprint — so a captured plan/context/replay
     bundle contains no usable secret. What travels is a :class:`CredentialGrant`: a *reference* (an opaque
     handle + a hash of the material), the scope it is bound to, and the authority chain that justified it.
     Redeeming the handle for the actual secret happens out of band, at use, against a broker.

  2. **Nothing that leaves the runtime carries a raw secret.** :func:`redact` walks any value and replaces
     secret-shaped material with a stable ``rcv1:redacted:<hash8>`` placeholder — same secret → same
     placeholder (so telemetry stays correlatable) but the value never appears. This is the reusable form of
     the telemetry invariant "hashes, not payloads".

The broker itself (Vault, cloud KMS, a keyring) lives outside this contract; here we fix the *shape* of a
grant and the *rule* that its scope must be satisfied by the authority that leased it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .seal import content_hash
from .security import AuthorityContext, SecurityDecision, SecurityVerdict

# ── redaction ──

# key names whose *values* are secrets regardless of content
_SECRET_KEYS = re.compile(
    r"(?i)(pass(word|wd)?|secret|token|api[_-]?key|auth(oriz(ation|ed))?|"
    r"credential|private[_-]?key|access[_-]?key|session[_-]?key|bearer|cookie)")

# value shapes that are secrets regardless of the key they sit under
_SECRET_VALUE_PATTERNS = [
    re.compile(r"\bBearer\s+[A-Za-z0-9._\-]+", re.I),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),                       # AWS access key id
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),                    # OpenAI-style
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),           # Slack
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,}\b"),  # JWT
    re.compile(r"\bhvs\.[A-Za-z0-9_\-]{20,}\b"),               # Vault
]


def _placeholder(secret: str) -> str:
    # stable, non-reversible: same secret → same tag, correlatable without disclosure
    return "rcv1:redacted:" + content_hash(str(secret)).split(":", 1)[-1][:8]


def redact(value, *, _key: str = ""):
    """Return a copy of ``value`` with secret-shaped material replaced by a stable non-reversible
    placeholder. Recurses through dicts/lists/tuples. A string under a secret-named key is fully replaced;
    otherwise only matched secret *substrings* are masked, so surrounding context survives."""
    if isinstance(value, dict):
        return {k: redact(v, _key=str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        red = [redact(v, _key=_key) for v in value]
        return type(value)(red) if isinstance(value, tuple) else red
    if isinstance(value, str):
        if _key and _SECRET_KEYS.search(_key):
            return _placeholder(value)
        out = value
        for pat in _SECRET_VALUE_PATTERNS:
            out = pat.sub(lambda m: _placeholder(m.group(0)), out)
        return out
    return value


# ── just-in-time credential grant ──

@dataclass(frozen=True)
class CredentialGrant:
    """A reference to a leased secret — never the secret itself. Carries the scope it is bound to and the
    authority chain that justified it, plus a hash of the material so redemption can be verified and the
    audit trail can correlate uses without disclosure."""
    grant_id: str
    principal: str                       # the principal ref this was leased for
    resource: str                        # what it unlocks (e.g. "vault:vibexgen/fal/api_key")
    scope: tuple[str, ...] = ()          # permissions this credential is bound to (⊆ authority scope)
    ttl_seconds: int = 300               # short-lived by construction
    authority_ref: str = ""              # chain_ref of the AuthorityContext that leased it
    material_hash: str = ""              # content_hash of the secret material (verify on redeem)
    handle: str = ""                     # opaque broker handle to redeem out of band
    # --- lease/lifecycle metadata (optional; additive — empty values stay out of the canonical form) ---
    request_id: str = ""                 # the CredentialRequest this grant answers
    credential_ref: Any = None           # a SecretRef naming the exact secret (location + version)
    lease_id: str = ""                   # backend lease id (renew/revoke handle)
    issued_at: str = ""
    expires_at: str = ""
    renewable: bool = False
    revocable: bool = True

    def canonical_form(self) -> dict:
        d = {"grant_id": self.grant_id, "principal": self.principal, "resource": self.resource,
             "ttl_seconds": self.ttl_seconds}
        if self.scope:
            d["scope"] = sorted(self.scope)
        if self.authority_ref:
            d["authority_ref"] = self.authority_ref
        if self.material_hash:
            d["material_hash"] = self.material_hash
        if self.request_id:
            d["request_id"] = self.request_id
        if self.credential_ref is not None:
            d["credential_ref"] = self.credential_ref.canonical_form()
        if self.lease_id:
            d["lease_id"] = self.lease_id
        if self.issued_at:
            d["issued_at"] = self.issued_at
        if self.expires_at:
            d["expires_at"] = self.expires_at
        # NOTE: `handle` is intentionally OMITTED from the canonical form — it is a live redemption token,
        # not identity, and must not enter any fingerprint/seal. renewable/revocable are lifecycle flags,
        # also excluded from identity.
        return d

    @property
    def ref(self) -> str:
        return content_hash(self.canonical_form())


def lease_decision(*, requested_scope: "tuple[str, ...] | list[str]", resource: str,
                   authority: AuthorityContext) -> SecurityDecision:
    """Decide whether a credential for ``requested_scope`` may be leased under ``authority``. A JIT
    credential can never widen authority: every requested permission must already be within the authority's
    scope (deny-wins). This is the gate a broker consults *before* minting a CredentialGrant."""
    missing = sorted(p for p in set(requested_scope or ()) if not authority.permits(p))
    if missing:
        return SecurityDecision(SecurityVerdict.DENY, resource=resource,
                                reason=f"credential scope {missing} exceeds leased authority",
                                decided_by="credentials:lease")
    return SecurityDecision(SecurityVerdict.ALLOW, resource=resource, decided_by="credentials:lease")
