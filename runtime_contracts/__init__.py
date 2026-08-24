"""Canonical contracts for ReDevOps runtime interoperability.

0.3.x consolidates the runtimes onto ONE universal protocol identity. Two layers:

  * `runtime_contracts.canonical` — the strict Decimal canonical: `content_hash`
    over `canonical_json`, floats refused, `rcv1:` digests. This is the identity
    every runtime must reproduce byte-for-byte, in any language.
  * `runtime_contracts.protocol` — the seal semantics over that canonical: the
    domain-facing `seal_hash` / `content_hash` that apply one explicit number
    policy (floats quantized to a fixed scale) so domain payloads carrying floats
    can be hashed without re-introducing cross-language float ambiguity.

The top-level `content_hash` exported here is the **domain-facing** one (seal
policy); the strict, float-refusing form is `canonical.content_hash`
(re-exported as `strict_content_hash`). `runtime_contracts.models` carries domain
vocabulary and layers on top of the protocol, never the other way round.
"""
from .canonical import (
    CANONICALIZATION_VERSION,
    CONTRACT_VERSION,
    CanonicalizationError,
    canonical_json,
    canonicalize,
    decimal_string,
)
from .canonical import content_hash as strict_content_hash
from .protocol import (
    SEAL_CONTRACT_VERSION,
    SEAL_NUMBER_PLACES,
    canonical_form,
    content_hash,
    prepare,
    seal_hash,
    EvidenceRef,
    EvidenceChange,
    CREATED,
    UPDATED,
    DELETED,
    KNOWN_REF_TYPES,
    RelationKind,
    MemberRole,
    LineageMember,
    Relation,
    member,
    relation,
    derived_from,
    supersedes,
    TopologyKind,
    JoinPolicy,
    ConcurrencyGroup,
    TelemetryKind,
    SecurityEventType,
    GovernanceDisposition,
    RuntimeSecurityEvent,
    SecurityTrajectory,
    correlate,
    ContainmentState,
    Containment,
    ContainmentRefused,
    CausalCycle,
    SecurityVerdict,
    ContextIdentity,
    SecurityDecision,
    PrincipalRef,
    AuthorityContext,
    DelegationRefused,
    verify_chain,
)
from .models import *  # noqa: F401,F403,E402
from .models import __all__ as _model_all  # noqa: E402

__version__ = "0.3.0"
__all__ = [
    # strict canonical identity
    "CANONICALIZATION_VERSION", "CONTRACT_VERSION", "CanonicalizationError",
    "canonical_json", "canonicalize", "decimal_string", "strict_content_hash",
    # domain-facing seal (the protocol layer)
    "seal_hash", "content_hash", "canonical_form", "prepare",
    "SEAL_CONTRACT_VERSION", "SEAL_NUMBER_PLACES",
    # evidence-native protocol primitives
    "EvidenceRef", "EvidenceChange", "CREATED", "UPDATED", "DELETED", "KNOWN_REF_TYPES",
    "RelationKind", "MemberRole", "LineageMember", "Relation",
    "member", "relation", "derived_from", "supersedes",
    "TopologyKind", "JoinPolicy", "ConcurrencyGroup",
    "TelemetryKind", "SecurityEventType", "GovernanceDisposition", "RuntimeSecurityEvent", "SecurityTrajectory", "correlate", "ContainmentState", "Containment", "ContainmentRefused", "CausalCycle",
    "SecurityVerdict", "ContextIdentity", "SecurityDecision", "PrincipalRef", "AuthorityContext",
    "DelegationRefused", "verify_chain",
    *_model_all,
]
