"""The universal protocol layer — domain-neutral primitives every ReDevOps runtime
agrees on byte-for-byte: canonical identity/seal (and, as they land here,
provenance, versioning, evidence, lineage, verdicts). Domain models
(`runtime_contracts.models`) layer on top and are never imported by this layer."""
from .seal import (
    SEAL_CONTRACT_VERSION,
    SEAL_NUMBER_PLACES,
    canonical_form,
    content_hash,
    prepare,
    seal_hash,
)
from .evidence import (
    CREATED,
    UPDATED,
    DELETED,
    KNOWN_REF_TYPES,
    EvidenceRef,
    EvidenceChange,
)
from .lineage import (
    RelationKind,
    MemberRole,
    LineageMember,
    Relation,
    member,
    relation,
    derived_from,
    supersedes,
)
from .topology import (
    TopologyKind,
    JoinPolicy,
    ConcurrencyGroup,
)
from .telemetry import (
    TelemetryKind,
    SecurityEventType,
    GovernanceDisposition,
    RuntimeSecurityEvent,
    SecurityTrajectory,
    correlate,
    causal_order_events,
    ContainmentState,
    Containment,
    ContainmentRefused,
    CausalCycle,
)
from .security import (
    SecurityVerdict,
    ContextIdentity,
    SecurityDecision,
    PrincipalRef,
    AuthorityContext,
    DelegationRefused,
    verify_chain,
)
from .credentials import (
    CredentialGrant,
    redact,
    lease_decision,
)
from .trace import (
    TraceContext,
    span_of,
)
from .geospatial import (
    GeoRef,
    SpatialOp,
    geometry_hash,
    GEOMETRY_PRECISION,
)
from .adversarial import (
    validate_evidence,
    check_injection,
    check_self_granted_authority,
    check_hidden_instructions,
    check_source_spoofing,
    check_poisoned_tool_metadata,
    check_classification_escalation,
    check_cross_source_contradiction,
)

__all__ = [
    # concurrency topology vocabulary
    "TopologyKind",
    "JoinPolicy",
    "ConcurrencyGroup",
    # security telemetry protocol
    "TelemetryKind",
    "SecurityEventType",
    "GovernanceDisposition",
    "RuntimeSecurityEvent",
    "SecurityTrajectory",
    "correlate",
    "causal_order_events",
    "ContainmentState",
    "Containment",
    "ContainmentRefused",
    "CausalCycle",
    # canonical security contracts
    "SecurityVerdict",
    "ContextIdentity",
    "SecurityDecision",
    "PrincipalRef",
    "AuthorityContext",
    "DelegationRefused",
    "verify_chain",
    # just-in-time credentials + redaction
    "CredentialGrant",
    "redact",
    "lease_decision",
    # mission-native trace identity (OTel semantic source of truth)
    "TraceContext",
    "span_of",
    # canonical geospatial evidence primitive
    "GeoRef",
    "SpatialOp",
    "geometry_hash",
    "GEOMETRY_PRECISION",
    # adversarial evidence validators (epistemic layer)
    "validate_evidence",
    "check_injection",
    "check_self_granted_authority",
    "check_hidden_instructions",
    "check_source_spoofing",
    "check_poisoned_tool_metadata",
    "check_classification_escalation",
    "check_cross_source_contradiction",
    "seal_hash",
    "content_hash",
    "canonical_form",
    "prepare",
    "SEAL_CONTRACT_VERSION",
    "SEAL_NUMBER_PLACES",
    # evidence identity (versioned, content-addressed) + typed change delta
    "EvidenceRef",
    "EvidenceChange",
    "CREATED",
    "UPDATED",
    "DELETED",
    "KNOWN_REF_TYPES",
    # canonical lineage edge vocabulary
    "RelationKind",
    "MemberRole",
    "LineageMember",
    "Relation",
    "member",
    "relation",
    "derived_from",
    "supersedes",
]
