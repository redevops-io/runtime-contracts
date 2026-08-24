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
from .security import (
    SecurityVerdict,
    SecurityDecision,
    PrincipalRef,
    AuthorityContext,
    DelegationRefused,
    verify_chain,
)

__all__ = [
    # concurrency topology vocabulary
    "TopologyKind",
    "JoinPolicy",
    "ConcurrencyGroup",
    # canonical security contracts
    "SecurityVerdict",
    "SecurityDecision",
    "PrincipalRef",
    "AuthorityContext",
    "DelegationRefused",
    "verify_chain",
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
