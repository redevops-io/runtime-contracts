"""Lineage — the canonical, constrained edge vocabulary over runtime artifacts.

``models/intent.py`` carries a deliberately *unconstrained* ``IntentRelation`` (free-string ``kind``, so
a domain names its own relations and the package ships no finance/GRC vocabulary). This module is the
complementary protocol-level piece: a small, fixed set of *cross-runtime* relation kinds every runtime
agrees on — supersession, refinement, dependency, conflict, derivation, duplication — used to record
lineage (an embedding ``DERIVED_FROM`` a chunk; a re-cut ``SUPERSEDES`` its parent) without each runtime
inventing an edge shape. It sits above the existing lineage primitives (``Derivation``, ``Amendment``,
``Freshness.SUPERSEDED``, ``replay_ledger``) and reuses their conventions rather than replacing them.

Pure data + pure constructors. Identity is ``kind`` + ordered ``members`` (who/what is related); the
assertion's author and confidence are chain-of-custody, excluded from identity (``canonical.py`` rule).
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Dict, Sequence

from ..canonical import content_hash

# Re-exported so a caller can spell an evidence lineage member's ref_type consistently.
from .evidence import KNOWN_REF_TYPES  # noqa: F401


class RelationKind(str, Enum):
    """How one artifact relates to another. Additive within a major."""

    SUPERSEDES = "SUPERSEDES"          # this replaces the referent (the referent is retired)
    REFINES = "REFINES"                # this narrows/clarifies the referent without replacing it
    DEPENDS_ON = "DEPENDS_ON"          # this cannot proceed until the referent is satisfied
    CONFLICTS_WITH = "CONFLICTS_WITH"  # the two cannot both hold / two evidences disagree
    DERIVED_FROM = "DERIVED_FROM"      # this was produced from the referent (provenance / lineage)
    DUPLICATES = "DUPLICATES"          # this is the same artifact seen again


class MemberRole(str, Enum):
    SUBJECT = "SUBJECT"   # the artifact the relation is asserted about
    OBJECT = "OBJECT"     # the referent it points at


@dataclass(frozen=True)
class LineageMember:
    """One participant in a relation: a typed, versioned reference — never an inlined object, so a
    relation stays a pure edge as the referents evolve."""

    ref: str
    role: MemberRole = MemberRole.OBJECT
    ref_type: str = "artifact"
    ref_version: str = ""

    def canonical_form(self) -> Dict[str, Any]:
        return {
            "ref": self.ref,
            "ref_type": self.ref_type,
            "ref_version": self.ref_version or None,
            "role": self.role.value,
        }


@dataclass(frozen=True)
class Relation:
    """A named edge over an ordered set of members. Pure data: asserting/validating a relation is
    runtime behavior; this records the assertion. Identity is ``kind`` + ordered members."""

    kind: RelationKind
    members: Sequence[LineageMember] = ()
    asserted_by: str = ""     # who asserted it — chain-of-custody, excluded from identity
    confidence: str = "1"     # decimal string, excluded from identity

    def canonical_form(self) -> Dict[str, Any]:
        return {
            "kind": self.kind.value,
            "members": [m.canonical_form() for m in self.members],  # order-significant
        }

    def identity(self) -> str:
        return content_hash(self.canonical_form())


# ──────────────────────────── constructors ────────────────────────────
# One obvious way to assert each edge, so lineage never gets a parallel model.

def member(ref: str, *, role: MemberRole = MemberRole.OBJECT,
           ref_type: str = "artifact", ref_version: str = "") -> LineageMember:
    return LineageMember(ref=ref, role=role, ref_type=ref_type, ref_version=ref_version)


def _as(m: Any, role: MemberRole, default_type: str) -> LineageMember:
    m = m if isinstance(m, LineageMember) else LineageMember(m, role, default_type)
    return replace(m, role=role)


def relation(kind: RelationKind, subject: Any, obj: Any, *, asserted_by: str = "",
             confidence: str = "1", subject_type: str = "artifact",
             object_type: str = "artifact") -> Relation:
    """Assert a typed edge ``subject --kind--> obj``. Subjects/objects may be plain refs or
    :class:`LineageMember`\\ s; roles are normalized so the subject is first."""
    return Relation(
        kind=kind,
        members=(_as(subject, MemberRole.SUBJECT, subject_type),
                 _as(obj, MemberRole.OBJECT, object_type)),
        asserted_by=asserted_by, confidence=confidence)


def derived_from(subject: Any, source: Any, *, subject_type: str = "artifact",
                 source_type: str = "evidence", asserted_by: str = "", confidence: str = "1") -> Relation:
    """``subject`` was **DERIVED_FROM** ``source`` — the canonical lineage edge (raw→parsed→chunk→
    embedding, conclusion→evidence, cut→parent-cut)."""
    return relation(RelationKind.DERIVED_FROM, subject, source, asserted_by=asserted_by,
                    confidence=confidence, subject_type=subject_type, object_type=source_type)


def supersedes(subject: Any, prior: Any, *, subject_type: str = "artifact",
               prior_type: str = "artifact", asserted_by: str = "", confidence: str = "1") -> Relation:
    """``subject`` **SUPERSEDES** ``prior`` (a new version retiring its parent)."""
    return relation(RelationKind.SUPERSEDES, subject, prior, asserted_by=asserted_by,
                    confidence=confidence, subject_type=subject_type, object_type=prior_type)
