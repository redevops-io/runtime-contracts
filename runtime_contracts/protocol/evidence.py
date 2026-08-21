"""EvidenceRef and EvidenceChange — versioned, content-addressed evidence identity.

The protocol layer's answer to "which evidence, exactly?" An :class:`EvidenceRef` names an *exact
revision* of an artifact — a stable logical id plus the ``rcv1:`` content hash of that revision — so a
decision can pin the bytes it consumed and a replay can resolve them again. Two references to the same
logical artifact at different revisions are *different* evidence.

An :class:`EvidenceChange` is a typed world/evidence delta: which artifact changed, how, and its
identity before and after. It is the input to incremental discovery — a ``DELETED`` change removes the
basis of anything that depended on it; ``CREATED``/``UPDATED`` moves it.

Identity follows the package rule (``canonical.py``): the reference *is* its content, so all descriptive
fields participate; a change's identity is *what changed* (ref + kind + before/after), while *who
observed it* and *when* are chain-of-custody, excluded — the same convention ``ArtifactHandle`` uses for
``observed_at`` and ``protocol/seal.py`` uses for provenance. Numbers, if any, are decimal strings.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from ..canonical import content_hash

CREATED = "CREATED"
UPDATED = "UPDATED"
DELETED = "DELETED"

#: The evidence-artifact kinds a reference may name. Free-form for forward compatibility (a new kind
#: never forces a contract bump); this names the ones the runtimes use so they share the spelling.
KNOWN_REF_TYPES = frozenset({
    "evidence", "artifact", "raw_source", "parsed_doc", "chunk", "embedding",
    "context_view", "context_epoch", "dataset", "outcome",
})


@dataclass(frozen=True)
class EvidenceRef:
    """A versioned, content-addressed reference to one piece of evidence.

    ``ref`` is the stable logical id; ``content_hash`` (``"rcv1:…"``) pins the exact revision and is the
    strong identity — equal content hash means the same evidence regardless of ``ref``/label. The whole
    reference participates in its own canonical identity."""

    ref: str
    content_hash: str = ""
    version: str = ""
    modality: str = "text"
    media_type: str = ""
    source: str = ""
    ref_type: str = "evidence"

    def pin(self) -> str:
        """A stable pin string ``ref@version#content_hash`` (mirrors ``ArtifactHandle`` version-pinning)."""
        return f"{self.ref}@{self.version}#{self.content_hash}"

    def canonical_form(self) -> Dict[str, Any]:
        return {
            "content_hash": self.content_hash or None,
            "media_type": self.media_type or None,
            "modality": self.modality,
            "ref": self.ref,
            "ref_type": self.ref_type,
            "source": self.source or None,
            "version": self.version or None,
        }

    def identity(self) -> str:
        """The ``rcv1:`` content hash of this reference."""
        return content_hash(self.canonical_form())


@dataclass(frozen=True)
class EvidenceChange:
    """A typed world/evidence delta — the input to incremental discovery.

    ``ref`` is the *logical* artifact id (unversioned); ``prior``/``new`` pin the exact revisions before
    and after. Identity is *what changed* (ref + kind + before/after); ``observed_at`` and ``provenance``
    describe who noticed and when, and are excluded — a change is the same change however it was seen."""

    ref: str
    change_type: str = UPDATED
    prior: Optional[EvidenceRef] = None
    new: Optional[EvidenceRef] = None
    observed_at: Optional[str] = None
    provenance: str = ""

    @property
    def removes_basis(self) -> bool:
        return self.change_type == DELETED

    def canonical_form(self) -> Dict[str, Any]:
        return {
            "change_type": self.change_type,
            "new": self.new.canonical_form() if self.new is not None else None,
            "prior": self.prior.canonical_form() if self.prior is not None else None,
            "ref": self.ref,
            # observed_at + provenance are chain-of-custody, not identity — excluded.
        }

    def identity(self) -> str:
        return content_hash(self.canonical_form())
