"""Quantify → runtime-contracts, at the boundary only.

Deliberately narrow. It proves the contracts survive contact with real artifacts;
it does not migrate the application. Quantify keeps its own types internally, and
this translates at the edge — an adapter boundary is healthier than adoption
until the contract has met more than one consumer.

What it proves, and nothing more:

1. Quantify's public/private split maps onto `Tenancy` without loss.
2. A Quantify content hash and a `ContextView` hash never collide — they are
   different things and must not be interchangeable.
3. Projections are explicit rather than implied by artifact type.
4. Denied and omitted artifacts change the view identity.
5. Replay reproduces the golden digest.
6. No source artifact is copied into the handle — only its identity.
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping, Optional, Sequence

from runtime_contracts import (
    ArtifactHandle,
    AuthorizationOutcome,
    ContextPreviewPlan,
    ContextView,
    Freshness,
    Necessity,
    PlannedItem,
    Tenancy,
    Visibility,
)

#: Quantify artifact kind -> contract visibility. Read from Quantify's own
#: boundary declaration rather than restated, so the two cannot drift: the
#: mapping is a translation, not a second source of truth.
_QUANTIFY_VISIBILITY = {
    "PUBLIC_LIBRARY": Visibility.PUBLIC,
    "PRIVATE_WORKSPACE": Visibility.PRIVATE,
}


def visibility_of(reference: str, *, quantify_boundary) -> Visibility:
    """Translate a Quantify artifact reference into contract visibility.

    `quantify_boundary` is Quantify's own `visibility_of`, injected rather than
    imported, so this adapter does not depend on Quantify being installed and
    Quantify does not depend on the contracts.
    """
    return _QUANTIFY_VISIBILITY[quantify_boundary(reference).value]


def to_handle(
    reference: str,
    *,
    artifact_type: str,
    content_hash: str,
    visibility: Visibility,
    tenant_id: Optional[str] = None,
    projections: Sequence[str] = ("summary", "full"),
    authority: str = "quantify",
    estimated_expansion_tokens: Optional[int] = None,
) -> ArtifactHandle:
    """One Quantify artifact reference as a handle.

    The referent's own hash is carried, never its content. A handle that
    embedded the artifact would defeat the point of being a reference — the
    planner could no longer decide whether expanding it was worth the budget,
    because it would already have paid.
    """
    if "@" not in reference:
        raise ValueError(
            f"{reference!r} is not version-pinned. Quantify pins every artifact "
            "reference, so an unpinned one here means the caller resolved a "
            "concept id to 'latest' before the handle was built"
        )
    _, _, version = reference.partition("@")
    return ArtifactHandle(
        artifact_id=reference,
        artifact_type=artifact_type,
        version=version,
        artifact_content_hash=content_hash,
        tenancy=Tenancy(visibility, tenant_id),
        authority=authority,
        freshness=Freshness.CURRENT,
        projections=tuple(projections),
        estimated_expansion_tokens=estimated_expansion_tokens,
    )


def plan_from(
    items: Iterable[tuple],
    *,
    plan_id: str,
    budget_tokens: Optional[int] = None,
    omitted_count: int = 0,
) -> ContextPreviewPlan:
    """Build a plan from `(handle, necessity, projection, authorization)` tuples."""
    planned = [
        PlannedItem(handle=handle, necessity=necessity, projection=projection,
                    authorization=authorization)
        for handle, necessity, projection, authorization in items
    ]
    return ContextPreviewPlan(plan_id=plan_id, items=planned,
                              budget_tokens=budget_tokens,
                              omitted_count=omitted_count)


def view_from(
    plan: ContextPreviewPlan,
    *,
    view_id: str,
    version_pins: Mapping[str, str],
) -> ContextView:
    """Materialize, pinning every artifact by content hash.

    The pins are what make replay honest: resolving `methodology/hrp@3` next
    year must return the bytes it returned today, or the view reports divergence
    rather than silently refreshing.
    """
    return ContextView(view_id=view_id, plan=plan, version_pins=dict(version_pins))
