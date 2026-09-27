"""IdentityGraph — one canonical entity, many app projections.

The load-bearing piece of a dataset world: the same conceptual customer / company / invoice / property must
keep one identity as a mission crosses Twenty (CRM), Chatwoot (support), Lago (billing), ERPNext (books),
Metabase (BI), CrowdSec (security)… The graph maps a canonical ``entity_id`` to each system's native id —
explicitly registered where a projection seeder created a real record, or **deterministically derived**
(reproducible, content-addressed) otherwise. It also resolves the other way, so a webhook from an app maps
back to the canonical entity without inventing a new unrelated demo object.
"""
from __future__ import annotations

from typing import Dict, Optional

from ..canonical import content_hash


class IdentityGraph:
    """Bidirectional canonical-id ↔ per-app native-id mapping, with deterministic fallback derivation."""

    def __init__(self) -> None:
        self._fwd: Dict[str, Dict[str, str]] = {}      # entity_id -> {app: native_id}
        self._rev: Dict[str, str] = {}                 # f"{app}:{native_id}" -> entity_id

    def register(self, entity_id: str, app: str, native_id: str) -> None:
        """Record that a projection seeder created ``native_id`` in ``app`` for the canonical entity."""
        self._fwd.setdefault(entity_id, {})[app] = native_id
        self._rev[f"{app}:{native_id}"] = entity_id

    def derive(self, entity_id: str, app: str) -> str:
        """A deterministic, reproducible native id for ``entity_id`` in ``app`` — used when no real record
        was seeded. Same (entity, app) → same id across runs, so replay is stable."""
        h = content_hash({"app": app, "entity": entity_id}).split(":", 1)[-1][:16]
        return f"{app}-{h}"

    def resolve(self, entity_id: str, app: str) -> str:
        """The entity's native id in ``app`` — the registered one if a seeder created it, else derived."""
        got = self._fwd.get(entity_id, {}).get(app)
        return got if got is not None else self.derive(entity_id, app)

    def reverse(self, app: str, native_id: str) -> Optional[str]:
        """Map an app-native id back to its canonical entity (None if unknown — never fabricate one)."""
        got = self._rev.get(f"{app}:{native_id}")
        if got is not None:
            return got
        # a derived id round-trips deterministically: recover the entity only if it derives back to itself
        return None

    def projections(self, entity_id: str) -> Dict[str, str]:
        """Every registered projection of the entity ({app: native_id}). Derived ids are computed on demand
        via :meth:`resolve`, so this returns only the ids a seeder actually created."""
        return dict(self._fwd.get(entity_id, {}))
