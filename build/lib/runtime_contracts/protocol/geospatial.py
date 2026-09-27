"""Canonical geospatial evidence primitive (0.3.x) — a typed spatial reference every runtime agrees on.

`GeoRef` is the universal spatial-evidence primitive: it rides *alongside* evidence (it does not replace
`EvidenceRef`), pinning a geometry's identity, CRS, jurisdiction and spatiotemporal validity. The geometry
has a canonical, content-addressed identity (`geometry_hash`) so the *same* boundary in the *same* CRS is
one identity across providers — parcel/feature identity is never provider-specific — and reprojection is
always explicit downstream (a spatial engine refuses a silent CRS mismatch).

Domain models built on this (land-use dispositions, parcel entities, zoning ontologies) stay in the
consuming tenant, not here — this layer is domain-neutral. `geometry_hash` uses BLAKE2b over rounded,
float-normalized coordinates so any runtime (Python, Go, …) reproduces it byte-for-byte.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from ..canonical import content_hash

Coord = Tuple[float, float]                     # (lon, lat) or (x, y) in the ring's CRS
Ring = List[Coord]                              # a ring; we do not require first==last

# Coordinate rounding for geometry identity: 7 decimals ≈ 1.1cm at the equator — enough that the same
# surveyed boundary hashes equal across providers, without collapsing genuinely distinct vertices.
GEOMETRY_PRECISION = 7


class SpatialOp(str, Enum):
    """The spatial operations a planner may select as capabilities (the engine implements them)."""
    POINT_IN_POLYGON = "POINT_IN_POLYGON"
    INTERSECTS = "INTERSECTS"
    WITHIN = "WITHIN"
    CONTAINS = "CONTAINS"
    OVERLAPS = "OVERLAPS"
    TOUCHES = "TOUCHES"
    DISTANCE = "DISTANCE"
    NEAREST = "NEAREST"
    BUFFER = "BUFFER"
    CENTROID = "CENTROID"
    SPATIAL_JOIN = "SPATIAL_JOIN"
    BBOX_QUERY = "BBOX_QUERY"
    REPROJECT = "REPROJECT"
    AREA = "AREA"


def geometry_hash(rings: "list[Ring]", crs: str) -> str:
    """Canonical, stable identity for a geometry — float-normalized, rounded coords + CRS, BLAKE2b-hashed.
    Same boundary in the same CRS → same id across providers. Int and float coordinate twins hash equal.
    The ``geo:`` prefix marks it as a geometry identity (distinct from the ``rcv1:`` envelope hash)."""
    norm = [[[round(float(x), GEOMETRY_PRECISION), round(float(y), GEOMETRY_PRECISION)] for x, y in ring]
            for ring in rings]
    payload = json.dumps({"crs": crs, "rings": norm}, sort_keys=True, separators=(",", ":"))
    return "geo:" + hashlib.blake2b(payload.encode(), digest_size=16).hexdigest()


@dataclass(frozen=True)
class GeoRef:
    """A typed geospatial reference carried with evidence. Extends, never replaces, `EvidenceRef`.

    ``geometry_hash`` is the geometry's content identity (from :func:`geometry_hash`); ``ref`` is the
    content-addressed identity of the whole reference envelope (``rcv1:…``), so two GeoRefs describing the
    same geometry with the same CRS/jurisdiction/validity share a ``ref``."""
    geometry_type: str                          # "Polygon" | "Point" | "MultiPolygon" | …
    geometry_hash: str                          # canonical geometry identity (from geometry_hash())
    crs: str                                    # explicit CRS/SRID, e.g. "EPSG:4326" — part of identity
    bbox: Tuple[float, float, float, float]     # (minx, miny, maxx, maxy)
    centroid: Coord
    jurisdiction: str = ""
    spatial_resolution: Optional[float] = None
    horizontal_accuracy: Optional[float] = None
    valid_time: str = ""                        # world-time validity (ISO); "" = -inf
    observed_at: str = ""                       # transaction time (when recorded)
    source: str = ""
    source_version: str = ""

    def canonical_form(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "geometry_type": self.geometry_type,
            "geometry_hash": self.geometry_hash,
            "crs": self.crs,
            "bbox": [float(v) for v in self.bbox],
            "centroid": [float(self.centroid[0]), float(self.centroid[1])],
        }
        for k, v in (("jurisdiction", self.jurisdiction), ("valid_time", self.valid_time),
                     ("observed_at", self.observed_at), ("source", self.source),
                     ("source_version", self.source_version)):
            if v:
                d[k] = v
        if self.spatial_resolution is not None:
            d["spatial_resolution"] = float(self.spatial_resolution)
        if self.horizontal_accuracy is not None:
            d["horizontal_accuracy"] = float(self.horizontal_accuracy)
        return d

    @property
    def ref(self) -> str:
        """Content-addressed identity of the reference envelope (``rcv1:…``).

        Hashes the identity-bearing fields only — the geometry (via its ``geometry_hash``), CRS,
        jurisdiction and spatiotemporal validity. bbox/centroid/resolution/accuracy are *derived* geometry
        metadata, not identity, and are excluded (they are also floats, which the canonical hash refuses by
        design — the geometry's own float determinism is already handled inside ``geometry_hash``)."""
        return content_hash({
            "geometry_type": self.geometry_type,
            "geometry_hash": self.geometry_hash,
            "crs": self.crs,
            "jurisdiction": self.jurisdiction or None,
            "valid_time": self.valid_time or None,
            "observed_at": self.observed_at or None,
            "source": self.source or None,
            "source_version": self.source_version or None,
        })
