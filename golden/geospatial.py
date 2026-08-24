"""Language-neutral golden vectors for the canonical geospatial evidence primitive.

A Go (or any) port reproduces these hashes from the same inputs, or it does not conform. Deterministic:
geometry_hash is BLAKE2b over rounded float-normalized coords; the GeoRef envelope ref is the rcv1
content hash over the identity-bearing string fields. Regenerate with `python -m golden.geospatial`.
"""
from __future__ import annotations

import json
import pathlib

from runtime_contracts.protocol.geospatial import GeoRef, geometry_hash

HERE = pathlib.Path(__file__).parent

# A small square parcel in EPSG:4326 — int/float coordinate twins must hash identically.
_RINGS = [[(0, 0), (0, 1), (1, 1), (1.0, 0.0)]]
_CRS = "EPSG:4326"


def cases() -> dict:
    out: dict = {}
    gh = geometry_hash(_RINGS, _CRS)
    out["geometry_hash_square"] = {
        "why": "canonical geometry identity — rounded float-normalized coords + CRS, blake2b",
        "hash": gh,
    }
    # Int vs float twins → same geometry hash.
    out["geometry_hash_int_float_twins_equal"] = {
        "why": "int coord (0) and float twin (0.0) hash identically",
        "equal": geometry_hash([[(0, 0), (0, 1), (1, 1), (1, 0)]], _CRS)
        == geometry_hash([[(0.0, 0.0), (0.0, 1.0), (1.0, 1.0), (1.0, 0.0)]], _CRS),
    }
    # Same geometry, different CRS → different identity (CRS is part of identity).
    out["geometry_hash_crs_is_identity"] = {
        "why": "same rings in a different CRS is a different geometry identity",
        "differs": geometry_hash(_RINGS, "EPSG:4326") != geometry_hash(_RINGS, "EPSG:2240"),
    }
    ref = GeoRef(
        geometry_type="Polygon", geometry_hash=gh, crs=_CRS,
        bbox=(0.0, 0.0, 1.0, 1.0), centroid=(0.5, 0.5),
        jurisdiction="us/ga/fulton", valid_time="2026-01-01T00:00:00Z", source="official_gis",
        source_version="2026.1")
    out["georef_envelope_ref"] = {
        "why": "rcv1 identity of the GeoRef envelope over its identity-bearing string fields",
        "ref": ref.ref,
    }
    # bbox/centroid are derived metadata, not identity: changing them does not change ref.
    ref2 = GeoRef(
        geometry_type="Polygon", geometry_hash=gh, crs=_CRS,
        bbox=(0.0, 0.0, 2.0, 2.0), centroid=(1.0, 1.0),           # different derived metadata
        jurisdiction="us/ga/fulton", valid_time="2026-01-01T00:00:00Z", source="official_gis",
        source_version="2026.1")
    out["georef_ref_ignores_derived_metadata"] = {
        "why": "bbox/centroid are derived, not identity — ref unchanged when only they differ",
        "same": ref.ref == ref2.ref,
    }
    return out


if __name__ == "__main__":
    payload = {"contract_version": "0.3.x", "cases": cases()}
    (HERE / "geospatial.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    print(json.dumps(payload["cases"], indent=2))
