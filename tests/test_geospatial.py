"""Canonical geospatial evidence primitive — geometry identity + GeoRef envelope identity, and the
golden vectors a Go port must reproduce."""
import json
import pathlib

from runtime_contracts import GeoRef, SpatialOp, geometry_hash

from golden.geospatial import cases

GOLDEN = json.loads((pathlib.Path(__file__).parent.parent / "golden" / "geospatial.json").read_text())


def test_geometry_hash_is_stable_and_prefixed():
    h = geometry_hash([[(0, 0), (0, 1), (1, 1), (1, 0)]], "EPSG:4326")
    assert h.startswith("geo:") and len(h) == len("geo:") + 32


def test_int_and_float_coord_twins_hash_equal():
    a = geometry_hash([[(0, 0), (1, 1)]], "EPSG:4326")
    b = geometry_hash([[(0.0, 0.0), (1.0, 1.0)]], "EPSG:4326")
    assert a == b


def test_crs_is_part_of_geometry_identity():
    rings = [[(0, 0), (0, 1), (1, 1), (1, 0)]]
    assert geometry_hash(rings, "EPSG:4326") != geometry_hash(rings, "EPSG:2240")


def test_georef_ref_is_identity_not_derived_metadata():
    gh = geometry_hash([[(0, 0), (0, 1), (1, 1), (1, 0)]], "EPSG:4326")
    a = GeoRef(geometry_type="Polygon", geometry_hash=gh, crs="EPSG:4326",
               bbox=(0, 0, 1, 1), centroid=(0.5, 0.5), jurisdiction="us/ga/fulton", source="official_gis")
    b = GeoRef(geometry_type="Polygon", geometry_hash=gh, crs="EPSG:4326",
               bbox=(0, 0, 9, 9), centroid=(4.5, 4.5), jurisdiction="us/ga/fulton", source="official_gis")
    assert a.ref == b.ref and a.ref.startswith("rcv1:")          # bbox/centroid are derived, not identity
    c = GeoRef(geometry_type="Polygon", geometry_hash=gh, crs="EPSG:2240",   # different CRS → different id
               bbox=(0, 0, 1, 1), centroid=(0.5, 0.5), jurisdiction="us/ga/fulton", source="official_gis")
    assert a.ref != c.ref


def test_spatial_op_vocabulary_present():
    assert SpatialOp.POINT_IN_POLYGON.value == "POINT_IN_POLYGON"
    assert "REPROJECT" in {op.value for op in SpatialOp}


def test_committed_golden_vectors_reproduce():
    assert cases() == GOLDEN["cases"]
