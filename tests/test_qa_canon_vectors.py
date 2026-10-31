"""golden/qa_canon_vectors.json is self-contained: an independent canonicalizer needs only this file.

The canonicalizer below is deliberately NOT runtime_contracts.canonical. It is a second, minimal implementation of
the published rcv1 rules written from docs/canonicalization.md, using only the standard library. If the vectors pass
under both, they describe the rules and not one implementation's behaviour. (The harness has its own canon-v1; this
is the shape of what it consumes.)
"""
from __future__ import annotations

import hashlib
import json
import unicodedata

import pytest

from golden.qa import VECTORS_PATH
from runtime_contracts import canonical

DOC = json.loads(VECTORS_PATH.read_text())


class Refused(Exception):
    pass


def reduce(value):
    if value is None or isinstance(value, bool) or isinstance(value, int):
        return value
    if isinstance(value, float):
        raise Refused("float")
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [reduce(v) for v in value]
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            r = reduce(v)
            if r is not None:
                out[unicodedata.normalize("NFC", k)] = r
        return out
    raise Refused(type(value).__name__)


def canon_bytes(value) -> str:
    return json.dumps(reduce(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


@pytest.mark.parametrize("vec", DOC["vectors"], ids=lambda v: v["id"])
def test_independent_canonicalizer_reproduces_the_bytes_and_digest(vec):
    text = canon_bytes(vec["input"])
    assert text == vec["canonical_json"]
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    assert digest == vec["sha256_hex"]
    assert vec["rcv1"] == "rcv1:" + digest


@pytest.mark.parametrize("vec", DOC["vectors"], ids=lambda v: v["id"])
def test_the_repository_canonicalizer_agrees(vec):
    assert canonical.canonical_json(vec["input"]) == vec["canonical_json"]
    assert canonical.content_hash(vec["input"]) == vec["rcv1"]


@pytest.mark.parametrize("vec", DOC["refusals"], ids=lambda v: v["id"])
def test_floats_are_refused_by_both(vec):
    with pytest.raises(Refused):
        canon_bytes(vec["input"])
    with pytest.raises(canonical.CanonicalizationError):
        canonical.canonical_json(vec["input"])


def test_the_file_explains_how_to_use_it_and_each_vector_says_why():
    assert "sha256_hex" in DOC["how_to_use"] and "refused" in DOC["how_to_use"]
    assert all(v["why"] for v in DOC["vectors"]) and all(r["why"] for r in DOC["refusals"])


def test_the_file_names_its_contract_and_covers_the_portability_traps():
    ids = {v["id"] for v in DOC["vectors"]}
    assert DOC["contract"] == "qa/v1" and DOC["canonicalization"] == "rcv1"
    assert {"key_order_is_code_point_order", "nfc_normalization", "null_dropped_in_map", "string_escapes",
            "non_ascii_is_not_escaped", "decimal_string_stays_a_string"} <= ids
    assert any(i.startswith("qa:") for i in ids) and any(i.startswith("qa-assertion-set:") for i in ids)


def test_the_vector_file_depends_on_nothing_else():
    """Every value is literal JSON; no reference to a Python object, a path or another fixture."""
    text = VECTORS_PATH.read_text()
    assert "runtime_contracts" not in text.replace('"schema_id": "runtime-contracts', "")
    json.loads(text)


def test_key_order_is_by_code_point_not_utf16_unit():
    vec = next(v for v in DOC["vectors"] if v["id"] == "key_order_is_code_point_order")
    assert vec["canonical_json"].index("") < vec["canonical_json"].index("\U0001f600")
