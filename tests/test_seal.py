"""The seal identity is the cross-language contract. These golden vectors pin the
`rcv1:` digests a Go or Kotlin port must reproduce byte-for-byte, and the semantic
rules that make the identity meaningful: floats quantized (noise-free), evidence
and unresolved order-independent, lists inside `interpreted` order-significant,
schema/version and contract-version part of identity, provenance excluded.
"""
from __future__ import annotations

import json
from pathlib import Path

import runtime_contracts as rc

GOLDEN = json.loads((Path(__file__).parent / "golden_seal_vectors.json").read_text())


def test_golden_seal_vectors_reproduce():
    assert GOLDEN["canonicalization_version"] == rc.CANONICALIZATION_VERSION
    assert GOLDEN["seal_contract_version"] == rc.SEAL_CONTRACT_VERSION
    for c in GOLDEN["seal_cases"]:
        got = rc.seal_hash(c["interpreted"], c["evidence"], c["unresolved"],
                           payload_schema=c["payload_schema"],
                           payload_schema_version=c["payload_schema_version"])
        assert got == c["expected_seal_hash"], c["name"]
    for c in GOLDEN["content_cases"]:
        assert rc.content_hash(c["value"]) == c["expected_content_hash"], c["name"]


def test_digests_are_decimal_canonical_not_float():
    # rcv1 prefix, and float noise is absorbed by the seal number policy
    h = rc.content_hash({"a": 1})
    assert h.startswith("rcv1:")
    assert rc.content_hash({"w": 0.1 + 0.2}) == rc.content_hash({"w": 0.3})
    assert rc.content_hash({"w": 0.60}) == rc.content_hash({"w": 0.6})


def test_evidence_and_unresolved_are_order_independent():
    ev = [{"field": "a", "source_ref": "x"}, {"field": "b", "source_ref": "y"}]
    a = rc.seal_hash({"o": "x"}, ev, payload_schema="s", payload_schema_version="1")
    b = rc.seal_hash({"o": "x"}, list(reversed(ev)),
                     payload_schema="s", payload_schema_version="1")
    assert a == b                                   # sets: order does not matter


def test_lists_inside_interpreted_are_order_significant():
    a = rc.content_hash({"steps": [1, 2, 3]})
    b = rc.content_hash({"steps": [3, 2, 1]})
    assert a != b                                   # an ordered policy != its reverse


def test_schema_and_contract_version_participate_in_identity():
    base = dict(interpreted={"o": "x"}, payload_schema="s", payload_schema_version="1")
    h1 = rc.seal_hash(**base)
    h2 = rc.seal_hash(**{**base, "payload_schema": "other"})
    h3 = rc.seal_hash(**base, contract_version="9.9.9")
    assert len({h1, h2, h3}) == 3                   # each dimension changes identity
