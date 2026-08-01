"""The canonicalization rules, each with the failure it prevents."""
from __future__ import annotations

import unicodedata
from decimal import Decimal

import pytest

from runtime_contracts import CanonicalizationError, canonical_json, canonicalize, content_hash


class TestAmbiguityIsRefusedNotResolved:
    def test_floats_are_refused(self):
        """Python, Go and JS do not print the same digits for one double."""
        with pytest.raises(CanonicalizationError, match="do not agree"):
            canonicalize({"cost": 0.1})

    def test_decimals_are_accepted_as_strings(self):
        assert canonicalize(Decimal("0.10")) == "0.1"

    def test_sets_are_refused(self):
        with pytest.raises(CanonicalizationError, match="no defined order"):
            canonicalize({"tags": {"a", "b"}})

    def test_non_string_map_keys_are_refused(self):
        with pytest.raises(CanonicalizationError, match="not a string"):
            canonicalize({1: "x"})

    def test_unknown_types_are_refused_rather_than_stringified(self):
        class Thing:
            pass

        with pytest.raises(CanonicalizationError, match="no canonical"):
            canonicalize(Thing())


class TestEquivalenceRules:
    def test_null_and_absent_are_the_same(self):
        assert content_hash({"a": 1, "b": None}) == content_hash({"a": 1})

    def test_key_order_is_irrelevant(self):
        assert content_hash({"a": 1, "b": 2}) == content_hash({"b": 2, "a": 1})

    def test_unicode_normalizes_to_nfc(self):
        nfd = unicodedata.normalize("NFD", "café")
        assert nfd != "café"
        assert content_hash({"id": "café"}) == content_hash({"id": nfd})

    def test_list_order_is_preserved(self):
        """Sequences mean order; only maps are unordered."""
        assert content_hash([1, 2]) != content_hash([2, 1])

    def test_the_hash_carries_its_rules(self):
        assert content_hash({}).startswith("rcv1:")

    def test_serialization_is_compact_and_stable(self):
        assert canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'
