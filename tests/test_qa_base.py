"""The qa/v1 codec: strict parsing, identity versus custody, and the immutable containers.

Built on a toy schema so these rules are tested independently of any real qa/v1 object.
"""
from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from decimal import Decimal
from typing import Optional, Tuple

import pytest

from runtime_contracts import canonical
from runtime_contracts.qa.base import (Code, FrozenMap, Ident, Json, QAContractError, QARecord, QAValue,
                                       Rcv1, Sha256, SCHEMA_ID_PREFIX, UnknownEnumValue, freeze_json,
                                       strip_non_identity, thaw_json, value_digest, verify_stored_hash)
from runtime_contracts.qa.enums import Outcome


@dataclass(frozen=True)
class Inner(QAValue):
    SET_FIELDS = {"tags": None}

    name: Ident
    tags: Tuple[Ident, ...] = ()


@dataclass(frozen=True)
class Toy(QARecord):
    SCHEMA_ID = SCHEMA_ID_PREFIX + "toy"
    CUSTODY = frozenset({"note"})
    SET_FIELDS = {"inners": "name"}

    ident: Ident
    count: int
    outcome: Outcome
    inners: Tuple[Inner, ...] = ()
    payload: Optional[Json] = None
    digest: Optional[Rcv1] = None
    blob: Optional[Sha256] = None
    note: Optional[str] = None


def toy(**kw) -> Toy:
    base = dict(ident="t1", count=3, outcome=Outcome.PASS)
    base.update(kw)
    return Toy(**base)


class TestIdentityAndCustody:
    def test_custody_does_not_change_the_hash(self):
        assert toy(note="a").content_hash == toy(note="b").content_hash == toy().content_hash

    def test_identity_fields_change_the_hash(self):
        assert toy(count=4).content_hash != toy().content_hash

    def test_absent_equals_null(self):
        assert toy(payload=None).content_hash == toy().content_hash
        # and the hash of the identity form equals the hash of the same form with the null key dropped
        form = toy().canonical_form()
        assert canonical.content_hash(form) == canonical.content_hash({k: v for k, v in form.items() if v is not None})

    def test_sets_are_order_independent(self):
        a = toy(inners=(Inner(name="x"), Inner(name="y")))
        b = toy(inners=(Inner(name="y"), Inner(name="x")))
        assert a == b and a.content_hash == b.content_hash

    def test_nested_sets_are_sorted(self):
        assert Inner(name="n", tags=("b", "a")).tags == ("a", "b")

    def test_a_duplicate_in_a_set_is_refused(self):
        with pytest.raises(QAContractError) as e:
            toy(inners=(Inner(name="x"), Inner(name="x")))
        assert e.value.code == Code.DUPLICATE_ENTRY

    def test_strings_are_nfc(self):
        nfd = unicodedata.normalize("NFD", "café")
        assert toy(payload=nfd).payload == "café"
        assert toy(payload=nfd).content_hash == toy(payload="café").content_hash

    def test_the_hash_carries_the_schema_identity(self):
        form = toy().canonical_form()
        assert form["schema_id"] == "runtime-contracts/qa/toy" and form["schema_version"] == "0.1"


class TestNumbers:
    def test_floats_are_refused(self):
        with pytest.raises(QAContractError) as e:
            toy(payload={"x": 1.5})
        assert e.value.code == Code.FLOAT_REFUSED

    def test_a_float_for_an_integer_field_is_refused(self):
        with pytest.raises(QAContractError):
            toy(count=3.0)

    def test_a_boolean_is_not_an_integer(self):
        with pytest.raises(QAContractError):
            toy(count=True)

    def test_decimals_become_canonical_strings(self):
        assert toy(payload={"amount": Decimal("1.500")}).payload["amount"] == "1.5"


class TestImmutability:
    def test_attribute_assignment_is_refused(self):
        t = toy()
        with pytest.raises(Exception):
            t.count = 9  # type: ignore[misc]

    def test_json_objects_are_frozen(self):
        t = toy(payload={"a": [1, {"b": 2}]})
        assert isinstance(t.payload, FrozenMap)
        with pytest.raises(TypeError):
            t.payload["a"] = 1  # type: ignore[index]
        assert not hasattr(t.payload, "update") and not hasattr(t.payload, "pop")
        assert isinstance(t.payload["a"], tuple)

    def test_frozen_maps_compare_and_hash_by_content(self):
        assert FrozenMap({"a": 1, "b": 2}) == FrozenMap({"b": 2, "a": 1}) == {"a": 1, "b": 2}
        assert hash(FrozenMap({"a": 1})) == hash(FrozenMap({"a": 1}))

    def test_thaw_is_a_copy_for_serialization_only(self):
        t = toy(payload={"a": [1]})
        out = thaw_json(t.payload)
        out["a"].append(2)
        assert t.payload["a"] == (1,)

    def test_freeze_json_refuses_non_json(self):
        with pytest.raises(QAContractError):
            freeze_json({1: "x"})
        with pytest.raises(QAContractError):
            freeze_json(object())


class TestFieldRules:
    @pytest.mark.parametrize("bad", ["", "-x", "has space", "a" * 129, "a/b"])
    def test_identifiers_are_restricted(self, bad):
        with pytest.raises(QAContractError):
            toy(ident=bad)

    @pytest.mark.parametrize("bad", ["rcv1:abc", "sha256:" + "0" * 64, "rcv1:" + "G" * 64, "rcv1:" + "0" * 16])
    def test_record_hashes_must_be_full_width_rcv1(self, bad):
        with pytest.raises(QAContractError):
            toy(digest=bad)

    @pytest.mark.parametrize("bad", ["sha256:" + "0" * 16, "rcv1:" + "0" * 64, "sha256:" + "A" * 64, "0" * 64])
    def test_blob_digests_must_be_full_width_sha256(self, bad):
        with pytest.raises(QAContractError):
            toy(blob=bad)

    def test_control_characters_are_refused(self):
        with pytest.raises(QAContractError):
            toy(note="a\x00b")

    def test_an_oversized_json_value_is_refused(self):
        with pytest.raises(QAContractError):
            toy(payload={"k": "x" * 17000})

    def test_unknown_enum_value_is_refused_by_name(self):
        with pytest.raises(UnknownEnumValue):
            toy(outcome="MAYBE")


class TestCodec:
    def test_round_trip_is_lossless_including_custody(self):
        t = toy(inners=(Inner(name="x", tags=("a",)),), payload={"k": [1, "v"]}, note="n",
                digest="rcv1:" + "1" * 64)
        again = Toy.from_json(t.to_json())
        assert again == t and again.note == "n" and again.content_hash == t.content_hash

    def test_to_json_omits_nulls_and_nests_custody(self):
        j = toy(note="n").to_json()
        assert "payload" not in j and j["custody"] == {"note": "n"} and j["content_hash"] == toy().content_hash

    def test_unknown_key_is_refused(self):
        j = toy().to_json()
        j["extra"] = 1
        with pytest.raises(QAContractError) as e:
            Toy.from_json(j)
        assert e.value.code == Code.UNKNOWN_FIELD

    def test_unknown_custody_key_is_refused(self):
        j = toy().to_json()
        j["custody"] = {"count": 1}
        with pytest.raises(QAContractError) as e:
            Toy.from_json(j)
        assert e.value.code == Code.UNKNOWN_FIELD

    def test_wrong_schema_id_is_refused(self):
        j = toy().to_json()
        j["schema_id"] = "runtime-contracts/qa/other"
        with pytest.raises(QAContractError) as e:
            Toy.from_json(j)
        assert e.value.code == Code.SCHEMA_MISMATCH

    @pytest.mark.parametrize("version", ["1.0", "0.2", "2", None])
    def test_unknown_schema_version_fails_closed(self, version):
        j = toy().to_json()
        j["schema_version"] = version
        with pytest.raises(QAContractError) as e:
            Toy.from_json(j)
        assert e.value.code == Code.SCHEMA_VERSION_UNSUPPORTED

    def test_a_stored_hash_that_does_not_match_is_refused(self):
        j = toy().to_json()
        j["count"] = 99
        with pytest.raises(QAContractError) as e:
            Toy.from_json(j)
        assert e.value.code == Code.HASH_MISMATCH

    def test_a_missing_required_field_is_refused(self):
        j = toy().to_json()
        del j["count"]
        j.pop("content_hash")
        with pytest.raises(QAContractError) as e:
            Toy.from_json(j)
        assert e.value.code == Code.MISSING_FIELD

    def test_a_non_object_is_refused(self):
        with pytest.raises(QAContractError):
            Toy.from_json([1])  # type: ignore[arg-type]

    def test_a_string_for_a_list_is_refused(self):
        j = toy().to_json()
        j["inners"] = "x"
        j.pop("content_hash")
        with pytest.raises(QAContractError):
            Toy.from_json(j)


class TestForwardRead:
    """A reader older than a writer (same major) verifies the bytes it received, not a field list it half knows."""

    def test_stored_hash_verifies_without_a_model(self):
        assert verify_stored_hash(toy(note="n", inners=(Inner(name="x"),)).to_json())

    def test_an_additive_field_is_covered_by_the_stored_hash(self):
        t = toy()
        form = dict(t.canonical_form())
        form["added_later"] = "v"   # a newer writer's optional field
        newer = {**form, "content_hash": canonical.content_hash(form)}
        assert verify_stored_hash(newer)
        with pytest.raises(QAContractError):
            Toy.from_json(newer)    # the strict reader refuses what it does not model; it does not guess

    def test_a_tampered_payload_fails(self):
        j = toy().to_json()
        j["count"] = 4
        assert not verify_stored_hash(j)

    def test_only_records_are_stripped(self):
        payload = {"schema_id": SCHEMA_ID_PREFIX + "x", "content_hash": "rcv1:" + "0" * 64, "custody": {"a": 1},
                   "ref": {"content_hash": "keep"}}
        assert strip_non_identity(payload) == {"schema_id": SCHEMA_ID_PREFIX + "x", "ref": {"content_hash": "keep"}}

    def test_a_payload_without_a_stored_hash_does_not_verify(self):
        assert not verify_stored_hash({"a": 1})


def test_value_digest_is_the_rcv1_hash_of_the_nfc_string():
    assert value_digest("hunter2") == canonical.content_hash("hunter2")
    assert value_digest(unicodedata.normalize("NFD", "café")) == value_digest("café")
