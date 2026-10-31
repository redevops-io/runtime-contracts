"""The qa/v1 golden fixtures, reproduced from the models.

A port in another language reproduces these hashes from the same inputs, or it does not conform. Regenerating and
re-asserting would prove nothing, so the committed files are the reference and the models are checked against them.
"""
from __future__ import annotations

import json
import pathlib

import pytest

from golden import qa as golden_qa
from golden.qa import CASES_PATH, VECTORS_PATH
from runtime_contracts import canonical
from runtime_contracts.qa import QA_CONTRACT_ID
from runtime_contracts.qa.registry import RECORDS, VALUES

GOLDEN = json.loads(CASES_PATH.read_text())
CASES = GOLDEN["cases"]
BY_ID = {cls.SCHEMA_ID: cls for cls in RECORDS}


def payload(case):
    """The full wire document for a case: identity, custody and the stored hash."""
    doc = dict(case["input"])
    if "custody" in case:
        doc["custody"] = case["custody"]
    doc["content_hash"] = case["hash"]
    return doc


def test_the_committed_fixtures_still_reproduce():
    """Any change to canonicalization or to a schema's identity must be a deliberate fixture update."""
    assert golden_qa.cases() == GOLDEN


def test_the_committed_vector_file_still_reproduces():
    assert golden_qa.canon_vectors() == json.loads(VECTORS_PATH.read_text())


def test_the_files_are_generated_by_the_documented_command():
    assert CASES_PATH.read_text() == golden_qa._dump(golden_qa.cases())
    assert VECTORS_PATH.read_text() == golden_qa._dump(golden_qa.canon_vectors())


def test_the_fixture_names_the_contract_and_the_canonicalization():
    assert GOLDEN["contract"] == QA_CONTRACT_ID == "qa/v1" and GOLDEN["canonicalization"] == "rcv1"


def test_every_record_schema_has_a_golden_case():
    covered = {case["schema_id"] for case in CASES.values()}
    assert covered == {cls.SCHEMA_ID for cls in RECORDS}


def test_every_value_type_has_a_golden_case():
    covered = {case["type"] for case in GOLDEN["values"].values()}
    assert covered == {cls.__name__ for cls in VALUES}


def test_every_case_states_why_it_exists():
    for group in ("cases", "values", "assertion_sets"):
        for name, case in GOLDEN[group].items():
            assert case.get("why"), f"{group}.{name} does not say what it protects"
    for refusal in GOLDEN["refusals"]:
        assert refusal.get("why"), refusal["id"]


@pytest.mark.parametrize("name", sorted(CASES))
def test_a_case_hash_is_the_rcv1_hash_of_its_input_alone(name):
    """Recomputed from the JSON in the file with the repository's own rcv1 code, never by hand."""
    case = CASES[name]
    assert canonical.content_hash(case["input"]) == case["hash"]
    assert case["hash"].startswith("rcv1:") and len(case["hash"]) == len("rcv1:") + 64


@pytest.mark.parametrize("name", sorted(CASES))
def test_a_case_loads_and_round_trips_through_the_models(name):
    case = CASES[name]
    cls = BY_ID[case["schema_id"]]
    obj = cls.from_json(payload(case))
    assert obj.content_hash == case["hash"]
    assert obj.canonical_form() is not None
    assert cls.from_json(obj.to_json()) == obj


@pytest.mark.parametrize("name", sorted(CASES))
def test_custody_fields_are_not_in_the_hashed_input(name):
    case = CASES[name]
    cls = BY_ID[case["schema_id"]]
    assert not set(case["input"]) & set(cls.CUSTODY)
    assert "custody" not in case["input"] and "content_hash" not in case["input"]
    assert set(case.get("custody", {})) <= set(cls.CUSTODY)


@pytest.mark.parametrize("name", sorted(GOLDEN["values"]))
def test_a_value_hash_is_reproducible_from_its_input(name):
    case = GOLDEN["values"][name]
    assert canonical.content_hash(case["input"]) == case["hash"]


class TestHashRelations:
    SETS = GOLDEN["assertion_sets"]

    @pytest.mark.parametrize("name", sorted(SETS))
    def test_a_set_hash_is_reproducible_from_its_assertions(self, name):
        case = self.SETS[name]
        wrapped = {"schema_id": "runtime-contracts/qa/assertion-set", "schema_version": "0.1",
                   "assertions": case["assertions"]}
        assert canonical.content_hash(wrapped) == case["hash"]

    @pytest.mark.parametrize("rel", [r for r in GOLDEN["relations"] if "equal" in r], ids=lambda r: r["why"][:40])
    def test_these_do_not_change_the_hash(self, rel):
        hashes = {self.SETS[n]["hash"] for n in rel["equal"]}
        assert len(hashes) == 1, rel["why"]

    @pytest.mark.parametrize("rel", [r for r in GOLDEN["relations"] if "differ" in r], ids=lambda r: r["why"][:40])
    def test_these_must_change_the_hash(self, rel):
        for a, b in rel["differ"]:
            assert self.SETS[a]["hash"] != self.SETS[b]["hash"], f"{a} vs {b}: {rel['why']}"

    def test_absent_equals_null(self):
        p = GOLDEN["hash_properties"]["absent_equals_null"]
        assert p["omitted"] == p["explicit_null"]
        assert CASES["assertion_spec_without_requirement_ref"]["hash"] != CASES["assertion_spec_playwright"]["hash"]

    def test_custody_is_excluded(self):
        p = GOLDEN["hash_properties"]["custody_excluded"]
        assert p["spec_hash_a"] == p["spec_hash_b"]
        assert CASES["test_spec_ui"]["custody"] == {"author": "author-1"}

    def test_the_manifest_cases_differ_where_the_accounting_differs(self):
        assert (CASES["run_manifest_pass"]["hash"] != CASES["run_manifest_inconclusive_skipped"]["hash"]
                != CASES["run_manifest_assertion_integrity"]["hash"])


def test_a_new_optional_field_leaves_every_existing_hash_unchanged():
    """Absent equals null, so adding an optional field to a schema cannot move the hash of an object that omits it.

    Shown on the real fixtures: dropping the optional fields from an input changes nothing, and dropping a required
    field does.
    """
    case = CASES["assertion_spec_without_requirement_ref"]
    padded = dict(case["input"], future_optional_field=None)
    assert canonical.content_hash(padded) == case["hash"]
    assert canonical.content_hash(dict(case["input"], future_optional_field="v")) != case["hash"]
