"""LEAK GUARD: qa/v1 carries no ground truth, no scoring and no sealed-case vocabulary, anywhere.

The contracts describe what a run expects and what it did. What is true of a case, how a run is scored and how
cases are sealed or mutated all live outside this package. If any of that vocabulary appears in a field, an enum,
a schema id, the exported JSON Schema, the fixtures' payloads or this package's source, a system under test could
learn something it must not know. This test fails on any such word.
"""
from __future__ import annotations

import dataclasses
import enum
import inspect
import json
import pathlib
import re

import pytest

from golden.qa import CASES_PATH, VECTORS_PATH
from runtime_contracts.qa import schema_export
from runtime_contracts.qa.registry import ALL_ENUMS, PROTOCOLS, RECORDS, VALUES
from runtime_contracts.qa.schema_export import _foreign_dataclasses

QA_DIR = pathlib.Path(__file__).resolve().parent.parent / "runtime_contracts" / "qa"

#: Names that must never be a field, an enum member or an enum value of a run-side schema.
FORBIDDEN_NAME = re.compile(
    r"^(track|population|category|truth_class|defect_present|effect_signature|witness.*|false_pass|missed_defect|"
    r"miss_reason|injected_fault|certification_ref|contradiction_ref|case_id|lock_hash|expected_defect)$", re.I)

#: Vocabulary that must not appear anywhere in the package (source, comments, docstrings, schemas, payload keys).
#: ``category`` is deliberately absent: it is a documented attribute of QAAdapterError, not a schema field.
FORBIDDEN_WORDS = re.compile(
    r"seal(?:ed|s|ing)?\b|\bseals?\b|mutat\w*|mutant\w*|ground[ _-]?truth|injected[ _-]?fault|score[ _-]?record|"
    r"false[ _-]?pass|missed[ _-]?defect|miss[ _-]?reason|\boracle\w*|witness\w*|effect[ _-]?signature|"
    r"defect[ _-]?present|truth[ _-]?class|\bbenchmark\w*|lock[ _-]?hash|\bpopulation\b|\bheld[ _-]?out\b|"
    r"\btrack\b|\btracks\b", re.I)


def all_dataclasses():
    return [*RECORDS, *VALUES, *_foreign_dataclasses().values()]


def keys_of(value):
    if isinstance(value, dict):
        for k, v in value.items():
            yield k
            yield from keys_of(v)
    elif isinstance(value, list):
        for v in value:
            yield from keys_of(v)


@pytest.mark.parametrize("cls", all_dataclasses(), ids=lambda c: c.__name__)
def test_no_schema_has_a_forbidden_field(cls):
    bad = [f.name for f in dataclasses.fields(cls) if FORBIDDEN_NAME.match(f.name)]
    assert not bad, f"{cls.__name__} has forbidden field(s) {bad}"


@pytest.mark.parametrize("name", sorted(ALL_ENUMS))
def test_no_enum_member_or_value_is_forbidden(name):
    for member in ALL_ENUMS[name]:
        assert not FORBIDDEN_NAME.match(member.name), f"{name}.{member.name}"
        assert not FORBIDDEN_NAME.match(str(member.value)), f"{name}={member.value}"


def test_protocol_methods_and_attributes_are_clean():
    for name, proto in PROTOCOLS.items():
        members = [n for n in vars(proto) if not n.startswith("_")] + list(getattr(proto, "__annotations__", {}))
        assert not [m for m in members if FORBIDDEN_NAME.match(m)], name


def test_schema_ids_are_clean():
    for cls in RECORDS:
        assert not FORBIDDEN_WORDS.search(cls.SCHEMA_ID), cls.SCHEMA_ID


def test_the_package_source_never_uses_the_vocabulary():
    hits = []
    for path in sorted(QA_DIR.glob("*.py")):
        for n, line in enumerate(path.read_text().splitlines(), 1):
            if FORBIDDEN_WORDS.search(line):
                hits.append(f"{path.name}:{n}: {line.strip()}")
    assert not hits, "ground-truth, scoring or sealed-case vocabulary in qa/v1:\n" + "\n".join(hits)


def test_the_exported_json_schema_is_clean():
    text = schema_export.render()
    assert not FORBIDDEN_WORDS.search(text)
    names = {k for k in keys_of(json.loads(text))}
    assert not [n for n in names if FORBIDDEN_NAME.match(n)]


def test_fixture_payload_keys_are_clean():
    """The instances in the fixtures are instances of the contracts, so their keys must be clean too."""
    doc = json.loads(CASES_PATH.read_text())
    for group in ("cases", "values"):
        for name, case in doc[group].items():
            bad = [k for k in keys_of(case["input"]) if FORBIDDEN_NAME.match(k)]
            assert not bad, f"{group}.{name}: {bad}"
            assert not FORBIDDEN_WORDS.search(json.dumps(case["input"])), f"{group}.{name}"
    for vec in json.loads(VECTORS_PATH.read_text())["vectors"]:
        assert not [k for k in keys_of(vec["input"]) if FORBIDDEN_NAME.match(k)], vec["id"]


def test_the_manifest_and_plan_say_nothing_about_a_track_or_a_case():
    for cls in (*RECORDS,):
        names = {f.name for f in dataclasses.fields(cls)}
        assert not names & {"track", "case_id", "arm", "population", "truth_class"}, cls.__name__


def test_the_guard_itself_fires_on_the_vocabulary():
    for word in ("sealed", "mutation", "ground truth", "false_pass", "benchmark", "witness_id", "track"):
        assert FORBIDDEN_WORDS.search(word) or FORBIDDEN_NAME.match(word), word
    for field in ("track", "population", "category", "truth_class", "defect_present", "effect_signature",
                  "witness", "witness_ref"):
        assert FORBIDDEN_NAME.match(field), field
    assert not FORBIDDEN_NAME.match("tracking_id") and not FORBIDDEN_NAME.match("assertion_id")
