"""The JSON Schema export, checked against the golden fixtures.

For non-Python consumers. The exported schema is derived from the same annotations the validators use, so it states
structure (fields, types, enums, digest and identifier shapes, bounds, required, no other keys). It cannot state the
hash or cross-field rules; the golden fixtures carry those. There is no JSON Schema library in this repository's
dependencies, so a small validator for exactly the keywords the exporter emits is included here.
"""
from __future__ import annotations

import copy
import json
import re

import pytest

from golden.qa import CASES_PATH
from runtime_contracts.qa import schema_export
from runtime_contracts.qa.schema_export import DEFAULT_PATH, HASH_PATTERN

SCHEMA = json.loads(DEFAULT_PATH.read_text())
GOLDEN = json.loads(CASES_PATH.read_text())
DEFS = SCHEMA["$defs"]
BY_SCHEMA_ID = SCHEMA["x-records"]


def validate(instance, schema, path="$"):
    """Errors for the keywords the exporter emits: $ref, type, enum, const, pattern, length, bounds, required,
    properties, additionalProperties, items, uniqueItems."""
    errors = []
    if "$ref" in schema:
        return validate(instance, DEFS[schema["$ref"].rsplit("/", 1)[1]], path)
    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: expected {schema['const']!r}")
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: {instance!r} not in enum")
    kind = schema.get("type")
    if kind == "string":
        if not isinstance(instance, str):
            return errors + [f"{path}: not a string"]
        if "pattern" in schema and not re.search(schema["pattern"], instance):
            errors.append(f"{path}: {instance[:40]!r} does not match {schema['pattern']}")
        if len(instance) > schema.get("maxLength", 10 ** 9):
            errors.append(f"{path}: too long")
        if len(instance) < schema.get("minLength", 0):
            errors.append(f"{path}: too short")
    elif kind == "integer":
        if isinstance(instance, bool) or not isinstance(instance, int):
            return errors + [f"{path}: not an integer"]
        if instance < schema.get("minimum", -10 ** 18) or instance > schema.get("maximum", 10 ** 18):
            errors.append(f"{path}: out of bounds")
    elif kind == "boolean":
        if not isinstance(instance, bool):
            errors.append(f"{path}: not a boolean")
    elif kind == "array":
        if not isinstance(instance, list):
            return errors + [f"{path}: not an array"]
        if schema.get("uniqueItems") and len({json.dumps(i, sort_keys=True) for i in instance}) != len(instance):
            errors.append(f"{path}: items are not unique")
        for i, item in enumerate(instance):
            errors += validate(item, schema.get("items", {}), f"{path}[{i}]")
    elif kind == "object":
        if not isinstance(instance, dict):
            return errors + [f"{path}: not an object"]
        for name in schema.get("required", []):
            if name not in instance:
                errors.append(f"{path}: missing {name}")
        props = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for name in instance:
                if name not in props:
                    errors.append(f"{path}: unexpected {name}")
        for name, sub in props.items():
            if name in instance:
                errors += validate(instance[name], sub, f"{path}.{name}")
    return errors


def doc_for(case):
    doc = dict(case["input"])
    if "custody" in case:
        doc["custody"] = case["custody"]
    doc["content_hash"] = case["hash"]
    return doc


def test_the_committed_schema_is_what_the_dataclasses_generate():
    assert DEFAULT_PATH.read_text() == schema_export.render()


def test_it_is_draft_2020_12_and_names_the_contract():
    assert SCHEMA["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert SCHEMA["x-contract"] == "qa/v1" and SCHEMA["x-schema-version"] == "0.1"


def test_every_reference_resolves():
    refs = set(re.findall(r"#/\$defs/(\w+)", json.dumps(SCHEMA)))
    assert refs <= set(DEFS), refs - set(DEFS)


def test_every_record_schema_is_exported_with_its_identity():
    for schema_id, name in BY_SCHEMA_ID.items():
        props = DEFS[name]["properties"]
        assert props["schema_id"] == {"const": schema_id} and props["schema_version"] == {"const": "0.1"}
        assert props["content_hash"]["pattern"] == HASH_PATTERN
        assert {"schema_id", "schema_version"} <= set(DEFS[name]["required"])
        assert DEFS[name]["additionalProperties"] is False


def test_custody_is_exported_as_an_optional_object_and_never_required():
    assert "custody" in DEFS["TestSpec"]["properties"] and "custody" not in DEFS["TestSpec"]["required"]
    assert set(DEFS["TestSpec"]["properties"]["custody"]["properties"]) == {"author", "reviewer", "approved_at"}
    assert "author" not in DEFS["TestSpec"]["properties"]


@pytest.mark.parametrize("name", sorted(GOLDEN["cases"]))
def test_every_golden_case_validates_against_the_exported_schema(name):
    case = GOLDEN["cases"][name]
    target = DEFS[BY_SCHEMA_ID[case["schema_id"]]]
    assert validate(doc_for(case), target) == []


@pytest.mark.parametrize("name", sorted(GOLDEN["values"]))
def test_every_golden_value_validates_against_the_exported_schema(name):
    case = GOLDEN["values"][name]
    assert validate(case["input"], DEFS[case["type"]]) == []


def test_the_validator_can_fail():
    """A validator that never rejects proves nothing: break golden documents in ways the schema must catch."""
    case = GOLDEN["cases"]["test_spec_ui"]
    target = DEFS["TestSpec"]
    good = doc_for(case)
    assert validate(good, target) == []

    def broken(mutate):
        doc = copy.deepcopy(good)
        mutate(doc)
        return validate(doc, target)

    assert broken(lambda d: d.update(extra=1))                                         # unknown key
    assert broken(lambda d: d.pop("assertions"))                                       # missing required
    assert broken(lambda d: d.update(version="1"))                                     # wrong type
    assert broken(lambda d: d.update(version=0))                                       # below minimum
    assert broken(lambda d: d.update(id="has space"))                                  # identifier shape
    assert broken(lambda d: d.update(schema_version="9.9"))                            # const
    assert broken(lambda d: d["assertions"][0].update(executor="TELEPATHY"))           # enum
    assert broken(lambda d: d["assertions"][0].update(content_hash="rcv1:abc"))        # truncated hash
    assert broken(lambda d: d["fixtures"][0].update(content_hash="sha256:" + "0" * 16))   # truncated digest
    assert broken(lambda d: d["steps"][0]["target"].update(extra=1))                   # nested unknown key
    assert broken(lambda d: d.update(depends_on=["a@rcv1:" + "0" * 64, "a@rcv1:" + "0" * 64]))   # set uniqueness
    assert broken(lambda d: d.update(custody={"unknown": 1}))                          # custody keys


def test_the_schema_accepts_what_the_models_accept_and_rejects_the_refusals_it_can_express():
    """Structural refusals (unknown key, unknown enum value, wrong version) are visible to a JSON Schema user."""
    by_id = {r["id"]: r for r in GOLDEN["refusals"]}
    structural = {"plan_dynamic_dispatch_field": "QAPlan", "unknown_executor_is_non_certifying": "AssertionSpec",
                  "unknown_schema_version": "AssertionSpec"}
    for fid, name in structural.items():
        assert validate(by_id[fid]["input"], DEFS[name]), fid


def test_adapter_surfaces_have_no_expected_or_verdict_property():
    for name in ("ObservedValue", "ActionOutcome", "ActionRequest", "CheckSubject"):
        props = DEFS[name]["properties"]
        assert not [p for p in props if "expected" in p or "verdict" in p], name


def test_no_floats_are_expressible():
    text = json.dumps(SCHEMA)
    assert '"number"' not in text
