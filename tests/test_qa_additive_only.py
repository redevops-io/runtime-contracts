"""qa/v1 is additive only: a committed field inventory, and a checker that fails on anything else.

Within qa/v1 a later change may add optional fields, new schemas and new enum members (with consumers failing closed
on unknown members). It may not remove, rename or retype a field, make an optional field required, move a field
between identity and custody, remove an enum member or change a protocol. ``golden/qa.inventory.json`` is the
baseline. Regenerating it for an additive change is deliberate and visible in review as additions only.
"""
from __future__ import annotations

import copy
import json

import pytest

from runtime_contracts.qa import inventory
from runtime_contracts.qa.inventory import DEFAULT_PATH, breaking_changes

BASELINE = json.loads(DEFAULT_PATH.read_text())


def test_the_committed_inventory_is_what_the_dataclasses_declare():
    assert DEFAULT_PATH.read_text() == inventory.render()


def test_nothing_in_the_baseline_has_been_removed_renamed_retyped_or_newly_required():
    assert breaking_changes(BASELINE, inventory.inventory()) == []


def test_the_inventory_covers_every_schema_value_enum_and_protocol():
    from runtime_contracts.qa.registry import ALL_ENUMS, PROTOCOLS, RECORDS, VALUES
    assert set(BASELINE["records"]) == {c.__name__ for c in RECORDS}
    assert set(BASELINE["values"]) == {c.__name__ for c in VALUES}
    assert set(BASELINE["enums"]) == set(ALL_ENUMS)
    assert set(BASELINE["protocols"]) == set(PROTOCOLS)
    assert BASELINE["api_versions"] == {"QAAdapter": "qa-adapter/1", "CheckAdapter": "qa-check-adapter/1"}


def test_every_package_class_is_registered():
    """A schema added to the package but forgotten in the registry would escape the inventory and the export."""
    import dataclasses
    import importlib
    import pkgutil

    import runtime_contracts.qa as qa
    from runtime_contracts.qa.base import QARecord, QAValue
    from runtime_contracts.qa.registry import RECORDS, VALUES
    known = {*RECORDS, *VALUES}
    defined = set()
    for info in pkgutil.iter_modules(qa.__path__):
        module = importlib.import_module(f"runtime_contracts.qa.{info.name}")
        for obj in vars(module).values():
            if (isinstance(obj, type) and issubclass(obj, QAValue) and obj not in (QAValue, QARecord)
                    and obj.__module__ == module.__name__ and dataclasses.is_dataclass(obj)):
                defined.add(obj)
    assert defined == known, f"unregistered: {sorted(c.__name__ for c in defined - known)}"


class TestTheCheckerCatchesEachBreakingChange:
    """The checker must fail for each kind of break, or the snapshot test above guards nothing."""

    def mutated(self, fn):
        doc = copy.deepcopy(BASELINE)
        fn(doc)
        return breaking_changes(BASELINE, doc)

    def test_removed_field(self):
        assert any("removed" in c for c in self.mutated(lambda d: d["records"]["TestSpec"]["fields"].pop("budget")))

    def test_renamed_field(self):
        def rename(d):
            f = d["records"]["TestSpec"]["fields"]
            f["spend_limit"] = f.pop("budget")
        assert any("budget" in c for c in self.mutated(rename))

    def test_retyped_field(self):
        def retype(d):
            d["records"]["TestSpec"]["fields"]["version"]["type"] = "str"
        assert any("retyped" in c for c in self.mutated(retype))

    def test_optional_field_made_required(self):
        def require(d):
            d["records"]["AssertionSpec"]["fields"]["requirement_ref"]["required"] = True
        assert any("became required" in c for c in self.mutated(require))

    def test_a_new_required_field(self):
        def add(d):
            d["records"]["TestSpec"]["fields"]["owner"] = {"type": "str", "required": True, "custody": False}
        assert any("required field" in c for c in self.mutated(add))

    def test_field_moved_between_identity_and_custody(self):
        def move(d):
            d["records"]["TestSpec"]["fields"]["author"]["custody"] = False
        assert any("custody" in c for c in self.mutated(move))

    def test_removed_schema(self):
        assert any("removed" in c for c in self.mutated(lambda d: d["records"].pop("QAPlan")))

    def test_changed_schema_id(self):
        def change(d):
            d["records"]["QAPlan"]["schema_id"] = "runtime-contracts/qa/plan"
        assert any("schema_id" in c for c in self.mutated(change))

    def test_removed_enum_member(self):
        assert any("lost member" in c for c in self.mutated(lambda d: d["enums"]["Executor"].remove("SCRIPT")))

    def test_removed_enum(self):
        assert any("removed" in c for c in self.mutated(lambda d: d["enums"].pop("Outcome")))

    def test_changed_protocol(self):
        def change(d):
            d["protocols"]["QAAdapter"]["methods"]["assert_"]["parameters"].append("expected")
        assert any("protocol" in c for c in self.mutated(change))

    def test_changed_api_version(self):
        assert self.mutated(lambda d: d["api_versions"].update(QAAdapter="qa-adapter/2"))

    def test_changed_contract_id(self):
        assert self.mutated(lambda d: d.update(contract="qa/v2"))


class TestAdditiveChangesAreAllowed:
    def mutated(self, fn):
        doc = copy.deepcopy(BASELINE)
        fn(doc)
        return breaking_changes(BASELINE, doc)

    def test_a_new_optional_field(self):
        def add(d):
            d["records"]["TestSpec"]["fields"]["notes"] = {"type": "Optional[str]", "required": False, "custody": True}
        assert self.mutated(add) == []

    def test_a_new_schema(self):
        def add(d):
            d["records"]["NewThing"] = {"schema_id": "runtime-contracts/qa/new-thing", "schema_version": "0.1",
                                        "fields": {}}
        assert self.mutated(add) == []

    def test_a_new_enum_member(self):
        assert self.mutated(lambda d: d["enums"]["Executor"].append("REMOTE")) == []

    def test_a_new_enum(self):
        assert self.mutated(lambda d: d["enums"].update(Fresh=["A"])) == []

    def test_a_new_value_type(self):
        assert self.mutated(lambda d: d["values"].update(Fresh={"fields": {}})) == []
