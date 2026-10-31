"""AssertionSpec.check_program_ref: required for executor SCRIPT, hashed with the assertion (ADR A.4.2).

A missing reference is a spec validation failure; a program hash that no longer matches the pinned assertion set is
refused before execution as an assertion-integrity violation.
"""
from __future__ import annotations

import dataclasses

import pytest

from golden.qa_samples import d, script_assertion, ui_assertion
from runtime_contracts.qa import (AssertionSpec, CheckProgramRef, Code, Executor, QAContractError,
                                  assertion_set_hash)


def test_script_requires_a_check_program_ref():
    j = script_assertion().to_json()
    del j["check_program_ref"]
    j.pop("content_hash")
    with pytest.raises(QAContractError) as e:
        AssertionSpec.from_json(j)
    assert e.value.code == Code.CHECK_PROGRAM_REF_REQUIRED
    with pytest.raises(QAContractError) as e:
        dataclasses.replace(script_assertion(), check_program_ref=None)
    assert e.value.code == Code.CHECK_PROGRAM_REF_REQUIRED


def test_playwright_must_not_carry_one():
    with pytest.raises(QAContractError):
        dataclasses.replace(ui_assertion(), check_program_ref=script_assertion().check_program_ref)


def test_the_reference_is_hashed_with_the_assertion():
    base = script_assertion()
    other_program = script_assertion(program_hash=d(77))
    assert base.assertion_hash != other_program.assertion_hash
    assert assertion_set_hash([base]) != assertion_set_hash([other_program])


def test_program_identity_fields_are_each_hashed():
    ref = script_assertion().check_program_ref
    for change in (dict(id="another"), dict(version="2.0.0")):
        moved = dataclasses.replace(script_assertion(), check_program_ref=dataclasses.replace(ref, **change))
        assert moved.assertion_hash != script_assertion().assertion_hash


@pytest.mark.parametrize("bad", ["sha256:" + "0" * 16, "rcv1:" + "0" * 64, "0" * 64, ""])
def test_program_hash_is_the_full_sha256(bad):
    with pytest.raises(QAContractError):
        CheckProgramRef(id="p", version="1", program_hash=bad)


def test_playwright_assertions_hash_exactly_as_without_the_field():
    """Adding the optional field leaves every PLAYWRIGHT assertion's hash unchanged (absent equals null)."""
    a = ui_assertion()
    form = a.canonical_form()
    assert form.get("check_program_ref") is None
    from runtime_contracts import canonical
    assert a.assertion_hash == canonical.content_hash({k: v for k, v in form.items() if k != "check_program_ref"})


def test_round_trip():
    a = script_assertion()
    assert AssertionSpec.from_json(a.to_json()) == a and a.executor is Executor.SCRIPT
