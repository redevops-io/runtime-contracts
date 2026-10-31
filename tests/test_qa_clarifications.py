"""The qa/v1 clarifications: definitions the frozen text left implicit, added without changing any existing hash.

Covers the expected_hash of a predicate, the digest of a value, the idempotency key, the ordering of set-valued
fields, the distinct integrity refusal codes, ``FaultRecovery.reason_code`` and the identity boundary of engine
limits and kill-switch state. Every claim is checked against the committed fixtures and, where it is a hash or an
order, against a second implementation written only from the published rules.
"""
from __future__ import annotations

import collections
import copy
import dataclasses
import enum
import hashlib
import importlib
import json
import pathlib
import subprocess
import unicodedata

import pytest

from golden import qa as base_golden
from golden import qa_clarifications as C
from golden import qa_samples as S
from runtime_contracts import canonical
from runtime_contracts.models.verification import Verdict
from runtime_contracts.qa import (Action, ActionKind, ActionRecord, AssertionSpec, CheckProgramRef, Code,
                                  FaultRecovery, IntegrityRefusalCode, Outcome, Predicate, PredicateOp,
                                  QAContractError, RecoveryReason, RecoveryResult, RunManifest, SuppressedReason,
                                  UnknownEnumValue, action_value_digest, check_batch_not_halted, classify_refusal,
                                  default_exit_code, idempotency_key_violations, json_value_digest,
                                  load_pinned_assertion_set, outcome_to_verdict, refusal_halts_batch, value_digest,
                                  verify_assertion_set, verify_check_program, verify_manifest_against_spec,
                                  verify_pin_well_formed, verify_stored_hash)
from runtime_contracts.qa import integrity, inventory
from runtime_contracts.qa.base import _hints
from runtime_contracts.qa.integrity import (INTEGRITY_REFUSAL_CODES, INTEGRITY_REFUSAL_CODES_ADDED,
                                            INTEGRITY_REFUSAL_CODES_ORIGINAL, OTHER_KNOWN_CODES)
from runtime_contracts.qa.registry import ALL_ENUMS, RECORDS, VALUES
from runtime_contracts.qa.schema_export import _foreign_dataclasses

ROOT = pathlib.Path(__file__).resolve().parent.parent
GOLDEN = ROOT / "golden"
ADDENDUM = json.loads((GOLDEN / "qa_canon_vectors_addendum.json").read_text())
CLARIFICATIONS = json.loads((GOLDEN / "qa_clarifications.json").read_text())
C3_TIP = "13e00f23da74782af091aec607c47358e9814fc6"

#: sha256 of the files that stay byte-identical from the frozen interface onward.
FROZEN_FILES = {
    "golden/qa.json": "2aaed7aace5b9952ef56f43f73edc1745a15da4d1f83db92c7aad5af279bf5e1",
    "golden/qa_canon_vectors.json": "7241c570746a63e75431591b88e42562f6604fc2a8586474a267eedb51908a13",
}
#: sha256 of the two files that changed additively, as they were at the frozen interface.
C3_SCHEMA_SHA = "8d61738f488ddca2cad6a0eebd688f1d1fa2d5f2b1b7fd3904b97f93abc0cb22"
C3_INVENTORY_SHA = "8ebd0be1488233966ba66dc2cbb7c46b42ec3973a246f405e905130a4d28ba57"


def sha(path: str) -> str:
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def git_show(path: str):
    done = subprocess.run(["git", "show", f"{C3_TIP}:{path}"], cwd=ROOT, capture_output=True)
    return done.stdout if done.returncode == 0 else None


# ── a second canonicalizer, written only from the published rcv1 rules ─────────────────────────────────────

class Refused(Exception):
    pass


def reduce(value):
    if value is None or isinstance(value, (bool, int)):
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


def text(value) -> str:
    return json.dumps(reduce(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def rcv1(value) -> str:
    return "rcv1:" + hashlib.sha256(text(value).encode("utf-8")).hexdigest()


# ── nothing frozen changed ─────────────────────────────────────────────────────────────────────────────────

class TestNothingFrozenChanged:
    @pytest.mark.parametrize("path", sorted(FROZEN_FILES))
    def test_frozen_files_are_byte_identical(self, path):
        assert sha(path) == FROZEN_FILES[path]

    def test_the_97_vectors_and_3_refusals_are_still_there(self):
        base = json.loads((GOLDEN / "qa_canon_vectors.json").read_text())
        assert len(base["vectors"]) == 97 and len(base["refusals"]) == 3

    @pytest.mark.parametrize("path", sorted(FROZEN_FILES))
    def test_frozen_files_equal_the_interface_commit(self, path):
        old = git_show(path)
        if old is None:
            pytest.skip("the frozen interface commit is not visible in this checkout")
        assert (ROOT / path).read_bytes() == old

    def test_the_schema_and_inventory_only_grew(self):
        for path, key in (("golden/qa.schema.json", "schema"), ("golden/qa.inventory.json", "inventory")):
            old = git_show(path)
            if old is None:
                pytest.skip("the frozen interface commit is not visible in this checkout")
            new = (ROOT / path).read_text().splitlines()
            before = old.decode().splitlines()
            matcher = __import__("difflib").SequenceMatcher(a=before, b=new, autojunk=False)
            removed = [op for op in matcher.get_opcodes() if op[0] in ("delete", "replace")]
            assert not removed, f"{path}: lines were removed or replaced: {removed}"

    def test_the_inventory_checker_accepts_the_change(self):
        old = git_show("golden/qa.inventory.json")
        if old is None:
            pytest.skip("the frozen interface commit is not visible in this checkout")
        assert inventory.breaking_changes(json.loads(old), inventory.inventory()) == []

    def test_every_golden_case_still_has_its_hash(self):
        golden = json.loads((GOLDEN / "qa.json").read_text())
        assert base_golden.cases() == golden

    def test_a_recovery_without_reason_code_hashes_as_before(self):
        golden = json.loads((GOLDEN / "qa.json").read_text())
        assert S.fault_event().recovery.content_hash == golden["cases"]["fault_recovery"]["hash"]
        assert CLARIFICATIONS["fault_recovery"]["existing_golden_fault_recovery_hash"] == \
            golden["cases"]["fault_recovery"]["hash"]

    def test_the_package_version_matches_pyproject(self):
        import re
        import runtime_contracts
        text = (pathlib.Path(__file__).resolve().parents[1] / "pyproject.toml").read_text()
        assert re.search(r'^version = "(.+)"$', text, re.M).group(1) == runtime_contracts.__version__

    def test_the_new_fixture_files_are_what_the_documented_command_writes(self):
        assert (GOLDEN / "qa_canon_vectors_addendum.json").read_text() == C._dump(C.addendum())
        assert (GOLDEN / "qa_clarifications.json").read_text() == C._dump(C.clarifications())

    def test_the_addendum_names_the_file_it_extends_and_its_version(self):
        assert ADDENDUM["extends"]["sha256"] == FROZEN_FILES["golden/qa_canon_vectors.json"]
        assert ADDENDUM["addendum_version"] == "1" and CLARIFICATIONS["clarifications_version"] == "1"
        assert ADDENDUM["canonicalization"] == CLARIFICATIONS["canonicalization"] == "rcv1"
        assert ADDENDUM["contract"] == CLARIFICATIONS["contract"] == "qa/v1"

    def test_no_addendum_vector_repeats_a_base_vector_id(self):
        base_ids = {v["id"] for v in json.loads((GOLDEN / "qa_canon_vectors.json").read_text())["vectors"]}
        assert not base_ids & {v["id"] for v in ADDENDUM["vectors"]}


# ── the addendum is self-contained ─────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("vec", ADDENDUM["vectors"], ids=lambda v: v["id"])
def test_an_independent_canonicalizer_reproduces_every_addendum_vector(vec):
    got = text(vec["input"])
    assert got == vec["canonical_json"]
    digest = hashlib.sha256(got.encode("utf-8")).hexdigest()
    assert digest == vec["sha256_hex"] and vec["rcv1"] == "rcv1:" + digest
    assert canonical.canonical_json(vec["input"]) == vec["canonical_json"]


def test_the_addendum_refusals_are_refused():
    for r in ADDENDUM["refusals"]:
        with pytest.raises(Refused):
            text(r["input"])
        with pytest.raises(canonical.CanonicalizationError):
            canonical.canonical_json(r["input"])


# ── 1. expected_hash of a predicate ────────────────────────────────────────────────────────────────────────

class TestExpectedHash:
    @pytest.mark.parametrize("p", ADDENDUM["predicates"], ids=lambda p: p["id"])
    def test_it_is_rcv1_of_op_and_expected(self, p):
        form = {"op": p["op"]}
        if p["expected"] is not None:
            form["expected"] = p["expected"]
        assert rcv1(form) == p["expected_hash"]
        predicate = Predicate(PredicateOp(p["op"]), p["expected"])
        assert predicate.digest == predicate.value_hash() == p["expected_hash"]

    def test_the_assertion_reports_the_predicate_digest(self):
        for p in ADDENDUM["predicates"]:
            if p["op"] in ("EXISTS", "ABSENT"):
                continue
            a = S.ui_assertion(op=PredicateOp(p["op"]), expected=p["expected"])
            assert a.expected_hash == p["expected_hash"]

    def test_the_reference_vector_is_the_one_an_independent_implementation_reports(self):
        by_id = {p["id"]: p for p in ADDENDUM["predicates"]}
        assert by_id["equals_string"]["expected_hash"].startswith("rcv1:1b995d35")

    def test_nfd_and_nfc_spellings_agree(self):
        by_id = {p["id"]: p for p in ADDENDUM["predicates"]}
        assert by_id["equals_nfd_string"]["expected_hash"] == by_id["equals_nfc_string"]["expected_hash"]

    def test_exists_and_absent_hash_the_op_alone(self):
        by_id = {p["id"]: p for p in ADDENDUM["predicates"]}
        assert by_id["exists"]["expected_hash"] == rcv1({"op": "EXISTS"})
        assert by_id["exists"]["expected_hash"] != by_id["absent"]["expected_hash"]

    @pytest.mark.parametrize("rel", ADDENDUM["predicate_relations"], ids=lambda r: r["why"][:40])
    def test_relations(self, rel):
        assert rel["expected_hash_equal"] and rel["assertion_hashes_differ"]
        for form, h in zip(rel["assertions"], rel["assertion_hashes"]):
            assert AssertionSpec.from_json(form).assertion_hash == h
            assert rcv1(form) == h
            assert h != rel["expected_hash"]

    def test_result_expected_hash_is_checked_against_it(self):
        a = S.ui_assertion()
        assert S.assertion_result(a, S.ui_spec()).expected_hash == a.expected_hash == Predicate(
            PredicateOp.EQUALS, "Saved").digest


# ── 2. value digest, state hash, idempotency key ───────────────────────────────────────────────────────────

class TestValueDigest:
    @pytest.mark.parametrize("d", ADDENDUM["value_digests"], ids=lambda d: d["id"])
    def test_it_is_rcv1_of_the_canonical_json_text_of_the_value(self, d):
        assert rcv1(d["value"]) == d["digest"]
        if d["kind"] == "string":
            assert value_digest(d["value"]) == d["digest"]
        if d["kind"] in ("string", "json"):
            assert json_value_digest(d["value"]) == d["digest"]

    def test_a_string_is_hashed_with_its_quotes(self):
        assert value_digest("hunter2") == "rcv1:" + hashlib.sha256(b'"hunter2"').hexdigest()

    def test_nfd_and_nfc_digest_alike(self):
        assert value_digest(unicodedata.normalize("NFD", "café")) == value_digest("café")

    def test_a_float_has_no_digest(self):
        with pytest.raises(QAContractError, match="FLOAT_REFUSED"):
            json_value_digest(1.5)

    def test_an_action_digest_is_the_value_digest_with_no_domain_tag(self):
        fill = Action(ActionKind.FILL, value="hunter2")
        press = Action(ActionKind.PRESS, value="hunter2")
        assert action_value_digest(fill) == action_value_digest(press) == value_digest("hunter2")
        assert action_value_digest(Action(ActionKind.CLICK)) is None
        ActionRecord(kind=ActionKind.FILL, value_digest=action_value_digest(fill))

    def test_a_secret_ref_digests_the_reference_not_the_secret(self):
        d = next(d for d in ADDENDUM["value_digests"] if d["kind"] == "secret_ref")
        from runtime_contracts.protocol.secrets import SecretRef
        ref = SecretRef(provider="vault", namespace="tenant-a", path="kv/app", key="token", version="3")
        assert action_value_digest(Action(ActionKind.FILL, secret_ref=ref)) == ref.fingerprint() == d["digest"]


class TestStateHashAndIdempotency:
    def test_state_hashes_are_opaque_rcv1_and_identity(self):
        by = {r["id"]: r["hash"] for r in ADDENDUM["idempotency_receipts"]}
        rel = CLARIFICATIONS["state_and_value_digests"]["identity_relations"]
        assert by["receipt_attempt_1"] != by["receipt_state_after_changed"]
        assert by["receipt_attempt_1"] == by["receipt_duration_changed"]
        assert {tuple(r["differ"]) for r in rel if "differ" in r} >= {
            ("receipt_attempt_1", "receipt_state_after_changed")}
        with pytest.raises(QAContractError):
            S.action_receipt(state_after_hash="sha256:" + "0" * 64)

    def test_a_blocked_action_leaves_the_state_unchanged(self):
        with pytest.raises(QAContractError, match="RECORD_INCONSISTENT"):
            S.action_receipt(result=S.ResultCode.ACTION_BLOCKED_BY_POLICY,
                             postcondition=S.Postcondition(declared="x",
                                                           result=S.PostconditionResult.NOT_EVALUATED))

    def test_the_sample_key_does_not_depend_on_the_attempt(self):
        assert S.action_receipt("s1", 1).idempotency_key == S.action_receipt("s1", 2).idempotency_key
        assert S.action_receipt("s1", 1).content_hash != S.action_receipt("s1", 2).content_hash

    @pytest.mark.parametrize("case", CLARIFICATIONS["idempotency"]["cases"], ids=lambda c: c["id"])
    def test_the_key_rule(self, case):
        record = collections.namedtuple("R", "run_id step_id attempt idempotency_key")
        assert list(idempotency_key_violations([record(**r) for r in case["receipts"]])) == case["violations"]

    def test_the_key_is_identity(self):
        by = {r["id"]: r["hash"] for r in ADDENDUM["idempotency_receipts"]}
        assert by["receipt_attempt_1"] != by["receipt_key_changed"]

    def test_the_receipts_pass_the_rule(self):
        assert idempotency_key_violations([S.action_receipt("s1", 1), S.action_receipt("s1", 2),
                                           S.action_receipt("s2", 1, idempotency_key="idem-s2-1")]) == ()

    def test_the_key_keeps_its_ident_shape(self):
        with pytest.raises(QAContractError):
            S.action_receipt(idempotency_key="not an ident!")


# ── 3. ordering of set-valued fields ───────────────────────────────────────────────────────────────────────

def _derived_rules():
    rules = set()
    for cls in [*RECORDS, *VALUES, *_foreign_dataclasses().values()]:
        for field, key in getattr(cls, "SET_FIELDS", {}).items():
            rules.add((cls.__name__, field, "canonical_text" if key == "@json" else "value" if key is None
                       else "element_key", key if key not in (None, "@json") else None))
    return rules


def test_the_rules_table_is_exactly_what_the_code_declares():
    declared = {(r["record"], r["field"], r["order"], r.get("key")) for r in ADDENDUM["set_ordering"]["rules"]}
    derived = _derived_rules()
    # the embedded Check sorts its pins in its own canonical form (a reused type, not a QAValue)
    assert declared - derived == {("Check", "evidence_refs", "value", None)}
    assert derived - declared == set()


def test_every_other_sequence_is_listed_as_ordered():
    from typing import Annotated, Union, get_args, get_origin
    import collections.abc

    def is_tuple(t):
        o = get_origin(t)
        if o is Annotated:
            return is_tuple(get_args(t)[0])
        if o is Union:
            return is_tuple([a for a in get_args(t) if a is not type(None)][0])
        return o in (tuple, collections.abc.Sequence)

    found = set()
    for cls in [*RECORDS, *VALUES, *_foreign_dataclasses().values()]:
        sets = set(getattr(cls, "SET_FIELDS", {}))
        for name, t in _hints(cls).items():
            if is_tuple(t) and name not in sets:
                found.add((cls.__name__, name))
    listed = {(o["record"], o["field"]) for o in ADDENDUM["set_ordering"]["ordered_not_sets"]}
    # Check.evidence_refs is sorted by Check's own canonical form and is listed under rules instead
    assert found - {("Check", "evidence_refs")} == listed


def apply_rule(case, items):
    if case["order"] == "element_key":
        return sorted(items, key=lambda e: e[case["key"]])
    if case["order"] == "canonical_text":
        return sorted(items, key=text)
    return sorted(items)


def _walk(form, path):
    for p in path.split("."):
        form = form[p]
    return form


CASES = ADDENDUM["set_ordering"]["cases"]


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["id"])
class TestSetOrdering:
    def test_an_independent_sort_gives_the_canonical_order(self, case):
        assert apply_rule(case, _walk(case["record_listed"], case["field"])) == case["canonical"]

    def test_the_listed_order_is_not_the_canonical_order(self, case):
        assert case["listed"] != case["canonical"]

    def test_the_record_hashes_to_the_pinned_value_from_any_listing(self, case):
        vec = next(v for v in ADDENDUM["vectors"] if v["id"] == case["vector"])
        assert vec["rcv1"] == case["rcv1"]
        cls = next(c for c in RECORDS if c.__name__ == case["record"])
        assert cls.from_json(case["record_listed"]).content_hash == case["rcv1"]


@pytest.mark.parametrize("case", [c for c in CASES if c["order"] != "value"], ids=lambda c: c["id"])
def test_the_other_rule_gives_a_different_hash_where_the_orders_differ(case):
    if case["orders_differ"]:
        assert case["other_rule_order"] != case["canonical"]
        assert case["rcv1_if_ordered_the_other_way"] != case["rcv1"]
    else:
        assert case["other_rule_order"] == case["canonical"]


def test_at_least_seven_object_sets_pin_a_difference_between_the_two_rules():
    assert sum(1 for c in CASES if c["orders_differ"]) >= 7


def test_the_two_object_rules_do_split_on_the_named_fields():
    differ = {(c["record"], c["field"]) for c in CASES if c["orders_differ"]}
    assert differ >= {("TestSpec", "fixtures"), ("QAPlan", "items"), ("QAPlan", "gates"),
                      ("QAPlan", "resource_claims"), ("RunManifest", "assertion_results"),
                      ("RunManifest", "step_results"), ("ReviewItem", "evidence_refs")}


def test_evidence_refs_is_the_one_object_set_ordered_by_canonical_text():
    assert {(r["record"], r["field"]) for r in ADDENDUM["set_ordering"]["rules"]
            if r["order"] == "canonical_text"} == {("FaultDetection", "evidence_refs"), ("ReviewItem", "evidence_refs")}


def test_string_sets_use_code_point_order_not_numeric_or_case_folded():
    case = next(c for c in CASES if c["id"] == "assertion_ids_natural")
    assert case["canonical"] == ["B-1", "a-1", "a-10", "a-9"]


def test_a_duplicate_set_element_is_refused_not_dropped():
    for fx in ADDENDUM["set_ordering"]["refusals"]:
        assert C.run_fixture(fx["operation"], copy.deepcopy(fx["input"])) == fx["expect"]


def test_an_ordered_field_keeps_its_listed_order():
    rec = FaultRecovery.from_json(json.loads(json.dumps(
        {**C._json(C._recovery().canonical_form()), "candidates_rejected_reasons": ["B_ONE", "A_ONE"]})))
    assert rec.candidates_rejected_reasons == ("B_ONE", "A_ONE")


def test_the_assertion_set_document_sorts_by_assertion_id():
    spec = C._spec_for_ordering()
    forms = [C._json(a.canonical_form()) for a in spec.assertions]
    assert [f["assertion_id"] for f in forms] == ["a-1", "a-10", "a-2"]
    doc = {"schema_id": "runtime-contracts/qa/assertion-set", "schema_version": "0.1", "assertions": forms}
    assert rcv1(doc) == spec.assertion_set_hash


# ── 4. distinct integrity refusal codes ────────────────────────────────────────────────────────────────────

ADDED = ("ASSERTION_PROGRAM_MISMATCH", "ASSERTION_PROGRAM_UNREGISTERED", "ASSERTION_PIN_NOT_FOUND",
         "ASSERTION_PIN_MALFORMED", "BATCH_HALTED")


class TestIntegrityRefusalCodes:
    def test_the_codes_exist_and_are_spelled_as_documented(self):
        assert tuple(getattr(Code, c) for c in ADDED) == ADDED
        assert INTEGRITY_REFUSAL_CODES_ADDED == set(ADDED)

    def test_the_enum_is_the_union_of_the_original_and_the_added_codes(self):
        assert {m.value for m in IntegrityRefusalCode} == INTEGRITY_REFUSAL_CODES
        assert INTEGRITY_REFUSAL_CODES == INTEGRITY_REFUSAL_CODES_ORIGINAL | INTEGRITY_REFUSAL_CODES_ADDED
        assert not INTEGRITY_REFUSAL_CODES_ORIGINAL & INTEGRITY_REFUSAL_CODES_ADDED
        assert len(INTEGRITY_REFUSAL_CODES_ORIGINAL) == 6

    def test_the_enum_is_in_the_inventory_and_the_schema_export(self):
        assert "IntegrityRefusalCode" in inventory.inventory()["enums"]
        schema = json.loads((GOLDEN / "qa.schema.json").read_text())
        assert set(schema["$defs"]["IntegrityRefusalCode"]["enum"]) == INTEGRITY_REFUSAL_CODES
        assert "IntegrityRefusalCode" in ALL_ENUMS

    def test_no_record_field_has_the_type(self):
        for cls in [*RECORDS, *VALUES]:
            assert not [n for n, t in _hints(cls).items() if "IntegrityRefusalCode" in repr(t)], cls.__name__

    def test_known_non_integrity_codes_are_disjoint_from_the_integrity_ones(self):
        assert not OTHER_KNOWN_CODES & INTEGRITY_REFUSAL_CODES
        assert {"SPEC_INVALID", "HASH_MISMATCH", "CHECK_PROGRAM_REF_REQUIRED"} <= OTHER_KNOWN_CODES

    def test_every_added_code_is_a_code_token(self):
        import re
        for c in ADDED:
            assert re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", c)

    @pytest.mark.parametrize("fx", CLARIFICATIONS["refusals"], ids=lambda f: f["id"])
    def test_fixtures(self, fx):
        assert C.run_fixture(fx["operation"], copy.deepcopy(fx["input"])) == fx["expect"]

    def test_every_added_refusal_ends_the_run_inconclusive_with_assertion_integrity(self):
        for fx in CLARIFICATIONS["refusals"]:
            if fx["expect"]["refused"]:
                assert fx["expect"]["run_outcome"] == "INCONCLUSIVE"
                assert fx["expect"]["run_reason"] == "ASSERTION_INTEGRITY"

    def test_each_added_code_has_a_fixture(self):
        used = {fx["expect"].get("code") for fx in CLARIFICATIONS["refusals"]}
        assert set(ADDED) <= used and "ASSERTION_HASH_MISMATCH" in used

    def test_hash_mismatch_keeps_its_meaning(self):
        spec = S.ui_spec()
        with pytest.raises(QAContractError) as exc:
            verify_assertion_set(spec.assertions[:1], spec.assertion_set_hash)
        assert exc.value.code == "ASSERTION_HASH_MISMATCH"

    def test_verify_assertion_set_is_unchanged_for_a_malformed_pin(self):
        with pytest.raises(QAContractError) as exc:
            verify_assertion_set(S.ui_spec().assertions, "not-a-pin")
        assert exc.value.code == "ASSERTION_HASH_MISMATCH"

    def test_the_manifest_and_conformance_guards_keep_their_codes(self):
        spec, other = S.ui_spec(), S.ui_spec(assertions=(S.ui_assertion(expected="x"), S.url_assertion()))
        with pytest.raises(QAContractError) as exc:
            verify_manifest_against_spec(S.run_manifest(other), spec)
        assert exc.value.code == "ASSERTION_HASH_MISMATCH"

    def test_a_pin_is_checked_before_the_store_and_the_store_before_the_hash(self):
        spec = S.ui_spec()
        with pytest.raises(QAContractError) as a:
            load_pinned_assertion_set("rcv1:zz", spec.assertions)
        with pytest.raises(QAContractError) as b:
            load_pinned_assertion_set(S.h(1), None)
        with pytest.raises(QAContractError) as c:
            load_pinned_assertion_set(spec.assertion_set_hash, ())
        assert (a.value.code, b.value.code, c.value.code) == (
            "ASSERTION_PIN_MALFORMED", "ASSERTION_PIN_NOT_FOUND", "ASSERTION_HASH_MISMATCH")
        assert load_pinned_assertion_set(spec.assertion_set_hash, spec.assertions) == spec.assertions

    def test_the_program_checks_run_in_order(self):
        ref = S.script_assertion().check_program_ref
        with pytest.raises(QAContractError) as a:
            verify_check_program(ref, None)
        with pytest.raises(QAContractError) as b:
            verify_check_program(ref, S.d(1))
        assert (a.value.code, b.value.code) == ("ASSERTION_PROGRAM_UNREGISTERED", "ASSERTION_PROGRAM_MISMATCH")
        verify_check_program(ref, ref.program_hash)

    def test_batch_halted_names_its_cause(self):
        with pytest.raises(QAContractError) as exc:
            check_batch_not_halted("ASSERTION_PROGRAM_MISMATCH")
        assert exc.value.code == "BATCH_HALTED" and "ASSERTION_PROGRAM_MISMATCH" in exc.value.detail
        check_batch_not_halted(None)


GUARDS = {
    "pin_malformed_wrong_prefix": ("_guard_pin_well_formed", "ASSERTION_PIN_MALFORMED"),
    "pin_not_found": ("_guard_pin_found", "ASSERTION_PIN_NOT_FOUND"),
    "program_unregistered": ("_guard_program_registered", "ASSERTION_PROGRAM_UNREGISTERED"),
    "program_hash_differs": ("_guard_program_hash", "ASSERTION_PROGRAM_MISMATCH"),
    "batch_halted_by_an_integrity_refusal": ("_guard_batch_not_halted", "BATCH_HALTED"),
    "pin_found_but_content_differs": ("_guard_assertion_set_hash", "ASSERTION_HASH_MISMATCH"),
}


@pytest.mark.parametrize("fid", sorted(GUARDS))
def test_removing_the_guard_removes_the_refusal(fid, monkeypatch):
    fx = next(f for f in CLARIFICATIONS["refusals"] if f["id"] == fid)
    name, code = GUARDS[fid]
    assert fx["expect"]["code"] == code
    assert C.run_fixture(fx["operation"], copy.deepcopy(fx["input"])) == fx["expect"]
    monkeypatch.setattr(integrity, name, lambda *a, **k: None)
    try:
        after = C.run_fixture(fx["operation"], copy.deepcopy(fx["input"]))
    except (TypeError, AttributeError):
        return  # the removed guard was what kept the later code from failing; the refusal is gone either way
    assert after != fx["expect"], f"{fid} is still refused with {name} removed"


class TestConsumersFailClosedOnAnUnknownCode:
    @pytest.mark.parametrize("row", CLARIFICATIONS["classification"]["cases"], ids=lambda r: r["code"] or "empty")
    def test_classification(self, row):
        got = classify_refusal(row["code"])
        assert (None if got is None else [got[0].value, got[1]]) == row["classification"]

    def test_an_unknown_code_is_an_integrity_violation_that_halts(self):
        assert classify_refusal("FROM_THE_FUTURE") == (Outcome.INCONCLUSIVE, "ASSERTION_INTEGRITY")
        assert refusal_halts_batch("FROM_THE_FUTURE")
        for odd in (None, 7, b"x", ["A"]):
            assert classify_refusal(odd) == (Outcome.INCONCLUSIVE, "ASSERTION_INTEGRITY")

    def test_an_older_consumer_reaches_the_same_outcome_for_each_added_code(self):
        older = CLARIFICATIONS["classification"]["older_consumer"]
        for row in older["cases"]:
            fresh = classify_refusal(row["code"])
            old = classify_refusal(row["code"], known=older["known_codes"])
            assert old == fresh == (Outcome.INCONCLUSIVE, "ASSERTION_INTEGRITY")
            assert refusal_halts_batch(row["code"], known=older["known_codes"])

    def test_the_older_vocabulary_is_a_subset_of_this_one(self):
        older = set(CLARIFICATIONS["classification"]["older_consumer"]["known_codes"])
        assert older <= INTEGRITY_REFUSAL_CODES | OTHER_KNOWN_CODES
        assert not older & INTEGRITY_REFUSAL_CODES_ADDED

    def test_the_run_outcome_is_never_a_pass_and_exits_non_zero(self):
        outcome, _ = classify_refusal("FROM_THE_FUTURE")
        assert outcome_to_verdict(outcome) is Verdict.INDETERMINATE
        assert default_exit_code(outcome) == 1

    def test_a_known_non_integrity_code_is_left_to_the_caller(self):
        assert classify_refusal("SPEC_INVALID") is None and not refusal_halts_batch("SPEC_INVALID")

    def test_a_non_integrity_code_is_unknown_to_a_consumer_that_does_not_know_it(self):
        assert classify_refusal("SPEC_INVALID", known=["HASH_MISMATCH"]) == (
            Outcome.INCONCLUSIVE, "ASSERTION_INTEGRITY")

    def test_the_manifest_outcome_reason_stays_assertion_integrity(self):
        a1, a2 = S.ui_spec().assertions
        m = S.run_manifest(assertions_executed=(a1.assertion_id,),
                           assertion_results=(S.assertion_result(a1, S.ui_spec()),),
                           outcome=Outcome.INCONCLUSIVE, outcome_reason="ASSERTION_INTEGRITY")
        assert m.outcome_reason == "ASSERTION_INTEGRITY"

    def test_a_manifest_cannot_claim_pass_after_a_distinct_integrity_refusal(self):
        for code in ADDED:
            assert classify_refusal(code)[0] is Outcome.INCONCLUSIVE


# ── 5. recovery reasons ────────────────────────────────────────────────────────────────────────────────────

class TestRecoveryReasonCode:
    def test_the_field_is_optional_identity_and_additive(self):
        inv = inventory.inventory()["records"]["FaultRecovery"]["fields"]["reason_code"]
        assert inv == {"custody": False, "required": False, "type": "Optional[RecoveryReason]"}

    def test_the_vocabulary_is_closed_and_documented_in_the_fixture(self):
        assert CLARIFICATIONS["fault_recovery"]["reason_code_vocabulary"] == [m.value for m in RecoveryReason]
        with pytest.raises(UnknownEnumValue):
            FaultRecovery.from_json({**C._json(C._recovery().canonical_form()), "reason_code": "NOT_A_REASON"})

    @pytest.mark.parametrize("fx", CLARIFICATIONS["fault_recovery"]["refusals"], ids=lambda f: f["id"])
    def test_refusals(self, fx):
        assert C.run_fixture(fx["operation"], copy.deepcopy(fx["input"])) == fx["expect"]

    def test_hashes(self):
        hashes = CLARIFICATIONS["fault_recovery"]["hashes"]
        for case in C._recovery_cases():
            assert hashes[case["id"]] == case["hash"]
        assert hashes["not_recovered_without_reason"] != hashes["not_recovered_no_candidate"]
        assert hashes["not_recovered_without_reason"] != hashes["rejected_reasons_reordered"]

    def test_omitting_it_hashes_as_before(self):
        plain = C._recovery()
        explicit = dataclasses.replace(plain, reason_code=None)
        assert plain.content_hash == explicit.content_hash
        assert "reason_code" not in canonical.canonicalize(plain.canonical_form())
        assert "reason_code" not in plain.to_json()

    def test_a_record_with_it_round_trips_and_verifies_from_its_bytes(self):
        rec = C._recovery(reason_code=RecoveryReason.NO_CANDIDATE)
        assert FaultRecovery.from_json(rec.to_json()) == rec
        assert verify_stored_hash(rec.to_json())

    def test_a_stopped_recovery_with_no_candidates_has_only_this_field_to_say_why(self):
        with pytest.raises(QAContractError):
            C._recovery(candidates_considered=0, candidates_rejected_reasons=("NO_UI_TARGET",))
        ok = C._recovery(candidates_considered=0, candidates_rejected_reasons=(), reason_code=RecoveryReason.NO_UI_TARGET)
        assert ok.reason_code is RecoveryReason.NO_UI_TARGET

    def test_the_kill_switch_effect_is_a_suppressed_reason_and_a_reason_code(self):
        rec = C._recovery(attempted=False, strategy=S.RecoveryStrategy.NONE, attempts=0,
                          result=RecoveryResult.NOT_ATTEMPTED, candidates_considered=0,
                          candidates_rejected_reasons=(), suppressed_reason=SuppressedReason.KILL_SWITCH,
                          reason_code=RecoveryReason.KILL_SWITCH)
        assert rec.suppressed_reason is SuppressedReason.KILL_SWITCH

    def test_candidates_rejected_reasons_is_a_bounded_ordered_list_of_code_tokens(self):
        assert C._recovery(candidates_rejected_reasons=("B_X", "A_X", "B_X")).candidates_rejected_reasons == (
            "B_X", "A_X", "B_X")
        with pytest.raises(QAContractError):
            C._recovery(candidates_rejected_reasons=("lower",))
        with pytest.raises(QAContractError):
            C._recovery(candidates_considered=1, candidates_rejected_reasons=("A_X", "B_X"))

    def test_the_embedding_event_keeps_its_old_hash_when_the_field_is_absent(self):
        golden = json.loads((GOLDEN / "qa.json").read_text())
        assert S.fault_event().content_hash == golden["cases"]["fault_event"]["hash"]


# ── 6. what is not in the manifest ─────────────────────────────────────────────────────────────────────────

class TestIdentityBoundary:
    @pytest.mark.parametrize("fx", CLARIFICATIONS["identity_boundary"]["refusals"], ids=lambda f: f["id"])
    def test_a_manifest_refuses_these_keys(self, fx):
        assert C.run_fixture(fx["operation"], copy.deepcopy(fx["input"])) == fx["expect"]

    def test_no_record_has_a_kill_switch_or_engine_limit_field(self):
        names = {f.name for cls in [*RECORDS, *VALUES, *_foreign_dataclasses().values()]
                 for f in dataclasses.fields(cls)}
        assert not {n for n in names if "kill" in n or n.startswith("engine") or n in ("operator_caps", "caps")}
        assert not [n for n in names if "limit" in n and n not in ("resource_limits",)]

    def test_the_only_limit_in_a_manifest_is_the_sandbox_resource_limits(self):
        names = {f.name for f in dataclasses.fields(RunManifest)}
        assert {n for n in names if "limit" in n} == {"resource_limits"}

    def test_the_counters_are_custody(self):
        assert "counters" in RunManifest.CUSTODY
        assert {f.name for f in dataclasses.fields(S.Counters)} == {"tokens", "model_calls", "infrastructure_ms",
                                                                    "cost"}

    def test_counters_do_not_change_the_manifest_hash(self):
        a = S.run_manifest(counters=S.Counters(tokens=0, model_calls=0, infrastructure_ms=5400))
        b = S.run_manifest(counters=S.Counters(tokens=9, model_calls=2, infrastructure_ms=1, cost="0.5"))
        assert a.content_hash == b.content_hash

    def test_the_kill_switch_effect_is_representable_per_fault(self):
        assert SuppressedReason.KILL_SWITCH.value == "KILL_SWITCH"
        assert CLARIFICATIONS["identity_boundary"]["where_the_effect_is_recorded"] == {
            "record": "FaultRecovery", "field": "suppressed_reason", "member": "KILL_SWITCH"}

    def test_recovery_cost_is_custody(self):
        assert "cost" in FaultRecovery.CUSTODY


# ── the new vocabulary is clean, and the documents say what the code does ──────────────────────────────────

def test_the_new_enums_are_enums_and_exported():
    import runtime_contracts.qa as qa
    for name in ("IntegrityRefusalCode", "RecoveryReason"):
        assert issubclass(getattr(qa, name), enum.Enum) and name in qa.__all__
    for name in ("classify_refusal", "verify_pin_well_formed", "load_pinned_assertion_set", "verify_check_program",
                 "check_batch_not_halted", "idempotency_key_violations", "json_value_digest", "action_value_digest"):
        assert name in qa.__all__


def test_the_new_fixture_files_use_no_forbidden_vocabulary():
    leak = importlib.import_module("test_qa_leak_guard")
    for path in ("qa_canon_vectors_addendum.json", "qa_clarifications.json"):
        body = (GOLDEN / path).read_text()
        assert not leak.FORBIDDEN_WORDS.search(body), path

        def keys(v):
            if isinstance(v, dict):
                for k, x in v.items():
                    yield k
                    yield from keys(x)
            elif isinstance(v, list):
                for x in v:
                    yield from keys(x)
        assert not [k for k in keys(json.loads(body)) if leak.FORBIDDEN_NAME.match(k)], path


def test_the_docs_define_each_clarification_and_each_added_code():
    doc = (ROOT / "docs" / "QA_V1.md").read_text()
    for needle in (*ADDED, "expected_hash", "idempotency key", "reason_code", "candidates_rejected_reasons",
                   "kill-switch", "golden/qa_canon_vectors_addendum.json", "golden/qa_clarifications.json",
                   "canonical JSON text", "Unicode code point"):
        assert needle in doc, needle
    review = (ROOT / "docs" / "QA_V1_COMPATIBILITY_REVIEW.md").read_text()
    for needle in (*ADDED, FROZEN_FILES["golden/qa.json"], FROZEN_FILES["golden/qa_canon_vectors.json"],
                   C3_SCHEMA_SHA, C3_INVENTORY_SHA, "fail closed", "additive"):
        assert needle in review, needle
