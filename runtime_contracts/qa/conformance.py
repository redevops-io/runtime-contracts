"""Checking a record against the frozen spec it claims to come from, and checking what recovery hands back.

Pure functions that raise ``AssertionIntegrityError``. Each check is a named module-level function so a test can
remove it and prove the refusal disappears with it.

* A result whose executor differs from the frozen assertion's is refused (the verifier mirrors the executor; a
  mismatch means the assertion was evaluated some way the spec did not ask for).
* A result computed against a different expected value than the frozen one is refused.
* A manifest whose declared assertions, assertion-set hash or spec reference differ from the spec is refused.
* A recovery payload may express "try this locator" and nothing else. Any extra key, in particular an ``expected``
  value or an assertion object, is refused.
"""
from __future__ import annotations

import collections.abc
from typing import Any, Iterable, Tuple

from .base import AssertionIntegrityError, Code, QAContractError
from .manifest import RunManifest
from .records import AssertionResult, LocatorCandidate
from .spec import AssertionSpec, TestSpec


def _guard_result_executor(result: AssertionResult, assertion: AssertionSpec) -> None:
    if result.executor is not assertion.executor:
        raise AssertionIntegrityError(
            Code.EXECUTOR_MISMATCH,
            f"assertion {assertion.assertion_id} is frozen with executor {assertion.executor.value} but the "
            f"result says {result.executor.value}")


def _guard_result_expected(result: AssertionResult, assertion: AssertionSpec) -> None:
    if result.expected_hash != assertion.expected_hash:
        raise AssertionIntegrityError(
            Code.EXPECTED_MISMATCH,
            f"assertion {assertion.assertion_id} was evaluated against an expected value that is not the frozen "
            "one; a verifier handed a different expected refuses")


def check_result_matches_assertion(result: AssertionResult, assertion: AssertionSpec) -> None:
    if result.assertion_id != assertion.assertion_id:
        raise AssertionIntegrityError(Code.ASSERTION_HASH_MISMATCH, f"result for {result.assertion_id} checked "
                                      f"against assertion {assertion.assertion_id}")
    _guard_result_executor(result, assertion)
    _guard_result_expected(result, assertion)


def _guard_manifest_pins(manifest: RunManifest, spec: TestSpec) -> None:
    if manifest.spec_ref != spec.spec_ref:
        raise AssertionIntegrityError(Code.ASSERTION_HASH_MISMATCH, f"manifest spec_ref {manifest.spec_ref} is "
                                      f"not {spec.spec_ref}")
    if manifest.assertion_set_hash != spec.assertion_set_hash:
        raise AssertionIntegrityError(Code.ASSERTION_HASH_MISMATCH, "the manifest pinned a different assertion set "
                                      "than the spec holds")


def _guard_manifest_declares_the_spec(manifest: RunManifest, spec: TestSpec) -> None:
    if set(manifest.assertions_declared) != set(spec.assertion_ids):
        raise AssertionIntegrityError(Code.COVERAGE_VIOLATION, "assertions_declared is not the spec's assertion set")


def verify_manifest_against_spec(manifest: RunManifest, spec: TestSpec) -> None:
    """Refuse a manifest that does not describe a run of exactly this frozen spec."""
    _guard_manifest_pins(manifest, spec)
    _guard_manifest_declares_the_spec(manifest, spec)
    by_id = {a.assertion_id: a for a in spec.assertions}
    for result in manifest.assertion_results:
        if result.assertion_id not in by_id:
            raise AssertionIntegrityError(Code.COVERAGE_VIOLATION, f"a result exists for {result.assertion_id}, "
                                          "which the spec does not declare")
        check_result_matches_assertion(result, by_id[result.assertion_id])


# ── recovery payloads ──────────────────────────────────────────────────────────────────────────────────────

CANDIDATE_KEYS = frozenset({"strategy", "role", "name", "test_id", "label"})


def _guard_candidate_keys(raw: collections.abc.Mapping) -> None:
    extra = sorted(set(raw) - CANDIDATE_KEYS)
    if extra:
        raise AssertionIntegrityError(
            Code.RECOVERY_PAYLOAD_REJECTED,
            f"a recovery candidate expresses a locator and nothing else; it carried {extra}. Recovery cannot "
            "propose an expected value, an assertion or any field outside the candidate schema")


def parse_recovery_candidate(raw: Any) -> LocatorCandidate:
    """Parse one recovery output into the strict ``LocatorCandidate``, or refuse it."""
    if not isinstance(raw, collections.abc.Mapping):
        raise AssertionIntegrityError(Code.RECOVERY_PAYLOAD_REJECTED, "a recovery candidate is an object")
    _guard_candidate_keys(raw)
    try:
        return LocatorCandidate(**{k: raw[k] for k in raw if k in CANDIDATE_KEYS})
    except (QAContractError, TypeError) as exc:
        raise AssertionIntegrityError(Code.RECOVERY_PAYLOAD_REJECTED, f"not a valid locator candidate: {exc}") from None


def parse_recovery_candidates(raw: Iterable[Any], *, limit: int = 8) -> Tuple[LocatorCandidate, ...]:
    """Parse a recoverer's output. Anything that is not a bounded list of strict candidates is refused whole."""
    if isinstance(raw, (str, bytes, collections.abc.Mapping)) or not isinstance(raw, collections.abc.Iterable):
        raise AssertionIntegrityError(Code.RECOVERY_PAYLOAD_REJECTED, "recovery output is a list of candidates")
    items = list(raw)
    if len(items) > limit:
        raise AssertionIntegrityError(Code.RECOVERY_PAYLOAD_REJECTED, f"{len(items)} candidates exceed the limit {limit}")
    return tuple(parse_recovery_candidate(i) for i in items)
