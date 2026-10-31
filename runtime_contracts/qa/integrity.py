"""The frozen-assertion guards as pure functions.

Each guard is a named, module-level function so that a test can remove it and prove the refusal it provides
disappears with it. A guard raises ``AssertionIntegrityError``; whatever the specific ``code``, the run it occurs in
is ``INCONCLUSIVE(ASSERTION_INTEGRITY)`` and the batch halts.

The verifier that evaluates assertions lives in the harness, not here. These functions are the contract-level
definition of what "the assertion set is unchanged" means, so the loader (which computes ``rcv1``) and the
verifier (which recomputes with an independent ``canon-v1``) refuse on exactly the same conditions.
"""
from __future__ import annotations

import re
from typing import Any, Iterable, Optional, Sequence, Tuple

from .base import AssertionIntegrityError, Code, QAContractError
from .enums import Executor, Outcome
from .spec import AssertionSpec, CheckProgramRef, TestSpec, assertion_set_hash


def _guard_assertion_set_hash(assertions: Sequence[AssertionSpec], pinned_hash: str) -> None:
    actual = assertion_set_hash(assertions)
    if actual != pinned_hash:
        raise AssertionIntegrityError(
            Code.ASSERTION_HASH_MISMATCH,
            f"the assertion set hashes to {actual} but was pinned as {pinned_hash}; the assertions were "
            "changed after they were frozen, and nothing is evaluated")


def verify_assertion_set(assertions: Sequence[AssertionSpec], pinned_hash: str) -> None:
    """Refuse unless the assertions still hash to the value pinned before the run started.

    The hash is recomputed from content every time. An object edited after construction (which the types make
    hard, not impossible for someone who bypasses them) no longer matches what was pinned.
    """
    _guard_assertion_set_hash(assertions, pinned_hash)


def assertions_changed(previous: TestSpec, new: TestSpec) -> bool:
    """Whether two versions of a spec differ in their frozen assertions."""
    return previous.assertion_set_hash != new.assertion_set_hash


def _guard_successor(previous: TestSpec, new: TestSpec) -> None:
    if new.id != previous.id or new.version <= previous.version:
        raise QAContractError(Code.SPEC_INVALID, f"{new.id} v{new.version} does not succeed "
                              f"{previous.id} v{previous.version}; a change is a new, higher version of the same spec")


def required_approvals(previous: TestSpec, new: TestSpec) -> int:
    """Named human approvals a successor needs: two if any assertion changed, otherwise one.

    The count is a floor the runner enforces against the approval records; this function does not approve
    anything and no model or runner may.
    """
    _guard_successor(previous, new)
    return 2 if assertions_changed(previous, new) else 1


def executor_certifies(raw_executor: str) -> bool:
    """Whether a raw executor string is one this version defines. An unknown value is non-certifying."""
    try:
        Executor(raw_executor)
    except ValueError:
        return False
    return True


# ── assertion accounting ───────────────────────────────────────────────────────────────────────────────────

def coverage_violations(declared: Iterable[str], executed: Iterable[str], skipped: Iterable[str]) -> Tuple[str, ...]:
    """Breaches of ``declared == executed | skipped`` with ``executed & skipped == {}``, as stable codes."""
    declared, executed, skipped = set(declared), set(executed), set(skipped)
    found = []
    if executed - declared:
        found.append("EXECUTED_NOT_DECLARED")
    if skipped - declared:
        found.append("SKIPPED_NOT_DECLARED")
    if executed & skipped:
        found.append("EXECUTED_AND_SKIPPED")
    if declared - executed - skipped:
        found.append("DECLARED_UNACCOUNTED")
    return tuple(found)


def classify_coverage(declared: Iterable[str], executed: Iterable[str],
                      skipped: Iterable[str]) -> Optional[Tuple[Outcome, str]]:
    """``(INCONCLUSIVE, ASSERTION_INTEGRITY)`` if the accounting is broken, otherwise ``None``.

    The pure function the classifier applies first: an integrity violation outranks every other outcome and halts
    the batch.
    """
    if coverage_violations(declared, executed, skipped):
        return Outcome.INCONCLUSIVE, Code.ASSERTION_INTEGRITY
    return None


def _guard_result_accounting(results: Sequence[Tuple[str, str]], assertion_set_hash: str) -> Tuple[str, ...]:
    found = []
    if any(h != assertion_set_hash for _, h in results):
        found.append("RESULT_FOR_A_DIFFERENT_ASSERTION_SET")
    return tuple(found)


def integrity_violations(*, declared: Iterable[str], executed: Iterable[str], skipped: Iterable[str],
                         results: Sequence[Tuple[str, str]], assertion_set_hash: str) -> Tuple[str, ...]:
    """Every accounting breach in a run record: coverage, results that do not match the executed set, and results
    produced under a different assertion set than the run pinned."""
    found = list(coverage_violations(declared, executed, skipped))
    if {i for i, _ in results} != set(executed):
        found.append("RESULTS_DO_NOT_MATCH_EXECUTED")
    found.extend(_guard_result_accounting(results, assertion_set_hash))
    return tuple(found)


# ── distinct integrity refusals (added within qa/v1) ───────────────────────────────────────────────────────
#
# Every code below ends a run ``INCONCLUSIVE(ASSERTION_INTEGRITY)`` and halts the batch, exactly like the original
# six. They exist so that the refusals which used to share ``ASSERTION_HASH_MISMATCH`` can be told apart; that code
# keeps its meaning for a content hash recomputed from what was handed over that differs from its pin. The entry
# points here are pure: the store lookup and the registry lookup are done by the caller and handed in.

#: The codes of the original qa/v1 text.
INTEGRITY_REFUSAL_CODES_ORIGINAL = frozenset({
    Code.ASSERTION_INTEGRITY, Code.ASSERTION_HASH_MISMATCH, Code.EXECUTOR_MISMATCH, Code.EXPECTED_MISMATCH,
    Code.RECOVERY_PAYLOAD_REJECTED, Code.COVERAGE_VIOLATION})
#: The codes added within qa/v1 afterwards.
INTEGRITY_REFUSAL_CODES_ADDED = frozenset({
    Code.ASSERTION_PROGRAM_MISMATCH, Code.ASSERTION_PROGRAM_UNREGISTERED, Code.ASSERTION_PIN_NOT_FOUND,
    Code.ASSERTION_PIN_MALFORMED, Code.BATCH_HALTED})
INTEGRITY_REFUSAL_CODES = INTEGRITY_REFUSAL_CODES_ORIGINAL | INTEGRITY_REFUSAL_CODES_ADDED

#: Every other code this version defines. They are not integrity refusals; the caller classifies them by its own
#: rules (a spec defect is a ``TEST_DEFECT``, for example).
OTHER_KNOWN_CODES = frozenset(
    v for k, v in vars(Code).items() if not k.startswith("_") and isinstance(v, str)) - INTEGRITY_REFUSAL_CODES

_PIN_SHAPE = re.compile(r"rcv1:[0-9a-f]{64}")


def classify_refusal(code: Any, *, known: Optional[Iterable[str]] = None) -> Optional[Tuple[Outcome, str]]:
    """``(INCONCLUSIVE, ASSERTION_INTEGRITY)`` for an integrity refusal, ``None`` for a code that is known and is not
    one, and ``(INCONCLUSIVE, ASSERTION_INTEGRITY)`` for a code that is not known at all.

    The last case is the fail-closed rule: a consumer that meets a refusal code it has never heard of treats it as
    an integrity violation (the run is ``INCONCLUSIVE`` and the batch halts), never as a pass and never as
    something to skip. Because every member added within qa/v1 maps to that same classification, an older consumer
    that does not know them still reaches the outcome the newer one reaches.

    ``known`` narrows what this consumer knows (default: every code of this version), which is how a test plays an
    older consumer. A non-string code is unknown. Every classification returned here halts the batch.
    """
    if not isinstance(code, str):
        return Outcome.INCONCLUSIVE, Code.ASSERTION_INTEGRITY
    knowable = set(known) if known is not None else INTEGRITY_REFUSAL_CODES | OTHER_KNOWN_CODES
    if code not in knowable:
        return Outcome.INCONCLUSIVE, Code.ASSERTION_INTEGRITY
    if code in INTEGRITY_REFUSAL_CODES:
        return Outcome.INCONCLUSIVE, Code.ASSERTION_INTEGRITY
    return None


def refusal_halts_batch(code: Any, *, known: Optional[Iterable[str]] = None) -> bool:
    """Whether the refusal halts the batch: every integrity refusal does, and so does an unknown code."""
    return classify_refusal(code, known=known) is not None


def _guard_pin_well_formed(pin: Any) -> None:
    if not isinstance(pin, str) or _PIN_SHAPE.fullmatch(pin) is None:
        shown = pin if isinstance(pin, str) and len(pin) <= 80 else type(pin).__name__
        raise AssertionIntegrityError(
            Code.ASSERTION_PIN_MALFORMED,
            f"the pinned assertion_set_hash {shown!r} is not 'rcv1:' and 64 lowercase hex digits; nothing is "
            "looked up and nothing is evaluated")


def verify_pin_well_formed(pin: Any) -> None:
    """Refuse a pin that is not ``rcv1:`` and 64 lowercase hex digits (``ASSERTION_PIN_MALFORMED``)."""
    _guard_pin_well_formed(pin)


def _guard_pin_found(pin: str, stored: Optional[Sequence[AssertionSpec]]) -> None:
    if stored is None:
        raise AssertionIntegrityError(
            Code.ASSERTION_PIN_NOT_FOUND,
            f"no assertion set is stored under the pin {pin}; nothing is evaluated")


def load_pinned_assertion_set(pin: Any, stored: Optional[Sequence[AssertionSpec]]) -> Tuple[AssertionSpec, ...]:
    """The assertions a pin names, after the three checks in their fixed order: the pin is well formed
    (``ASSERTION_PIN_MALFORMED``), the store holds a set under it (``ASSERTION_PIN_NOT_FOUND``, ``stored`` is
    ``None``), and that set hashes to the pin (``ASSERTION_HASH_MISMATCH``, the content-hash case).

    ``stored`` is what the caller's spec store returned for the pin, or ``None`` when it holds nothing. An empty
    sequence is a stored set with no assertions, which then fails the hash check like any other wrong content.
    """
    _guard_pin_well_formed(pin)
    _guard_pin_found(pin, stored)
    assertions = tuple(stored)
    verify_assertion_set(assertions, pin)
    return assertions


def _guard_program_registered(ref: CheckProgramRef, registered_hash: Optional[str]) -> None:
    if registered_hash is None:
        raise AssertionIntegrityError(
            Code.ASSERTION_PROGRAM_UNREGISTERED,
            f"check program {ref.id}@{ref.version} has no registry entry; the assertion that names it is not "
            "evaluated")


def _guard_program_hash(ref: CheckProgramRef, registered_hash: str) -> None:
    if registered_hash != ref.program_hash:
        raise AssertionIntegrityError(
            Code.ASSERTION_PROGRAM_MISMATCH,
            f"check program {ref.id}@{ref.version} is registered as {registered_hash} but the assertion froze "
            f"{ref.program_hash}; a different program is a different assertion")


def verify_check_program(ref: CheckProgramRef, registered_hash: Optional[str]) -> None:
    """Refuse unless the registry holds the program an assertion froze: no entry is ``ASSERTION_PROGRAM_UNREGISTERED``
    and an entry with a different hash is ``ASSERTION_PROGRAM_MISMATCH``. ``registered_hash`` is the full sha256 the
    caller's registry holds for ``ref.id`` and ``ref.version``, or ``None``."""
    _guard_program_registered(ref, registered_hash)
    _guard_program_hash(ref, registered_hash)


def _guard_batch_not_halted(halted_by: Optional[str]) -> None:
    if halted_by is not None:
        raise AssertionIntegrityError(
            Code.BATCH_HALTED,
            f"the batch was halted by {halted_by}; nothing else in it starts. The run is recorded "
            "INCONCLUSIVE(ASSERTION_INTEGRITY) and what did not start is skipped with HALTED_INTEGRITY")


def check_batch_not_halted(halted_by: Optional[str]) -> None:
    """Refuse a call made after an integrity refusal halted the batch (``BATCH_HALTED``). ``halted_by`` is the code
    of the refusal that halted it, or ``None`` while the batch is running. The halting refusal keeps its own code;
    ``BATCH_HALTED`` is what every later call gets."""
    _guard_batch_not_halted(halted_by)


# ── idempotency keys ───────────────────────────────────────────────────────────────────────────────────────

def idempotency_key_violations(receipts: Iterable[Any]) -> Tuple[str, ...]:
    """Breaches of the idempotency-key rule over a run's ``ActionReceipt`` records, as stable codes.

    The key is per step, not per attempt: every attempt of one step in one run carries the same key (so a target can
    recognise a replay), and different steps of one run carry different keys. The key is an opaque identifier; its
    spelling is the producer's.
    """
    keys_by_step: dict = {}
    steps_by_key: dict = {}
    for r in receipts:
        keys_by_step.setdefault((r.run_id, r.step_id), set()).add(r.idempotency_key)
        steps_by_key.setdefault((r.run_id, r.idempotency_key), set()).add(r.step_id)
    found = []
    if any(len(keys) > 1 for keys in keys_by_step.values()):
        found.append("IDEMPOTENCY_KEY_CHANGED_ACROSS_ATTEMPTS")
    if any(len(steps) > 1 for steps in steps_by_key.values()):
        found.append("IDEMPOTENCY_KEY_SHARED_ACROSS_STEPS")
    return tuple(found)
