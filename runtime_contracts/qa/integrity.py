"""The frozen-assertion guards as pure functions.

Each guard is a named, module-level function so that a test can remove it and prove the refusal it provides
disappears with it. A guard raises ``AssertionIntegrityError``; whatever the specific ``code``, the run it occurs in
is ``INCONCLUSIVE(ASSERTION_INTEGRITY)`` and the batch halts.

The verifier that evaluates assertions lives in the harness, not here. These functions are the contract-level
definition of what "the assertion set is unchanged" means, so the loader (which computes ``rcv1``) and the
verifier (which recomputes with an independent ``canon-v1``) refuse on exactly the same conditions.
"""
from __future__ import annotations

from typing import Sequence

from .base import AssertionIntegrityError, Code, QAContractError
from .enums import Executor
from .spec import AssertionSpec, TestSpec, assertion_set_hash


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
