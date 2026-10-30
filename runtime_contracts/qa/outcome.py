"""Failure taxonomy mapped onto the existing ``Verdict``.

Run outcomes are ``PASS``, ``PRODUCT_FAIL``, ``TEST_DEFECT``, ``ENVIRONMENT_FAIL`` and ``INCONCLUSIVE``. They are
decided by a pure deterministic function in the harness, never by a model, and rolled up in this order (first match
wins): integrity violation (``INCONCLUSIVE(ASSERTION_INTEGRITY)``, halt); environment health failed; baseline
conformance or spec invalid; a deterministic ``FAIL`` meeting the ``PRODUCT_FAIL`` requirements; any indeterminate
assertion, omission or unresolved subject; otherwise ``PASS``.

This module holds the part contracts own: the vocabulary and its mapping onto the verdict every other ReDevOps
verifier already speaks. Only ``PRODUCT_FAIL`` is a ``FAIL``. ``TEST_DEFECT``, ``ENVIRONMENT_FAIL`` and
``INCONCLUSIVE`` are ``INDETERMINATE``: "we could not tell" must not be reported as either answer. An unknown
outcome string maps to ``INDETERMINATE`` and a non-zero exit, so a newer producer can never be read as a pass.
"""
from __future__ import annotations

from typing import Mapping, Union

from ..models.verification import Verdict
from .enums import Outcome

OUTCOME_VERDICT: Mapping[Outcome, Verdict] = {
    Outcome.PASS: Verdict.PASS,
    Outcome.PRODUCT_FAIL: Verdict.FAIL,
    Outcome.TEST_DEFECT: Verdict.INDETERMINATE,
    Outcome.ENVIRONMENT_FAIL: Verdict.INDETERMINATE,
    Outcome.INCONCLUSIVE: Verdict.INDETERMINATE,
}


def _outcome(outcome: Union[Outcome, str]):
    try:
        return Outcome(outcome)
    except ValueError:
        return None


def outcome_to_verdict(outcome: Union[Outcome, str]) -> Verdict:
    """The contract ``Verdict`` for a run outcome. Unknown means ``INDETERMINATE`` (non-certifying)."""
    known = _outcome(outcome)
    return OUTCOME_VERDICT[known] if known is not None else Verdict.INDETERMINATE


def default_exit_code(outcome: Union[Outcome, str]) -> int:
    """CI exit code by default: ``0`` only for ``PASS``. Fail closed for everything else, including unknown."""
    return 0 if _outcome(outcome) is Outcome.PASS else 1
