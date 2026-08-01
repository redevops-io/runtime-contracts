"""VerificationResult — the smallest and most reusable contract.

Deliberately **not** `valid: bool`. A boolean cannot distinguish "we checked and
it failed" from "we could not check", and those demand opposite responses: the
first is a defect, the second is a gap in the harness. Collapsing them means an
unverifiable result is indistinguishable from a verified one at the call site
that matters.

It also cannot say *which* check failed, which makes a failure unactionable, or
that a check was skipped, which makes a partial run look complete.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence

from ..canonical import content_hash


class Verdict(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    """Checked, and it did not hold."""

    INDETERMINATE = "INDETERMINATE"
    """Could not be checked — a dependency was unavailable, a budget ran out, a
    non-deterministic verifier disagreed with itself. Not a pass and not a
    failure, and treating it as either is how an unverifiable result gets
    promoted."""

    NOT_APPLICABLE = "NOT_APPLICABLE"
    """The check does not arise for this target. A correct answer, not a gap."""

    @property
    def is_conclusive(self) -> bool:
        return self in {Verdict.PASS, Verdict.FAIL}


class Determinism(str, Enum):
    DETERMINISTIC = "DETERMINISTIC"
    """Same input, same verdict, always. Safe to cache and to replay."""

    NON_DETERMINISTIC = "NON_DETERMINISTIC"
    """A model judged it. The verdict is evidence, not proof, and must not be
    the last gate before promotion."""


class Completion(str, Enum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    ABORTED = "ABORTED"


@dataclass(frozen=True)
class Check:
    """One condition, and what it did."""

    check_id: str
    verdict: Verdict
    determinism: Determinism = Determinism.DETERMINISTIC
    detail: str = ""
    evidence_refs: Sequence[str] = ()

    def canonical_form(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "verdict": self.verdict.value,
            "determinism": self.determinism.value,
            "evidence_refs": sorted(self.evidence_refs),
            # `detail` is excluded: wording is not part of the verdict.
        }


@dataclass(frozen=True)
class VerificationResult:
    """What a verifier did to a target, in enough detail to act on."""

    SCHEMA_ID: str = field(default="runtime-contracts/verification-result",
                           init=False, repr=False)
    SCHEMA_VERSION: str = field(default="0.1", init=False, repr=False)

    verifier_id: str
    verifier_version: str
    target_handle_hash: str
    checks: Sequence[Check] = ()
    completion: Completion = Completion.COMPLETE
    omissions: Sequence[str] = ()
    """Checks that were not run. A partial verification reporting no omissions
    is indistinguishable from a complete one."""

    verified_at: Optional[str] = None
    """Excluded from identity — the same verifier reaching the same verdict on
    the same target twice produced one result, not two."""

    @property
    def verdict(self) -> Verdict:
        """The weakest outcome present.

        Order matters: a single FAIL outranks any number of passes, and an
        INDETERMINATE outranks a pass because "we could not tell" must not be
        reported as "it holds".
        """
        verdicts = {c.verdict for c in self.checks}
        for outcome in (Verdict.FAIL, Verdict.INDETERMINATE, Verdict.PASS):
            if outcome in verdicts:
                return outcome
        return Verdict.NOT_APPLICABLE

    @property
    def failed(self) -> List[Check]:
        return [c for c in self.checks if c.verdict is Verdict.FAIL]

    @property
    def is_deterministic(self) -> bool:
        return all(c.determinism is Determinism.DETERMINISTIC for c in self.checks)

    @property
    def may_promote(self) -> bool:
        """Whether this result alone can carry something forward.

        Three ways to fail, all of which a boolean would hide: something failed,
        something could not be checked, or the run did not finish. A
        non-deterministic verdict does not block promotion here — it is the
        acceptance chain's job to require a human or a deterministic check
        alongside it — but `is_deterministic` is exposed so that chain can.
        """
        return (self.verdict is not Verdict.FAIL
                and self.verdict is not Verdict.INDETERMINATE
                and self.completion is Completion.COMPLETE
                and not self.omissions)

    def canonical_form(self) -> Dict[str, Any]:
        return {
            "schema_id": self.SCHEMA_ID,
            "schema_version": self.SCHEMA_VERSION,
            "verifier_id": self.verifier_id,
            "verifier_version": self.verifier_version,
            "target_handle_hash": self.target_handle_hash,
            "checks": sorted(
                (c.canonical_form() for c in self.checks),
                key=lambda c: c["check_id"]),
            "completion": self.completion.value,
            "omissions": sorted(self.omissions),
        }

    @property
    def result_hash(self) -> str:
        return content_hash(self.canonical_form())

    def to_json(self) -> Dict[str, Any]:
        return {
            **self.canonical_form(),
            "result_hash": self.result_hash,
            "verdict": self.verdict.value,
            "is_deterministic": self.is_deterministic,
            "may_promote": self.may_promote,
            "failed_checks": [c.check_id for c in self.failed],
            "verified_at": self.verified_at,
        }
