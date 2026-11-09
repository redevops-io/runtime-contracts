"""The authorization contract (`authz/v1`) — one decision receipt, one qualification vocabulary.

Both ReDevOps editions decide authorization (the AGPL kernel's resource-grant plane and the enterprise
capability plane) and both claim to fail closed. Until now each proved itself in its own test suite, which
proves the seam, never the other edition. This package is the shared artifact those suites must answer to:

* :mod:`~runtime_contracts.authz.decision` — the machine-readable decision envelope both planes emit, the
  canonical `roles_hash`, and the validation rules a receipt must satisfy to be auditable at all.
* :mod:`~runtime_contracts.authz.qualification` — the per-adapter verdicts (`PASS` · `FAIL` · `UNSUPPORTED`
  · `BLOCKED`) and the qualification matrix that pins what each edition is currently known to do.
* :mod:`~runtime_contracts.authz.suite` — the seven cross-edition invariants, written against a narrow
  adapter protocol so an implementation is tested through its own enforcement seams, and the runner that
  classifies the result.

The envelope is a *receipt*, not proof of a data boundary: an honest `DENY` line saying `tenant_isolation`
records that the plane refused, and only a scenario that measures content — what entered a candidate set,
a cache, a log, a model's context — shows that data stayed inside its boundary. The suite keeps those two
kinds of evidence apart on purpose.
"""
from .decision import (
    AUTHZ_CONTRACT_VERSION,
    DECISION_EVENT,
    ENVELOPE_FIELDS,
    ENVELOPE_VERSION,
    ROLES_HASH_HEX_LEN,
    AuthorizationDecision,
    EnvelopeError,
    PolicyReason,
    parse_envelope,
    roles_hash,
    validate_envelope,
)
from .qualification import (
    CaseResult,
    Invariant,
    Matrix,
    Qualification,
    qualification_to_verdict,
)
from .suite import (
    AdapterBlocked,
    AuthzAdapter,
    InvariantFailure,
    Unsupported,
    run_invariant,
)

__all__ = [
    "AUTHZ_CONTRACT_VERSION", "DECISION_EVENT", "ENVELOPE_VERSION", "ENVELOPE_FIELDS", "ROLES_HASH_HEX_LEN",
    "AuthorizationDecision", "EnvelopeError", "PolicyReason", "parse_envelope", "roles_hash",
    "validate_envelope",
    "CaseResult", "Invariant", "Matrix", "Qualification", "qualification_to_verdict",
    "AdapterBlocked", "AuthzAdapter", "InvariantFailure", "Unsupported", "run_invariant",
]