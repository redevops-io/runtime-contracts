"""Canonical contracts for ReDevOps runtime interoperability.

Status: v0.1 — proposed canonical contract, implementation adoption pending.
No implementation currently claims conformance.
"""
from .canonical import (
    CANONICALIZATION_VERSION,
    CONTRACT_VERSION,
    CanonicalizationError,
    canonical_json,
    canonicalize,
    content_hash,
    decimal_string,
)
from .models import *  # noqa: F401,F403
from .models import __all__ as _model_all

__version__ = "0.2.1"
__all__ = ["CANONICALIZATION_VERSION", "CONTRACT_VERSION", "decimal_string", "CanonicalizationError", "canonical_json",
           "canonicalize", "content_hash", *_model_all]
