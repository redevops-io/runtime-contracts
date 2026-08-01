"""Canonical contracts for ReDevOps runtime interoperability.

Status: v0.1 — proposed canonical contract, implementation adoption pending.
No implementation currently claims conformance.
"""
from .canonical import (
    CONTRACT_VERSION,
    CanonicalizationError,
    canonical_json,
    canonicalize,
    content_hash,
)
from .models import *  # noqa: F401,F403
from .models import __all__ as _model_all

__version__ = "0.1.0"
__all__ = ["CONTRACT_VERSION", "CanonicalizationError", "canonical_json",
           "canonicalize", "content_hash", *_model_all]
