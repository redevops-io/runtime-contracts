"""``qa/v1``: the QA schema family. Contracts only: no browser, adapter implementation, scheduler or store.

``runtime-contracts`` owns these schemas; nobody else defines them. The harness executes and records, Context
Runtime plans, and the product packages and adapts. Within ``qa/v1`` the rule is additive only: new optional
fields and new schemas, no removal, rename or retype, and a consumer refuses an unknown major. Hashing is
``rcv1`` (``runtime_contracts.canonical``), unchanged.
"""
from .base import (QA_CONTRACT_ID, QA_SCHEMA_VERSION, AssertionIntegrityError, Code, FrozenMap,
                   QAContractError, QARecord, QAValue, UnknownEnumValue, strip_non_identity, value_digest,
                   verify_stored_hash)

__all__ = [
    "QA_CONTRACT_ID", "QA_SCHEMA_VERSION", "AssertionIntegrityError", "Code", "FrozenMap", "QAContractError",
    "QARecord", "QAValue", "UnknownEnumValue", "strip_non_identity", "value_digest", "verify_stored_hash",
]
