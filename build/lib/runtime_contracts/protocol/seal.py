"""Seal semantics over the Decimal canonical — the universal intent identity.

`canonical.py` refuses floats on purpose: cross-language float printing is the
classic source of hashes that agree on one runtime and disagree on another. Domain
payloads carry floats — allocation ratios, prices, share quantities — so the seal
applies **one explicit, documented number policy** at the boundary: project
dataclasses/enums to JSON-native values, and quantize every float to
`SEAL_NUMBER_PLACES` decimal places (half-even) as a `Decimal`. `decimal_string`
then strips trailing zeros, so `0.6`, `0.60`, and a float that arithmetic produced
as `0.5999999999` all seal identically. Money is already integer minor units
upstream (see a consumer's money policy) and passes through unchanged.

Two collection rules, unchanged from the seal's original meaning:
- **evidence and unresolved are order-INDEPENDENT sets** — canonicalized, then
  sorted by their own canonical bytes, so the order they were discovered in is not
  part of identity;
- **lists inside `interpreted` stay order-significant** — an ordered policy is not
  the same as its reverse.

Provenance is never part of identity. The payload schema and its version are, so a
finance policy and a healthcare order can never collide on the same hash.

The digest is the canonical layer's `rcv1:<sha256>` — one identity function for
the whole runtime, numbers and all.
"""
from __future__ import annotations

import dataclasses
from decimal import ROUND_HALF_EVEN, Decimal
from enum import Enum
from typing import Any, Iterable

from ..canonical import canonical_json
from ..canonical import content_hash as _canonical_hash

#: The seal's number policy: floats are quantized to this many decimal places
#: before hashing. Deliberately explicit — the canonical layer refuses to guess a
#: float's precision, so the seal decides it here, once, for every runtime.
SEAL_NUMBER_PLACES = 9

#: The seal contract version — participates in identity, so a change to the seal's
#: *meaning* (which fields, which rules) is a visible hash change.
SEAL_CONTRACT_VERSION = "1.0.0"

_QUANT = Decimal(1).scaleb(-SEAL_NUMBER_PLACES)   # Decimal("1e-9")


def prepare(value: Any) -> Any:
    """Project a domain value to canonical-safe form under the seal number policy:
    dataclasses/enums to JSON-native, every float to a quantized Decimal. The
    result contains no floats, so the canonical layer accepts it."""
    if isinstance(value, bool):
        return value
    if isinstance(value, float):
        return Decimal(str(value)).quantize(_QUANT, rounding=ROUND_HALF_EVEN)
    if value is None or isinstance(value, (int, str, Decimal)):
        return value
    if isinstance(value, Enum):
        return prepare(value.value)
    if isinstance(value, dict):
        return {str(k): prepare(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [prepare(v) for v in value]
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return prepare(dataclasses.asdict(value))
    return value


def content_hash(value: Any) -> str:
    """Content address for any domain artifact, under the seal number policy —
    the generic form used for execution proposals, approvals, reconciliations and
    the like. Lists keep their order (a proposal's order list is order-significant);
    use `seal_hash` for a VerifiedIntent whose evidence/unresolved are sets."""
    return _canonical_hash(prepare(value))


def _as_set(items: Iterable[Any]) -> list[Any]:
    """An order-independent collection: prepare each item, then sort by its own
    canonical bytes."""
    prepared = [prepare(i) for i in items]
    return sorted(prepared, key=canonical_json)


def canonical_form(interpreted: dict[str, Any], evidence: Iterable[Any] = (),
                   unresolved: Iterable[Any] = (), *, payload_schema: str,
                   payload_schema_version: str,
                   contract_version: str = SEAL_CONTRACT_VERSION) -> dict[str, Any]:
    """The canonical semantic form whose bytes are hashed. Pure; no I/O."""
    return {
        "contract_version": contract_version,
        "evidence": _as_set(evidence),
        "interpreted": prepare(interpreted),
        "payload_schema": payload_schema,
        "payload_schema_version": payload_schema_version,
        "unresolved": _as_set(unresolved),
    }


def seal_hash(interpreted: dict[str, Any], evidence: Iterable[Any] = (),
              unresolved: Iterable[Any] = (), *, payload_schema: str,
              payload_schema_version: str,
              contract_version: str = SEAL_CONTRACT_VERSION) -> str:
    """The identity of a sealed intent: `rcv1:<sha256>` over the canonical form."""
    return _canonical_hash(canonical_form(
        interpreted, evidence, unresolved, payload_schema=payload_schema,
        payload_schema_version=payload_schema_version,
        contract_version=contract_version))
