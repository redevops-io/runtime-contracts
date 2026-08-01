"""Canonical serialization and hashing.

Every other contract in this package depends on exactly one property:

    same handles + same preview plan + same version pins + same contract version
        = same ContextView hash

That has to hold across implementations, across process restarts, and across
languages. It does not hold by accident — it holds because every ambiguity in
serialization is decided here once, in a form another language can reproduce.

The decisions, and why each is the way it is:

**Map keys are sorted.** Insertion order is a property of the process that built
the object, not of what the object means.

**Absent and null are the same thing.** A field set to null is dropped. An
implementation that populates an optional field with null must not hash
differently from one that omits it, or every adapter has to guess which style
the reference implementation used.

**Floats are refused in canonical form.** Cross-language float formatting is the
classic source of hashes that agree on one runtime and disagree on another —
Python, Go and JavaScript do not print the same digits for the same double.
Anything fractional is carried as a decimal *string* and compared as one.

**Strings are NFC-normalized.** Two byte sequences that display identically must
hash identically; an artifact id typed on macOS should not differ from the same
id typed on Linux.

**Volatile timestamps do not participate.** When a handle was last accessed says
nothing about what it refers to.

**Authorization and omission decisions do participate.** They change what the
model was permitted to see, and two views that showed different subsets of the
same graph are not the same view — even when the difference is a redaction.

**Materialized content participates through its pinned hash, never its bytes.**
The canonical form stays small and stays comparable without carrying payloads.
"""
from __future__ import annotations

import hashlib
import json
import unicodedata
from decimal import Decimal
from typing import Any, Mapping, Sequence

CONTRACT_VERSION = "0.1"

#: Prefix on every hash, so a digest carries the rules that produced it. A hash
#: with no algorithm label is unversionable — the day the rules change, nothing
#: distinguishes an old digest from a wrong one.
HASH_PREFIX = "rcv1"


class CanonicalizationError(ValueError):
    """A value cannot be represented canonically.

    Raised rather than coerced. A silent coercion is a hash that differs between
    implementations for a reason nobody logged.
    """


def _text(value: str) -> str:
    return unicodedata.normalize("NFC", value)


def canonicalize(value: Any) -> Any:
    """Reduce a value to its canonical form.

    Recursive, total, and refusing anything it cannot represent unambiguously.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        raise CanonicalizationError(
            f"float {value!r} cannot appear in canonical form. Python, Go and "
            "JavaScript do not agree on how to print a double, so a float here "
            "produces hashes that match on one runtime and differ on another. "
            "Carry fractional values as decimal strings."
        )
    if isinstance(value, Decimal):
        return format(value.normalize(), "f")
    if isinstance(value, str):
        return _text(value)
    if isinstance(value, Mapping):
        out = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(
                    f"map key {key!r} is not a string; key ordering would depend "
                    "on a comparison other languages define differently"
                )
            reduced = canonicalize(item)
            if reduced is None:
                continue  # absent and null are the same thing
            out[_text(key)] = reduced
        return {k: out[k] for k in sorted(out)}
    if isinstance(value, (list, tuple)):
        return [canonicalize(v) for v in value]
    if isinstance(value, (set, frozenset)):
        raise CanonicalizationError(
            "sets have no defined order; sort into a list at the point the "
            "ordering rule is known rather than leaving it to the hasher"
        )
    if hasattr(value, "canonical_form"):
        return canonicalize(value.canonical_form())
    raise CanonicalizationError(
        f"{type(value).__name__} has no canonical representation. Add one "
        "deliberately rather than letting the hasher guess."
    )


def canonical_json(value: Any) -> str:
    """The exact bytes another implementation must produce."""
    return json.dumps(
        canonicalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def content_hash(value: Any) -> str:
    """Prefixed SHA-256 over the canonical bytes."""
    digest = hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
    return f"{HASH_PREFIX}:{digest}"


def sorted_unique(items: Sequence[Any], *, key) -> list:
    """Deduplicate and order, in that order.

    Duplicates are **normalized, not rejected**. Two independent parts of a plan
    legitimately reference the same artifact, and refusing that would push
    deduplication into every caller — where some would forget. Two handles that
    differ in any canonical field are different handles and both survive.
    """
    seen = {}
    for item in items:
        seen.setdefault(key(item), item)
    return [seen[k] for k in sorted(seen)]
