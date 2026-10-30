"""Shared machinery for the ``qa/v1`` contracts.

Every ``qa/v1`` schema is a frozen dataclass. This module supplies the three things they all share, so that no
schema re-implements them (and so that a guard exists in one place):

* **Typed coercion and validation** driven by the field annotations. A field is a ``str``, an ``int``, an enum, a
  tuple of something or a nested schema; ``Annotated[..., Rule(...)]`` narrows it (identifier charset, digest
  shape, integer bounds). The same annotations feed the JSON Schema export, so the validator and the exported
  schema cannot drift apart.
* **Identity versus custody.** A schema lists the fields that are *custody* (who, when, how long); everything
  else is identity and enters the ``rcv1`` hash. Order-independent sequences are declared in ``SET_FIELDS`` and
  are sorted at construction, so two producers that list the same set in a different order build the same object.
* **A strict codec.** ``from_json`` refuses unknown keys, an unknown schema id or version, an unknown enum value
  and a stored ``content_hash`` that does not match the recomputed one. Nothing is coerced into acceptance.

Canonicalization is unchanged ``rcv1`` (``runtime_contracts.canonical``): sorted keys, null equals absent, NFC
strings, floats refused, decimals as strings. This module adds no hashing rule of its own.
"""
from __future__ import annotations

import collections.abc
import dataclasses
import enum
import functools
import re
import unicodedata
from dataclasses import dataclass, fields
from decimal import Decimal
from typing import (Annotated, Any, ClassVar, Dict, Iterator, Mapping, Optional,
                    Tuple, Union, get_args, get_origin, get_type_hints)

from ..canonical import canonical_json, canonicalize, content_hash, decimal_string

#: The contract family identity. Consumers pin an exact tag and refuse an unknown major.
QA_CONTRACT_ID = "qa/v1"
#: Version of every schema introduced with ``qa/v1``. Additive changes keep it; an incompatible change is ``qa/v2``.
QA_SCHEMA_VERSION = "0.1"
SCHEMA_ID_PREFIX = "runtime-contracts/qa/"

DEFAULT_MAX_TEXT = 4096
MAX_JSON_DEPTH = 12
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class Code:
    """Stable error and reason codes. They are strings so a port in any language can compare them."""

    INVALID_FIELD = "INVALID_FIELD"
    MISSING_FIELD = "MISSING_FIELD"
    UNKNOWN_FIELD = "UNKNOWN_FIELD"
    UNKNOWN_ENUM_VALUE = "UNKNOWN_ENUM_VALUE"
    DUPLICATE_ENTRY = "DUPLICATE_ENTRY"
    FLOAT_REFUSED = "FLOAT_REFUSED"
    SCHEMA_MISMATCH = "SCHEMA_MISMATCH"
    SCHEMA_VERSION_UNSUPPORTED = "SCHEMA_VERSION_UNSUPPORTED"
    HASH_MISMATCH = "HASH_MISMATCH"
    # assertion integrity: every one of these ends a run INCONCLUSIVE(ASSERTION_INTEGRITY)
    ASSERTION_INTEGRITY = "ASSERTION_INTEGRITY"
    ASSERTION_HASH_MISMATCH = "ASSERTION_HASH_MISMATCH"
    EXECUTOR_MISMATCH = "EXECUTOR_MISMATCH"
    EXPECTED_MISMATCH = "EXPECTED_MISMATCH"
    RECOVERY_PAYLOAD_REJECTED = "RECOVERY_PAYLOAD_REJECTED"
    COVERAGE_VIOLATION = "COVERAGE_VIOLATION"
    # plan
    UNSUPPORTED_COVERAGE_CONTRACT = "UNSUPPORTED_COVERAGE_CONTRACT"
    PLAN_INVALID = "PLAN_INVALID"
    # spec
    SPEC_INVALID = "SPEC_INVALID"
    CHECK_PROGRAM_REF_REQUIRED = "CHECK_PROGRAM_REF_REQUIRED"
    # records
    RECORD_INCONSISTENT = "RECORD_INCONSISTENT"
    FAULT_BINDING_MISMATCH = "FAULT_BINDING_MISMATCH"


class QAContractError(ValueError):
    """A value cannot be a valid ``qa/v1`` object. Raised rather than coerced; ``code`` is stable."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.detail = message


class UnknownEnumValue(QAContractError):
    """An enum value this version does not define. Consumers treat it as non-certifying (fail closed)."""

    def __init__(self, message: str):
        super().__init__(Code.UNKNOWN_ENUM_VALUE, message)


class AssertionIntegrityError(QAContractError):
    """Something tried to change, bypass or contradict a frozen assertion.

    ``code`` names the specific violation; ``run_outcome`` and ``run_reason`` are what the run is classified as
    whatever the specific code is: ``INCONCLUSIVE(ASSERTION_INTEGRITY)``, and the batch halts.
    """

    run_outcome = "INCONCLUSIVE"
    run_reason = Code.ASSERTION_INTEGRITY


# ── field rules ────────────────────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Rule:
    """A constraint carried in ``Annotated[...]``. Used by validation and by the JSON Schema export."""

    pattern: Optional[str] = None
    max_length: Optional[int] = None
    min_length: Optional[int] = None
    minimum: Optional[int] = None
    maximum: Optional[int] = None
    max_json_bytes: Optional[int] = None

    def check(self, path: str, value: Any) -> None:
        if value is None:
            return
        if isinstance(value, str):
            if self.pattern is not None and not re.fullmatch(self.pattern, value):
                raise QAContractError(Code.INVALID_FIELD, f"{path}={_clip(value)!r} does not match {self.pattern}")
            if self.max_length is not None and len(value) > self.max_length:
                raise QAContractError(Code.INVALID_FIELD, f"{path} is longer than {self.max_length}")
            if self.min_length is not None and len(value) < self.min_length:
                raise QAContractError(Code.INVALID_FIELD, f"{path} is shorter than {self.min_length}")
        elif isinstance(value, int) and not isinstance(value, bool):
            if self.minimum is not None and value < self.minimum:
                raise QAContractError(Code.INVALID_FIELD, f"{path}={value} is below {self.minimum}")
            if self.maximum is not None and value > self.maximum:
                raise QAContractError(Code.INVALID_FIELD, f"{path}={value} is above {self.maximum}")
        if self.max_json_bytes is not None and len(canonical_json(value).encode("utf-8")) > self.max_json_bytes:
            raise QAContractError(Code.INVALID_FIELD, f"{path} exceeds {self.max_json_bytes} canonical bytes")


def _clip(value: str, n: int = 60) -> str:
    return value if len(value) <= n else value[:n] + "..."


_ID = r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}"
_HEX = r"[0-9a-f]{64}"

#: A stable identifier: assertion ids, step ids, run ids, lane names, schema-level names.
Ident = Annotated[str, Rule(pattern=_ID)]
#: ``[A-Za-z0-9._:/-]``, at most 128 characters (the ADR's ``requirement_ref`` charset).
RefToken = Annotated[str, Rule(pattern=r"[A-Za-z0-9._:/-]{1,128}")]
#: An upper-case code token such as ``SUBJECT_UNRESOLVED``.
CodeToken = Annotated[str, Rule(pattern=r"[A-Z][A-Z0-9_]{0,63}")]
#: A record hash: ``rcv1:`` and the full 64 hex digits.
Rcv1 = Annotated[str, Rule(pattern=rf"rcv1:{_HEX}")]
#: A blob, program, image or fixture digest: ``sha256:`` and the full 64 hex digits. Truncated forms are refused.
Sha256 = Annotated[str, Rule(pattern=rf"sha256:{_HEX}")]
#: Either full-width digest form. For fields that may name a blob or a record.
AnyDigest = Annotated[str, Rule(pattern=rf"(rcv1|sha256):{_HEX}")]
#: ``<id>@rcv1:<64 hex>``, a spec reference.
SPEC_REF_RULE = Rule(pattern=rf"{_ID}@rcv1:{_HEX}")
SpecRefStr = Annotated[str, SPEC_REF_RULE]
#: A semantic-version-like token for components and programs.
Version = Annotated[str, Rule(pattern=r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}")]
#: A source revision: 7 to 64 lowercase hex digits.
Revision = Annotated[str, Rule(pattern=r"[0-9a-f]{7,64}")]
#: A bounded duration in integer milliseconds. Durations are integers; floats are refused.
DeadlineMs = Annotated[int, Rule(minimum=1, maximum=86400000)]
Text = Annotated[str, Rule(max_length=DEFAULT_MAX_TEXT)]
ShortText = Annotated[str, Rule(max_length=512)]
NonEmptyText = Annotated[str, Rule(min_length=1, max_length=1024)]
NonNeg = Annotated[int, Rule(minimum=0)]
Pos = Annotated[int, Rule(minimum=1)]
#: Bounded canonical JSON. Floats are refused; decimals are strings.
Json = Annotated[Any, Rule(max_json_bytes=16384)]
BoundedJson = Annotated[Any, Rule(max_json_bytes=4096)]


# ── immutable JSON ─────────────────────────────────────────────────────────────────────────────────────────

class FrozenMap(collections.abc.Mapping):
    """An immutable, hashable mapping with string keys, for JSON objects inside a frozen schema.

    A frozen dataclass stops attribute assignment but not ``spec.assertion.expected["x"] = ...`` on a dict it
    holds. Holding a ``FrozenMap`` closes that path: there is no item assignment, no ``update`` and no ``pop``.
    """

    __slots__ = ("_items", "_index")

    def __init__(self, items: Mapping[str, Any]):
        pairs = tuple(sorted(items.items()))
        object.__setattr__(self, "_items", pairs)
        object.__setattr__(self, "_index", dict(pairs))

    def __setattr__(self, name, value):  # pragma: no cover - guard
        raise AttributeError("FrozenMap is immutable")

    def __getitem__(self, key):
        return self._index[key]

    def __iter__(self) -> Iterator[str]:
        return (k for k, _ in self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __hash__(self) -> int:
        return hash(self._items)

    def __eq__(self, other) -> bool:
        if isinstance(other, FrozenMap):
            return self._items == other._items
        if isinstance(other, collections.abc.Mapping):
            return dict(self._items) == dict(other)
        return NotImplemented

    def __repr__(self) -> str:
        return f"FrozenMap({dict(self._items)!r})"


def freeze_json(value: Any, path: str = "value", _depth: int = 0) -> Any:
    """Convert JSON-shaped input into an immutable canonical-ready form, refusing what ``rcv1`` refuses."""
    if _depth > MAX_JSON_DEPTH:
        raise QAContractError(Code.INVALID_FIELD, f"{path} is nested deeper than {MAX_JSON_DEPTH}")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        raise QAContractError(Code.FLOAT_REFUSED, f"{path} is a float; carry fractional values as decimal strings")
    if isinstance(value, Decimal):
        return decimal_string(value)
    if isinstance(value, str):
        return _text(path, value)
    if isinstance(value, collections.abc.Mapping):
        out = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise QAContractError(Code.INVALID_FIELD, f"{path} has a non-string key {key!r}")
            out[_text(path, key)] = freeze_json(item, f"{path}.{key}", _depth + 1)
        return FrozenMap(out)
    if isinstance(value, (list, tuple)):
        return tuple(freeze_json(v, f"{path}[{i}]", _depth + 1) for i, v in enumerate(value))
    raise QAContractError(Code.INVALID_FIELD, f"{path} is a {type(value).__name__}, which is not JSON")


def thaw_json(value: Any) -> Any:
    """The mutable plain-JSON view of a frozen value, for serialization only."""
    if isinstance(value, FrozenMap):
        return {k: thaw_json(v) for k, v in value.items()}
    if isinstance(value, tuple):
        return [thaw_json(v) for v in value]
    return value


def _text(path: str, value: str) -> str:
    if _CONTROL.search(value):
        raise QAContractError(Code.INVALID_FIELD, f"{path} contains a control character")
    return unicodedata.normalize("NFC", value)


# ── coercion ───────────────────────────────────────────────────────────────────────────────────────────────

@functools.lru_cache(maxsize=None)
def _hints(cls) -> Dict[str, Any]:
    return get_type_hints(cls, include_extras=True)


def _coerce(tp: Any, value: Any, path: str) -> Any:
    origin = get_origin(tp)
    if origin is Annotated:
        base, *meta = get_args(tp)
        out = _coerce(base, value, path)
        for m in meta:
            if isinstance(m, Rule):
                m.check(path, out)
        return out
    if origin is Union:
        inner = [a for a in get_args(tp) if a is not type(None)]
        if value is None:
            return None
        return _coerce(inner[0], value, path)
    if value is None:
        raise QAContractError(Code.MISSING_FIELD, f"{path} is required")
    if tp is Any:
        return freeze_json(value, path)
    if origin in (tuple, collections.abc.Sequence):
        if not isinstance(value, (list, tuple)):
            raise QAContractError(Code.INVALID_FIELD, f"{path} must be a list")
        elem = get_args(tp)[0]
        return tuple(_coerce(elem, v, f"{path}[{i}]") for i, v in enumerate(value))
    if tp is bool:
        if not isinstance(value, bool):
            raise QAContractError(Code.INVALID_FIELD, f"{path} must be a boolean")
        return value
    if tp is int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise QAContractError(Code.INVALID_FIELD, f"{path} must be an integer (floats and booleans are refused)")
        return value
    if tp is str:
        if isinstance(value, enum.Enum):
            value = value.value
        if not isinstance(value, str):
            raise QAContractError(Code.INVALID_FIELD, f"{path} must be a string")
        if len(value) > DEFAULT_MAX_TEXT:
            raise QAContractError(Code.INVALID_FIELD, f"{path} is longer than {DEFAULT_MAX_TEXT}")
        return _text(path, value)
    if isinstance(tp, type) and issubclass(tp, enum.Enum):
        if isinstance(value, tp):
            return value
        try:
            return tp(value)
        except ValueError:
            raise UnknownEnumValue(
                f"{path}={_clip(str(value))!r} is not a {tp.__name__}; an unknown value is non-certifying") from None
    if isinstance(tp, type) and dataclasses.is_dataclass(tp):
        if isinstance(value, tp):
            return value
        if isinstance(value, collections.abc.Mapping):
            return _decode(tp, value, path)
        raise QAContractError(Code.INVALID_FIELD, f"{path} must be a {tp.__name__}")
    raise TypeError(f"unsupported annotation {tp!r} at {path}")  # pragma: no cover - a schema bug, not input


def _decode(tp: type, data: collections.abc.Mapping, path: str) -> Any:
    if hasattr(tp, "from_json"):
        return tp.from_json(data, _path=path)
    names = {f.name for f in fields(tp)}
    extra = sorted(set(data) - names)
    if extra:
        raise QAContractError(Code.UNKNOWN_FIELD, f"{path} has unknown field(s) {extra}")
    hints = _hints(tp)
    return tp(**{k: _coerce(hints[k], data[k], f"{path}.{k}") for k in data})


# ── schema base classes ────────────────────────────────────────────────────────────────────────────────────

def _set_key(item: Any, key: Optional[str]) -> Any:
    if key is None:
        return item.value if isinstance(item, enum.Enum) else item
    if key == "@json":
        return canonical_json(_encode(item, full=False))
    return getattr(item, key)


@dataclass(frozen=True)
class QAValue:
    """A nested ``qa/v1`` value: identity by its fields, no schema id of its own."""

    #: Fields that are custody (not hashed): who, when, how long.
    CUSTODY: ClassVar[frozenset] = frozenset()
    #: Sequence fields that are sets. ``{field: element attribute | "@json" | None}``. Sorted at construction.
    SET_FIELDS: ClassVar[Mapping[str, Optional[str]]] = {}

    def __post_init__(self) -> None:
        hints = _hints(type(self))
        for f in fields(self):
            object.__setattr__(self, f.name, _coerce(hints[f.name], getattr(self, f.name), f.name))
        for name, key in self.SET_FIELDS.items():
            items = getattr(self, name)
            keys = [_set_key(i, key) for i in items]
            if len(set(keys)) != len(keys):
                dup = sorted({str(k) for k in keys if keys.count(k) > 1})
                raise QAContractError(Code.DUPLICATE_ENTRY, f"{name} lists {dup} more than once")
            object.__setattr__(self, name, tuple(sorted(items, key=lambda i: _set_key(i, key))))
        self.validate()

    def validate(self) -> None:
        """Cross-field rules. Subclasses override; per-field rules live in the annotations."""

    # identity ---------------------------------------------------------------------------------------------

    def canonical_form(self) -> Dict[str, Any]:
        return _identity(self, full=False)

    def value_hash(self) -> str:
        """``rcv1:`` hash of the identity form. Custody fields never enter it.

        A method, not ``content_hash``: a nested value may legitimately have a field of that name
        (``FixtureRef.content_hash``). Independently addressed records expose ``content_hash``.
        """
        return content_hash(self.canonical_form())

    def to_json(self) -> Dict[str, Any]:
        return canonicalize(_identity(self, full=True))

    @classmethod
    def from_json(cls, data: Any, *, _path: str = "") -> "QAValue":
        path = _path or cls.__name__
        if not isinstance(data, collections.abc.Mapping):
            raise QAContractError(Code.INVALID_FIELD, f"{path} must be an object")
        names = {f.name for f in fields(cls)}
        extra = sorted(set(data) - names - _RESERVED)
        if extra:
            raise QAContractError(Code.UNKNOWN_FIELD, f"{path} has unknown field(s) {extra}")
        kwargs = {k: data[k] for k in data if k in names}
        custody = data.get("custody")
        if custody is not None:
            if not isinstance(custody, collections.abc.Mapping):
                raise QAContractError(Code.INVALID_FIELD, f"{path}.custody must be an object")
            bad = sorted(set(custody) - cls.CUSTODY)
            if bad:
                raise QAContractError(Code.UNKNOWN_FIELD, f"{path}.custody has unknown field(s) {bad}")
            kwargs.update(custody)
        _require(cls, kwargs, path)
        try:
            return cls(**kwargs)
        except QAContractError:
            raise
        except TypeError as exc:  # pragma: no cover - defensive
            raise QAContractError(Code.INVALID_FIELD, f"{path}: {exc}") from None


_RESERVED = frozenset({"schema_id", "schema_version", "content_hash", "custody"})


def _require(cls: type, kwargs: Dict[str, Any], path: str) -> None:
    for f in fields(cls):
        if f.name not in kwargs and f.default is dataclasses.MISSING and f.default_factory is dataclasses.MISSING:
            raise QAContractError(Code.MISSING_FIELD, f"{path}.{f.name} is required")


@dataclass(frozen=True)
class QARecord(QAValue):
    """An independently addressed ``qa/v1`` schema: carries its schema id and version in the hashed form."""

    SCHEMA_ID: ClassVar[str] = ""
    SCHEMA_VERSION: ClassVar[str] = QA_SCHEMA_VERSION

    @property
    def content_hash(self) -> str:
        """``rcv1:`` hash of the identity form, schema id and version included. Custody never enters it."""
        return self.value_hash()

    @classmethod
    def from_json(cls, data: Any, *, _path: str = "") -> "QARecord":
        path = _path or cls.__name__
        if not isinstance(data, collections.abc.Mapping):
            raise QAContractError(Code.INVALID_FIELD, f"{path} must be an object")
        _guard_schema_identity(cls, data, path)
        obj = super().from_json(data, _path=path)
        _guard_stored_hash(obj, data, path)
        return obj


def _guard_schema_identity(cls: type, data: collections.abc.Mapping, path: str) -> None:
    if data.get("schema_id") != cls.SCHEMA_ID:
        raise QAContractError(Code.SCHEMA_MISMATCH, f"{path}.schema_id is {data.get('schema_id')!r}, "
                              f"expected {cls.SCHEMA_ID!r}")
    if data.get("schema_version") != cls.SCHEMA_VERSION:
        raise QAContractError(Code.SCHEMA_VERSION_UNSUPPORTED,
                              f"{path}.schema_version is {data.get('schema_version')!r}; this reader supports "
                              f"{cls.SCHEMA_VERSION!r} and refuses any other (unknown major fails closed)")


def _guard_stored_hash(obj: "QARecord", data: collections.abc.Mapping, path: str) -> None:
    stored = data.get("content_hash")
    if stored is not None and stored != obj.content_hash:
        raise QAContractError(Code.HASH_MISMATCH, f"{path}.content_hash {stored!r} does not match the "
                              f"recomputed {obj.content_hash!r}")


def _encode(value: Any, *, full: bool) -> Any:
    if value is None:
        return None
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, FrozenMap):
        return {k: _encode(v, full=full) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [_encode(v, full=full) for v in value]
    if isinstance(value, QARecord):
        return value.to_json() if full else value.canonical_form()
    if isinstance(value, QAValue):
        return _identity(value, full=full)
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        if full:  # a reused repository type: every field, so the round trip is lossless
            return {f.name: _encode(getattr(value, f.name), full=True) for f in fields(value)}
        return value.canonical_form()
    return value


def _identity(obj: QAValue, *, full: bool) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if isinstance(obj, QARecord):
        out["schema_id"] = obj.SCHEMA_ID
        out["schema_version"] = obj.SCHEMA_VERSION
    for f in fields(obj):
        if f.name in obj.CUSTODY:
            continue
        out[f.name] = _encode(getattr(obj, f.name), full=full)
    if full and isinstance(obj, QARecord):
        out["content_hash"] = obj.content_hash
    if full and obj.CUSTODY:
        custody = {n: _encode(getattr(obj, n), full=True) for n in sorted(obj.CUSTODY)
                   if getattr(obj, n) is not None}
        if custody:
            out["custody"] = custody
    return out


# ── hash verification without a model ──────────────────────────────────────────────────────────────────────

def strip_non_identity(payload: Any) -> Any:
    """Remove ``content_hash`` and ``custody`` from every ``qa/v1`` record inside a received payload.

    A reader older than a writer (same major) must not recompute from a field list it does not fully know; it
    verifies the bytes it received. Only mappings that carry a ``qa/v1`` schema id are stripped, so an
    ``EvidenceRef.content_hash`` inside a record is left alone.
    """
    if isinstance(payload, collections.abc.Mapping):
        is_record = str(payload.get("schema_id", "")).startswith(SCHEMA_ID_PREFIX)
        return {k: strip_non_identity(v) for k, v in payload.items()
                if not (is_record and k in ("content_hash", "custody"))}
    if isinstance(payload, (list, tuple)):
        return [strip_non_identity(v) for v in payload]
    return payload


def verify_stored_hash(payload: Mapping[str, Any]) -> bool:
    """True when a received record's ``content_hash`` equals the ``rcv1`` hash of its own identity bytes.

    Works on any same-major payload, including one with additive fields this version does not model.
    """
    stored = payload.get("content_hash")
    if not isinstance(stored, str):
        return False
    return content_hash(strip_non_identity(payload)) == stored


def value_digest(value: str) -> str:
    """``rcv1`` digest of a (possibly sensitive) string value, for records that carry the digest, not the value."""
    return content_hash(unicodedata.normalize("NFC", value))
