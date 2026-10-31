"""JSON Schema (draft 2020-12) export for ``qa/v1``, generated from the dataclasses.

For non-Python consumers. It is derived from the same annotations the validators use, so the exported schema and
the Python validation cannot drift apart. It states the structural contract: field names, types, enum members,
digest and identifier shapes, bounds, required fields and "no other keys". Cross-field rules (for example "SCRIPT
needs a check_program_ref") and the hash itself are not expressible in JSON Schema; the golden fixtures carry those.

Regenerate with ``python -m runtime_contracts.qa.schema_export``; a test fails if the committed file differs.
"""
from __future__ import annotations

import dataclasses
import enum
import json
import pathlib
import sys
import collections.abc
from typing import Annotated, Any, Dict, Optional, Union, get_args, get_origin

from .base import QA_CONTRACT_ID, QA_SCHEMA_VERSION, QARecord, QAValue, Rule, _hints
from .registry import ALL_ENUMS, RECORDS, VALUES

DIALECT = "https://json-schema.org/draft/2020-12/schema"
HASH_PATTERN = r"^rcv1:[0-9a-f]{64}$"
DEFAULT_PATH = pathlib.Path(__file__).resolve().parents[2] / "golden" / "qa.schema.json"


def _rule_keywords(rule: Rule, base: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    if rule.pattern is not None:
        out["pattern"] = f"^(?:{rule.pattern})$"
    if rule.max_length is not None:
        out["maxLength"] = rule.max_length
    if rule.min_length is not None:
        out["minLength"] = rule.min_length
    if rule.minimum is not None:
        out["minimum"] = rule.minimum
    if rule.maximum is not None:
        out["maximum"] = rule.maximum
    return out


def _schema(tp: Any) -> Dict[str, Any]:
    origin = get_origin(tp)
    if origin is Annotated:
        base, *meta = get_args(tp)
        out = _schema(base)
        for m in meta:
            if isinstance(m, Rule):
                out = _rule_keywords(m, out)
        return out
    if origin is Union:
        return _schema([a for a in get_args(tp) if a is not type(None)][0])
    if tp is Any:
        return {}
    if origin in (tuple, collections.abc.Sequence):
        return {"type": "array", "items": _schema(get_args(tp)[0])}
    if tp is bool:
        return {"type": "boolean"}
    if tp is int:
        return {"type": "integer"}
    if tp is str:
        return {"type": "string"}
    if isinstance(tp, type) and issubclass(tp, enum.Enum):
        return {"$ref": f"#/$defs/{tp.__name__}"}
    if isinstance(tp, type) and dataclasses.is_dataclass(tp):
        return {"$ref": f"#/$defs/{tp.__name__}"}
    raise TypeError(f"no JSON Schema for {tp!r}")  # pragma: no cover - a schema bug


def _object(cls: type) -> Dict[str, Any]:
    hints = _hints(cls)
    custody = getattr(cls, "CUSTODY", frozenset())
    set_fields = getattr(cls, "SET_FIELDS", {})
    props: Dict[str, Any] = {}
    cust_props: Dict[str, Any] = {}
    required = []
    for f in dataclasses.fields(cls):
        prop = _schema(hints[f.name])
        if f.name in set_fields and prop.get("type") == "array":
            prop = {**prop, "uniqueItems": True}
        required_field = f.default is dataclasses.MISSING and f.default_factory is dataclasses.MISSING
        if f.name in custody:
            cust_props[f.name] = prop
            continue
        props[f.name] = prop
        if required_field:
            required.append(f.name)
    if issubclass(cls, QARecord):
        props = {"schema_id": {"const": cls.SCHEMA_ID}, "schema_version": {"const": cls.SCHEMA_VERSION}, **props,
                 "content_hash": {"type": "string", "pattern": HASH_PATTERN}}
        required = ["schema_id", "schema_version", *required]
        if cust_props:
            props["custody"] = {"type": "object", "properties": cust_props, "additionalProperties": False}
    # Custody fields that are required are not required in the document: they live under "custody" and are optional.
    return {"type": "object", "properties": props, "required": required, "additionalProperties": False}


def _foreign_dataclasses() -> Dict[str, type]:
    """Reused repository types referenced by qa/v1 schemas (Check, EvidenceRef, SecretRef)."""
    found: Dict[str, type] = {}
    for cls in [*RECORDS, *VALUES]:
        for tp in _hints(cls).values():
            stack = [tp]
            while stack:
                t = stack.pop()
                stack.extend(get_args(t))
                if isinstance(t, type) and dataclasses.is_dataclass(t) and not issubclass(t, QAValue):
                    found[t.__name__] = t
    return dict(sorted(found.items()))


def export() -> Dict[str, Any]:
    defs: Dict[str, Any] = {}
    for name, members in ALL_ENUMS.items():
        defs[name] = {"enum": [m.value for m in members]}
    for cls in [*VALUES, *RECORDS]:
        defs[cls.__name__] = _object(cls)
    for name, cls in _foreign_dataclasses().items():
        defs[name] = _object(cls)
    return {
        "$schema": DIALECT,
        "title": f"runtime-contracts {QA_CONTRACT_ID}",
        "description": ("Structural JSON Schema for the qa/v1 contracts, generated from the dataclasses. "
                        "Hashes (rcv1) and cross-field rules are specified by the golden fixtures, not here."),
        "x-contract": QA_CONTRACT_ID,
        "x-schema-version": QA_SCHEMA_VERSION,
        "x-records": {cls.SCHEMA_ID: cls.__name__ for cls in RECORDS},
        "$defs": dict(sorted(defs.items())),
    }


def render(doc: Optional[Dict[str, Any]] = None) -> str:
    return json.dumps(doc if doc is not None else export(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv=None) -> int:
    path = pathlib.Path((argv or sys.argv[1:] or [str(DEFAULT_PATH)])[0])
    path.write_text(render(), encoding="utf-8")
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
