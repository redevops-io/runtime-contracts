"""The additive-only field inventory for ``qa/v1``.

A committed snapshot (``golden/qa.inventory.json``) lists every schema, value type, enum and protocol with each
field's type, whether it is required and whether it is custody. Within ``qa/v1`` a later change may add optional
fields, new schemas and new enum members; it may not remove, rename, retype or newly require anything, move a field
between identity and custody, or change a protocol. ``breaking_changes(old, new)`` returns every such difference,
and a test fails on any.

Regenerate the snapshot only for a deliberate additive change: ``python -m runtime_contracts.qa.inventory``.
"""
from __future__ import annotations

import collections.abc
import dataclasses
import enum
import inspect
import json
import pathlib
import sys
from typing import Annotated, Any, Dict, List, Union, get_args, get_origin

from .base import QA_CONTRACT_ID, QA_SCHEMA_VERSION, QARecord, Rule, _hints
from .registry import ALL_ENUMS, PROTOCOLS, RECORDS, VALUES
from .schema_export import _foreign_dataclasses

DEFAULT_PATH = pathlib.Path(__file__).resolve().parents[2] / "golden" / "qa.inventory.json"


def _render(tp: Any) -> str:
    origin = get_origin(tp)
    if origin is Annotated:
        base, *meta = get_args(tp)
        rules = []
        for m in meta:
            if isinstance(m, Rule):
                rules.extend(f"{k}={v}" for k, v in dataclasses.asdict(m).items() if v is not None)
        return _render(base) + (f"[{';'.join(rules)}]" if rules else "")
    if origin is Union:
        return "Optional[" + _render([a for a in get_args(tp) if a is not type(None)][0]) + "]"
    if tp is Any:
        return "Json"
    if origin in (tuple, collections.abc.Sequence):
        return "Tuple[" + _render(get_args(tp)[0]) + "]"
    return tp.__name__


def _fields(cls: type) -> Dict[str, Any]:
    hints = _hints(cls)
    custody = getattr(cls, "CUSTODY", frozenset())
    return {f.name: {"type": _render(hints[f.name]),
                     "required": f.default is dataclasses.MISSING and f.default_factory is dataclasses.MISSING,
                     "custody": f.name in custody}
            for f in dataclasses.fields(cls)}


def _protocol(proto: type) -> Dict[str, Any]:
    methods = {}
    for name, fn in vars(proto).items():
        if inspect.isfunction(fn) and not name.startswith("_"):
            sig = inspect.signature(fn)
            methods[name] = {"parameters": [p for p in sig.parameters if p != "self"],
                             "returns": str(sig.return_annotation)}
    return {"attributes": sorted(getattr(proto, "__annotations__", {})), "methods": methods}


def inventory() -> Dict[str, Any]:
    return {
        "contract": QA_CONTRACT_ID,
        "schema_version": QA_SCHEMA_VERSION,
        "records": {cls.__name__: {"schema_id": cls.SCHEMA_ID, "schema_version": cls.SCHEMA_VERSION,
                                   "fields": _fields(cls)} for cls in RECORDS},
        "values": {cls.__name__: {"fields": _fields(cls)} for cls in VALUES},
        "reused": {name: {"fields": _fields(cls)} for name, cls in _foreign_dataclasses().items()},
        "enums": {name: [m.value for m in members] for name, members in ALL_ENUMS.items()},
        "protocols": {name: _protocol(p) for name, p in PROTOCOLS.items()},
        "api_versions": _api_versions(),
    }


def _api_versions() -> Dict[str, str]:
    from .adapter import QA_ADAPTER_API_VERSION
    from .check_adapter import CHECK_ADAPTER_API_VERSION
    return {"QAAdapter": QA_ADAPTER_API_VERSION, "CheckAdapter": CHECK_ADAPTER_API_VERSION}


def breaking_changes(old: Dict[str, Any], new: Dict[str, Any]) -> List[str]:
    """Differences that are not additive. Empty means ``new`` only adds to ``old``."""
    found: List[str] = []
    if old.get("contract") != new.get("contract") or old.get("schema_version") != new.get("schema_version"):
        found.append("contract id or schema version changed")
    for section in ("records", "values", "reused"):
        for name, spec in old.get(section, {}).items():
            cur = new.get(section, {}).get(name)
            if cur is None:
                found.append(f"{section[:-1]} {name} was removed")
                continue
            for key in ("schema_id", "schema_version"):
                if spec.get(key) != cur.get(key):
                    found.append(f"{name}.{key} changed")
            for fname, f in spec["fields"].items():
                c = cur["fields"].get(fname)
                if c is None:
                    found.append(f"{name}.{fname} was removed or renamed")
                    continue
                if c["type"] != f["type"]:
                    found.append(f"{name}.{fname} was retyped: {f['type']} -> {c['type']}")
                if c["custody"] != f["custody"]:
                    found.append(f"{name}.{fname} moved between identity and custody")
                if c["required"] and not f["required"]:
                    found.append(f"{name}.{fname} became required")
            for fname, c in cur["fields"].items():
                if fname not in spec["fields"] and c["required"]:
                    found.append(f"{name}.{fname} was added as a required field")
    for name, members in old.get("enums", {}).items():
        cur = new.get("enums", {}).get(name)
        if cur is None:
            found.append(f"enum {name} was removed")
        else:
            for m in members:
                if m not in cur:
                    found.append(f"enum {name} lost member {m}")
    for name, spec in old.get("protocols", {}).items():
        if new.get("protocols", {}).get(name) != spec:
            found.append(f"protocol {name} changed (a protocol change needs a new api_version)")
    if old.get("api_versions") != new.get("api_versions"):
        found.append("an adapter api_version changed")
    return found


def render(doc: Dict[str, Any] = None) -> str:
    return json.dumps(doc if doc is not None else inventory(), indent=2, sort_keys=True) + "\n"


def main(argv=None) -> int:
    path = pathlib.Path((argv or sys.argv[1:] or [str(DEFAULT_PATH)])[0])
    path.write_text(render(), encoding="utf-8")
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
