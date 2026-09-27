"""Backend registry — the pluggable storage layer.

A store is opened by *name*, and a name resolves to a registered factory. The open runtime registers
two dependency-free backends (``memory``, ``file``). An Enterprise plugin, at import time, registers as
many more as a deployment needs — a managed relational database, a data warehouse, or a lakehouse table
format — each behind the same :class:`EvidenceStore` interface:

    from runtime_contracts.store import register_backend, open_store
    register_backend("iceberg", lambda **cfg: IcebergEvidenceStore(**cfg))   # in the enterprise plugin
    store = open_store("iceberg", warehouse="s3://…", catalog="…")           # in the runtime

This is what lets "a large number of standalone / managed relational databases and lakehouse schemas"
serve as the storage layer without the runtime knowing any of their names. The runtime depends on the
capability; the deployment chooses the backend.
"""
from __future__ import annotations

from typing import Callable, Dict, List

from .base import EvidenceStore
from .file import FileEvidenceStore, InMemoryEvidenceStore

#: name -> factory(**config) -> EvidenceStore
_BACKENDS: Dict[str, Callable[..., EvidenceStore]] = {}


def register_backend(name: str, factory: Callable[..., EvidenceStore]) -> None:
    """Register (or replace) a storage backend under ``name``. Called by enterprise plugins at import."""
    _BACKENDS[name] = factory


def available_backends() -> List[str]:
    """The backend names currently registered, sorted."""
    return sorted(_BACKENDS)


def open_store(name: str, **config: object) -> EvidenceStore:
    """Open an :class:`EvidenceStore` by registered backend ``name``, passing ``config`` to its factory."""
    try:
        factory = _BACKENDS[name]
    except KeyError:
        raise LookupError(
            f"unknown evidence-store backend {name!r}; registered: {available_backends()}"
        ) from None
    return factory(**config)


# -- the open, dependency-free floor --
register_backend("memory", lambda **cfg: InMemoryEvidenceStore(**cfg))
register_backend("file", lambda **cfg: FileEvidenceStore(**cfg))
