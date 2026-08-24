"""Pluggable registries for secret stores and credential brokers — the seam an enterprise plugin extends.

The open runtime registers the local ``env`` / ``file`` stores and the ``local`` broker. An enterprise
plugin, at import, registers ``vault`` / ``openbao`` / cloud backends behind the *same* protocols — the
runtime opens a store or broker by name and never learns the backend's identity.
"""
from __future__ import annotations

from typing import Callable, Dict, List

from ..protocol.secrets import CredentialBroker, SecretStore
from .broker import LocalCredentialBroker
from .store import EnvironmentSecretStore, FileSecretStore

_SECRET_BACKENDS: Dict[str, Callable[..., SecretStore]] = {}
_BROKER_BACKENDS: Dict[str, Callable[..., CredentialBroker]] = {}


def register_secret_store(name: str, factory: Callable[..., SecretStore]) -> None:
    _SECRET_BACKENDS[name] = factory


def register_broker(name: str, factory: Callable[..., CredentialBroker]) -> None:
    _BROKER_BACKENDS[name] = factory


def available_secret_stores() -> List[str]:
    return sorted(_SECRET_BACKENDS)


def available_brokers() -> List[str]:
    return sorted(_BROKER_BACKENDS)


def open_secret_store(name: str, **config: object) -> SecretStore:
    try:
        return _SECRET_BACKENDS[name](**config)
    except KeyError:
        raise LookupError(f"unknown secret store {name!r}; registered: {available_secret_stores()}") from None


def open_broker(name: str, **config: object) -> CredentialBroker:
    try:
        return _BROKER_BACKENDS[name](**config)
    except KeyError:
        raise LookupError(f"unknown broker {name!r}; registered: {available_brokers()}") from None


# -- the open, development-grade floor --
register_secret_store("env", lambda **cfg: EnvironmentSecretStore(**cfg))
register_secret_store("file", lambda **cfg: FileSecretStore(**cfg))
register_broker("local", lambda **cfg: LocalCredentialBroker(**cfg))
