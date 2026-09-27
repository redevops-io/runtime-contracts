"""AGPL local-development secret providers + broker, and their pluggable registries.

The open floor of authority-scoped credential brokerage: run and test the runtime with no secret manager,
while an enterprise plugin registers Vault/OpenBao/cloud backends behind the same open protocols.
"""
from __future__ import annotations

from .broker import CredentialDenied, LocalCredentialBroker
from .registry import (
    available_brokers,
    available_secret_stores,
    open_broker,
    open_secret_store,
    register_broker,
    register_secret_store,
)
from .store import EnvironmentSecretStore, FileSecretStore, SecretAccessError

__all__ = [
    "EnvironmentSecretStore",
    "FileSecretStore",
    "SecretAccessError",
    "LocalCredentialBroker",
    "CredentialDenied",
    "open_secret_store",
    "open_broker",
    "register_secret_store",
    "register_broker",
    "available_secret_stores",
    "available_brokers",
]
