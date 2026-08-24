"""AGPL local-development secret stores — Environment and File.

These are the open floor: enough to run, test, and demo the runtime without any secret manager. They are
explicitly **development / air-gapped-eval grade** — not production credential systems. A capability that
declares ``production_broker_required=True`` is refused by the local broker that reads these.

Neither store lets arbitrary runtime components read a secret: the value is reached only through
``_read()``, which the :class:`LocalCredentialBroker` calls at the capability boundary. Nothing here prints
a path together with its value.
"""
from __future__ import annotations

import os
import stat
from typing import Dict, Optional, Tuple

from ..protocol.secrets import SecretDescriptor, SecretRef


class SecretAccessError(RuntimeError):
    """A local secret could not be read safely (missing, unsafe permissions, path escape)."""


class EnvironmentSecretStore:
    """Reads secrets from environment variables. For local dev, CI fixtures, examples, and public demos
    with **non-sensitive** credentials. Read-only: ``put``/``rotate`` are unsupported."""

    provider = "env"

    def __init__(self, *, prefix: str = "") -> None:
        self._prefix = prefix

    def _var(self, ref: SecretRef) -> str:
        base = ref.key or ref.path
        return f"{self._prefix}{base}"

    def describe(self, ref: SecretRef) -> SecretDescriptor:
        if self._var(ref) not in os.environ:
            raise SecretAccessError(f"env secret not found: {ref.redacted()}")
        return SecretDescriptor(ref=ref, classifications=("credential",), dynamic=False, renewable=False)

    def _read(self, ref: SecretRef) -> bytes:
        try:
            return os.environ[self._var(ref)].encode()
        except KeyError:
            raise SecretAccessError(f"env secret not found: {ref.redacted()}") from None

    def put(self, **_: object) -> SecretRef:
        raise NotImplementedError("EnvironmentSecretStore is read-only")

    def rotate(self, ref: SecretRef) -> SecretRef:
        raise NotImplementedError("EnvironmentSecretStore is read-only")

    def revoke(self, ref: SecretRef) -> None:  # nothing to revoke for an env var
        pass


class FileSecretStore:
    """Reads/writes secrets under ``$REDEVOPS_SECRET_DIR`` (or a given root). For local self-hosted testing,
    air-gapped evaluation, and deterministic integration tests. Hardened: refuses world-readable files and
    symlinks, and confines every path to the canonical root (no traversal)."""

    provider = "file"

    def __init__(self, root: Optional[str] = None) -> None:
        root = root or os.environ.get("REDEVOPS_SECRET_DIR", "")
        if not root:
            raise SecretAccessError("FileSecretStore needs a root (REDEVOPS_SECRET_DIR)")
        self.root = os.path.realpath(root)

    def _resolve(self, namespace: str, path: str) -> str:
        # Confine to the canonical root — reject any traversal or symlink escape.
        target = os.path.realpath(os.path.join(self.root, namespace, path))
        if target != self.root and not target.startswith(self.root + os.sep):
            raise SecretAccessError("secret path escapes the store root")
        return target

    def _check_safe(self, target: str) -> None:
        if not os.path.exists(target):
            raise SecretAccessError("secret not found")
        if os.path.islink(target):
            raise SecretAccessError("refusing to read a symlinked secret")
        mode = os.lstat(target).st_mode
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise SecretAccessError("refusing world/group-accessible secret file")

    def describe(self, ref: SecretRef) -> SecretDescriptor:
        target = self._resolve(ref.namespace, ref.path)
        self._check_safe(target)
        return SecretDescriptor(ref=ref, classifications=("credential",), dynamic=False, rotatable=True)

    def _read(self, ref: SecretRef) -> bytes:
        target = self._resolve(ref.namespace, ref.path)
        self._check_safe(target)
        with open(target, "rb") as fh:
            return fh.read()

    def put(self, *, namespace: str, path: str, value: bytes,
            classifications: Tuple[str, ...] = (), metadata: Optional[Dict[str, str]] = None) -> SecretRef:
        target = self._resolve(namespace, path)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, value)
        finally:
            os.close(fd)
        os.chmod(target, 0o600)
        return SecretRef(provider="file", namespace=namespace, path=path, version="1")

    def rotate(self, ref: SecretRef) -> SecretRef:
        # A real store versions; the local floor rewrites in place and bumps the label.
        nxt = str(int(ref.version or "1") + 1)
        return SecretRef(provider="file", namespace=ref.namespace, path=ref.path, key=ref.key, version=nxt)

    def revoke(self, ref: SecretRef) -> None:
        target = self._resolve(ref.namespace, ref.path)
        if os.path.exists(target) and not os.path.islink(target):
            os.remove(target)
