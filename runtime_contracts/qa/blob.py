"""``BlobStore`` and ``Redactor``: the binary-evidence seams.

Blob identity is the **full** SHA-256. The 16-hex truncation used by the harness trace recorder is not evidence
identity here: a digest that is not ``sha256:`` plus 64 lowercase hex digits is refused by name. The store is
content-addressed and append-only; ``put`` of the same bytes returns the same digest and no call overwrites.

A ``Redactor`` returns redacted bytes or raises ``RedactionFailed``. It never returns the input unredacted on
failure, and a caller that cannot redact drops the artifact.
"""
from __future__ import annotations

import hashlib
import re
from typing import Protocol, runtime_checkable

from .errors import BlobDigestInvalid, BlobDigestMismatch

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def blob_digest(data: bytes) -> str:
    """The ``sha256:<64 hex>`` identity of some bytes."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def require_blob_digest(digest: str) -> str:
    if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
        raise BlobDigestInvalid(f"{digest!r} is not a full-width sha256 digest (sha256: and 64 lowercase hex)")
    return digest


def verify_blob(digest: str, data: bytes) -> None:
    """Refuse bytes that do not hash to the digest they claim."""
    if blob_digest(data) != require_blob_digest(digest):
        raise BlobDigestMismatch(f"bytes do not hash to {digest}")


@runtime_checkable
class BlobStore(Protocol):
    """Append-only, content-addressed binary storage. Implemented by the product (``qa-evidence``)."""

    def put(self, data: bytes, *, media_type: str) -> str:
        """Store bytes and return their ``sha256:`` digest. Idempotent. Raises ``BlobTooLarge`` over the cap."""
        ...

    def get(self, digest: str) -> bytes:
        """The bytes for a digest, verified against it. ``BlobNotFound``, ``BlobDigestInvalid`` or
        ``BlobDigestMismatch`` otherwise."""
        ...

    def exists(self, digest: str) -> bool: ...

    def size(self, digest: str) -> int: ...


@runtime_checkable
class Redactor(Protocol):
    """Redacts an artifact under a named policy. Fails closed with ``RedactionFailed``."""

    policy_id: str

    def redact(self, data: bytes, *, media_type: str) -> bytes: ...
