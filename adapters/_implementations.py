"""Locating and observing the real implementations.

The authz suite is only worth running if it runs against the actual plane code. These helpers do two things
and nothing else:

* **Find a checkout.** An implementation is available when its root is on ``sys.path`` — either already
  importable, or named by an environment variable (``AGENTIC_OS_ROOT``, ``AGENTIC_OS_ENTERPRISE_ROOT``,
  ``REDEVOPS_RAG_ROOT``). When it is not, adapters raise ``AdapterBlocked``: the cell is reported as
  un-runnable, never as a pass. No checkout path is baked into the repository.
* **Read the audit trail the way an auditor does.** The envelopes both planes emit are log lines. Adapters
  attach a handler to the plane's own logger and parse what the implementation wrote, so a Receipt reflects
  the emitted audit record — not a dictionary the adapter assembled to look like one.
"""
from __future__ import annotations

import importlib
import json
import logging
import os
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from runtime_contracts.authz.decision import DECISION_EVENT, parse_envelope
from runtime_contracts.authz.decision import EnvelopeError
from runtime_contracts.authz.suite import AdapterBlocked

_ROOT_ENV = {
    "agentic-os": "AGENTIC_OS_ROOT",
    "agentic-os-enterprise": "AGENTIC_OS_ENTERPRISE_ROOT",
    "redevops-rag": "REDEVOPS_RAG_ROOT",
}
#: Public name for the same mapping, so a qualification record can say which variable names which checkout.
ROOT_ENV = _ROOT_ENV


def add_implementation_root(implementation: str) -> Path | None:
    """Put an implementation's checkout on ``sys.path`` if one is configured. Returns the root or None."""
    env = _ROOT_ENV.get(implementation, "")
    raw = os.environ.get(env, "").strip()
    if not raw:
        return None
    root = Path(raw).expanduser().resolve()
    if not root.is_dir():
        raise AdapterBlocked(f"{implementation}: {env}={raw!r} is not a directory")
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    return root


def import_module(implementation: str, module: str):
    """Import an implementation module, or explain in one line why the cell cannot run."""
    # The configured checkout wins. Without this call the ``*_ROOT`` variables above were documentation only:
    # an installed copy of the plane answered, and the matrix recorded a commit nobody had measured.
    add_implementation_root(implementation)
    try:
        return importlib.import_module(module)
    except ImportError as exc:
        env = _ROOT_ENV.get(implementation, "its checkout")
        raise AdapterBlocked(
            f"{implementation}: cannot import {module!r} ({exc}). Set {env} to the checkout and re-run; "
            "the cell stays BLOCKED until then.") from exc


def imported_root(implementation: str, module: str) -> Path:
    """The checkout the imported code actually came from, or :class:`AdapterBlocked`.

    A matrix cell records a commit. That record is worth nothing unless it can be traced to the file the
    decision came out of, so the binding is resolved from the import system (``module.__file__``) and walked
    up to the containing git working tree — not from an environment variable somebody may or may not have set.
    """
    path = Path(getattr(import_module(implementation, module), "__file__", "") or "").resolve()
    for parent in path.parents:
        if (parent / ".git").exists():
            return parent
    raise AdapterBlocked(f"{implementation}: {path} is not inside a git working tree, so its commit cannot be "
                         "recorded — install it as a checkout (or point the root variable at one)")


class AuditCapture(logging.Handler):
    """The decision envelopes an implementation logged, in order.

    ``plane`` is harness attribution, not implementation output: an envelope says what was decided, never
    *which checkout* decided it. A run that measures two editions must still be able to say whose decision a
    receipt was, which is what lets :mod:`runtime_contracts.authz.suite` reject a cross-talk receipt.
    """

    def __init__(self, plane: str = "") -> None:
        super().__init__(level=logging.DEBUG)
        self.plane = plane
        self.lines: list[str] = []
        self.envelopes: list[dict[str, Any]] = []
        self.malformed: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 — a broken log line is a finding, not a crash
            return
        if DECISION_EVENT not in message:
            return
        self.lines.append(message)
        start = message.find("{")
        if start < 0:
            self.malformed.append(message)
            return
        try:
            self.envelopes.append(json.loads(message[start:]))
        except json.JSONDecodeError:
            self.malformed.append(message)

    def last(self):
        """The most recent decision as a contract object, or None when nothing was (well-formed) emitted."""
        for raw in reversed(self.envelopes):
            try:
                return parse_envelope(raw, plane=self.plane)
            except EnvelopeError:
                self.malformed.append(json.dumps(raw, sort_keys=True))
        return None

    @property
    def receipts(self) -> list:
        out = []
        for raw in self.envelopes:
            try:
                out.append(parse_envelope(raw, plane=self.plane))
            except EnvelopeError:
                continue
        return out


@contextmanager
def capture_audit(*logger_names: str, plane: str = "") -> Iterator[AuditCapture]:
    """Capture ``authorization_decision`` lines written by the implementation during the block.

    Pass ``plane=<implementation>`` so the captured receipts stay attributable to the edition under test.
    """
    handler = AuditCapture(plane)
    attached = []
    for name in logger_names:
        logger = logging.getLogger(name)
        logger.addHandler(handler)
        if logger.level == logging.NOTSET or logger.level > logging.INFO:
            logger.setLevel(logging.INFO)
        attached.append(logger)
    try:
        yield handler
    finally:
        for logger in attached:
            logger.removeHandler(handler)
        handler.close()


def block(implementation: str, what: str) -> AdapterBlocked:
    return AdapterBlocked(f"{implementation}: {what}")