"""File-level and in-memory reference implementations of :class:`EvidenceStore`.

These are the **AGPL floor**: durable-enough, dependency-free persistence that makes the open runtime
fully usable and inspectable on its own. ``FileEvidenceStore`` is an append-only newline-delimited log
of canonical-JSON envelopes — the honest "file-level durability" the open edition ships. The heavy
machinery (streaming ingestion, columnar table formats, retention/legal-hold, warehouse integration)
is what an Enterprise backend adds *behind the same interface* — it is not reimplemented here.

Query operators (``snapshot`` / ``changes`` / ``scan``) filter the in-memory list; that is appropriate
for a reference/file-scale store and keeps the semantics obvious. A production backend pushes the same
predicates down into its engine.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Callable, Iterator, List, Optional

from ..canonical import canonical_json
from .base import Predicate, TimeRange
from .envelope import EvidenceEnvelope


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _in_range(value: str, time_range: Optional[TimeRange]) -> bool:
    if not time_range:
        return True
    lo, hi = time_range
    if lo and value < lo:
        return False
    if hi and value > hi:
        return False
    return True


class _ListEvidenceStore:
    """Shared query logic over an in-memory, append-ordered list of envelopes.

    Subclasses supply persistence: :meth:`_persist` (on append) and initial :meth:`_load`. ``clock``
    is injectable so ``known_at`` stamping is deterministic in tests."""

    def __init__(self, *, clock: Callable[[], str] = _utc_now) -> None:
        self._clock = clock
        self._events: List[EvidenceEnvelope] = []
        self._by_event_id: dict[str, EvidenceEnvelope] = {}
        self._by_hash: dict[str, EvidenceEnvelope] = {}

    # -- persistence hooks (overridden by FileEvidenceStore) --
    def _persist(self, env: EvidenceEnvelope) -> None:  # pragma: no cover - trivial
        pass

    def _index(self, env: EvidenceEnvelope) -> None:
        self._events.append(env)
        self._by_event_id.setdefault(env.event_id, env)
        if env.content_hash:
            self._by_hash.setdefault(env.content_hash, env)

    # -- EvidenceStore capabilities --
    def append(self, envelope: EvidenceEnvelope) -> str:
        env = envelope if envelope.known_at else envelope.with_known_at(self._clock())
        self._index(env)
        self._persist(env)
        return env.event_id

    def resolve(self, ref: str) -> Optional[EvidenceEnvelope]:
        if ref in self._by_event_id:
            return self._by_event_id[ref]
        if ref in self._by_hash:
            return self._by_hash[ref]
        if "#" in ref:  # a "ref@version#hash" pin — resolve on the hash tail
            tail = ref.rsplit("#", 1)[-1]
            return self._by_hash.get(tail)
        return None

    def snapshot(self, as_of: str) -> Iterator[EvidenceEnvelope]:
        for e in self._events:
            if not as_of or (e.known_at and e.known_at <= as_of):
                yield e

    def changes(self, since: str) -> Iterator[EvidenceEnvelope]:
        for e in self._events:
            if not since or (e.known_at and e.known_at > since):
                yield e

    def scan(self, predicate: Optional[Predicate] = None, *, time_range: Optional[TimeRange] = None) -> Iterator[EvidenceEnvelope]:
        pred = dict(predicate or {})
        for e in self._events:
            row = e.row()
            if any(row.get(k) != v for k, v in pred.items()):
                continue
            if not _in_range(e.event_time, time_range):
                continue
            yield e

    def verify(self, ref: str) -> bool:
        env = self.resolve(ref)
        return bool(env) and env.verify_payload()

    def __len__(self) -> int:
        return len(self._events)


class InMemoryEvidenceStore(_ListEvidenceStore):
    """Volatile reference store — the zero-config default (demos, tests, ephemeral runs)."""


class FileEvidenceStore(_ListEvidenceStore):
    """Append-only newline-delimited canonical-JSON log at ``path``; reloaded on open.

    This is the open edition's durable floor: no server, no dependencies, replay-ready. Each line is one
    envelope in canonical JSON (stable key order), so the file is diff-able and content-verifiable."""

    def __init__(self, path: str, *, clock: Callable[[], str] = _utc_now) -> None:
        super().__init__(clock=clock)
        self.path = path
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self.path):
            return
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    self._index(EvidenceEnvelope.from_json(json.loads(line)))

    def _persist(self, env: EvidenceEnvelope) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(canonical_json(env.to_json()) + "\n")
