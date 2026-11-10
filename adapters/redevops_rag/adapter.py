"""redevops-rag → the retrieval half of the authorization contract (issue #627).

This is a **probe**, not an adapter that makes retrieval authorized. It drives the implementation's real
indexing and retrieval functions and reports where document content ends up, so the acceptance criteria in
``tests/authz_contract/test_retrieval_baseline.py`` can be evaluated against facts rather than against
assumptions. What it deliberately does not do is supply the ACL the implementation does not have: a probe
that filters the results itself would turn a failing acceptance test into a passing fiction.

One fixture is substituted, and it is not an enforcement point: embeddings come from a deterministic
hashing embedder instead of ``sentence-transformers``, because ``Store`` accepts any object with ``dim`` and
``encode`` and a model download is not the boundary under test. Chunking, storage, BM25, vector search, RRF
fusion, boosting and the answer-context assembly are all the implementation's own code.
"""
from __future__ import annotations

import hashlib
import inspect
import logging
import math
import pathlib
import tempfile
from typing import Any, Callable, Iterable, Sequence

from adapters._implementations import import_module

RAG_LOGGER = "redevops_rag"
# The answer-context expression, spelled exactly as ``redevops_rag.rag.RAG.ask`` spells it. A test asserts
# this literal still appears in that source, so the mirror below cannot quietly drift.
CONTEXT_EXPRESSION = 'f"[{i + 1}] {h[\'filename\']}: {h[\'text\']}"'


class _FixtureEmbedder:
    """Token-hash embeddings: stable, offline, and irrelevant to authorization."""

    dim = 96

    def encode(self, texts: Iterable[str]) -> list[list[float]]:
        out = []
        for text in texts:
            vector = [0.0] * self.dim
            for token in filter(None, (t.strip(".,;:()\"'").lower() for t in str(text).split())):
                vector[int(hashlib.sha256(token.encode()).hexdigest(), 16) % self.dim] += 1.0
            norm = math.sqrt(sum(v * v for v in vector)) or 1.0
            out.append([v / norm for v in vector])
        return out


class RetrievalProbe:
    """The implementation's own indexing and retrieval surface, with observation points."""

    implementation = "redevops-rag"

    def __init__(self, *, db_path: str | None = None) -> None:
        self._store_mod = import_module(self.implementation, "redevops_rag.store")
        self._ingest_mod = import_module(self.implementation, "redevops_rag.ingest")
        self._retrieve_mod = import_module(self.implementation, "redevops_rag.retrieve")
        self._rag_mod = import_module(self.implementation, "redevops_rag.rag")
        self.embedder = _FixtureEmbedder()
        self.db_path = db_path or ":memory:"
        self.store = self._store_mod.Store(self.embedder, self.db_path)
        self._tmp = tempfile.TemporaryDirectory(prefix="rc-retrieval-")

    # -- indexing (the real ingest path) --------------------------------------
    def index(self, text: str, *, filename: str) -> dict[str, Any]:
        path = pathlib.Path(self._tmp.name) / filename
        path.write_text(text, encoding="utf-8")
        result = self._ingest_mod.ingest(self.store, self.embedder, str(path))
        self.store.reindex_fts()
        return result if isinstance(result, dict) else {"result": result}

    # -- retrieval ------------------------------------------------------------
    def hybrid(self, query: str, *, limit: int = 8, document_ids: Sequence[str] | None = None) -> list[dict]:
        return self._retrieve_mod.hybrid_search(self.store, query, limit=limit, document_ids=document_ids)

    def vector(self, query: str, *, document_ids: Sequence[str] | None = None) -> list[dict]:
        return self.store.semantic_search(query, document_ids=list(document_ids) if document_ids else None)

    def bm25(self, query: str, *, document_ids: Sequence[str] | None = None) -> list[dict]:
        return self.store.bm25_search(query, document_ids=list(document_ids) if document_ids else None)

    def llm_context(self, query: str, *, limit: int = 8) -> str:
        """The exact string ``RAG.ask`` hands a model, assembled the way the implementation assembles it.

        The mirror is checked against the implementation's source in ``test_answer_context_mirror_matches``,
        so this cannot drift into flattering the product.
        """
        hits = self.hybrid(query, limit=limit)
        return "\n\n".join(f"[{i + 1}] {h['filename']}: {h['text']}" for i, h in enumerate(hits))

    # -- what landed where ----------------------------------------------------
    def persisted_texts(self) -> list[str]:
        rows = self.store.con.execute("SELECT text FROM chunks").fetchall()
        return [r[0] for r in rows]

    def schema_columns(self) -> list[str]:
        rows = self.store.con.execute("DESCRIBE SELECT * FROM chunks").fetchall()
        return [r[0] for r in rows]

    def logs_during(self, call: Callable[[], Any]) -> tuple[Any, list[str]]:
        """Run something and return whatever the library logged — log snippets are part of the boundary."""
        records: list[str] = []

        class _Capture(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                try:
                    records.append(record.getMessage())
                except Exception:  # noqa: BLE001
                    pass

        handler = _Capture()
        logger = logging.getLogger(RAG_LOGGER)
        logger.addHandler(handler)
        try:
            result = call()
        finally:
            logger.removeHandler(handler)
        return result, records

    # -- revocation -----------------------------------------------------------
    def revocation_api(self) -> dict[str, Any]:
        """What the library offers for withdrawing indexed content. Currently: nothing."""
        names = [n for n in dir(self.store) if not n.startswith("_")]
        return {"store_methods": sorted(names),
                "delete": [n for n in names if "delete" in n.lower() or "remove" in n.lower()
                           or "revoke" in n.lower() or "forget" in n.lower()],
                "epoch_fields": [c for c in self.schema_columns() if "epoch" in c.lower()
                                 or "acl" in c.lower() or "tenant" in c.lower()]}

    def delete_by_sql(self, document_id: str) -> int:
        """The only withdrawal path that exists: raw SQL by the operator. Recorded as an escape hatch, not
        as the contract's revocation mechanism."""
        before = len(self.persisted_texts())
        self.store.con.execute("DELETE FROM chunks WHERE document_id = ?", [document_id])
        return before - len(self.persisted_texts())

    def reopen(self) -> "RetrievalProbe":
        """A second, independent indexer instance over the same storage — the existing-instance test."""
        twin = RetrievalProbe.__new__(RetrievalProbe)
        twin._store_mod, twin._ingest_mod, twin._retrieve_mod, twin._rag_mod = (self._store_mod,
                                                                               self._ingest_mod,
                                                                               self._retrieve_mod,
                                                                               self._rag_mod)
        twin.embedder, twin.db_path, twin._tmp = self.embedder, self.db_path, self._tmp
        twin.store = self._store_mod.Store(self.embedder, self.db_path)
        return twin

    # -- the authorization seam, or its absence -------------------------------
    def authorization_inputs(self) -> dict[str, list[str]]:
        """Every parameter the retrieval entry points accept that could carry authority."""
        out = {}
        for label, fn in (("hybrid_search", self._retrieve_mod.hybrid_search),
                          ("semantic_search", self._store_mod.Store.semantic_search),
                          ("bm25_search", self._store_mod.Store.bm25_search),
                          ("ingest", self._ingest_mod.ingest)):
            out[label] = sorted(inspect.signature(fn).parameters)
        return out

    def ask_source(self) -> str:
        return inspect.getsource(self._rag_mod.RAG.ask)

    def close(self) -> None:
        try:
            self.store.close()
        finally:
            self._tmp.cleanup()