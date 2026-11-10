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

The probe reports *capabilities* rather than assuming a shape: an implementation that cannot express a
document policy is a missing seam, not a missing import, and ``AdapterBlocked`` keeps that cell BLOCKED
instead of letting it pass. ``is_denial`` is deliberately narrow — a renamed method or a dead fixture must
never be mistaken for the implementation refusing to read.
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
from runtime_contracts.authz.suite import AdapterBlocked

RAG_LOGGER = "redevops_rag"


class _StatementSpy:
    """A pass-through connection that records what the store actually sent to the database.

    Needed because "the results were filtered" and "the candidates were filtered" are indistinguishable from
    the outside, and only one of them is what #627 asks for. A ``DuckDBPyConnection`` refuses attribute
    assignment, so the store's attribute is swapped for this proxy rather than instrumented in place.
    """

    def __init__(self, inner: Any, sink: list[str]) -> None:
        self._inner, self._sink = inner, sink

    def execute(self, sql: Any, *args: Any, **kwargs: Any) -> Any:
        self._sink.append(str(sql))
        return self._inner.execute(sql, *args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def __setattr__(self, name: str, value: Any) -> None:
        if name in ("_inner", "_sink"):
            object.__setattr__(self, name, value)
            return
        setattr(self._inner, name, value)
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

    def __init__(self, *, db_path: str | None = None, declared: bool = False,
                 policy: Any = None) -> None:
        self._store_mod = import_module(self.implementation, "redevops_rag.store")
        self._ingest_mod = import_module(self.implementation, "redevops_rag.ingest")
        self._retrieve_mod = import_module(self.implementation, "redevops_rag.retrieve")
        self._rag_mod = import_module(self.implementation, "redevops_rag.rag")
        # The decision type is optional on purpose. Its absence is the finding, not an import error.
        try:
            self._authority_mod: Any = import_module(self.implementation, "redevops_rag.authority")
        except AdapterBlocked:
            self._authority_mod = None
        self.embedder = _FixtureEmbedder()
        self.db_path = db_path or ":memory:"
        self._owns_tmp = True
        self._ctor: dict[str, Any] = {}
        ctor_params = set(inspect.signature(self._store_mod.Store.__init__).parameters)
        if declared:
            if "single_namespace" not in ctor_params:
                raise AdapterBlocked(f"{self.implementation} cannot declare a single-owner store")
            self._ctor["single_namespace"] = True
        if policy is not None:
            if "policy" not in ctor_params:
                raise AdapterBlocked(f"{self.implementation} cannot attach a document policy to a store")
            self._ctor["policy"] = policy
        self.store = self._store_mod.Store(self.embedder, self.db_path, **self._ctor)
        self._tmp = tempfile.TemporaryDirectory(prefix="rc-retrieval-")

    # -- indexing (the real ingest path) --------------------------------------
    def index(self, text: str, *, filename: str,
              owners: Callable[[Any], Iterable[str]] | None = None) -> dict[str, Any]:
        path = pathlib.Path(self._tmp.name) / filename
        path.write_text(text, encoding="utf-8")
        kwargs: dict[str, Any] = {}
        if owners is not None:
            if "owners" not in inspect.signature(self._ingest_mod.ingest).parameters:
                raise AdapterBlocked(
                    f"{self.implementation} ingest cannot declare owners before writing, so content can "
                    "only enter the index unowned — an owned index cannot be built to be measured")
            kwargs["owners"] = owners
        result = self._ingest_mod.ingest(self.store, self.embedder, str(path), **kwargs)
        self.store.reindex_fts()
        return result if isinstance(result, dict) else {"result": result}

    # -- retrieval ------------------------------------------------------------
    def _read_kwargs(self, authority: Any, document_ids: Sequence[str] | None,
                     params: set[str]) -> dict[str, Any]:
        """Build read arguments. A caller cannot hand an authority to an implementation that would ignore
        it: that would report an authorized read where the implementation did an unauthorized one."""
        kwargs: dict[str, Any] = {}
        if document_ids:
            kwargs["document_ids"] = list(document_ids)
        if authority is not None:
            if "authority" not in params:
                raise AdapterBlocked(f"{self.implementation} retrieval takes no authorization decision, "
                                     "so an authorized read cannot be measured")
            kwargs["authority"] = authority
        return kwargs

    def hybrid(self, query: str, *, limit: int = 8, document_ids: Sequence[str] | None = None,
               authority: Any = None) -> list[dict]:
        params = set(inspect.signature(self._retrieve_mod.hybrid_search).parameters)
        return self._retrieve_mod.hybrid_search(self.store, query, limit=limit,
                                                **self._read_kwargs(authority, document_ids, params))

    def vector(self, query: str, *, document_ids: Sequence[str] | None = None,
               authority: Any = None) -> list[dict]:
        params = set(inspect.signature(self._store_mod.Store.semantic_search).parameters)
        return self.store.semantic_search(query, **self._read_kwargs(authority, document_ids, params))

    def bm25(self, query: str, *, document_ids: Sequence[str] | None = None,
             authority: Any = None) -> list[dict]:
        params = set(inspect.signature(self._store_mod.Store.bm25_search).parameters)
        return self.store.bm25_search(query, **self._read_kwargs(authority, document_ids, params))

    def llm_context(self, query: str, *, limit: int = 8, authority: Any = None) -> str:
        """The exact string ``RAG.ask`` hands a model, assembled the way the implementation assembles it.

        The mirror is checked against the implementation's source in ``test_answer_context_mirror_matches``,
        so this cannot drift into flattering the product.
        """
        hits = self.hybrid(query, limit=limit, authority=authority)
        return "\n\n".join(f"[{i + 1}] {h['filename']}: {h['text']}" for i, h in enumerate(hits))

    # -- what landed where ----------------------------------------------------
    def observing_sql(self, call: Callable[[], Any]) -> tuple[Any, list[str]]:
        """Run a read, returning its result and every statement the store sent while running it."""
        statements: list[str] = []
        original = self.store.con
        self.store.con = _StatementSpy(original, statements)          # type: ignore[assignment]
        try:
            result = call()
        finally:
            self.store.con = original                                 # type: ignore[assignment]
        return result, statements

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

    def revoke(self, document_id: str) -> Any:
        """Withdrawal through the library's own interface. BLOCKED where the library offers none — raw SQL
        is an operator escape hatch, not the contract's revocation mechanism (see ``delete_by_sql``)."""
        for name in ("revoke", "delete", "remove", "forget"):
            fn = getattr(self.store, name, None)
            if callable(fn):
                return fn(document_id)
        raise AdapterBlocked(f"{self.implementation} exposes no revocation interface on "
                             f"{type(self.store).__name__}: content cannot be withdrawn through the library")

    # -- authorization seam ---------------------------------------------------
    def capabilities(self) -> dict[str, Any]:
        """What this implementation can be asked to do. Tests branch on this so that an absent seam is
        reported as BLOCKED or as a violation, never as a criterion that held."""
        ctor = set(inspect.signature(self._store_mod.Store.__init__).parameters)
        read = set(inspect.signature(self._retrieve_mod.hybrid_search).parameters)
        return {"authority_module": self._authority_mod is not None,
                "declared_store": "single_namespace" in ctor,
                "policy_attach": "policy" in ctor,
                "authority_on_read": "authority" in read,
                "revocation_interface": sorted(self.revocation_api()["delete"]),
                "fts_live": bool(getattr(self.store, "_fts", True)),
                "decision_required": self._decision_required()}

    def _decision_required(self) -> bool:
        """Does reading this store with no decision get refused? Measured, not inferred: an undeclared or
        policy-bound store that answers a decision-less read is a store that does not need one."""
        try:
            self.hybrid("authorization probe", limit=1)
        except Exception as exc:                                       # noqa: BLE001
            return self.is_denial(exc)
        return False

    def is_denial(self, exc: BaseException) -> bool:
        """True only for the implementation's own refusal to read without a decision.

        Kept narrow on purpose: ``ImportError``, ``AttributeError``, ``TypeError`` and this repo's own
        ``AdapterBlocked`` must never classify as a denial, or a broken measurement would be read as the
        fail-closed property holding. Unwraps the cause chain because stores commonly re-raise.
        """
        target: BaseException | None = exc
        for _ in range(5):
            if target is None:
                break
            module = type(target).__module__ or ""
            if module.startswith("redevops_rag") and type(target).__name__ in (
                    "RetrievalDenied", "AuthorizationUnavailable"):
                return True
            target = target.__cause__ or target.__context__
        return False

    def make_policy(self, acls: dict[str, Sequence[str]], *, subjects: Sequence[str] = ()) -> Any:
        """The library's own policy object, built from its own classes. Where none exists the cell is
        BLOCKED: a probe-side ACL would measure the probe, not the implementation."""
        if self._authority_mod is None:
            raise AdapterBlocked(f"{self.implementation} has no policy interface, so per-document authority "
                                 "cannot be expressed and an authorized read cannot be measured")
        return self._authority_mod.DocumentPolicy(
            [self._authority_mod.DocumentAcl(document_id=doc, tenants=frozenset(tenants),
                                             subjects=frozenset(subjects))
             for doc, tenants in acls.items()])

    def authority(self, policy: Any, tenant: str, *, subject: str = "agent",
                  roles: Sequence[str] = ()) -> Any:
        """The decision the library itself reaches for one principal in one tenant."""
        if self._authority_mod is None:
            raise AdapterBlocked(f"{self.implementation} has no principal or decision type")
        principal = self._authority_mod.Principal(subject=subject, tenant=tenant, roles=frozenset(roles))
        return policy.resolve(principal)

    def grant(self, policy: Any, document_id: str, tenants: Sequence[str],
              subjects: Sequence[str] = ()) -> Any:
        """Owner-side grant, through the library's own register. Document ids are only known after ingest,
        so a policy is attached first and populated from what the store actually stored.

        ``subjects`` is not decoration: the implementation checks tenancy *and* a subject or role match, so a
        tenants-only grant authorizes nobody. A test that granted tenants alone would watch every read come
        back empty and report a security property it never measured.
        """
        if self._authority_mod is None:
            raise AdapterBlocked(f"{self.implementation} has no policy interface to grant through")
        return policy.grant(self._authority_mod.DocumentAcl(document_id=document_id,
                                                            tenants=frozenset(tenants),
                                                            subjects=frozenset(subjects)))

    def delete_by_sql(self, document_id: str) -> int:
        """The only withdrawal path that exists: raw SQL by the operator. Recorded as an escape hatch, not
        as the contract's revocation mechanism."""
        before = len(self.persisted_texts())
        self.store.con.execute("DELETE FROM chunks WHERE document_id = ?", [document_id])
        return before - len(self.persisted_texts())

    def _twin(self, *, declared: bool) -> "RetrievalProbe":
        """A second, independent store instance over the same file, carrying this probe's declaration."""
        twin = RetrievalProbe.__new__(RetrievalProbe)
        twin._store_mod, twin._ingest_mod, twin._retrieve_mod, twin._rag_mod = (self._store_mod,
                                                                               self._ingest_mod,
                                                                               self._retrieve_mod,
                                                                               self._rag_mod)
        twin._authority_mod = self._authority_mod
        twin.embedder, twin.db_path, twin._tmp = self.embedder, self.db_path, self._tmp
        twin._owns_tmp = False          # the twin shares the directory: closing it must not delete it
        ctor = dict(self._ctor)
        if declared:
            if "single_namespace" in inspect.signature(self._store_mod.Store.__init__).parameters:
                ctor.pop("policy", None)
                ctor["single_namespace"] = True
            # An implementation that cannot declare a store has no undeclared state to escape from: a plain
            # instance reads rows, which is what an anti-vacuity check needs. Degrading here is honest
            # because the caller asks for a store that reads, not for a particular declaration.
        twin._ctor = ctor
        twin.store = self._store_mod.Store(twin.embedder, twin.db_path, **ctor)
        return twin

    def reopen(self) -> "RetrievalProbe":
        """A second, independent indexer instance over the same storage — the existing-instance test."""
        return self._twin(declared=False)

    def readable_probe(self) -> "RetrievalProbe":
        """A probe over the same file whose reads return rows: a declared single-owner store where the
        implementation can declare one, plain where it cannot. Anti-vacuity needs a read that reads."""
        return self._twin(declared=True)

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
            if self._owns_tmp:
                self._tmp.cleanup()