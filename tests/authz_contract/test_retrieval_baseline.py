"""#627 — the retrieval-authorization baseline, recorded before any fix.

redevops-rag indexes into one store with no ACL and no tenant filter, and the kernel delegates retrieval
authorization entirely to its callers; nobody proves a caller filter was applied. This file records that
state as **executable** evidence rather than as prose: the acceptance criteria are written the way the
contract requires them, marked ``xfail(strict=True)``, and the enforcement boundary is documented by tests
that pass today.

The strict-xfail marking is deliberate. A skipped test would say "unknown"; a passing test would say
"enforced". ``xfail(strict=True)`` says *this criterion is unmet and this file knows it* — and the moment
somebody fixes the leak, the XPASS turns the suite red so the marking, and the matrix row, must be updated
in the same change.

Nothing here makes retrieval authorized. The moment the suite can pass these criteria honestly, that is the
fix landing — in redevops-rag, not in this file.
"""
from __future__ import annotations

import pytest

from runtime_contracts.authz.suite import AdapterBlocked

BASELINE = ("E-4/#627 baseline: redevops-rag has no ACL, no tenant filter and no revocation interface, so "
            "unauthorized content reaches this stage. Fix in redevops-rag, then flip this marking — do not "
            "weaken the assertion.")

ACME_SECRET = "ACME-SLEEPER-9133 quarterly restatement: revenue recognized a quarter early."
GLOBEX_NOTE = "Globex logistics: the Rotterdam lane slipped two days in the same quarter."
MARKER = "ACME-SLEEPER-9133"

def _probe_or_skip(**kwargs):
    try:
        from adapters.redevops_rag import RetrievalProbe
        return RetrievalProbe(**kwargs)
    except AdapterBlocked as exc:
        pytest.skip(f"BLOCKED — {exc}")
    except ImportError as exc:                              # duckdb is an implementation dependency
        pytest.skip(f"BLOCKED — redevops-rag could not be imported ({exc})")


@pytest.fixture()
def shared_store(tmp_path):
    """One store, two tenants' documents — the deployment the library documents today."""
    probe = _probe_or_skip(db_path=str(tmp_path / "shared.duckdb"))
    probe.index(ACME_SECRET, filename="acme-restatement.md")
    probe.index(GLOBEX_NOTE, filename="globex-logistics.md")
    yield probe
    probe.close()


# ── the enforcement boundary, as it exists now (these pass, and they are the documentation) ──

def test_no_retrieval_entry_point_takes_an_authorization_input(shared_store) -> None:
    inputs = shared_store.authorization_inputs()
    authority_words = ("principal", "acl", "tenant", "subject", "permission", "authorization")
    carrying = {fn: [p for p in params if any(w in p for w in authority_words)]
                for fn, params in inputs.items()}
    assert all(not v for v in carrying.values()), f"an entry point now takes authority: {carrying}"


def test_stored_chunks_have_no_authorization_column(shared_store) -> None:
    columns = shared_store.schema_columns()
    assert not [c for c in columns if any(w in c.lower() for w in ("acl", "tenant", "epoch", "owner"))], \
        f"the chunks table now carries authorization data: {columns}"


def test_the_library_offers_no_revocation_interface(shared_store) -> None:
    """Withdrawal exists only as somebody else's SQL. That is an escape hatch, not a contract."""
    assert shared_store.revocation_api()["delete"] == []


def test_document_ids_is_a_caller_supplied_subset_not_authority(shared_store) -> None:
    """The filter works, which is exactly why it is not enforcement: the caller supplies the allow-list and
    nothing checks that it named the right documents — or any documents at all."""
    globex = [h["document_id"] for h in shared_store.hybrid("Rotterdam lane", limit=5)]
    assert globex, "the fixture stopped producing a globex document"
    assert all(h["document_id"] in globex for h in
               shared_store.hybrid("restatement revenue recognized", limit=5, document_ids=globex))
    unfiltered = shared_store.hybrid("restatement revenue recognized", limit=5)
    assert any(MARKER in h["text"] for h in unfiltered), "the default path no longer reads the whole store"


def test_answer_context_mirror_matches_the_implementation(shared_store) -> None:
    from adapters.redevops_rag.adapter import CONTEXT_EXPRESSION
    assert CONTEXT_EXPRESSION in shared_store.ask_source(), (
        "redevops_rag.rag.RAG.ask changed how it builds a model's context; update the mirror, do not "
        "silently stop measuring it")


def test_log_snippets_do_not_quote_retrieved_content(shared_store) -> None:
    """This criterion holds today — the library logs nothing about a query. Recorded so that adding a debug
    log line with retrieved text is a change this suite notices."""
    _, lines = shared_store.logs_during(lambda: shared_store.hybrid("restatement revenue", limit=5))
    assert not [line for line in lines if MARKER in line], f"a log line now carries retrieved content: {lines}"


def test_the_leak_assertions_below_are_not_vacuous(tmp_path) -> None:
    """The same assertions pass against per-tenant stores, so a failure below is about authorization and not
    about a marker that could never appear. Physical separation is a mitigation the shell can do today; it
    is not an ACL, and it does not survive a shared index."""
    acme = _probe_or_skip(db_path=str(tmp_path / "acme.duckdb"))
    globex = _probe_or_skip(db_path=str(tmp_path / "globex.duckdb"))
    try:
        acme.index(ACME_SECRET, filename="acme-restatement.md")
        globex.index(GLOBEX_NOTE, filename="globex-logistics.md")
        assert not any(MARKER in h["text"] for h in globex.hybrid("restatement revenue recognized", limit=5))
    finally:
        acme.close()
        globex.close()


# ── the acceptance criteria, unmet (strict xfail: they must fail until the fix lands) ──────────

@pytest.mark.xfail(strict=True, reason=BASELINE)
def test_unauthorized_document_content_stays_out_of_candidate_generation(shared_store) -> None:
    """A globex-only caller's query must not put acme content into the candidate pool."""
    candidates = shared_store.vector("quarterly restatement revenue recognized early")
    assert not any(MARKER in c["text"] for c in candidates), \
        "acme content is a candidate for a query made without acme authority"


@pytest.mark.xfail(strict=True, reason=BASELINE)
def test_unauthorized_document_content_stays_out_of_ranking(shared_store) -> None:
    ranked = shared_store.hybrid("quarterly restatement revenue recognized early", limit=5)
    assert not any(MARKER in h["text"] for h in ranked), \
        "acme content survived into the ranked result set"


@pytest.mark.xfail(strict=True, reason=BASELINE)
def test_unauthorized_content_is_not_persisted_in_readable_storage(shared_store) -> None:
    """#627 says *before any tenant data enters an index*. Unencrypted text in a shared store fails that
    criterion whether or not a query ever returns it."""
    assert not any(MARKER in text for text in shared_store.persisted_texts()), \
        "acme chunk text sits in the shared store in plaintext"


@pytest.mark.xfail(strict=True, reason=BASELINE)
def test_unauthorized_content_never_enters_the_llm_context(shared_store) -> None:
    context = shared_store.llm_context("quarterly restatement revenue", limit=5)
    assert MARKER not in context, "the answer context handed to a model contains acme content"


@pytest.mark.xfail(strict=True, reason=BASELINE)
def test_revocation_is_expressible_and_honoured_by_an_existing_indexer_instance(shared_store) -> None:
    """Revocation across an *existing* instance, through an interface — not out-of-band SQL against a file.

    The measured state: there is no revoke/delete API at all, so a caller cannot express revocation. Raw SQL
    happens to be visible to a second connection over the same file, which is why the leak measured here is
    the absence of the interface rather than the propagation of a deletion.
    """
    document_id = shared_store.hybrid("restatement revenue", limit=1)[0]["document_id"]
    revoke = getattr(shared_store.store, "revoke", None) or getattr(shared_store.store, "delete", None)
    assert callable(revoke), (
        f"no revocation interface exists on {type(shared_store.store).__name__}; "
        f"available: {shared_store.revocation_api()['store_methods']}")
    revoke(document_id)
    assert not any(MARKER in h["text"] for h in shared_store.hybrid("quarterly restatement revenue", limit=5))


@pytest.mark.xfail(strict=True, reason=BASELINE)
def test_a_tenant_shaped_filename_or_project_id_is_not_authorization(shared_store) -> None:
    """A file named for one tenant is not a boundary: content is matched on content, and nothing binds a
    query to a tenant, so the filename buys nothing."""
    shared_store.index(ACME_SECRET.replace(MARKER, "ACME-SLEEPER-4510"), filename="globex-own-notes.md")
    hits = shared_store.hybrid("quarterly restatement revenue recognized", limit=5)
    assert not any("globex-own-notes.md" == h["filename"] and "ACME-SLEEPER-4510" in h["text"] for h in hits), (
        "acme content stored under a globex-shaped filename is retrievable by filename-blind content search, "
        "which is the point: the filename is data, not an ACL")


@pytest.mark.xfail(strict=True, reason=BASELINE)
def test_deny_on_adapter_error_never_degrades_into_a_broad_read(shared_store) -> None:
    """#627's fail-closed clause. Measured here as: what does a retrieval call do when its own vector feed
    fails? ``hybrid_search`` swallows the exception and keeps the BM25 feed — a partial failure silently
    becomes a different, broader retrieval with no signal that authority could not be evaluated."""
    def _broken_vector(*args, **kwargs):
        raise RuntimeError("vector feed unavailable")

    original = shared_store.store.semantic_search
    shared_store.store.semantic_search = _broken_vector      # type: ignore[method-assign]
    try:
        _, logs = shared_store.logs_during(
            lambda: shared_store.hybrid("Rotterdam lane slipped", limit=5))
        hits = shared_store.hybrid("Rotterdam lane slipped", limit=5)
    finally:
        shared_store.store.semantic_search = original        # type: ignore[method-assign]
    assert not hits or logs, (
        "the vector feed failed, the call answered anyway from the surviving feed, and nothing recorded "
        "that part of retrieval could not run")


# ── keeping the xfail set honest ───────────────────────────────────────────────────────────────

def _xfail_cases() -> list[str]:
    return sorted(name for name, obj in globals().items()
                  if name.startswith("test_")
                  and callable(obj)
                  and any(marker.name == "xfail" for marker in getattr(obj, "pytestmark", [])))


@pytest.mark.parametrize("case_name", _xfail_cases())
def test_each_xfail_fails_for_the_leak_it_claims(shared_store, case_name: str) -> None:
    """A strict xfail reports "expected failure" for *any* exception, so a renamed probe method or a dead
    fixture keeps the suite green while the measurement is gone. Running each body directly distinguishes the
    two: the only acceptable failure is an AssertionError naming the leak, and a pass means the marking is
    stale. This is what stops the xfail set from rotting into decoration.
    """
    try:
        globals()[case_name](shared_store)
    except AssertionError as exc:
        assert str(exc), f"{case_name} failed with no message — an assertion that names no leak measures nothing"
    except Exception as exc:                                     # noqa: BLE001
        pytest.fail(f"{case_name} is marked xfail as an unmet criterion but raised {type(exc).__name__}: {exc}. "
                    "That is a broken measurement, not a measured gap — fix the test, do not leave the marking "
                    "to hide it.")
    else:
        pytest.fail(f"{case_name} now passes: the leak it documents is closed. Remove the xfail marking and "
                    "update the matrix row in the same change.")