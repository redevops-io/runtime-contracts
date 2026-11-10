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

The boundary tests below used to assert the leak itself ("no entry point takes authority"), which made them
false in both directions: they reported the fix as a regression. They are now properties with two acceptable
states, so this one file measures the insecure baseline (``6e50d6d``) and a protected candidate
(``0245d8f``) without being edited between them — a read either takes a decision or refuses to answer
without one, authority is decided above the index rather than inside the table it protects, and content can
be withdrawn through an interface. The baseline fails them and demonstrates the violation; a candidate that
holds them passes. A refusal is reported as *denied*, never as *satisfied*, and the anti-vacuity controls
still fail a dead fixture or a renamed method.
"""
from __future__ import annotations

import re
from types import SimpleNamespace

import pytest

from runtime_contracts.authz.suite import AdapterBlocked

BASELINE = ("E-4/#627 baseline: redevops-rag has no ACL, no tenant filter and no revocation interface, so "
            "unauthorized content reaches this stage. Fix in redevops-rag, then flip this marking — do not "
            "weaken the assertion.")

ACME_SECRET = "ACME-SLEEPER-9133 quarterly restatement: revenue recognized a quarter early."
GLOBEX_NOTE = "Globex logistics: the Rotterdam lane slipped two days in the same quarter."
MARKER = "ACME-SLEEPER-9133"
# "authority" joins this list because an implementation added a parameter of exactly that name, and none of
# the words this suite looked for contained it. A boundary test that cannot see the seam it watches for is
# worse than no boundary test: it reports the fix as a pass, for the wrong reason.
AUTHORITY_WORDS = ("principal", "acl", "tenant", "subject", "permission", "authorization", "authority")


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


OWNERS = {"acme-restatement.md": ("acme",), "globex-logistics.md": ("globex",)}


def _document_id(probe, filename: str) -> str:
    rows = probe.store.con.execute(
        "SELECT DISTINCT document_id FROM chunks WHERE filename = ?", [filename]).fetchall()
    assert rows, f"no document named {filename} was stored, so nothing below measures a real document"
    return rows[0][0]


@pytest.fixture()
def owned_store(tmp_path):
    """One shared index, each document owned through the implementation's own policy register.

    The subject is named next to the tenant on purpose. Tenancy alone authorizes nobody here, and a
    tenants-only grant reads back empty — which every "no leak" assertion in this file would report as a
    security property it had never measured. Where no policy register exists the cell is BLOCKED, because an
    ACL invented by the probe would certify a boundary the implementation does not have.
    """
    plain = _probe_or_skip(db_path=str(tmp_path / "owned.duckdb"))
    try:
        policy = plain.make_policy({})
    except AdapterBlocked as exc:
        plain.close()
        pytest.skip(f"BLOCKED — {exc}")
    plain.close()

    probe = _probe_or_skip(db_path=str(tmp_path / "owned.duckdb"), policy=policy)
    try:
        documents = ((ACME_SECRET, "acme-restatement.md"), (GLOBEX_NOTE, "globex-logistics.md"))
        for text, filename in documents:
            probe.index(text, filename=filename, owners=lambda path: OWNERS[path.name])
        for filename in OWNERS:
            probe.grant(policy, _document_id(probe, filename), OWNERS[filename], ("agent",))
        acme_id = _document_id(probe, "acme-restatement.md")
        assert acme_id != _document_id(probe, "globex-logistics.md"), (
            "the two documents collapsed into one id, so a cross-tenant read is not being measured")
        assert bool(probe.authority(policy, "acme")) and bool(probe.authority(policy, "globex")), (
            "neither tenant can read what it owns: reads below would return nothing and look like enforcement")
        yield SimpleNamespace(probe=probe, policy=policy, acme_id=acme_id,
                              globex_id=_document_id(probe, "globex-logistics.md"),
                              acme=lambda: probe.authority(policy, "acme"),
                              globex=lambda: probe.authority(policy, "globex"))
    finally:
        probe.close()


# ── the enforcement boundary, as a property rather than as today's embarrassment ──────────────
#
# Each test below holds of an implementation that authorizes retrieval and fails of one that does not, so
# the baseline reads as a violation and a fix reads as a pass. A test that asserted the leak instead would
# have gone red for the right reason and the wrong one alike.

DENIED = object()


def _read_or_denied(probe, call):
    """Run a read and return its rows, or DENIED when the implementation refused to run it at all.

    Only the implementation's own refusal counts; every other exception propagates, because treating a
    broken probe as a refusal is how a suite starts grading empty results as security.
    """
    try:
        return call()
    except Exception as exc:                                        # noqa: BLE001
        if probe.is_denial(exc):
            return DENIED
        raise


def test_retrieval_either_takes_authority_or_refuses_to_read_without_it(shared_store) -> None:
    """A read that accepts no authority had better not answer for every principal there is.

    Two acceptable states, one unacceptable one. Entry points may take a decision — and ``authority`` is in
    ``AUTHORITY_WORDS`` because an implementation named its parameter exactly that and the old word list
    could not see it, which is how a boundary test reports a fix as a pass for the wrong reason. Or an
    entry point may take nothing and refuse a decision-less read. Answering everybody is the violation.
    """
    inputs = shared_store.authorization_inputs()
    carrying = {fn: [p for p in params if any(w in p for w in AUTHORITY_WORDS)]
                for fn, params in inputs.items()}
    silent = sorted(fn for fn, params in carrying.items() if not params)
    if not silent:
        return
    assert shared_store.capabilities()["decision_required"], (
        f"{silent} take no authorization input and answer anyway: the caller's own restraint is the access "
        f"control, and nothing checks it ({inputs})")


def test_stored_chunks_have_no_authorization_column(shared_store) -> None:
    columns = shared_store.schema_columns()
    assert not [c for c in columns if any(w in c.lower() for w in ("acl", "tenant", "epoch", "owner"))], \
        f"the chunks table now carries authorization data: {columns}"


def test_withdrawal_is_expressible_through_a_library_interface(shared_store) -> None:
    """Content in this index must be withdrawable through something the library itself provides.

    This used to assert ``revocation_api()["delete"] == []`` and pass — recording "there is no way to take
    content back" as if it were a property of a well-built store. Withdrawal by raw SQL is an operator's
    escape hatch: it needs a shell on the file, it is invisible to the library's own readers and caches, and
    it cannot be the mechanism a contract points at. The baseline fails here because it has no interface.
    """
    available = shared_store.revocation_api()["delete"]
    assert available, (
        f"{type(shared_store.store).__name__} exposes no revoke/delete/remove/forget, so withdrawing one "
        f"document means somebody's DELETE against the store file ({shared_store.revocation_api()['store_methods']})")


def test_a_caller_supplied_allow_list_is_not_the_access_control(shared_store) -> None:
    """``document_ids`` may narrow a decision; it must not be the thing that makes one.

    At the baseline this list *was* the control, and the default call — naming nothing — read every document
    in the store. Either a decision-less read does not happen, or it does not reach content the caller was
    never given. Which arm is being satisfied is reported, so the test cannot pass by accident.
    """
    unfiltered = _read_or_denied(
        shared_store, lambda: shared_store.hybrid("restatement revenue recognized", limit=5))
    if unfiltered is DENIED:
        return                                       # no decision, no read; nothing was exposed to scope
    assert not any(MARKER in h["text"] for h in unfiltered), (
        "the default read answers for every principal at once: with no decision to consult, the only thing "
        "standing between a globex caller and acme's restatement is a list the caller chose not to pass")


def test_answer_context_mirror_matches_the_implementation(shared_store) -> None:
    from adapters.redevops_rag.adapter import CONTEXT_EXPRESSION
    assert CONTEXT_EXPRESSION in shared_store.ask_source(), (
        "redevops_rag.rag.RAG.ask changed how it builds a model's context; update the mirror, do not "
        "silently stop measuring it")


def test_log_snippets_do_not_quote_retrieved_content(shared_store) -> None:
    """The library logs nothing that quotes retrieved text, and that must stay measurable.

    Measured through a store that can actually read. Measured against a refusal instead, this passes by
    inspecting the log of a query that never ran — the suite would certify a silent pipeline by making it
    silent, so the read is asserted to have produced rows first.
    """
    reader = shared_store.readable_probe()
    try:
        hits, lines = reader.logs_during(lambda: reader.hybrid("restatement revenue", limit=5))
    finally:
        reader.close()
    assert hits, "the probe read nothing, so there was no log line for this assertion to look at"
    assert not [line for line in lines if MARKER in line], f"a log line now carries retrieved content: {lines}"


def test_the_leak_assertions_below_are_not_vacuous(tmp_path) -> None:
    """The marker has to be retrievable somewhere, or every "did not appear" below it means nothing.

    Physical separation is a mitigation the shell can do today; it is not an ACL and it does not survive a
    shared index. The retrievable-first check is the whole point of this test, and it is asserted against a
    store that reads: a refusal returns no rows, which would satisfy a leak assertion without measuring one.
    """
    acme = _probe_or_skip(db_path=str(tmp_path / "acme.duckdb"))
    globex = _probe_or_skip(db_path=str(tmp_path / "globex.duckdb"))
    try:
        acme.index(ACME_SECRET, filename="acme-restatement.md")
        globex.index(GLOBEX_NOTE, filename="globex-logistics.md")
        acme_reader, globex_reader = acme.readable_probe(), globex.readable_probe()
        try:
            own = acme_reader.hybrid("restatement revenue recognized", limit=5)
            hits = globex_reader.hybrid("restatement revenue recognized", limit=5)
        finally:
            acme_reader.close()
            globex_reader.close()
        assert any(MARKER in h["text"] for h in own), (
            "the marker cannot be retrieved even from the store that holds it, so every absence asserted "
            "below is a property of the fixture and not of authorization")
        assert not any(MARKER in h["text"] for h in hits), (
            "content stored under one tenant is retrievable from a physically separate store, so nothing "
            "below distinguishes an ACL from a lucky query")
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


def _outcome_of(probe, call) -> tuple[str, str]:
    """What did running this criterion actually do: leak, refuse, satisfy, or break?

    A strict xfail calls any exception an expected failure, so the marking alone cannot tell a measured leak
    from a dead fixture — and now that a fail-closed refusal is also an acceptable answer, that distinction
    matters more rather than less. Only the implementation's own refusal counts as ``denied``: a renamed
    method, a missing module or an assertion that names no leak is ``broken`` and stays a failure.
    """
    try:
        call()
    except AssertionError as exc:
        if not str(exc):
            return "broken", "assertion raised with no message, naming no leak"
        return "leak", str(exc)
    except Exception as exc:                                            # noqa: BLE001
        if probe.is_denial(exc):
            return "denied", f"{type(exc).__name__}: {exc}"
        return "broken", f"{type(exc).__name__}: {exc}"
    return "satisfied", ""


def test_the_denial_classifier_does_not_flatter_a_broken_measurement(shared_store) -> None:
    """Accepting "it refused to read" as fail-closed is safe only if a broken probe cannot look like one.

    The negative control for ``_outcome_of``: the common ways a measurement dies — including this repo's own
    ``AdapterBlocked`` and the implementation's unrelated store errors — must all still classify as broken.
    Without this, widening the xfail rule to accept denials would widen it to accept bugs as well.
    """
    class Refusal(Exception):
        """Shaped like the implementation's own refusal: same name, same module, same effect."""
        __module__ = "redevops_rag.authority"

    Refusal.__name__ = "RetrievalDenied"

    class StoreError(Exception):
        __module__ = "redevops_rag.store"

    StoreError.__name__ = "StoreError"

    assert shared_store.is_denial(Refusal("no decision")), \
        "the classifier does not recognize the refusal this suite now accepts"
    real = getattr(shared_store._authority_mod, "RetrievalDenied", None) if shared_store._authority_mod else None
    if real is not None:
        assert shared_store.is_denial(real("no decision")), \
            "the classifier does not recognize the real exception of the implementation under test"
    else:
        assert not shared_store.capabilities()["authority_module"], \
            "no real refusal type and no authority module: these two should agree"
    wrapped = StoreError("retrieval failed")
    try:
        raise Refusal("no decision")
    except Refusal as inner:
        wrapped.__cause__ = inner
    assert shared_store.is_denial(wrapped), "a refusal the store re-raises must still read as a refusal"
    for not_a_refusal in (StoreError("the index file is corrupt"), AttributeError("semantic_search"),
                          ImportError("redevops_rag.authority"), TypeError("unexpected keyword 'authority'"),
                          KeyError("document_id"), AdapterBlocked("no checkout here"),
                          AssertionError("acme content is a candidate")):
        assert not shared_store.is_denial(not_a_refusal), (
            f"{type(not_a_refusal).__name__} classified as a fail-closed denial — broken measurements would "
            "stop failing")
    assert _outcome_of(shared_store, lambda: shared_store.no_such_probe_method())[0] == "broken"
    assert _outcome_of(shared_store, lambda: (_ for _ in ()).throw(AssertionError("")))[0] == "broken"
    assert _outcome_of(shared_store, lambda: (_ for _ in ()).throw(Refusal("no decision")))[0] == "denied"
    assert _outcome_of(shared_store, lambda: (_ for _ in ()).throw(AssertionError("leak named")))[0] == "leak"
    assert _outcome_of(shared_store, lambda: None)[0] == "satisfied"


def _propagates_instead_of_degrading(probe) -> bool:
    """Does a leg that cannot run fail the read, or answer anyway from the surviving leg?

    This is the measurement behind the one allowance the meta-test below makes, and it is what keeps that
    allowance from becoming an exception list: the baseline swallows the injected failure and returns hits
    from whichever feed survived, so it cannot claim the exemption and keeps reporting its leak.
    """
    reader = probe.readable_probe()

    def _broken(*args, **kwargs):
        raise RuntimeError("injected: vector feed unavailable")

    original = reader.store.semantic_search
    reader.store.semantic_search = _broken                        # type: ignore[method-assign]
    try:
        hits = reader.hybrid("Rotterdam lane slipped", limit=5)
    except Exception:                                             # noqa: BLE001
        return True
    else:
        return not hits
    finally:
        reader.store.semantic_search = original                   # type: ignore[method-assign]
        reader.close()


# Criteria whose whole subject is what happens when part of retrieval fails. For these, an injected failure
# that propagates instead of degrading into a broader read is the criterion being met, not a broken probe.
# Named one at a time on purpose: every other criterion still has to produce a leak or a refusal.
FAIL_CLOSED_CRITERIA = frozenset({"test_deny_on_adapter_error_never_degrades_into_a_broad_read"})


@pytest.mark.parametrize("case_name", _xfail_cases())
def test_each_xfail_fails_for_the_leak_it_claims(shared_store, case_name: str) -> None:
    """Every strict xfail must still be failing for the reason it was marked.

    Two outcomes are acceptable and they do not mean the same thing. ``leak``: an AssertionError naming the
    gap, which is what a baseline should produce. ``denied``: the implementation refused to run the read at
    all — #627's fail-closed clause arriving. A denial does *not* demonstrate the criterion, because nothing
    was read, so the positive property is measured against an owned index in the section below; what a
    denial proves is that the old leak can no longer happen by omission. A pass means the marking is stale,
    and anything else means the measurement itself broke, which is never a green cell.
    """
    outcome, detail = _outcome_of(shared_store, lambda: globals()[case_name](shared_store))
    if outcome == "leak":
        return
    if outcome == "denied":
        assert shared_store.capabilities()["decision_required"], (
            f"{case_name} was refused, but this store answers a decision-less read anyway: {detail!r} came "
            "from somewhere other than the enforcement point this criterion is about")
        return
    if outcome == "broken" and case_name in FAIL_CLOSED_CRITERIA:
        # Not an exemption handed out on the strength of the exception's name: the propagation is measured
        # here, on this store. Where a failed leg still yields a broad read, this assert fails and the
        # criterion keeps its leak.
        assert _propagates_instead_of_degrading(shared_store), (
            f"{case_name} raised {detail} rather than naming its leak, and a failed leg here still produced "
            "a degraded read — that is the baseline behaviour this criterion documents, not fail-closed")
        return
    if outcome == "satisfied":
        pytest.fail(f"{case_name} now passes: the leak it documents is closed. Remove the xfail marking "
                    "and update the matrix row in the same change.")
    pytest.fail(f"{case_name} is marked xfail as an unmet criterion but produced a broken measurement "
                f"({detail}). A strict xfail cannot tell that from a leak on its own — fix the measurement, "
                "do not leave the marking to hide it.")


# ── the same criteria, measured under an authority ─────────────────────────────────────────────
#
# The strict-xfail set above asks each question of a store that was never told who is asking, which is the
# baseline's own shape. On an implementation that refuses such reads, those bodies can only ever report a
# refusal, so the criteria that need an owner are asked again here against an index whose documents each
# have one. Where no policy register exists, the fixture BLOCKS: these cells never pass by default.

def test_an_authorized_read_returns_what_its_owner_may_see_and_nothing_else(owned_store) -> None:
    """Both halves, in one test, because either one alone can be faked by reading nothing."""
    own = owned_store.probe.hybrid("quarterly restatement revenue recognized", limit=5,
                                   authority=owned_store.acme())
    assert any(MARKER in h["text"] for h in own), \
        "acme cannot read the document acme owns: every absence asserted below is the fixture, not enforcement"
    seen = owned_store.probe.hybrid("quarterly restatement revenue recognized", limit=5,
                                    authority=owned_store.globex())
    assert not any(MARKER in h["text"] for h in seen), \
        "acme's restatement is readable by a globex-only principal on a shared index"
    assert not [h for h in seen if h["document_id"] == owned_store.acme_id], \
        "a globex read returned acme's document id even where the text was withheld"


def test_authorization_narrows_each_retrieval_leg_before_any_ranking(owned_store) -> None:
    """#627 is about candidate generation, so each leg is asked on its own, not just the fused answer.

    A filter applied after fusion would pass the test above on the strength of a ranking change and leave
    unauthorized text in the pool a reranker, a cache or a debug dump can still reach.
    """
    vector = owned_store.probe.vector("quarterly restatement revenue recognized early",
                                      authority=owned_store.globex())
    assert not any(MARKER in c["text"] for c in vector), \
        "acme content is a vector candidate for a globex-only decision"
    sparse = owned_store.probe.bm25("quarterly restatement revenue recognized early",
                                    authority=owned_store.globex())
    assert not any(MARKER in c["text"] for c in sparse), \
        "acme content is a BM25 candidate for a globex-only decision"
    own = owned_store.probe.vector("quarterly restatement revenue recognized", authority=owned_store.acme())
    assert any(MARKER in c["text"] for c in own), \
        "the vector leg returns nothing even to the owning principal, so the two checks above prove nothing"


def test_naming_a_document_cannot_widen_a_decision(owned_store) -> None:
    """The caller's ``document_ids`` filter is a narrowing input; handing it a foreign id buys nothing."""
    widened = owned_store.probe.hybrid("restatement revenue", limit=5,
                                       document_ids=[owned_store.acme_id],
                                       authority=owned_store.globex())
    assert not any(MARKER in h["text"] for h in widened), (
        "naming acme's document id widened globex's decision — the allow-list is still the access control, "
        "and it is the caller's to write")


def test_the_decision_is_applied_where_candidates_are_produced(owned_store) -> None:
    """#627 says *before* candidate generation, and filtering afterwards does not satisfy that.

    A post-query filter is invisible in the results: the caller still sees only permitted text. What differs
    is everything that happened on the way to dropping the row — the unauthorized chunk was read out of the
    store, fused, scored, and left reachable by a cache, a reranker or a debug dump. So the statements the
    store actually sent are what gets inspected: each leg's candidate query must carry the authorization
    predicate in the same statement that limits it.
    """
    acme = owned_store.acme()
    for leg, call in (("vector", lambda: owned_store.probe.vector("quarterly restatement revenue",
                                                                  authority=acme)),
                      ("bm25", lambda: owned_store.probe.bm25("quarterly restatement revenue",
                                                               authority=acme))):
        hits, statements = owned_store.probe.observing_sql(call)
        assert any(MARKER in h["text"] for h in hits), (
            f"the {leg} leg returned nothing to its own owner, so its statements prove nothing about placement")
        limited = [s for s in statements if "LIMIT" in s.upper()]
        assert limited, f"the {leg} leg sent no statement carrying a LIMIT, so placement cannot be measured"
        for statement in limited:
            head = statement.upper().split("LIMIT", 1)[0]
            # A predicate, not the column name: document_id sits in the select list of every one of these
            # queries, so an assertion that only looks for it is satisfied by the statement that does no
            # filtering at all — which is precisely the implementation this test exists to fail.
            assert re.search(r"DOCUMENT_ID\s*(?:=|<|>|!=|<>)|DOCUMENT_ID\s+IS\s+(?:NOT\s+)?NULL"
                             r"|DOCUMENT_ID\s+(?:NOT\s+)?IN\b", head), (
                f"the {leg} leg limits candidates in a statement that carries no authorization predicate — "
                f"unauthorized chunks are read, ranked and dropped afterwards, the shape #627 rules out: "
                f"{statement[:200]}")


def test_the_answer_context_carries_only_what_the_decision_allows(owned_store) -> None:
    """The string handed to a model is the leak that matters most, so it is measured on both sides."""
    foreign = owned_store.probe.llm_context("quarterly restatement revenue", limit=5,
                                            authority=owned_store.globex())
    assert MARKER not in foreign, "the answer context handed to a model contains acme content for a globex caller"
    own = owned_store.probe.llm_context("quarterly restatement revenue", limit=5,
                                        authority=owned_store.acme())
    assert MARKER in own, "the owning principal's answer context is empty, so the check above measured nothing"


def test_a_decision_this_store_never_issued_is_not_honoured(owned_store) -> None:
    """An authority is a decision from one policy, not a bearer token any store will accept."""
    plain = _probe_or_skip(db_path=str(owned_store.probe.db_path))
    try:
        foreign_policy = plain.make_policy({})
    except AdapterBlocked as exc:
        plain.close()
        pytest.skip(f"BLOCKED — {exc}")
    plain.close()
    stranger = owned_store.probe.authority(foreign_policy, "acme")
    outcome, detail = _outcome_of(owned_store.probe,
                                  lambda: owned_store.probe.hybrid("restatement revenue", limit=5,
                                                                   authority=stranger))
    assert outcome in ("denied", "leak") and outcome != "satisfied", (
        f"an authority minted by an unrelated policy was honoured ({detail}): decisions are being trusted "
        "as tokens rather than re-checked against the policy that owns this index")
    if outcome == "leak":
        pytest.fail(f"the store answered a foreign authority instead of refusing it ({detail})")


def test_revocation_through_the_library_interface_reaches_an_existing_reader(owned_store) -> None:
    """Revocation that only the writing process notices is not revocation.

    This is the honest counterpart of the strict-xfail criterion above, which at the baseline measures the
    absence of any interface at all. Here there is one, so what gets measured is propagation: a second
    instance that has been serving this index since before the revoke must stop serving the document.
    """
    reader = owned_store.probe.reopen()
    try:
        before = owned_store.probe.hybrid("quarterly restatement revenue", limit=5,
                                          authority=owned_store.acme())
        assert any(MARKER in h["text"] for h in before), \
            "the document was not readable before revocation, so the check below proves nothing"
        owned_store.probe.revoke(owned_store.acme_id)
        after = _read_or_denied(reader, lambda: reader.hybrid("quarterly restatement revenue", limit=5,
                                                              authority=owned_store.acme()))
        assert after is DENIED or not any(MARKER in h["text"] for h in after), (
            "an existing indexer instance still serves a document that has been revoked: the decision, or "
            "the cache built on it, outlived the withdrawal")
    finally:
        reader.close()
