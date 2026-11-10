"""The seven cross-edition authorization invariants, and the adapter seam they are run through.

Every scenario here is written once, against a narrow adapter protocol, and run against the real
implementation of each edition. The rules that make that worth reading:

**Adapters translate; they do not decide.** An adapter may map arguments and read results, but the allow or
deny must come out of the implementation's own enforcement code. An adapter that filters a list itself, or
that answers a scenario from a stub, proves nothing about the edition — so each adapter names the
implementation symbol it consulted, and that name is recorded in the matrix evidence.

**A criterion that cannot run is not a pass.** A seam an edition does not have raises
:class:`Unsupported`, and the cell is qualified ``UNSUPPORTED``. Required sub-criteria that are all
unsupported make the cell unsupported; a required sub-criterion that fails makes it fail. Nothing quietly
upgrades a missing feature.

**Receipts and boundaries are different evidence.** ``policy_reason == "tenant_isolation"`` says the plane
refused. It does not say a document, a row, or a candidate stayed inside its boundary. The scenarios that
claim a data boundary therefore measure content — what a dispatch executed, what a cache served, what a
candidate set contained — and a matching receipt across planes never substitutes for that.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Sequence

from .decision import AuthorizationDecision, PolicyReason, validate_envelope
from .qualification import CaseResult, Invariant, Qualification


class Unsupported(Exception):
    """This implementation has no seam that could satisfy the criterion. A gap, reported as such."""

    def __init__(self, detail: str, subs: list[dict[str, Any]] | None = None) -> None:
        super().__init__(detail)
        self.subs = subs or []              # sub-criteria still describe what was and was not runnable


class AdapterBlocked(Exception):
    """The implementation under test could not be loaded or started in this environment."""


class InvariantFailure(AssertionError):
    """A criterion ran and did not hold."""

    def __init__(self, invariant: Invariant, detail: str, evidence: dict[str, Any] | None = None) -> None:
        super().__init__(f"{invariant.value}: {detail}")
        self.invariant = invariant
        self.detail = detail
        self.evidence = evidence or {}


# ───────────────────────────── what an adapter hands back ─────────────────────────────


@dataclass(frozen=True)
class Receipt:
    """One decision as the implementation produced it, plus where it came from.

    ``decision`` is ``None`` when the implementation answered without an `authz/v1` envelope (a bare reason
    string, or an exception). That is itself a finding — an unenveloped decision is unauditable — and the
    scenarios report it as ``no_envelope`` rather than papering over it.
    """
    allowed: bool
    reason: str = ""
    decision: AuthorizationDecision | None = None
    seam: str = ""
    raw: Mapping[str, Any] = field(default_factory=dict)

    @property
    def enveloped(self) -> bool:
        return self.decision is not None

    @property
    def policy_reason(self) -> str:
        return (self.decision.policy_reason.value if self.decision else PolicyReason.UNCLASSIFIED.value)

    @property
    def grant_ids(self) -> tuple[str, ...]:
        return self.decision.grant_ids if self.decision else ()

    @property
    def tenant(self) -> str:
        return self.decision.tenant if self.decision else ""

    def codes(self, *, request_tenant: str | None = None) -> list[str]:
        if self.decision is None:
            return ["no_envelope"]
        return validate_envelope(self.decision, request_tenant=request_tenant)


@dataclass(frozen=True)
class ExecutionOutcome:
    """What actually ran. ``dispatched`` is observed side effect, not an intent the plane stated."""
    dispatched: tuple[str, ...] = ()
    denied: tuple[str, ...] = ()
    state: str = ""
    receipts: tuple[Receipt, ...] = ()
    raw: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CandidateSet:
    """The output of a scoped discovery call, before anything is planned over it."""
    names: tuple[str, ...] = ()
    limit: int = 0
    expected_present: tuple[str, ...] = ()
    forbidden: tuple[str, ...] = ()
    seam: str = ""
    raw: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CacheOutcome:
    """Whether a stale authorization decision was served, and what the implementation's own rule said."""
    served: bool = False
    implementation_says_fresh: bool | None = None
    seam: str = ""
    raw: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BackendOutcome:
    """The result of asking for a decision while the authority backend is failing."""
    allowed: bool = False
    error: str = ""
    receipt: Receipt | None = None
    seam: str = ""
    raw: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PrincipalSpec:
    """The principal a scenario asks about, in edition-neutral terms.

    ``roles`` is deliberately just data: a scenario that hands over ``roles=("admin",)`` and no grant is
    asking whether a name carries authority, which is exactly what must not happen.
    """
    subject: str = ""                    # ``user:al`` / ``service:crm`` style reference
    roles: tuple[str, ...] = ()
    tenant: str = ""
    permissions: tuple[str, ...] = ()    # already-held grants, staged by the adapter, not asserted here


# ───────────────────────────── the adapter protocol ─────────────────────────────


class AuthzAdapter:
    """What an edition must expose for the suite to test it.

    Every method raises :class:`Unsupported` by default: an adapter overrides the seams its implementation
    actually has, and the suite reports the rest. ``seam(symbol)`` records which implementation code answered.
    """

    implementation: str = ""        # adoption-manifest key, e.g. ``agentic-os``
    edition: str = ""               # ``kernel`` | ``enterprise``
    variant: str = "real"           # ``real`` or the id of a deliberately-broken mutant
    _seams: dict[str, str] = {}

    # -- lifecycle ------------------------------------------------------------
    def close(self) -> None:
        pass

    def seam(self, name: str) -> str:
        """The implementation symbol that answers this kind of request (recorded in matrix evidence)."""
        return self._seams.get(name, f"{self.implementation}?{name}")

    # -- authority administration (the implementation's own grant APIs) -------
    def grant(self, principal: PrincipalSpec, *, resource: str = "", actions: Sequence[str] = (),
              permissions: Sequence[str] = (), tenant: str | None = None) -> str:
        raise Unsupported(f"{self.implementation}: no grant API exposed to the suite")

    def revoke(self, grant_id: str) -> bool:
        raise Unsupported(f"{self.implementation}: no revocation API exposed to the suite")

    # -- decisions at the plane's own enforcement seams -----------------------
    def decide_resource(self, principal: PrincipalSpec, *, resource: str, action: str = "read",
                        request_tenant: str | None = None) -> Receipt:
        raise Unsupported(f"{self.implementation}: no resource-grant decision seam")

    def decide_capability(self, principal: PrincipalSpec, *, capability: str,
                          permissions: Sequence[str] = (), request_tenant: str | None = None) -> Receipt:
        raise Unsupported(f"{self.implementation}: no capability decision seam")

    def decide_tenant_scoped_resource(self, principal: PrincipalSpec, *, grant_tenant: str,
                                      request_tenant: str, resource: str, action: str = "read") -> Receipt:
        raise Unsupported(f"{self.implementation}: no tenant-tagged grant decision seam")

    def decide_resource_tenancy(self, principal: PrincipalSpec, *, owner_tenant: str, resource_tenant: str,
                                capability: str, delegated: bool = False) -> Receipt:
        raise Unsupported(f"{self.implementation}: no resource-tenancy authority gate")

    # -- queued execution -----------------------------------------------------
    def execute_queued(self, principal: PrincipalSpec, *, capability: str,
                       revoke_before_dispatch: str | None = None) -> ExecutionOutcome:
        raise Unsupported(f"{self.implementation}: no queued-execution seam")

    # -- epoch / cached decisions --------------------------------------------
    def freshness_predicate(self, *, write_epoch: int, read_epoch: int) -> bool:
        raise Unsupported(f"{self.implementation}: no authorization-epoch freshness predicate")

    def serve_cached(self, principal: PrincipalSpec, *, resource: str, action: str = "read",
                     write_epoch: int, read_epoch: int) -> CacheOutcome:
        raise Unsupported(f"{self.implementation}: no authorization decision cache")

    # -- candidate graph ------------------------------------------------------
    def candidates(self, principal: PrincipalSpec, *, need: str, limit: int,
                   authorized: Sequence[str], unauthorized: Sequence[str]) -> CandidateSet:
        raise Unsupported(f"{self.implementation}: no policy-scoped candidate seam")

    def run_plan(self, principal: PrincipalSpec, *, steps: "Sequence[tuple[str, Sequence[str]]]"
                 ) -> "ExecutionOutcome":
        """Run a real plan over ``steps``: each entry is an outcome and the capabilities that could provide
        it, listed in the order an unfiltered planner prefers. Listing a provider the principal may not use
        is what makes the exclusion observable: if nothing filters, that is the provider that runs."""
        raise Unsupported(f"{self.implementation}: no plan-execution seam")

    # -- fault injection ------------------------------------------------------
    def break_authority_backend(self) -> None:
        raise Unsupported(f"{self.implementation}: cannot inject an authority-backend failure")


# ───────────────────────────── scenario plumbing ─────────────────────────────


class Criteria:
    """Sub-criteria of one invariant, resolved into exactly one verdict.

    ``required`` names the sub-criteria the invariant is *about*. If every required one is unsupported the
    invariant is unsupported; if any fails it fails; otherwise it passes, and non-required sub-criteria are
    reported in the evidence without silently softening the verdict.
    """

    def __init__(self, invariant: Invariant, required: Sequence[str]) -> None:
        self.invariant = invariant
        self.required = tuple(required)
        self.subs: list[dict[str, Any]] = []

    def ok(self, name: str, **evidence: Any) -> None:
        self.subs.append({"id": name, "status": Qualification.PASS.value, **evidence})

    def fail(self, name: str, detail: str, **evidence: Any) -> None:
        self.subs.append({"id": name, "status": Qualification.FAIL.value, "detail": detail, **evidence})

    def unsupported(self, name: str, detail: str, **evidence: Any) -> None:
        self.subs.append({"id": name, "status": Qualification.UNSUPPORTED.value, "detail": detail, **evidence})

    def check(self, name: str, held: bool, detail: str, **evidence: Any) -> None:
        (self.ok if held else self.fail)(name, **({"detail": detail} if not held else {}), **evidence)

    def resolve(self) -> dict[str, Any]:
        by_id = {s["id"]: s for s in self.subs}
        required = [by_id.get(n, {"id": n, "status": Qualification.UNSUPPORTED.value,
                                  "detail": "the scenario never reported this sub-criterion"})
                    for n in self.required]
        failures = [s for s in required if s["status"] == Qualification.FAIL.value]
        if failures:
            detail = "; ".join(f"{s['id']}: {s.get('detail', '')}" for s in failures)
            raise InvariantFailure(self.invariant, detail, {"sub_criteria": self.subs})
        missing = [s for s in required if s["status"] == Qualification.UNSUPPORTED.value]
        if missing:
            # A required criterion nobody could run is not a pass because its neighbours held: "the predicate
            # exists" never answers "the boundary is enforced".
            raise Unsupported("; ".join(f"{s['id']}: {s.get('detail', '')}" for s in missing), list(self.subs))
        return {"sub_criteria": self.subs}


def _deny_or_explain(receipt: Receipt) -> str:
    return f"allowed={receipt.allowed} reason={receipt.policy_reason!r} grants={list(receipt.grant_ids)}"


def _require_denial(receipt: Receipt, *, expect_reason: str | None = None) -> str | None:
    """``None`` when the receipt denies correctly, else the reason it does not."""
    if receipt.allowed:
        return f"the implementation allowed it ({_deny_or_explain(receipt)})"
    if expect_reason and receipt.policy_reason != expect_reason:
        return (f"denied, but classifies it {receipt.policy_reason!r} instead of {expect_reason!r} "
                f"({_deny_or_explain(receipt)})")
    return None


# ───────────────────────────── receipt provenance ─────────────────────────────
#: Decision seams whose answer must be about the principal and target the scenario named. The other seams are
#: checked for attribution only: a queued dispatch or a candidate set legitimately reports on more than the
#: one thing asked for, and pretending otherwise would flag honest evidence.
_BOUND_SEAMS = ("decide_resource", "decide_capability", "decide_tenant_scoped_resource")
_ATTRIBUTED_SEAMS = _BOUND_SEAMS + ("decide_resource_tenancy", "execute_queued", "run_plan", "serve_cached",
                                    "candidates")


def _same_subject(enveloped: str, requested: str) -> bool:
    """``user:al`` and ``al`` are the same principal; the two planes spell it differently.

    An envelope that names no principal cannot contradict the request — that gap is reported by
    :func:`~runtime_contracts.authz.decision.validate_envelope`, not here.
    """
    if not enveloped or not requested:
        return True
    return enveloped.rsplit(":", 1)[-1] == requested.rsplit(":", 1)[-1]


def _about_any(enveloped: str, targets: Iterable[str]) -> bool:
    """Whether the envelope decides something the request named, or a scoped form of it.

    ``crm.customers.read`` answering a request about ``crm.customers`` is the same question at a finer grain
    (the enterprise capability plane spells grants that way); ``erp.invoice`` answering it is another
    question entirely.
    """
    wanted = {t for t in targets if t}
    if not enveloped or not wanted:
        return True
    return any(enveloped == t or t in enveloped or enveloped in t for t in wanted)


class _Provenance:
    """Wraps an adapter for one scenario run so no answer can quietly arrive from somewhere else.

    Two things count as cross-talk, and each is a FAIL, never a pass:

    * **Wrong source.** A receipt whose plane names a different implementation. Without this, an adapter that
      borrowed another edition's enforcement would earn a pass for the edition under test — and a matrix that
      cannot say which edition decided is not a qualification matrix.
    * **Wrong question.** A receipt that decides a different principal or a different resource than the one
      the scenario requested. This is how a replayed, cached, or borrowed decision could otherwise satisfy a
      criterion it was never about.

    An envelope-free receipt is not cross-talk: the scenarios already report an unenveloped decision as
    ``no_envelope``, and inventing a provenance failure on top would hide the real finding.
    """

    def __init__(self, adapter: AuthzAdapter, invariant: Invariant) -> None:
        self._adapter = adapter
        self._invariant = invariant

    def __getattr__(self, name: str) -> Any:
        attribute = getattr(self._adapter, name)
        if name not in _ATTRIBUTED_SEAMS or not callable(attribute):
            return attribute

        def call(*args: Any, **kwargs: Any) -> Any:
            outcome = attribute(*args, **kwargs)
            self._check(name, args, kwargs, outcome)
            return outcome

        return call

    def _receipts(self, outcome: Any) -> Iterable[Receipt]:
        if isinstance(outcome, Receipt):
            yield outcome
        for attribute in ("receipt", "receipts"):
            value = getattr(outcome, attribute, None)
            if isinstance(value, Receipt):
                yield value
            elif isinstance(value, (tuple, list)):
                yield from (item for item in value if isinstance(item, Receipt))

    def _cross_talk(self, detail: str, receipt: Receipt) -> None:
        raise InvariantFailure(self._invariant, f"cross-talk: {detail}",
                               {"seam": receipt.seam, "envelope": dict(receipt.raw)})

    def _check(self, method: str, args: tuple, kwargs: dict, outcome: Any) -> None:
        implementation = self._adapter.implementation
        principal = args[0] if args else kwargs.get("principal")
        subject = getattr(principal, "subject", "") or ""
        targets = [kwargs.get("resource", ""), kwargs.get("capability", "")]
        targets += list(kwargs.get("permissions") or ())
        for receipt in self._receipts(outcome):
            decision = receipt.decision
            if decision is None:
                continue
            if implementation and decision.plane and decision.plane != implementation:
                self._cross_talk(
                    f"a decision emitted by {decision.plane!r} answered a call made to {implementation!r}; "
                    f"{implementation} is not credited with another edition's enforcement", receipt)
            if method in _BOUND_SEAMS:
                if not _same_subject(decision.principal, subject):
                    self._cross_talk(
                        f"the request was made for {subject!r} but the receipt decides "
                        f"{decision.principal!r}", receipt)
                if not _about_any(decision.resource_name, targets):
                    self._cross_talk(
                        f"the request concerned {sorted(t for t in targets if t)!r} but the receipt decides "
                        f"{decision.resource_name!r}", receipt)

# ───────────────────────────── the seven scenarios ─────────────────────────────


def _cross_tenant_denied(adapter: AuthzAdapter) -> dict[str, Any]:
    c = Criteria(Invariant.CROSS_TENANT_DENIED,
                 ("capability_boundary", "resource_boundary", "grant_tenant_tag"))

    principal = PrincipalSpec(subject="user:al", roles=("operator",), tenant="acme")
    # 1. A principal of tenant `acme` asks to act in the context of tenant `globex`.
    try:
        rule = adapter.grant(principal, permissions=("reports.read",), tenant="acme")
        r = adapter.decide_capability(principal, capability="reports.read", permissions=("reports.read",),
                                      request_tenant="globex")
        problem = _require_denial(r, expect_reason="tenant_isolation")
        if problem:
            c.fail("capability_boundary", problem, seam=r.seam, envelope=r.raw, grant_id=rule)
        else:
            c.ok("capability_boundary", seam=r.seam, envelope=r.raw, grant_id=rule)
    except Unsupported as exc:
        c.unsupported("capability_boundary", str(exc))

    # 2. A mission owned by `acme` touches a resource owned by `globex`.
    try:
        r = adapter.decide_resource_tenancy(principal, owner_tenant="acme", resource_tenant="globex",
                                            capability="erp.invoice.read")
        problem = _require_denial(r)
        if problem:
            c.fail("resource_boundary", problem, seam=r.seam, envelope=r.raw)
        else:
            c.ok("resource_boundary", seam=r.seam, envelope=r.raw)
        # and with an explicit delegation the same call is allowed — a boundary that only ever denies
        # would pass sub-criterion 2 without enforcing anything.
        try:
            d = adapter.decide_resource_tenancy(principal, owner_tenant="acme", resource_tenant="globex",
                                                capability="erp.invoice.read", delegated=True)
            c.check("delegation_allows_the_exception", bool(d.allowed),
                    "an explicit delegation did not open the resource it names", seam=d.seam, envelope=d.raw)
        except Unsupported:
            pass
    except Unsupported as exc:
        c.unsupported("resource_boundary", str(exc))

    # 3. A grant tagged to one tenant must not answer for another tenant's request.
    try:
        g = adapter.grant(PrincipalSpec(subject="user:bo", roles=("clerk",), tenant="acme"),
                          resource="crm.customers", actions=("read",), tenant="acme")
        r = adapter.decide_tenant_scoped_resource(PrincipalSpec(subject="user:bo", roles=("clerk",),
                                                                tenant="globex"),
                                                  grant_tenant="acme", request_tenant="globex",
                                                  resource="crm.customers")
        problem = _require_denial(r)
        if problem:
            c.fail("grant_tenant_tag", problem, seam=r.seam, envelope=r.raw, grant_id=g)
        else:
            c.ok("grant_tenant_tag", seam=r.seam, envelope=r.raw, grant_id=g)
    except Unsupported as exc:
        c.unsupported("grant_tenant_tag", str(exc))

    return c.resolve()


def _no_privilege_laundering(adapter: AuthzAdapter) -> dict[str, Any]:
    c = Criteria(Invariant.NO_PRIVILEGE_LAUNDERING,
                 ("role_name_is_data", "capability_plane_role_claim", "explicit_grant_is_bounded",
                  "delegation_cannot_widen"))

    # 1. A role name with no grant of its own buys nothing.
    claimer = PrincipalSpec(subject="user:carol", roles=("admin",))
    try:
        r = adapter.decide_resource(claimer, resource="crm.customers", action="read")
        p1 = _require_denial(r, expect_reason="missing_explicit_grant")
        if p1:
            c.fail("role_name_is_data", p1, seam=r.seam, envelope=r.raw)
        else:
            c.ok("role_name_is_data", seam=r.seam, envelope=r.raw)
    except Unsupported as exc:
        c.unsupported("role_name_is_data", str(exc))

    # 1b. The same question at the capability plane, if the edition has one.
    try:
        r = adapter.decide_capability(claimer, capability="crm.customers.read", permissions=("crm.read",))
        p1b = _require_denial(r, expect_reason="missing_explicit_grant")
        if p1b:
            c.fail("capability_plane_role_claim", p1b, seam=r.seam, envelope=r.raw)
        else:
            c.ok("capability_plane_role_claim", seam=r.seam, envelope=r.raw)
    except Unsupported as exc:
        c.unsupported("capability_plane_role_claim", str(exc))

    # 2. An explicit grant is honoured and stays inside what it says.
    holder = PrincipalSpec(subject="user:dave", roles=("operator",))
    try:
        adapter.grant(holder, resource="crm.customers", actions=("read",))
        adapter.grant(holder, permissions=("reports.read",))
        allowed = adapter.decide_resource(holder, resource="crm.customers", action="read")
        capability = adapter.decide_capability(holder, capability="reports.read", permissions=("reports.read",))
        beyond_resource = adapter.decide_resource(holder, resource="crm.customers", action="write")
        beyond_capability = adapter.decide_capability(holder, capability="billing.charge",
                                                     permissions=("billing.charge",))
        problems = []
        if not allowed.allowed:
            problems.append(f"an explicit grant did not authorize what it names ({_deny_or_explain(allowed)})")
        if not capability.allowed:
            problems.append(f"an explicit grant did not authorize the capability it names "
                            f"({_deny_or_explain(capability)})")
        for name, extra in (("write on the same resource", beyond_resource), ("a different capability",
                                                                            beyond_capability)):
            p = _require_denial(extra)
            if p:
                problems.append(f"authority widened to {name} ({p})")
        if problems:
            c.fail("explicit_grant_is_bounded", "; ".join(problems),
                   seams=[allowed.seam, capability.seam], envelopes=[allowed.raw, capability.raw,
                                                                    beyond_resource.raw, beyond_capability.raw])
        else:
            c.ok("explicit_grant_is_bounded", seams=[allowed.seam, capability.seam],
                 grant_ids=list(allowed.grant_ids) + list(capability.grant_ids))
    except Unsupported as exc:
        c.unsupported("explicit_grant_is_bounded", str(exc))

    # 3. A delegated or acting-for principal acquires nothing its delegator did not hold.
    try:
        r = adapter.decide_resource_tenancy(PrincipalSpec(subject="user:dave", roles=("operator",),
                                                          tenant="acme"),
                                            owner_tenant="acme", resource_tenant="acme",
                                            capability="erp.invoice.read", delegated=False)
        w = adapter.decide_resource_tenancy(PrincipalSpec(subject="user:dave", roles=("operator",),
                                                          tenant="acme"),
                                            owner_tenant="acme", resource_tenant="globex",
                                            capability="erp.invoice.read", delegated=False)
        if w.allowed:
            c.fail("delegation_cannot_widen",
                   "a principal acting without any delegation reached another tenant's resource",
                   seam=w.seam, envelope=w.raw)
        else:
            c.ok("delegation_cannot_widen", seam=w.seam, envelope=w.raw, same_tenant_allowed=r.allowed)
    except Unsupported as exc:
        c.unsupported("delegation_cannot_widen", str(exc))

    # 4. Stage-1 scoping: a planner shows a principal only what it holds.
    try:
        seen = adapter.candidates(PrincipalSpec(subject="user:erin", roles=("admin",)), need="anything",
                                  limit=5, authorized=(), unauthorized=("secret.capability",))
        if seen.names:
            c.fail("stage1_scoping_shows_nothing", f"an ungranted principal was shown {list(seen.names)}",
                   seam=seen.seam, candidates=list(seen.names))
        else:
            c.ok("stage1_scoping_shows_nothing", seam=seen.seam)
    except Unsupported as exc:
        c.unsupported("stage1_scoping_shows_nothing", str(exc))

    return c.resolve()


def _revocation_during_queue(adapter: AuthzAdapter) -> dict[str, Any]:
    c = Criteria(Invariant.REVOCATION_DURING_QUEUE, ("refused_at_dispatch", "no_side_effect"))
    principal = PrincipalSpec(subject="service:dispatcher", roles=("operator",))
    try:
        # The family-read grant is what the dispatch gate demands of `billing.charge` in both editions, so
        # the scenario would otherwise be measuring a fixture mismatch rather than revocation.
        grant_id = adapter.grant(principal, permissions=("billing.read",), resource="billing.charges",
                                 actions=("write",))
        # A grant that is real when the work is queued — the scenario would be vacuous otherwise.
        before = adapter.decide_capability(principal, capability="billing.charge",
                                           permissions=("billing.read",))
        outcome = adapter.execute_queued(principal, capability="billing.charge", revoke_before_dispatch=grant_id)
        revoked = adapter.revoke(grant_id)
        leaked = [n for n in outcome.dispatched if n == "billing.charge"]
        if leaked:
            c.fail("no_side_effect", "the capability executed after its grant was revoked",
                   seam=adapter.seam("execute_queued"), dispatched=list(outcome.dispatched),
                   state=outcome.state)
        else:
            c.ok("no_side_effect", seam=adapter.seam("execute_queued"), dispatched=list(outcome.dispatched),
                 denied=list(outcome.denied), state=outcome.state, ledger=revoked)
        refused = (not leaked) and any(not r.allowed for r in outcome.receipts)
        if not refused:
            c.fail("refused_at_dispatch",
                   "nothing refused it: the queued work ran, or no decision was taken at dispatch "
                   f"(receipts={[r.policy_reason for r in outcome.receipts]}, state={outcome.state})",
                   receipts=[dict(r.raw) for r in outcome.receipts])
        elif not outcome.receipts:
            c.fail("refused_at_dispatch",
                   "the work was refused without any decision being recorded, so the refusal is unauditable",
                   receipts=[], state=outcome.state)
        else:
            c.ok("refused_at_dispatch", receipts=[r.policy_reason for r in outcome.receipts],
                 allowed_before_revocation=before.allowed, seam=adapter.seam("execute_queued"))
    except Unsupported as exc:
        c.unsupported("refused_at_dispatch", str(exc))
        c.unsupported("no_side_effect", str(exc))
    return c.resolve()


def _stale_epoch_refusal(adapter: AuthzAdapter) -> dict[str, Any]:
    c = Criteria(Invariant.STALE_EPOCH_REFUSAL, ("cached_decision_refused", "freshness_predicate"))
    principal = PrincipalSpec(subject="user:fred", roles=("operator",))
    try:
        adapter.grant(principal, resource="crm.customers", actions=("read",))
        # The epoch moves (a revocation happens) between the decision being cached and being served.
        served = adapter.serve_cached(principal, resource="crm.customers", action="read", write_epoch=1,
                                      read_epoch=2)
        if served.served:
            c.fail("cached_decision_refused",
                   "an authorization decision cached under epoch 1 was served at epoch 2",
                   seam=served.seam, evidence=dict(served.raw))
        else:
            c.ok("cached_decision_refused", seam=served.seam, evidence=dict(served.raw))
    except Unsupported as exc:
        c.unsupported("cached_decision_refused", str(exc))
    try:
        fresh = adapter.freshness_predicate(write_epoch=1, read_epoch=2)
        if fresh:
            c.fail("freshness_predicate", "the implementation's own freshness rule calls an epoch-1 entry "
                   "fresh at epoch 2", seam=adapter.seam("freshness_predicate"))
        else:
            c.ok("freshness_predicate", seam=adapter.seam("freshness_predicate"))
    except Unsupported as exc:
        c.unsupported("freshness_predicate", str(exc))
    return c.resolve()



def _authorization_before_limit(adapter: AuthzAdapter) -> dict[str, Any]:
    c = Criteria(Invariant.AUTHORIZATION_BEFORE_LIMIT,
                 ("no_unauthorized_candidate", "permitted_edge_survives_the_limit"))
    limit = 3
    # Fifteen capabilities the principal may NOT use are ranked ahead of the one it may: a filter applied
    # after any limit shorter than the queue (including a bounded over-fetch) loses the permitted edge.
    unauthorized = tuple(f"secret.look_{i}" for i in range(15))
    principal = PrincipalSpec(subject="user:gina", roles=("analyst",))
    try:
        adapter.grant(principal, permissions=("reports.read",))
        found = adapter.candidates(principal, need="monthly report", limit=limit,
                                   authorized=("reports.monthly",), unauthorized=unauthorized)
        leaked = sorted(set(found.names) & set(found.forbidden))
        if leaked:
            c.fail("no_unauthorized_candidate", f"unauthorized capabilities were offered: {leaked}",
                   seam=found.seam, candidates=list(found.names))
        else:
            c.ok("no_unauthorized_candidate", seam=found.seam, candidates=list(found.names), limit=limit)
        missing = sorted(set(found.expected_present) - set(found.names))
        if missing:
            c.fail("permitted_edge_survives_the_limit",
                   f"the permitted capabilities {missing} never reached the planner: the limit was applied "
                   "to the unauthorized queue, so the permitted edge is silently absent "
                   f"(limit={limit}, unauthorized ranked ahead={len(unauthorized)})",
                   seam=found.seam, candidates=list(found.names), unauthorized_ahead=len(unauthorized))
        else:
            c.ok("permitted_edge_survives_the_limit", seam=found.seam, candidates=list(found.names),
                 unauthorized_ahead=len(unauthorized), limit=limit)
    except Unsupported as exc:
        c.unsupported("no_unauthorized_candidate", str(exc))
        c.unsupported("permitted_edge_survives_the_limit", str(exc))
    return c.resolve()


def _permitted_edges_survive(adapter: AuthzAdapter) -> dict[str, Any]:
    c = Criteria(Invariant.PERMITTED_EDGES_SURVIVE, ("authorized_plan_completes",
                                                     "unauthorized_edge_never_dispatches"))
    holder = PrincipalSpec(subject="service:pipeline", roles=("operator",))
    try:
        adapter.grant(holder, permissions=("billing.read", "reports.read"))
        # 1. A plan whose every edge is permitted must still finish. Filtering that breaks the graph is a
        #    defect of the same severity as filtering that leaks — both are paid for with correctness.
        ok_run = adapter.run_plan(holder, steps=(("invoice_ok", ("billing.invoice",)),
                                                 ("report_ready", ("reports.monthly",))))
        if sorted(ok_run.dispatched) != ["billing.invoice", "reports.monthly"]:
            c.fail("authorized_plan_completes",
                   f"a fully-authorized plan executed {list(ok_run.dispatched)} and ended {ok_run.state} "
                   f"(timeline={ok_run.raw.get('timeline')})",
                   state=ok_run.state, dispatched=list(ok_run.dispatched), denied=list(ok_run.denied))
        else:
            c.ok("authorized_plan_completes", state=ok_run.state, dispatched=list(ok_run.dispatched))
        restricted = PrincipalSpec(subject="service:restricted", roles=("operator",))
        adapter.grant(restricted, permissions=("billing.read", "reports.read"))
        # 2. `report_ready` has two providers and the unauthorized one ranks first, so an implementation
        #    that does not filter picks it. The permitted edge must still run, and the unauthorized one
        #    must never run — neither "everything fails" nor "everything runs" satisfies this.
        mixed = adapter.run_plan(restricted, steps=(("invoice_ok", ("billing.invoice",)),
                                                    ("report_ready", ("secret.exfiltrate", "reports.monthly"))))
        if "secret.exfiltrate" in mixed.dispatched:
            c.fail("unauthorized_edge_never_dispatches",
                   "the unauthorized provider ran: an unfiltered planner took the highest-ranked provider, "
                   "which is the leak this criterion exists to catch", dispatched=list(mixed.dispatched),
                   state=mixed.state, timeline=list(mixed.raw.get("timeline", ())))
        elif "reports.monthly" not in mixed.dispatched or "billing.invoice" not in mixed.dispatched:
            c.fail("unauthorized_edge_never_dispatches",
                   "excluding the unauthorized edge also stopped the permitted ones from running "
                   f"(dispatched={list(mixed.dispatched)}, state={mixed.state}, "
                   f"timeline={mixed.raw.get('timeline')})",
                   dispatched=list(mixed.dispatched), state=mixed.state,
                   timeline=list(mixed.raw.get("timeline", ())))
        else:
            c.ok("unauthorized_edge_never_dispatches", dispatched=list(mixed.dispatched),
                 denied=list(mixed.denied), state=mixed.state)
    except Unsupported as exc:
        c.unsupported("authorized_plan_completes", str(exc))
        c.unsupported("unauthorized_edge_never_dispatches", str(exc))
    return c.resolve()


def _adapter_error_fails_closed(adapter: AuthzAdapter) -> dict[str, Any]:
    c = Criteria(Invariant.ADAPTER_ERROR_FAILS_CLOSED, ("never_allows_on_error", "error_is_recorded"))
    principal = PrincipalSpec(subject="service:breaker", roles=("operator",))
    try:
        adapter.grant(principal, resource="crm.customers", actions=("read",))
        adapter.break_authority_backend()
        receipt = adapter.decide_resource(principal, resource="crm.customers", action="read")
        if receipt.allowed:
            c.fail("never_allows_on_error",
                   "the plane allowed a request while its authority backend was failing — a silent "
                   "degradation to a broad read", seam=receipt.seam, error=receipt.reason,
                   envelope=dict(receipt.raw))
        else:
            c.ok("never_allows_on_error", seam=receipt.seam, error=receipt.reason or "denied",
                 envelope=dict(receipt.raw))
        if receipt.enveloped:
            c.ok("error_is_recorded", seam=receipt.seam, policy_reason=receipt.policy_reason)
        else:
            c.fail("error_is_recorded",
                   f"the failure surfaced as {receipt.reason or 'an exception'} with no decision recorded; "
                   "a refusal nobody can point at is not an auditable one", seam=receipt.seam)
    except Unsupported as exc:
        c.unsupported("never_allows_on_error", str(exc))
        c.unsupported("error_is_recorded", str(exc))
    return c.resolve()


SCENARIOS: dict[Invariant, Callable[[AuthzAdapter], dict[str, Any]]] = {
    Invariant.CROSS_TENANT_DENIED: _cross_tenant_denied,
    Invariant.NO_PRIVILEGE_LAUNDERING: _no_privilege_laundering,
    Invariant.REVOCATION_DURING_QUEUE: _revocation_during_queue,
    Invariant.STALE_EPOCH_REFUSAL: _stale_epoch_refusal,
    Invariant.AUTHORIZATION_BEFORE_LIMIT: _authorization_before_limit,
    Invariant.PERMITTED_EDGES_SURVIVE: _permitted_edges_survive,
    Invariant.ADAPTER_ERROR_FAILS_CLOSED: _adapter_error_fails_closed,
}


def run_invariant(invariant: Invariant | str, adapter: AuthzAdapter) -> CaseResult:
    """Run one scenario against one implementation and classify it.

    An unexpected exception is a FAIL with the exception named — never a skip and never a pass. If the
    implementation cannot be loaded at all the cell is BLOCKED, which says something about the run.
    """
    inv = Invariant(invariant) if not isinstance(invariant, Invariant) else invariant
    try:
        evidence = SCENARIOS[inv](_Provenance(adapter, inv))
    except Unsupported as exc:
        return CaseResult(inv, adapter.implementation, Qualification.UNSUPPORTED, str(exc),
                          {"variant": adapter.variant, "sub_criteria": getattr(exc, "subs", [])})
    except AdapterBlocked as exc:
        return CaseResult(inv, adapter.implementation, Qualification.BLOCKED, str(exc),
                          {"variant": adapter.variant})
    except InvariantFailure as exc:
        return CaseResult(inv, adapter.implementation, Qualification.FAIL, exc.detail,
                          dict(exc.evidence, variant=adapter.variant))
    except Exception as exc:  # noqa: BLE001 — an error we did not predict is still not a pass
        return CaseResult(inv, adapter.implementation, Qualification.FAIL,
                          f"{type(exc).__name__}: {exc}", {"variant": adapter.variant})
    return CaseResult(inv, adapter.implementation, Qualification.PASS, "",
                      dict(evidence, variant=adapter.variant))


def run_all(adapters: Iterable[AuthzAdapter],
            invariants: Iterable[Invariant] | None = None) -> list[CaseResult]:
    """Every (invariant, implementation) cell. Adapters are closed when the run finishes."""
    chosen = tuple(invariants or SCENARIOS)
    results: list[CaseResult] = []
    opened: list[AuthzAdapter] = []
    for adapter in adapters:
        opened.append(adapter)
        for inv in chosen:
            results.append(run_invariant(inv, adapter))
    for adapter in opened:
        try:
            adapter.close()
        except Exception:  # noqa: BLE001 — closing must not change a verdict
            pass
    return results