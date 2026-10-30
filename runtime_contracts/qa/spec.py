"""``TestSpec`` and what it is made of: steps, a tagged target, and frozen assertions.

The rule this module exists to enforce, structurally and not by policy text:

    A run's expected results are fixed before the first adapter call and cannot be changed by any component during
    the run. A change to an assertion is a new reviewed ``TestSpec`` version with a new hash.

How the types enforce it:

* ``AssertionSpec`` and everything inside it are frozen dataclasses holding tuples and ``FrozenMap``: there is no
  attribute assignment, no item assignment and no method that returns an edited copy.
* An assertion is identified by the ``rcv1`` hash of its whole canonical form (``assertion_hash``) and a spec by the
  hash of its set (``assertion_set_hash``). Both are recomputed from content on every read, never cached, so an
  object that was tampered with after construction no longer matches the hash it was pinned under.
* ``Step.target`` carries locators that recovery is measured against; the mutable facts of a run (which locator
  was actually used, which attempt) live in ``ActionReceipt``, a different object.
* A recovery payload can express "try this locator" and nothing else (``LocatorCandidate`` in ``records``).

These contracts describe what is expected and what happened. They carry nothing about how a run is scored.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Optional, Sequence, Tuple

from ..canonical import content_hash
from ..models.capability import Idempotency, RetrySafety, SideEffect
from ..models.verification import Determinism, Verdict
from ..protocol.secrets import SecretRef
from .base import (SCHEMA_ID_PREFIX, SPEC_REF_RULE, AnyDigest, BoundedJson, Code, DeadlineMs, Ident,
                   NonEmptyText, Pos, QAContractError, QARecord, QAValue, RefToken, Revision, Rule,
                   Sha256, ShortText, SpecRefStr, Version)
from .enums import (NO_EXPECTED_OPS, RESOURCE_ACTIONS, UI_ACTIONS, VALUE_ACTIONS, ActionKind, Executor,
                    PermittedRecovery, PredicateOp, ResourceKind, SubjectKind, TargetKind)

#: A path relative to a case root. Shape rules are in ``_guard_relative_path``.
RelPath = Annotated[str, Rule(min_length=1, max_length=512)]
#: Version range of a verifier, for example ``>=1.0,<2``.
VersionRange = Annotated[str, Rule(pattern=r"[A-Za-z0-9.<>=!~,*+ -]{1,64}")]
#: An observation deadline for one step.
StepDeadlineMs = Annotated[int, Rule(minimum=1, maximum=3600000)]


@dataclass(frozen=True)
class ComponentRef(QAValue):
    """``{id, version}`` of whatever produced something."""

    id: Ident
    version: Version


# ── locators and resources ─────────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class LocatorDescriptor(QAValue):
    """The frozen descriptor a step target or assertion subject is measured against."""

    role: Optional[ShortText] = None
    name: Optional[ShortText] = None
    test_id: Optional[ShortText] = None
    label: Optional[ShortText] = None
    text_hint: Optional[ShortText] = None
    frame_path: Tuple[ShortText, ...] = ()
    """Outermost frame first. Order is meaning."""

    def validate(self) -> None:
        if not any((self.role, self.name, self.test_id, self.label, self.text_hint)):
            raise QAContractError(Code.INVALID_FIELD, "a locator needs at least one of role, name, test_id, "
                                  "label or text_hint; an empty locator would match anything")


def _guard_relative_path(path: str) -> None:
    parts = path.split("/")
    if (path.startswith("/") or "\\" in path or ":" in path[:2]
            or any(p in ("", ".", "..") for p in parts)):
        raise QAContractError(Code.INVALID_FIELD, f"path {path!r} must be relative to the case root, with no "
                              "empty, '.' or '..' segment and no drive or backslash")


@dataclass(frozen=True)
class ResourceRef(QAValue):
    """A typed reference to an infrastructure resource: a manifest path, an image digest or a namespaced object.

    Exactly the fields of its kind are present. ``object_kind`` is the Kubernetes ``kind`` (``kind`` itself is the
    tag of this union).
    """

    kind: ResourceKind
    path: Optional[RelPath] = None
    digest: Optional[Sha256] = None
    api_version: Optional[ShortText] = None
    object_kind: Optional[ShortText] = None
    namespace: Optional[ShortText] = None
    name: Optional[ShortText] = None

    def validate(self) -> None:
        present = {n for n in ("path", "digest", "api_version", "object_kind", "namespace", "name")
                   if getattr(self, n) is not None}
        need = {
            ResourceKind.MANIFEST_PATH: {"path"},
            ResourceKind.IMAGE_DIGEST: {"digest"},
            ResourceKind.NAMESPACE_OBJECT: {"api_version", "object_kind", "namespace", "name"},
        }[self.kind]
        if present != need:
            raise QAContractError(Code.INVALID_FIELD, f"a {self.kind.value} resource carries exactly "
                                  f"{sorted(need)}; got {sorted(present)}")
        if self.path is not None:
            _guard_relative_path(self.path)


@dataclass(frozen=True)
class CheckProgramRef(QAValue):
    """A registered check program, pinned by the full sha256 of its source. Registry entries are individually
    hashed, so what a check does is fixed by this reference and not by whatever the registry holds later."""

    id: Ident
    version: Version
    program_hash: Sha256


# ── steps ──────────────────────────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class StepTarget(QAValue):
    """Tagged union: ``kind = ui`` carries a ``LocatorDescriptor``; ``kind = resource`` carries a ``ResourceRef``."""

    kind: TargetKind
    locator: Optional[LocatorDescriptor] = None
    resource: Optional[ResourceRef] = None

    @classmethod
    def ui(cls, locator: LocatorDescriptor) -> "StepTarget":
        return cls(TargetKind.UI, locator=locator)

    @classmethod
    def for_resource(cls, resource: ResourceRef) -> "StepTarget":
        return cls(TargetKind.RESOURCE, resource=resource)

    def validate(self) -> None:
        if self.kind is TargetKind.UI and not (self.locator is not None and self.resource is None):
            raise QAContractError(Code.INVALID_FIELD, "a ui target carries a locator and no resource")
        if self.kind is TargetKind.RESOURCE and not (self.resource is not None and self.locator is None):
            raise QAContractError(Code.INVALID_FIELD, "a resource target carries a resource and no locator")


@dataclass(frozen=True)
class Action(QAValue):
    """What a step does. A value is literal text or a ``SecretRef`` and never both; the receipt keeps a digest."""

    kind: ActionKind
    value: Optional[ShortText] = None
    secret_ref: Optional[SecretRef] = None

    def validate(self) -> None:
        carries = (self.value is not None) + (self.secret_ref is not None)
        if self.kind in VALUE_ACTIONS and carries != 1:
            raise QAContractError(Code.INVALID_FIELD, f"{self.kind.value} carries exactly one of value or "
                                  "secret_ref")
        if self.kind not in VALUE_ACTIONS and carries:
            raise QAContractError(Code.INVALID_FIELD, f"{self.kind.value} carries no value")


def _guard_action_matches_target(step_id: str, action: Action, target: StepTarget) -> None:
    allowed = UI_ACTIONS if target.kind is TargetKind.UI else RESOURCE_ACTIONS
    if action.kind not in allowed:
        raise QAContractError(Code.SPEC_INVALID, f"step {step_id}: a {target.kind.value} target cannot take "
                              f"action {action.kind.value}")


def _guard_recovery_is_safe(step: "Step") -> None:
    if (PermittedRecovery.RETRY_SAME in step.permitted_recovery
            and step.idempotency is not Idempotency.IDEMPOTENT):
        raise QAContractError(Code.SPEC_INVALID, f"step {step.step_id}: RETRY_SAME needs idempotency "
                              f"IDEMPOTENT, not {step.idempotency.value}; an unmarked step is never retried blind")
    if step.retry_safety is RetrySafety.SAFE and step.idempotency is Idempotency.AT_MOST_ONCE:
        raise QAContractError(Code.SPEC_INVALID, f"step {step.step_id} is at-most-once and claims retries are "
                              "safe; one of the two is wrong")
    if step.target.kind is TargetKind.RESOURCE:
        locator_based = {PermittedRecovery.SEMANTIC_LOCATOR, PermittedRecovery.MODEL_CANDIDATE}
        if locator_based & set(step.permitted_recovery):
            raise QAContractError(Code.SPEC_INVALID, f"step {step.step_id}: a resource target has no locator "
                                  "to heal; healing applies to ui step targets only")


@dataclass(frozen=True)
class Step(QAValue):
    SET_FIELDS = {"permitted_recovery": None}

    step_id: Ident
    intent: NonEmptyText
    target: StepTarget
    action: Action
    expected_transition: NonEmptyText
    """The observable postcondition. Recovery is judged by this and by nothing else."""

    observation_deadline_ms: StepDeadlineMs
    side_effect: SideEffect
    idempotency: Idempotency = Idempotency.UNKNOWN
    retry_safety: RetrySafety = RetrySafety.UNSAFE
    permitted_recovery: Tuple[PermittedRecovery, ...] = ()

    def validate(self) -> None:
        _guard_action_matches_target(self.step_id, self.action, self.target)
        _guard_recovery_is_safe(self)


# ── assertions ─────────────────────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Predicate(QAValue):
    """``op`` and the canonical ``expected`` value (decimals as strings). Hashed with the assertion."""

    op: PredicateOp
    expected: Optional[BoundedJson] = None

    def validate(self) -> None:
        if self.op in NO_EXPECTED_OPS:
            if self.expected is not None:
                raise QAContractError(Code.INVALID_FIELD, f"{self.op.value} takes no expected value")
            return
        if self.expected is None:
            raise QAContractError(Code.INVALID_FIELD, f"{self.op.value} needs an expected value")
        if self.op in (PredicateOp.LESS_THAN, PredicateOp.GREATER_THAN):
            from ..canonical import CanonicalizationError, decimal_string
            try:
                if not isinstance(self.expected, str) or decimal_string(self.expected) != self.expected:
                    raise CanonicalizationError("not canonical")
            except CanonicalizationError:
                raise QAContractError(Code.INVALID_FIELD, f"{self.op.value} compares canonical decimal strings; "
                                      f"{self.expected!r} is not one") from None
        if self.op is PredicateOp.MATCHES and not (isinstance(self.expected, str) and len(self.expected) <= 512):
            raise QAContractError(Code.INVALID_FIELD, "MATCHES takes a pattern string of at most 512 characters")

    @property
    def digest(self) -> str:
        """``expected_hash``: what a result repeats so a verifier handed a different value is caught."""
        return self.value_hash()


@dataclass(frozen=True)
class AssertionSubject(QAValue):
    """What an assertion reads. Resolution is through the frozen locator and only the listed alternates; an
    unresolved or ambiguous subject is indeterminate and is never healed."""

    kind: SubjectKind
    locator: Optional[LocatorDescriptor] = None
    pattern: Optional[ShortText] = None
    inputs: Tuple[ResourceRef, ...] = ()
    subject_alternates: Tuple[LocatorDescriptor, ...] = ()
    """Tried in order, only these. Listed inside the frozen spec so the hash covers them."""

    def validate(self) -> None:
        k = self.kind
        if k is SubjectKind.UI_ELEMENT:
            ok = self.locator is not None and self.pattern is None and not self.inputs
        elif k in (SubjectKind.URL, SubjectKind.RESPONSE):
            ok = (self.pattern is not None and self.locator is None and not self.inputs
                  and not self.subject_alternates)
        else:  # RESOURCE_INPUTS
            ok = (bool(self.inputs) and len(self.inputs) <= 16 and self.locator is None
                  and self.pattern is None and not self.subject_alternates)
        if not ok:
            raise QAContractError(Code.INVALID_FIELD, f"subject fields do not match kind {k.value}")


def _guard_determinism(a: "AssertionSpec") -> None:
    if a.determinism is not Determinism.DETERMINISTIC:
        raise QAContractError(Code.SPEC_INVALID, f"assertion {a.assertion_id}: a gating assertion is "
                              "DETERMINISTIC; a non-deterministic judgement is evidence, never a gate")


def _guard_on_unresolvable(a: "AssertionSpec") -> None:
    if a.on_unresolvable is not Verdict.INDETERMINATE:
        raise QAContractError(Code.SPEC_INVALID, f"assertion {a.assertion_id}: on_unresolvable is fixed at "
                              "INDETERMINATE; an unresolved subject is never a pass and never healed")


def _guard_executor_matches_subject(a: "AssertionSpec") -> None:
    is_inputs = a.subject.kind is SubjectKind.RESOURCE_INPUTS
    if (a.executor is Executor.SCRIPT) != is_inputs:
        raise QAContractError(Code.SPEC_INVALID, f"assertion {a.assertion_id}: executor {a.executor.value} "
                              f"cannot read a {a.subject.kind.value} subject (SCRIPT reads RESOURCE_INPUTS, "
                              "PLAYWRIGHT reads the rest)")


def _guard_check_program_ref(a: "AssertionSpec") -> None:
    if a.executor is Executor.SCRIPT and a.check_program_ref is None:
        raise QAContractError(Code.CHECK_PROGRAM_REF_REQUIRED, f"assertion {a.assertion_id}: executor SCRIPT "
                              "requires check_program_ref, the hashed identity of the program it runs")
    if a.executor is not Executor.SCRIPT and a.check_program_ref is not None:
        raise QAContractError(Code.SPEC_INVALID, f"assertion {a.assertion_id}: check_program_ref is only for "
                              "executor SCRIPT")


@dataclass(frozen=True)
class AssertionSpec(QARecord):
    """One frozen expectation. Immutable, hashed whole, and referenced by hash from then on."""

    SCHEMA_ID = SCHEMA_ID_PREFIX + "assertion-spec"

    assertion_id: Ident
    executor: Executor
    """Required and hashed. Changing it changes ``assertion_set_hash``. An unknown value is non-certifying."""

    subject: AssertionSubject
    predicate: Predicate
    verifier_id: Ident
    verifier_version_range: VersionRange
    requirement_ref: Optional[RefToken] = None
    """The requirement a PASS certifies. Absent equals null, so an assertion without it hashes as it always did."""

    determinism: Determinism = Determinism.DETERMINISTIC
    on_unresolvable: Verdict = Verdict.INDETERMINATE
    check_program_ref: Optional[CheckProgramRef] = None
    """Required when ``executor = SCRIPT``, absent otherwise, and hashed with the assertion. Check programs are
    individually hashed, and this is where that hash is frozen. A SCRIPT assertion without it is an invalid spec
    (``CHECK_PROGRAM_REF_REQUIRED``, a test defect); a changed program hash is a changed assertion set."""

    def validate(self) -> None:
        _guard_determinism(self)
        _guard_on_unresolvable(self)
        _guard_executor_matches_subject(self)
        _guard_check_program_ref(self)

    @property
    def assertion_hash(self) -> str:
        return self.content_hash

    @property
    def expected_hash(self) -> str:
        return self.predicate.digest


ASSERTION_SET_SCHEMA_ID = SCHEMA_ID_PREFIX + "assertion-set"


def assertion_set_hash(assertions: Sequence[AssertionSpec]) -> str:
    """``rcv1`` hash of the frozen assertion set: order-independent, content-complete, never cached."""
    forms = sorted((a.canonical_form() for a in assertions), key=lambda f: f["assertion_id"])
    ids = [f["assertion_id"] for f in forms]
    if len(set(ids)) != len(ids):
        raise QAContractError(Code.DUPLICATE_ENTRY, "an assertion id appears twice in the set")
    return content_hash({"schema_id": ASSERTION_SET_SCHEMA_ID, "schema_version": AssertionSpec.SCHEMA_VERSION,
                         "assertions": forms})


# ── the spec ───────────────────────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class TestTarget(QAValue):
    __test__ = False

    app_id: Ident
    build_sha: Revision
    environment_profile: Ident


@dataclass(frozen=True)
class FixtureRef(QAValue):
    id: Ident
    content_hash: AnyDigest


SmallCount = Annotated[int, Rule(minimum=0, maximum=1000)]


@dataclass(frozen=True)
class Budget(QAValue):
    """Hard caps for one run of a spec. Model use is off unless a budget grants it."""

    deadline_ms: DeadlineMs
    max_retries: SmallCount = 0
    max_recovery_attempts: SmallCount = 0
    max_model_calls: Annotated[int, Rule(minimum=0, maximum=100000)] = 0
    max_tokens: Annotated[int, Rule(minimum=0, maximum=100000000)] = 0


def make_spec_ref(spec_id: str, spec_hash: str) -> str:
    """``id@spec_hash``: how a spec is referenced by a plan, a dependency or a manifest."""
    ref = f"{spec_id}@{spec_hash}"
    SPEC_REF_RULE.check("spec_ref", ref)
    return ref


def split_spec_ref(ref: str) -> Tuple[str, str]:
    SPEC_REF_RULE.check("spec_ref", ref)
    spec_id, spec_hash = ref.split("@", 1)
    return spec_id, spec_hash


def _guard_unique_ids(spec: "TestSpec") -> None:
    ids = [s.step_id for s in spec.steps]
    if len(set(ids)) != len(ids):
        raise QAContractError(Code.DUPLICATE_ENTRY, f"spec {spec.id}: a step id appears twice")


def _guard_has_assertions(spec: "TestSpec") -> None:
    if not spec.assertions:
        raise QAContractError(Code.SPEC_INVALID, f"spec {spec.id} declares no assertion; a spec with nothing "
                              "to check could only pass vacuously")


def _guard_side_effects_allowed(spec: "TestSpec") -> None:
    allowed = set(spec.allowed_side_effects) | {SideEffect.NONE}
    for step in spec.steps:
        if step.side_effect not in allowed:
            raise QAContractError(Code.SPEC_INVALID, f"spec {spec.id}: step {step.step_id} has side effect "
                                  f"{step.side_effect.value}, which allowed_side_effects does not list")


def _guard_no_self_dependency(spec: "TestSpec") -> None:
    if any(d.split("@", 1)[0] == spec.id for d in spec.depends_on):
        raise QAContractError(Code.SPEC_INVALID, f"spec {spec.id} depends on itself")


@dataclass(frozen=True)
class TestSpec(QARecord):
    """What to run and what must hold. Versioned: a change to an assertion is a new version with a new hash."""

    __test__ = False  # not a pytest class, whatever its name suggests

    SCHEMA_ID = SCHEMA_ID_PREFIX + "test-spec"
    CUSTODY = frozenset({"author", "reviewer", "approved_at"})
    SET_FIELDS = {"assertions": "assertion_id", "fixtures": "id", "depends_on": None,
                  "allowed_side_effects": None, "sensitivity_labels": None}

    id: Ident
    version: Pos
    target: TestTarget
    steps: Tuple[Step, ...]
    assertions: Tuple[AssertionSpec, ...]
    budget: Budget
    egress_profile: Ident
    """A name. The allow-list itself lives in operator configuration and never in the spec."""

    preconditions: Tuple[ShortText, ...] = ()
    fixtures: Tuple[FixtureRef, ...] = ()
    depends_on: Tuple[SpecRefStr, ...] = ()
    allowed_side_effects: Tuple[SideEffect, ...] = ()
    cleanup: Tuple[ShortText, ...] = ()
    sensitivity_labels: Tuple[Ident, ...] = ()
    author: Optional[ShortText] = None
    reviewer: Optional[ShortText] = None
    approved_at: Optional[ShortText] = None

    def validate(self) -> None:
        _guard_unique_ids(self)
        _guard_has_assertions(self)
        _guard_side_effects_allowed(self)
        _guard_no_self_dependency(self)

    @property
    def spec_hash(self) -> str:
        return self.content_hash

    @property
    def spec_ref(self) -> str:
        return make_spec_ref(self.id, self.spec_hash)

    @property
    def assertion_set_hash(self) -> str:
        return assertion_set_hash(self.assertions)

    @property
    def assertion_ids(self) -> Tuple[str, ...]:
        return tuple(a.assertion_id for a in self.assertions)
