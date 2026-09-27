"""Concurrency topology — the cross-runtime vocabulary for expressing that plan steps run together.

Today concurrency is an executor implementation detail (agentic-os dispatches its ready DAG wave in
parallel). To make it **governed and cross-language**, the shared contract needs a small, fixed way to say
*these members run concurrently, joined this way, bounded like this* — so Python and Go executors honour one
declaration rather than each inventing behaviour. This module is that vocabulary; it is pure data and adds
no execution engine. Pairs with the ``DEPENDS_ON`` relation (protocol/lineage) for the edges and the
partial-order ``parents`` on the transition event (models/investigation) for the replayable history.

Additive: existing programs that declare no topology are unaffected (a single sequential path).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Sequence


class TopologyKind(str, Enum):
    """How a group of members is executed."""
    SEQUENCE = "SEQUENCE"                 # one after another (the default when no topology is declared)
    PARALLEL_ALL = "PARALLEL_ALL"         # all members run concurrently; join per join_policy
    PARALLEL_ANY = "PARALLEL_ANY"         # run concurrently, first success suffices
    RACE_UNTIL_VALID = "RACE_UNTIL_VALID" # run concurrently, first result that passes acceptance wins
    FALLBACK = "FALLBACK"                 # try members in order until one succeeds
    SPECULATIVE = "SPECULATIVE"           # run ahead of confirmation; discard if not needed (later work)


class JoinPolicy(str, Enum):
    """When a concurrent group is considered complete."""
    ALL = "ALL"                 # every member must succeed
    ANY = "ANY"                 # one success is enough
    QUORUM = "QUORUM"           # at least ``min_successes`` succeed
    FIRST_VALID = "FIRST_VALID" # first member to pass acceptance wins
    BEST_EFFORT = "BEST_EFFORT" # collect whatever succeeds by the deadline
    FAIL_FAST = "FAIL_FAST"     # any hard failure cancels the remaining members


@dataclass(frozen=True)
class ConcurrencyGroup:
    """A declared concurrent group over member node/step ids — the unit an executor schedules together.

    Pure data: asserting/scheduling a group is the executor's job; this only *declares* the intent so it
    can be planned, budgeted, governed and replayed consistently across languages.
    """
    kind: TopologyKind
    members: Sequence[str]                       # node/step ids that run together
    max_concurrency: int = 0                     # 0 = unbounded (bounded only by the runtime's own cap)
    join_policy: JoinPolicy = JoinPolicy.ALL
    min_successes: int = 0                       # for QUORUM
    deadline_seconds: float | None = None
    cancel_on_failure: bool = True               # cancel siblings on a hard failure (FAIL_FAST semantics)
    acceptance_verifier: str = ""                # capability/verifier id for RACE_UNTIL_VALID / FIRST_VALID
    budget_usd: float | None = None              # optional spend cap for hedged/speculative groups
    metadata: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.max_concurrency < 0:
            raise ValueError("max_concurrency must be >= 0 (0 = unbounded)")
        if self.join_policy is JoinPolicy.QUORUM and self.min_successes <= 0:
            raise ValueError("QUORUM join_policy requires min_successes > 0")
