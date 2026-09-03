"""The stateless-agent contract — the agent is disposable, the Mission is durable.

Agent frameworks accumulate state in framework-specific places: chat histories,
checkpoints, memory objects, scratchpads, graph state, tool logs. That state is hard to
compare, migrate, audit, or reuse across frameworks — and it quietly makes the *agent*,
not the Runtime, the system of record.

ReDevOps already runs the other way through its integrations. This module makes the rule
explicit and conformable:

    Agent  != memory
    Agent  != mission state
    Agent  != evidence store
    Agent  != authority ledger
    Agent  != execution history
    Agent  == compute capability

An agent is invoked with everything it needs and returns a result. Durable ownership
lives elsewhere and is *named here* so a conformance test can assert an implementation
does not smuggle it back into the agent:

    Context Runtime    owns evidence and context construction
    Mission Runtime    owns durable workflow state
    Governance         owns authority and admissibility
    runtime-contracts  owns portable identity and semantics
    Execution Plane    owns physical containment
    Agent              performs bounded computation

The practical payoff: an agent implementation (PydanticAI, NeMo, CrewAI, LangGraph,
plain Python, a remote service) can be swapped without changing the identity or history
of the Mission it served. Disposability is the point — a stateless agent can be killed,
retried, relocated, or replaced, because nothing that must survive lives inside it.
"""
from __future__ import annotations

from typing import Any, Mapping, Protocol, runtime_checkable

#: The concerns an agent must NOT own. A conformance harness checks that an
#: implementation exposes no durable handle to any of these — they belong to the
#: Runtime, not the compute step.
RUNTIME_OWNED = (
    "memory",
    "mission_state",
    "evidence_store",
    "authority_ledger",
    "execution_history",
)


@runtime_checkable
class StatelessAgent(Protocol):
    """A disposable unit of computation.

    One call takes everything the step needs and returns everything it produced. The
    agent holds no state *between* calls that the Runtime would need to reconstruct the
    Mission: given the same ``inputs``, a fresh instance is an acceptable substitute.

    What the Runtime supplies (never the agent's to persist): the constructed context,
    the mission/authority binding, and — when the step causes a side effect — the
    ``ExecutionEnvelope`` that authorizes and contains it. What the agent returns is a
    plain result plus whatever evidence it generated, for the Runtime to record. Any
    secret needed is referenced, resolved behind the execution boundary, and never held.
    """

    def run(self, inputs: Mapping[str, Any]) -> Mapping[str, Any]:
        """Compute a result from inputs. Pure with respect to durable Runtime state:
        no reads or writes of mission state, evidence, authority, or history that the
        Runtime is the system of record for."""
        ...
