# ReDevOps implementation split

**Status:** architectural ownership map for the public runtime stack and reference deployments.

This document defines which repository owns each class of behavior, contract, adapter, policy, and deployment concern across ReDevOps.

The governing rule is:

> Contracts define stable meaning. Runtimes implement one kind of decision. Harnesses provide reusable execution primitives. Products compose those pieces. Deployments prove that the composition works.

No reference application should become the accidental owner of reusable runtime behavior, and no neutral contract package should absorb planning algorithms or product policy.

---

## 1. Stack overview

```text
Applications and deployments
  quantify.club · demo.redevops.io · domain apps
            │
            ▼
Mission SDK
  curated authoring and Mission DevOps surface
            │
            ▼
Mission Runtime
  compile and execute governed MissionPrograms
            │
            ├──────────────┐
            ▼              ▼
Context Runtime       Discovery Runtime
plan context          propose work
            │              │
            └──────┬───────┘
                   ▼
             ReDevOps RAG
      retrieve and materialize evidence
                   │
                   ▼
             Agent Harness
  models · tools · approvals · sandbox · guardrails · eval
                   │
                   ▼
                Sidekick
  opinionated coding-agent orchestration product

Cross-cutting canonical contracts:
  runtime-contracts

Fleet deployment and control-plane composition:
  agentic-os
```

The arrows indicate composition and runtime calls, not package ownership. `runtime-contracts` is imported by conforming implementations but does not execute their algorithms.

---

## 2. `runtime-contracts`

### Owns

`runtime-contracts` is the canonical, application-neutral interoperability layer.

It owns:

- schema identity and contract versioning;
- canonical serialization and hashing rules;
- compatibility and evolution rules;
- visibility, audience, tenancy and provenance types;
- portable identifiers and references;
- neutral policy and proof result schemas;
- adoption manifests and maturity declarations;
- golden fixtures and cross-language conformance vectors;
- contract-level validation and conformance reporting.

Existing core types remain here, including:

- `ArtifactHandle`;
- `ContextPreviewPlan`;
- `ContextView`;
- `DereferenceEvent`;
- `RuntimeEvent`;
- `CapabilityDescriptor`;
- `MissionProgram` wire representation;
- `InvestigationTransitionEvent`;
- `VerificationResult`.

The following reusable contracts should also live here when implemented:

- `DeploymentManifest`;
- `RuntimePin` and implementation identity;
- `SecurityPostureDescriptor`;
- `PolicyFloor` and resolved-policy evidence;
- `CapabilityGrant` with owner, audience, expiry, revocation and once/standing mode;
- `BackgroundTrigger` / `WatchDescriptor`;
- `DeploymentProofRequest` and `DeploymentProofResult`;
- `ConformanceResult`;
- `SecretRequirement` names and purpose metadata, never secret values;
- `EgressRequirement` and `DataResidencyRequirement` declarations.

### Does not own

- planning or optimization algorithms;
- retrieval and ranking logic;
- mission compilation or execution;
- agent loops, tool execution or sandboxing;
- persistence engines;
- deployment commands or cloud providers;
- product-specific policy values;
- financial, coding, support or other domain semantics.

### Implementation rule

A schema in this repository establishes portable meaning, not enforcement. Every runtime must claim conformance through an adapter and executable fixtures. Reproducing a golden hash proves translation only; it does not prove that the production path adopted the contract.

---

## 3. `context-runtime`

### Owns

Context Runtime decides **what evidence and configuration a model or agent should receive**.

It owns:

- intent classification for context planning;
- candidate context-plan generation;
- hard feasibility checks for context constraints;
- cost, latency, token, quality and trust estimates;
- plan optimization and selection;
- provider, retriever, compression and representation routing;
- `ContextPreviewPlan` creation;
- `ContextView` assembly from referenced artifacts;
- context-plan explanation, simulation and replay;
- context-specific learning and calibration;
- context-plan caching and cache-key semantics;
- context-specific verification such as grounding, citation coverage and abstention;
- adapters from internal plans to `runtime-contracts` artifacts.

### Does not own

- the canonical wire meaning of `ArtifactHandle` or `ContextView`;
- general mission DAG execution;
- discovery of whether work should be proposed;
- low-level vector, lexical or graph retrieval implementations;
- generic model clients, tool registries, sandboxing or approval UI;
- deployment-wide policy configuration;
- product-specific retrieval policy.

### Boundary

The application states an intent and constraints. Context Runtime returns an inspectable plan and a governed `ContextView`. It may call ReDevOps RAG and Agent Harness adapters, but it remains the sole owner of the context-selection decision.

---

## 4. `redevops-rag`

### Owns

ReDevOps RAG is the representation, indexing, retrieval and dereference engine.

It owns:

- ingestion and chunking;
- lexical, dense, hybrid, graph and multimodal indexes;
- candidate retrieval;
- reranking and score fusion;
- source-aware filtering;
- artifact dereferencing;
- retrieval provenance;
- corpus and index statistics;
- retrieval benchmarks;
- adapters that emit contract-compatible artifact references and dereference events.

### Does not own

- deciding which retrieval strategy is optimal for an application goal;
- mission execution;
- global model routing;
- policy floors or human approval;
- product-specific conclusions.

### Boundary

Context Runtime chooses which retrieval capability and parameters to use. ReDevOps RAG performs that retrieval faithfully and returns referenced evidence with provenance.

---

## 5. Mission Runtime inside `agentic-os`

The public Mission Runtime currently lives under `agentic_os/mission/`, with corresponding Go implementation where maintained.

### Owns

Mission Runtime decides **how governed work executes**.

It owns:

- MissionProgram validation and compilation;
- capability binding;
- logical-plan to physical execution-graph lowering;
- graph feasibility, dependency and cycle checks;
- execution scheduling and parallel waves;
- mission budgets, deadlines and approval gates;
- side-effect and undo boundaries;
- durable event recording;
- pause, resume, replay and recovery;
- mission outcome and terminal-state derivation;
- execution verification hooks;
- mission-level `EXPLAIN`, profiling and simulation primitives;
- runtime adapters for contract-compatible `MissionProgram`, events and verification results.

### Does not own

- the curated public authoring API;
- context-selection optimization;
- discovery of new work;
- generic tool execution implementation;
- deployment-specific module catalogs;
- domain scenario semantics.

### Boundary

Mission Runtime receives a validated MissionProgram and executes it under explicit grants, policy, budgets and side-effect rules. It may invoke Context Runtime for context decisions and Agent Harness for individual model/tool steps.

---

## 6. `mission-sdk`

### Owns

Mission SDK is the curated developer boundary over Mission Runtime.

It owns:

- public `redevops_mission` authoring types;
- mission templates, steps, operators and capabilities;
- `MissionProposal` conversion;
- the one compilation path for human, compiler and Discovery sources;
- origin and provenance propagation into case bundles;
- `rdo mission` commands:
  - `init`;
  - `validate`;
  - `explain`;
  - `profile`;
  - `simulate`;
  - `run`;
  - `bundle`;
  - `replay`;
  - `diff`;
  - `verify`;
  - `ci`;
- adapter SPIs that keep users from importing Mission Runtime internals;
- SDK compatibility and upgrade discipline;
- developer-facing Mission DevOps workflows and CI templates.

### Does not own

- the Mission Runtime engine;
- deployment control-plane behavior;
- domain-specific scenario compilers;
- generic agent execution primitives;
- contract canonicalization.

### Boundary

The SDK exposes one stable artifact, `MissionProgram`, and one stable operational surface. It must remain thinner than the runtime and must not fork runtime semantics.

---

## 7. Discovery Runtime

### Owns

Discovery Runtime decides **what work should be proposed**.

It owns:

- world-state and signal intake;
- opportunity and anomaly detection;
- candidate investigation or mission proposals;
- prioritization and suppression;
- repetition, novelty and expiry semantics;
- discovery provenance;
- proposal confidence and limitations;
- proposal-policy checks;
- conversion into SDK-compatible discovery inputs.

### Does not own

- executing the mission;
- assembling the final context;
- directly mutating application state;
- general cron infrastructure;
- domain-specific acceptance of a proposal.

### Boundary

Discovery produces proposals. It never bypasses the Mission SDK/Runtime path. Human-authored, compiler-authored and discovery-authored missions must validate, execute, replay and verify identically apart from provenance.

---

## 8. `agent-harness`

### Owns

Agent Harness is the reusable execution substrate for one agent step or tool-using loop.

It owns:

- LLM client and provider adapter interfaces;
- model gateway primitives;
- tool registry and invocation contracts;
- approval mechanisms;
- sandbox execution interfaces;
- generic command and tool guardrails;
- generic secret materialization interfaces;
- generic egress enforcement adapters;
- generic agent-loop state;
- structured tool and model events;
- evaluator and test harness primitives;
- implementation adapters for neutral policy, grant and proof contracts.

It should implement, but not canonically define, reusable mechanisms for:

- security-posture enforcement;
- policy-floor resolution;
- capability grants;
- background-trigger execution;
- deployment proof execution;
- sandbox and egress conformance checks.

### Does not own

- canonical contract schemas;
- context optimization;
- mission graph compilation;
- coding-specific worktrees and merges;
- fleet deployment;
- product policy values.

### Boundary

Agent Harness provides primitives. It does not decide the business goal, the context plan or the mission topology.

---

## 9. `sidekick`

### Owns

Sidekick is an opinionated coding-agent orchestration product built on the shared runtime stack.

It owns:

- coding-task decomposition;
- coding-specific DAG construction;
- worktree and branch isolation;
- coding-agent fan-out and merge;
- coding command allowlists;
- repository-aware context and skill recall;
- coding-specific acceptance checks;
- coding provider profiles;
- coding progress surfaces and editor integration;
- coding metrics;
- coding-specific deployment checks and proofs;
- repository and organization watches;
- coding-skill promotion workflows.

Examples of Sidekick proofs:

- worktree isolation;
- command-policy enforcement;
- credential scope;
- acceptance-gate reachability;
- merge only after green checks;
- no cross-run workspace collision.

### Does not own

- generic model, tool, sandbox or approval primitives;
- neutral deployment contracts;
- Mission Runtime internals;
- financial or other application-domain semantics.

### Boundary

Sidekick may emit or execute MissionPrograms for coding work, but coding-specific topology and acceptance remain Sidekick behavior. Reusable execution mechanisms must move down to Agent Harness or Mission Runtime rather than being duplicated.

---

## 10. `agentic-os`

### Owns

`agentic-os` is the fleet control plane and current host repository for Mission Runtime.

At the control-plane layer it owns:

- module registry and catalog;
- deployment, start, stop and health operations for modules;
- fleet scheduling;
- cross-module workflow initiation;
- organization-level runtime configuration;
- model-tier and budget configuration for the fleet;
- approval and audit surfaces;
- permission-plane administration;
- control-plane API and CLI;
- deployment-wide posture selection and policy-floor configuration;
- live deployment conformance orchestration;
- collection and presentation of proof results from runtimes and apps.

### Does not own

- the neutral schemas used to describe policies and proof results;
- application-specific domain policy;
- all individual agent primitives;
- context-selection algorithms;
- domain scenario compilation.

### Boundary

`agentic-os` composes runtimes and services. It should not reimplement their internal decisions. It selects implementations, supplies configuration, invokes health/proof endpoints and enforces deployment-wide floors.

### Future extraction rule

Mission Runtime may later become its own public repository without changing semantic ownership. Until then, `agentic_os/mission/` remains the implementation location and `mission-sdk` remains the public developer boundary.

---

## 11. Deployment contract and proof split

The QM-inspired deployment features should be divided as follows.

### `runtime-contracts`

Defines:

- deployment manifest schema;
- runtime pins;
- posture and policy-floor contracts;
- capability-grant schema;
- proof request/result schema;
- conformance result schema;
- background-trigger descriptors;
- secret and egress requirement declarations.

### `agent-harness`

Implements reusable proof adapters for:

- model gateway reachability;
- sandbox isolation;
- tool approval enforcement;
- secret materialization boundaries;
- egress policy;
- provider availability;
- generic evaluator execution.

### `context-runtime`

Implements proofs for:

- context-plan determinism;
- ContextView hash reproduction;
- version-pin use;
- context-policy feasibility;
- retriever/provider routing explanation;
- context replay.

### `redevops-rag`

Implements proofs for:

- artifact dereference integrity;
- index/corpus pinning;
- retrieval provenance;
- filter enforcement;
- retrieval reproducibility under declared pins.

### Mission Runtime

Implements proofs for:

- MissionProgram compilation;
- grant coverage;
- graph feasibility;
- approval and side-effect gates;
- replay to the same terminal state;
- event-ledger integrity;
- rollback and resume behavior.

### `mission-sdk`

Exposes proof and conformance commands to developers through `rdo mission`; it does not reimplement the checks.

### `agentic-os`

Aggregates component proofs and applies deployment-wide release gates.

Suggested control-plane surface:

```bash
agentic-os deploy check
agentic-os deploy doctor
agentic-os deploy plan
agentic-os proof all
agentic-os proof context
agentic-os proof mission
agentic-os proof harness
agentic-os conformance
```

### `sidekick`

Adds coding-specific proofs and deployment checks.

### Reference applications

Add only domain-specific proofs and policy profiles.

---

## 12. Reference applications and deployments

Examples include Quantify.club and the public ReDevOps demo applications.

### Own

- domain entities and vocabulary;
- domain scenario/compiler semantics;
- domain-specific policy profiles;
- application persistence and UI;
- application workflows;
- adapters into runtime contracts and Mission SDK;
- application-specific proofs;
- deployment manifests selecting runtime implementations and pins;
- evidence that the complete stack works in a real domain.

For Quantify this includes, for example:

- financial scenarios, worksheets and results;
- account and tax runtimes;
- RSU vesting, disposition and reconciliation;
- market-data policy;
- immutable financial artifacts;
- tenant-safe persistence;
- financial comparability and presentability;
- proofs such as synthetic-only data, immutable financial redelivery and snapshot egress.

### Do not own

- neutral capability grants;
- generic policy hierarchy;
- generic background scheduling;
- reusable proof result schemas;
- generic model/tool/sandbox behavior;
- Mission Runtime or Context Runtime algorithms.

### Boundary

A reference deployment proves adoption; it does not semantically own the reusable mechanism. When an application uncovers a general invariant, the contract or mechanism moves to the correct lower layer while the application retains only its domain configuration and proof fixture.

---

## 13. Policy hierarchy

The canonical shape belongs in `runtime-contracts`; resolution and enforcement are distributed.

```text
deployment policy floor
  → organization policy
    → application/workspace policy
      → mission policy
        → operation policy
```

Rules:

- lower scopes may tighten but never weaken an inherited floor;
- every resolution emits a typed, versioned decision;
- Mission Runtime enforces mission and operation gates;
- Context Runtime enforces context-plan constraints;
- Agent Harness enforces model, tool, sandbox and egress constraints;
- `agentic-os` sets deployment and organization floors;
- applications define domain policy values;
- all implementations serialize policy evidence through `runtime-contracts`.

No runtime may treat prose purpose as authorization.

---

## 14. Background work and watches

### `runtime-contracts`

Defines trigger, ownership, scope, cadence, expiry, policy and provenance fields.

### Discovery Runtime

Decides whether a signal should become a proposal.

### Mission Runtime

Executes the resulting governed mission.

### `agentic-os`

Schedules and supervises fleet-level watches and recurring work.

### `agent-harness`

Provides reusable timer/webhook/task execution adapters where appropriate.

### Applications

Define domain signals and resulting proposal types.

A watch must not directly perform a domain side effect. It should emit a signal or proposal that follows the normal mission path.

---

## 15. Dependency direction

Allowed dependency direction:

```text
runtime-contracts
      ▲
      │ imported by adapters
      │
agent-harness   redevops-rag
      ▲              ▲
      │              │
context-runtime      │
      ▲              │
      └──────┬───────┘
             │
Mission Runtime
      ▲
mission-sdk
      ▲
sidekick / applications
      ▲
agentic-os deployment composition
```

This diagram is conceptual. `agentic-os` currently contains Mission Runtime and therefore has an internal implementation dependency that a future extraction may simplify.

Forbidden dependency patterns:

- `runtime-contracts` importing any runtime implementation;
- Agent Harness importing Sidekick;
- Context Runtime importing Quantify domain types;
- Mission Runtime importing a reference application;
- Mission SDK exposing `agentic_os` internals in its public API;
- applications becoming required dependencies of runtimes;
- one runtime defining a competing copy of a canonical contract.

---

## 16. Where a new feature goes

Use this decision test.

### Put it in `runtime-contracts` when

It defines portable identity, meaning, serialization, compatibility, policy evidence or a cross-runtime proof result.

### Put it in `context-runtime` when

It decides what context, retriever, representation, compression or model configuration should be used.

### Put it in `redevops-rag` when

It indexes, retrieves, ranks, filters or dereferences evidence.

### Put it in Mission Runtime when

It compiles, schedules, executes, pauses, resumes, replays or verifies a governed execution graph.

### Put it in `mission-sdk` when

It improves authoring, inspection, simulation, bundling, replay or CI without requiring users to import runtime internals.

### Put it in Discovery Runtime when

It notices that work should exist and emits a proposal rather than executing it.

### Put it in `agent-harness` when

It is a reusable model, tool, approval, sandbox, guardrail, egress, secret or evaluator primitive.

### Put it in `sidekick` when

It is specifically about coding-task decomposition, repositories, worktrees, acceptance checks, merges or coding UX.

### Put it in `agentic-os` when

It deploys, configures, supervises or governs the fleet as a whole.

### Put it in an application when

It expresses domain meaning, policy values, persistence, UI, workflows or an application-specific proof.

---

## 17. Migration of the proposed QM-derived ideas

| Idea | Canonical owner | Enforcement/implementation | Product adaptation |
|---|---|---|---|
| Deployment manifest | runtime-contracts | agentic-os CLI/control plane | each deployment repository |
| Live proof result format | runtime-contracts | each runtime; aggregated by agentic-os | domain proof commands |
| Security posture | runtime-contracts | agentic-os floor; runtimes/harness enforce their dimensions | Sidekick and Quantify profiles |
| Policy tightening hierarchy | runtime-contracts | agentic-os + Mission/Context/Harness | application-specific values |
| Capability grants | runtime-contracts | Mission Runtime and Agent Harness | domain capability names |
| Background watches | runtime-contracts | agentic-os scheduler + Discovery + Mission Runtime | application signals |
| Sandbox isolation | agent-harness | agent-harness backends | Sidekick coding sandbox |
| Provider interchangeability | agent-harness | agent-harness adapters | Sidekick and runtime profiles |
| Coding worktree isolation | Sidekick | Sidekick | Sidekick only |
| Deployment snapshots and rollback manifest | agentic-os | target-specific deploy adapter | deployment configuration |
| Dependency release-age/provenance policy | agentic-os deployment tooling | CI/package tooling | repository-specific policy |

---

## 18. Adoption sequence

1. Extend `runtime-contracts` only with the minimum neutral schemas required by a live adopter.
2. Implement enforcement in the owning runtime or harness.
3. Add an explicit adapter and adoption declaration.
4. Add golden vectors for cross-language meaning.
5. Add a constructed invalid state for each guard.
6. Add reachability tests proving the production caller cannot bypass the control.
7. Add coverage evidence generated by the exercised path.
8. Add one reference-application proof.
9. Aggregate the proof in `agentic-os` only after the component proof exists.
10. Advance conformance maturity only to the level mechanically demonstrated.

A schema without a live adopter remains `SPECIFIED`. An adapter that round-trips fixtures is not `CONFORMANT`. A repository may claim `DEPLOYED_CONFORMANT` only when its deployed path produces and verifies the contract artifacts.

---

## 19. Architectural invariants

The implementation split is governed by the following invariants:

- unknown must never silently become known;
- every material claim must be mechanically falsifiable;
- a control is not implemented until the production path cannot bypass it;
- a guard is not tested until a fixture constructs the state it rejects;
- coverage evidence must be produced by the covered path;
- every persistent record must have a mechanically provable ownership path or be explicitly global;
- consistency checks must compare independently produced representations;
- structural invariants must be checked against typed structures, metadata, emitted output or behavior rather than prose;
- contract meaning is centralized, but enforcement remains in the runtime that owns the decision;
- applications prove composition but do not become accidental owners of reusable behavior.

---

## 20. Summary

```text
runtime-contracts  defines portable meaning
context-runtime    chooses context
redevops-rag       retrieves and materializes evidence
Discovery Runtime  proposes work
Mission Runtime    compiles and executes work
mission-sdk        exposes the stable developer workflow
agent-harness      executes model/tool steps safely
sidekick           applies the stack to coding work
agentic-os         deploys and governs the fleet
applications       define domain meaning and prove the composition
```

When ownership is unclear, place canonical meaning lower and application policy higher. Do not move algorithms into the contract repository, and do not leave reusable enforcement trapped inside a reference deployment.