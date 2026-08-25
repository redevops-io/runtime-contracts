"""WorldRegistry — the catalog of reproducible dataset worlds.

A world is a replayable scenario with canonical entities, source provenance, a realism class, an adapter
version, a scenario seed, and (where benchmarkable) ground truth. The registry catalogs them so a demo /
product can select one by id and project it into the OSS-backed apps. ``default_registry()`` seeds the
strongest real/public sources already in the fleet (per the 2026-08-25 datasource audit).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from ..canonical import content_hash
from .event import RealismClass


@dataclass(frozen=True)
class WorldDescriptor:
    world_id: str
    dataset_id: str
    title: str = ""
    license: str = ""
    provenance: str = ""                            # source url / attribution
    realism: str = RealismClass.SYNTHETIC.value      # the DEFAULT realism of this world's data
    adapter_version: str = "0.1.0"
    scenario_seed: str = ""
    datasources: Tuple[str, ...] = ()
    ground_truth_available: bool = False
    supported_scenarios: Tuple[str, ...] = ()
    capability_requirements: Tuple[str, ...] = ()

    def canonical_form(self) -> Dict[str, object]:
        d: Dict[str, object] = {"world_id": self.world_id, "dataset_id": self.dataset_id,
                                "realism": self.realism, "adapter_version": self.adapter_version}
        for k in ("title", "license", "provenance", "scenario_seed"):
            v = getattr(self, k)
            if v:
                d[k] = v
        for k in ("datasources", "supported_scenarios", "capability_requirements"):
            v = getattr(self, k)
            if v:
                d[k] = sorted(v)
        d["ground_truth_available"] = self.ground_truth_available
        return d

    def ref(self) -> str:
        return content_hash(self.canonical_form())


class WorldRegistry:
    def __init__(self) -> None:
        self._worlds: Dict[str, WorldDescriptor] = {}

    def register(self, d: WorldDescriptor) -> None:
        self._worlds[d.world_id] = d

    def get(self, world_id: str) -> "WorldDescriptor | None":
        return self._worlds.get(world_id)

    def list(self) -> List[WorldDescriptor]:
        return sorted(self._worlds.values(), key=lambda w: w.world_id)


def default_registry() -> WorldRegistry:
    """The initial world registry — the fleet's strongest real/public sources, labelled by realism."""
    r = WorldRegistry()
    L = RealismClass
    for d in [
        WorldDescriptor("finance-evidence", "financebench", "Financial filings evidence quality",
                        license="CC-BY-4.0", provenance="patronus-ai/financebench",
                        realism=L.REAL_LIVE.value, datasources=("FinanceBench (SEC 10-K/10-Q)", "PubMedQA"),
                        supported_scenarios=("evidence-quality", "retrieval-abstention"),
                        capability_requirements=("context.retrieve",)),
        WorldDescriptor("b2b-signals", "github-hn", "B2B signal → qualified outreach",
                        provenance="api.github.com + hn.algolia.com", realism=L.REAL_LIVE.value,
                        datasources=("GitHub search", "Hacker News"),
                        supported_scenarios=("signal-to-outreach",),
                        capability_requirements=("crm.write", "outreach.draft")),
        WorldDescriptor("kyc-ownership", "gleif-opensanctions", "KYC / vendor onboarding",
                        license="CC0 + CC-BY-NC", provenance="GLEIF golden-copy + OpenSanctions",
                        realism=L.REAL_SNAPSHOT.value, datasources=("GLEIF LEI", "OpenSanctions"),
                        ground_truth_available=True, supported_scenarios=("kyc-go-no-go",),
                        capability_requirements=("kyc.screen",)),
        WorldDescriptor("geo-zoning", "us-parcels", "Geospatial / zoning intelligence",
                        provenance="government ArcGIS / GIS portals", realism=L.REAL_SNAPSHOT.value,
                        datasources=("harvested_us_sample (32 parcels)",),
                        supported_scenarios=("zoning-permit",), capability_requirements=("geo.resolve",)),
        WorldDescriptor("security-telemetry", "crowdsec", "Compromised agent / unsafe tool call",
                        provenance="CrowdSec LAPI", realism=L.REAL_LIVE.value,
                        datasources=("CrowdSec decisions/alerts",), ground_truth_available=True,
                        supported_scenarios=("compromised-agent",),
                        capability_requirements=("security.contain",)),
        WorldDescriptor("agent-trajectories", "tau-bench", "Governance over recorded agent runs",
                        license="MIT", provenance="sierra-research/tau-bench (gpt-4o-retail)",
                        realism=L.REAL_SNAPSHOT.value, datasources=("τ-bench retail trajectories",),
                        ground_truth_available=True, supported_scenarios=("governance-correlation",)),
    ]:
        r.register(d)
    return r
