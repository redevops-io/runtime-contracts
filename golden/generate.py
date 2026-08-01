"""Generate the language-neutral golden fixtures.

These are the artifact another implementation checks itself against. A Go or
TypeScript port does not read the Python — it reproduces these hashes from these
inputs, or it does not conform.
"""
from __future__ import annotations

import json
import pathlib
import unicodedata

from runtime_contracts import (
    ArtifactHandle,
    AuthorizationOutcome,
    ContextPreviewPlan,
    ContextView,
    Necessity,
    PlannedItem,
    Tenancy,
    Visibility,
    content_hash,
    decimal_string,
)

HERE = pathlib.Path(__file__).parent


def handle(n: int, *, tenant=None, visibility=Visibility.PUBLIC,
           projections=("summary", "full"), tokens=120) -> ArtifactHandle:
    return ArtifactHandle(
        artifact_id=f"evidence/e{n}@1", artifact_type="evidence", version="1",
        artifact_content_hash=f"rcv1:{n:064d}",
        tenancy=Tenancy(visibility, tenant), authority="redevops-rag",
        projections=projections, estimated_expansion_tokens=tokens,
    )


def cases() -> dict:
    base_items = [
        PlannedItem(handle(1), Necessity.REQUIRED, "full"),
        PlannedItem(handle(2), Necessity.OPTIONAL, "summary"),
    ]
    base_plan = ContextPreviewPlan("plan-1", base_items, budget_tokens=1000)
    base_pins = {"evidence/e1@1": f"rcv1:{1:064d}",
                 "evidence/e2@1": f"rcv1:{2:064d}"}

    out = {}

    # 1. The load-bearing invariant.
    out["reproducible_working_set"] = {
        "why": "same handles + same plan + same pins = same view hash",
        "view_hash": ContextView("v-a", base_plan, base_pins).view_hash,
    }

    # 2. Field and declaration order must not matter.
    reordered = ContextPreviewPlan("plan-2", list(reversed(base_items)),
                                   budget_tokens=1000)
    out["order_variation"] = {
        "why": "declaration order is a property of the builder, not the plan",
        "view_hash": ContextView("v-b", reordered,
                                 dict(reversed(list(base_pins.items())))).view_hash,
    }

    # 3. Duplicates normalize rather than being refused.
    duplicated = ContextPreviewPlan(
        "plan-3", base_items + [base_items[0]], budget_tokens=1000)
    out["duplicate_handle_normalization"] = {
        "why": "two parts of a plan may legitimately cite one artifact",
        "view_hash": ContextView("v-c", duplicated, base_pins).view_hash,
    }

    # 4. A different projection is a different item, not a duplicate.
    distinct_projection = ContextPreviewPlan(
        "plan-4",
        base_items + [PlannedItem(handle(1), Necessity.REQUIRED, "diagnostics")],
        budget_tokens=1000)
    out["projection_is_part_of_identity"] = {
        "why": "the same artifact at two projections is two planned items",
        "view_hash": ContextView("v-d", distinct_projection, base_pins).view_hash,
    }

    # 5. Unicode identifiers normalize to NFC.
    out["unicode_identity"] = {
        "why": "an id typed on macOS must hash as one typed on Linux",
        "nfc": content_hash({"id": "café"}),
        "nfd": content_hash({"id": "café"}),
    }

    # 6. Authorization participates; two views over one graph that showed
    #    different subsets are different views.
    denied = ContextPreviewPlan(
        "plan-5",
        [PlannedItem(handle(1), Necessity.OPTIONAL, "full",
                     authorization=AuthorizationOutcome.DENIED_TENANT),
         base_items[1]],
        budget_tokens=1000)
    out["authorization_participates"] = {
        "why": "a redaction changes what the model was permitted to see",
        "view_hash": ContextView("v-e", denied, base_pins).view_hash,
    }

    # 7. Omission disclosure participates.
    out["omission_disclosure"] = {
        "why": "a view showing a subset without saying so claims completeness",
        "view_hash": ContextView(
            "v-f",
            ContextPreviewPlan("plan-6", base_items, budget_tokens=1000,
                               omitted_count=7),
            base_pins).view_hash,
    }

    # 8. A moved version pin is a different working set.
    out["stale_version_pin"] = {
        "why": "resolving a pin must return that version or report divergence",
        "view_hash": ContextView(
            "v-g", base_plan,
            {**base_pins, "evidence/e1@1": f"rcv1:{99:064d}"}).view_hash,
    }

    # 9. Volatile fields do not participate.
    out["volatile_fields_excluded"] = {
        "why": "observation time and ids describe the run, not the working set",
        "view_hash": ContextView("v-h", base_plan, base_pins,
                                 materialized_at="2026-07-31T12:00:00Z").view_hash,
    }

    # 10. Everything that has ever differed between languages, in one payload.
    #     The first parity check a Go or TypeScript port runs.
    out["cross_language_torture_case"] = {
        "why": (
            "every known cross-language divergence in one object: composed and "
            "decomposed Unicode, decimal spellings, map insertion order, "
            "duplicate handles, multiple projections, denied and omitted "
            "entries, null against absent, and version pins out of order"
        ),
        "decimals": {
            spelling: decimal_string(spelling)
            for spelling in ("1.0", "1.500", "-0", "-0.0", "1e-3", "+1", "007",
                             "0.001", "-2.50", "1000000")
        },
        "unicode_pairs_agree": (
            content_hash({"k": "café · ñoño · 한국"})
            == content_hash({"k": unicodedata.normalize(
                "NFD", "café · ñoño · 한국")})
        ),
        "null_equals_absent": (
            content_hash({"a": 1, "b": None, "c": {"d": None}})
            == content_hash({"a": 1, "c": {}})
        ),
        "view_hash": ContextView(
            "v-torture",
            ContextPreviewPlan(
                "plan-torture",
                [
                    PlannedItem(handle(1, projections=("full", "summary")),
                                Necessity.REQUIRED, "full"),
                    PlannedItem(handle(1, projections=("summary", "full")),
                                Necessity.REQUIRED, "full"),   # exact duplicate
                    PlannedItem(handle(1), Necessity.OPTIONAL, "diagnostics"),
                    PlannedItem(handle(2, visibility=Visibility.PRIVATE,
                                       tenant="acme"),
                                Necessity.OPTIONAL, "summary",
                                authorization=AuthorizationOutcome.DENIED_TENANT),
                    PlannedItem(handle(3), Necessity.EXCLUDED, "summary",
                                authorization=AuthorizationOutcome.DENIED_STALE),
                ],
                budget_tokens=5000,
                omitted_count=3,
            ),
            {
                "evidence/e3@1": f"rcv1:{3:064d}",
                "evidence/e1@1": f"rcv1:{1:064d}",
                "evidence/e2@1": f"rcv1:{2:064d}",
            },
        ).view_hash,
    }
    return out


if __name__ == "__main__":
    payload = {"contract_version": "0.1", "cases": cases()}
    (HERE / "context_view.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    print(json.dumps(payload["cases"], indent=2)[:400])
