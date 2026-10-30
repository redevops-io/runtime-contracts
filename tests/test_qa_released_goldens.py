"""Released golden hashes are never rewritten (docs/RELEASE_DISCIPLINE.md, rule 1).

Two checks against the tags that exist in the checkout:

* every golden file that existed at ``v0.3.14`` is byte-identical now (qa/v1 added files; it changed none);
* once a tag carries ``golden/qa.json``, every case in it keeps its hash. New cases may be added; an existing case
  may not change.

Skipped, not failed, where the history is unavailable: a shallow clone is not evidence of a rewrite.
"""
from __future__ import annotations

import json
import pathlib
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
BASELINE_TAG = "v0.3.14"
RELEASED = ("context_view.json", "geospatial.json", "investigation_lifecycle.json", "security.json")


def _git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True)


def _show(tag: str, path: str):
    done = _git("show", f"{tag}:{path}")
    return done.stdout if done.returncode == 0 else None


def _tags():
    done = _git("tag", "--list", "v*")
    return [t for t in done.stdout.decode().split() if t] if done.returncode == 0 else []


def test_goldens_released_at_the_baseline_tag_are_byte_identical():
    if BASELINE_TAG not in _tags():
        pytest.skip(f"{BASELINE_TAG} is not visible in this checkout")
    changed = [n for n in RELEASED if _show(BASELINE_TAG, f"golden/{n}") != (ROOT / "golden" / n).read_bytes()]
    assert not changed, f"released golden files changed since {BASELINE_TAG}: {changed}"


def test_the_tests_golden_vectors_released_at_the_baseline_are_byte_identical():
    if BASELINE_TAG not in _tags():
        pytest.skip(f"{BASELINE_TAG} is not visible in this checkout")
    names = ("golden_evidence_native.json", "golden_seal_vectors.json", "credential_tenant_vectors.json")
    changed = [n for n in names if _show(BASELINE_TAG, f"tests/{n}") not in (None, (ROOT / "tests" / n).read_bytes())]
    assert not changed, f"released vectors changed since {BASELINE_TAG}: {changed}"


def test_a_released_qa_case_never_changes_its_hash():
    current = json.loads((ROOT / "golden" / "qa.json").read_text())
    released = [t for t in _tags() if _show(t, "golden/qa.json") is not None]
    if not released:
        pytest.skip("no tag carries golden/qa.json yet; this guards the first release onward")
    for tag in released:
        old = json.loads(_show(tag, "golden/qa.json"))
        for group in ("cases", "values", "assertion_sets"):
            for name, case in old.get(group, {}).items():
                assert name in current[group], f"{group}.{name} released in {tag} was removed"
                assert current[group][name]["hash"] == case["hash"], (
                    f"{group}.{name} released in {tag} now hashes differently. A released hash is a promise: "
                    "add a new case or bump the schema version, never edit this one.")
