"""A published tag is immutable, and the version must agree before it is cut.

Both halves were violated in one release. `v0.2.3` shipped with `pyproject`
saying 0.2.3 and `runtime_contracts.__version__` still saying 0.2.2; the fix
was to force-move the published tag, which is the thing tags exist not to do.
`v0.2.4` was then cut at a commit still declaring 0.2.3 — the same defect one
layer out.

Neither was caught by anything. The version disagreement was found by a
*downstream consumer* pinning the tag and checking what it got, which is the
latest possible moment and the wrong repository.

This runs before tagging: the two version strings must agree, and every tag
that exists must point at a commit declaring the version it names. A tag that
moves later will fail the second check the next time this runs, which does not
prevent the move but does stop it staying invisible.
"""
from __future__ import annotations

import pathlib
import subprocess
import tomllib

import pytest

import runtime_contracts

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _declared() -> str:
    return tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]


def test_the_two_version_strings_agree():
    """Checked before a tag is cut, not by whoever pins it afterwards."""
    assert runtime_contracts.__version__ == _declared(), (
        f"pyproject says {_declared()} and the module says "
        f"{runtime_contracts.__version__}. A package whose two version strings "
        "differ can satisfy a pin while running something else.")


def _tags():
    done = subprocess.run(["git", "tag", "--list", "v*"], cwd=ROOT,
                          capture_output=True, text=True)
    return [t for t in done.stdout.split() if t]


def _version_at(tag: str):
    done = subprocess.run(["git", "show", f"{tag}:pyproject.toml"], cwd=ROOT,
                          capture_output=True, text=True)
    if done.returncode != 0:
        return None
    try:
        return tomllib.loads(done.stdout)["project"]["version"]
    except Exception:                                          # noqa: BLE001
        return None


def test_every_tag_names_the_version_its_commit_declares():
    """A tag pointing at a different version is a moved or mis-cut tag.

    Skipped rather than failed where the history is unavailable — a shallow
    clone is not evidence of a bad tag, and failing on it would train people to
    ignore this.
    """
    tags = _tags()
    if not tags:
        pytest.skip("no tags visible in this checkout")

    wrong = []
    for tag in tags:
        declared = _version_at(tag)
        if declared is None:
            continue
        expected = tag.lstrip("v").split("-")[0]
        if declared != expected:
            wrong.append(f"{tag} -> pyproject {declared}")

    assert not wrong, (
        "these tags name a version their commit does not declare:\n  "
        + "\n  ".join(wrong)
        + "\n\nA tag is immutable once pushed. Cut a new one rather than "
          "moving this, and bump the version in the commit the tag will name.")
