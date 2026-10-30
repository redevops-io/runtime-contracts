"""Import boundary: runtime_contracts.qa imports the standard library and its own package, nothing else.

``runtime-contracts`` imports no runtime and no third-party package beyond pyyaml (which qa does not need). In
particular it never imports a harness, Context Runtime, the product, a browser driver or a network client.
"""
from __future__ import annotations

import ast
import pathlib
import sys

import pytest

QA_DIR = pathlib.Path(__file__).resolve().parent.parent / "runtime_contracts" / "qa"
FORBIDDEN = {"agent_harness", "context_runtime", "redevops_qa", "playwright", "selenium", "requests", "httpx",
             "aiohttp", "urllib3", "socket", "subprocess", "sqlite3", "yaml", "docker", "kubernetes", "openai",
             "anthropic", "agentic_os"}
STDLIB = set(sys.stdlib_module_names)


def imports(path: pathlib.Path):
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name.split(".")[0], node.lineno, 0
        elif isinstance(node, ast.ImportFrom):
            yield (node.module or "").split(".")[0], node.lineno, node.level


MODULES = sorted(QA_DIR.glob("*.py"))


@pytest.mark.parametrize("path", MODULES, ids=lambda p: p.name)
def test_only_the_standard_library_and_the_package_are_imported(path):
    for top, line, level in imports(path):
        if level:                       # relative: stays inside runtime_contracts
            continue
        assert top not in FORBIDDEN, f"{path.name}:{line} imports {top}"
        assert top in STDLIB or top == "runtime_contracts", f"{path.name}:{line} imports non-stdlib {top}"


@pytest.mark.parametrize("path", MODULES, ids=lambda p: p.name)
def test_relative_imports_do_not_reach_into_adapters_or_the_cli(path):
    for top, line, level in imports(path):
        if level > 1:
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.level > 1 and node.lineno == line:
                    assert (node.module or "").split(".")[0] not in {"cli", "adapters"}, f"{path.name}:{line}"


def test_the_package_has_no_io_or_clock_or_randomness():
    banned = {"random", "secrets", "time", "datetime", "uuid", "os", "pathlib", "shutil", "tempfile", "socket"}
    # registry/schema_export/inventory are tooling (they write the committed export files) and are the only
    # modules allowed a path; none of them may use a clock, randomness or the network.
    tooling = {"schema_export.py", "inventory.py"}
    for path in MODULES:
        for top, line, level in imports(path):
            if level:
                continue
            if top in {"random", "secrets", "time", "datetime", "uuid", "socket"}:
                raise AssertionError(f"{path.name}:{line} imports {top}")
            if top in banned and path.name not in tooling:
                raise AssertionError(f"{path.name}:{line} imports {top}")


def test_importing_the_package_does_not_import_a_forbidden_module():
    import importlib
    importlib.import_module("runtime_contracts.qa")
    loaded = {m.split(".")[0] for m in sys.modules}
    assert not loaded & {"agent_harness", "context_runtime", "redevops_qa", "playwright"}
