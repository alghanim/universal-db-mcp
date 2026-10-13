"""The PyPI distribution: `udbmcp` (`universal-db-mcp` on PyPI is another
project), with an `all` extra of the drivers that install from wheels alone."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from packaging.requirements import Requirement

ROOT = Path(__file__).resolve().parents[2]
PROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]


def test_the_distribution_is_udbmcp_and_installs_the_udbmcp_command() -> None:
    assert PROJECT["name"] == "udbmcp"
    assert PROJECT["scripts"] == {"udbmcp": "universal_db_mcp.__main__:main"}


def test_all_is_the_drivers_that_need_no_native_client_library() -> None:
    (req,) = [Requirement(r) for r in PROJECT["optional-dependencies"]["all"]]
    assert req.name == "udbmcp"
    # pyodbc (mssql) needs unixODBC and Microsoft's driver; ibm-db (db2) its clidriver
    assert req.extras == {"pg", "mysql", "clickhouse", "oracle"}
    assert set(PROJECT["optional-dependencies"]) >= req.extras | {"mssql", "db2"}


def test_the_classifiers_claim_only_what_is_tested() -> None:
    classifiers = PROJECT["classifiers"]
    assert not [c for c in classifiers if "Windows" in c]  # the MSI has never run on Windows
    assert [c for c in classifiers if re.fullmatch(r"Programming Language :: Python :: 3\.\d+", c)] == [
        "Programming Language :: Python :: 3.12"
    ]
    assert PROJECT["requires-python"] == ">=3.12"


def test_the_pypi_readme_names_the_mcp_registry_entry() -> None:
    """The MCP Registry accepts a PyPI package only when its README carries
    the entry's name in this form."""
    assert PROJECT["readme"] == "README.md"
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert readme.count("<!-- mcp-name: io.github.alghanim/universal-db-mcp -->") == 1

