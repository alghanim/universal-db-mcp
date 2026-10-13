"""One release version: pyproject.toml's. The bundle builder reads it, and
scripts/bump_version.py keeps every copy it cannot read in step (the package
templates, server.json, uv.lock and the artifact names in the docs)."""

from __future__ import annotations

import importlib.util
import re
import shutil
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[2]


def _script(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BUMP = _script("bump_version")


def test_every_version_reference_names_the_project_version() -> None:
    assert BUMP.check() == []


def test_the_package_reports_the_project_version() -> None:
    import universal_db_mcp

    assert universal_db_mcp.__version__ == BUMP.project_version()


def test_the_builders_read_the_version_instead_of_carrying_one() -> None:
    builder = _script("prepare_offline_bundle")
    assert builder.project_version() == BUMP.project_version()
    for rel in ("scripts/prepare_offline_bundle.py", "scripts/package/release_usb.sh",
                "scripts/load_images_offline.sh"):
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert not re.search(r"universal-db-mcp[-_:]\d+\.\d+\.\d+|\"release\": \"\d", text), rel


def _copy_tree(dst: Path) -> None:
    rels = [rel for rel, _ in BUMP.FILES] + ["server.json"]
    rels += [str(p.relative_to(ROOT)) for p in BUMP._doc_paths(ROOT)]
    rels += ["SECURITY.md"]  # outside DOC_FILES: its history must survive a bump
    for rel in rels:
        (dst / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / rel, dst / rel)


def test_a_bump_rewrites_every_reference_and_only_those(tmp_path: Path) -> None:
    _copy_tree(tmp_path)
    deployment = (tmp_path / "docs/offline-deployment.md").read_text(encoding="utf-8")
    history = [line for line in deployment.splitlines() if "(`0.1.0`)" in line]  # MSIs before release_seq

    BUMP.bump("9.8.7", root=tmp_path)

    assert BUMP.check(root=tmp_path) == []
    for rel, pattern in BUMP.FILES:
        assert [m.group("v") for m in re.finditer(pattern, (tmp_path / rel).read_text(encoding="utf-8"))] == ["9.8.7"]
    assert '"identifier": "ghcr.io/alghanim/universal-db-mcp:9.8.7"' in (tmp_path / "server.json").read_text(
        encoding="utf-8")
    assert "docker pull ghcr.io/alghanim/universal-db-mcp:9.8.7" in (tmp_path / "README.md").read_text(
        encoding="utf-8")
    # history names the old release in other words and keeps it
    after = (tmp_path / "docs/offline-deployment.md").read_text(encoding="utf-8")
    assert history and all(line in after.splitlines() for line in history)
    assert "Releases from v0.1.0 on" in (tmp_path / "SECURITY.md").read_text(encoding="utf-8")


def test_a_stale_artifact_name_in_the_docs_is_reported(tmp_path: Path) -> None:
    _copy_tree(tmp_path)
    readme = tmp_path / "README.md"
    readme.write_text(readme.read_text(encoding="utf-8") + "\ndocker pull ghcr.io/x/universal-db-mcp:0.0.9\n",
                      encoding="utf-8")
    problems = BUMP.check(root=tmp_path)
    assert len(problems) == 1 and problems[0].startswith("README.md:") and "0.0.9" in problems[0]


def test_a_bump_refuses_a_version_that_is_not_major_minor_patch(tmp_path: Path) -> None:
    _copy_tree(tmp_path)
    for bad in ("1.2", "v1.2.3", "1.2.3rc1", "1.2.3\n"):
        try:
            BUMP.bump(bad, root=tmp_path)
        except SystemExit:
            continue
        raise AssertionError(f"accepted {bad!r}")
    assert BUMP.check(root=tmp_path) == []
