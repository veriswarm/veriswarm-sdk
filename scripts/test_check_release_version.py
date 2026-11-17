"""Tests for check_release_version.py. Run: python -m pytest scripts/test_check_release_version.py"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent / "check_release_version.py"


PACKAGES = {
    "node": ("node-v", "node/package.json"),
    "python": ("python-v", "python/pyproject.toml"),
    "mcp": ("mcp-v", "mcp-server/pyproject.toml"),
    "openclaw": ("openclaw-v", "openclaw-plugin/package.json"),
    "schemas": ("schemas-v", "schemas/package.json"),
}


def make_repo(
    tmp_path,
    *,
    node="1.2.3",
    python="1.2.3",
    mcp="1.2.3",
    openclaw="1.2.3",
    schemas="1.2.3",
    mcp_server_json="1.2.3",
    mcp_pkg_json="1.2.3",
):
    (tmp_path / "node").mkdir()
    (tmp_path / "node/package.json").write_text(json.dumps({"version": node}))
    (tmp_path / "python").mkdir()
    (tmp_path / "python/pyproject.toml").write_text(f'[project]\nname = "x"\nversion = "{python}"\n')
    (tmp_path / "mcp-server").mkdir()
    (tmp_path / "mcp-server/pyproject.toml").write_text(f'[project]\nname = "x"\nversion = "{mcp}"\n')
    (tmp_path / "mcp-server/server.json").write_text(
        json.dumps({"version": mcp_server_json, "packages": [{"version": mcp_pkg_json}]})
    )
    (tmp_path / "openclaw-plugin").mkdir()
    (tmp_path / "openclaw-plugin/package.json").write_text(json.dumps({"version": openclaw}))
    (tmp_path / "schemas").mkdir()
    (tmp_path / "schemas/package.json").write_text(json.dumps({"version": schemas}))
    return tmp_path


def run(root, package, ref):
    return subprocess.run(
        [sys.executable, str(SCRIPT), package, ref, "--root", str(root)],
        capture_output=True, text=True,
    )


@pytest.mark.parametrize("package", sorted(PACKAGES))
def test_matching_tag_passes_and_prints_version(tmp_path, package):
    prefix, _ = PACKAGES[package]
    r = run(make_repo(tmp_path), package, f"refs/tags/{prefix}1.2.3")
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "1.2.3"


def test_branch_ref_rejected(tmp_path):
    r = run(make_repo(tmp_path), "node", "refs/heads/main")
    assert r.returncode != 0
    assert "tag" in r.stderr


@pytest.mark.parametrize("package", sorted(PACKAGES))
def test_tag_version_mismatch_rejected(tmp_path, package):
    prefix, manifest = PACKAGES[package]
    r = run(make_repo(tmp_path), package, f"refs/tags/{prefix}1.2.4")
    assert r.returncode != 0
    assert "1.2.4" in r.stderr
    assert manifest in r.stderr


def test_wrong_prefix_rejected(tmp_path):
    r = run(make_repo(tmp_path), "node", "refs/tags/python-v1.2.3")
    assert r.returncode != 0


def test_mcp_matching_passes(tmp_path):
    assert run(make_repo(tmp_path), "mcp", "refs/tags/mcp-v1.2.3").returncode == 0


@pytest.mark.parametrize("kw", [{"mcp_server_json": "9.9.9"}, {"mcp_pkg_json": "9.9.9"}])
def test_mcp_server_json_drift_rejected(tmp_path, kw):
    r = run(make_repo(tmp_path, **kw), "mcp", "refs/tags/mcp-v1.2.3")
    assert r.returncode != 0
    assert "9.9.9" in r.stderr


def test_unknown_package_rejected(tmp_path):
    assert run(make_repo(tmp_path), "bogus", "refs/tags/bogus-v1.2.3").returncode != 0
