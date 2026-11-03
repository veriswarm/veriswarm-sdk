"""Packaging and generated-config checks: what veriswarm-setup writes must
launch the installed package, and published metadata must not drift."""
from __future__ import annotations

import asyncio
import json
import re
import shlex
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

tomllib = pytest.importorskip("tomllib")  # stdlib on Python 3.11+

from veriswarm_mcp import setup as vs_setup

PKG_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = tomllib.loads((PKG_ROOT / "pyproject.toml").read_text())


def test_mcp_config_launches_the_installed_package():
    server = vs_setup._generate_mcp_config("vs_key")["mcpServers"]["veriswarm"]

    assert server["command"] == sys.executable
    assert server["args"] == ["-m", "veriswarm_mcp"]
    assert "cwd" not in server


def test_generated_mcp_command_starts_the_server_module():
    server = vs_setup._generate_mcp_config("vs_key")["mcpServers"]["veriswarm"]
    # `-m veriswarm_mcp` must resolve to a runnable module for this interpreter.
    result = subprocess.run(
        [server["command"], "-c", "import importlib.util as u; print(u.find_spec('veriswarm_mcp.__main__') is not None)"],
        capture_output=True, text=True, check=True,
    )
    assert result.stdout.strip() == "True"


def test_hook_commands_use_this_interpreter_not_bare_python3():
    hooks = vs_setup._generate_hooks_config(vs_setup._hook_script_path(), "vs_key")["hooks"]
    commands = [
        h["command"]
        for entries in hooks.values()
        for entry in entries
        for h in entry["hooks"]
    ]
    guard_cmds = [c for c in commands if "guard_hook" in c]

    assert guard_cmds
    for cmd in guard_cmds:
        argv = shlex.split(cmd)
        assert argv[0] == sys.executable
        assert Path(argv[1]).is_file()
    for cmd in commands:
        assert not cmd.startswith("python3 ")
        assert Path(shlex.split(cmd)[-1]).is_file()


def test_activity_logger_is_declared_package_data():
    data = PYPROJECT["tool"]["setuptools"]["package-data"]["veriswarm_mcp"]
    assert "hooks/activity_logger.sh" in data


def test_server_json_version_matches_pyproject():
    version = PYPROJECT["project"]["version"]
    server = json.loads((PKG_ROOT / "server.json").read_text())

    assert server["version"] == version
    assert all(p["version"] == version for p in server["packages"])


def test_readme_tool_count_matches_registered_tools():
    from veriswarm_mcp.server import create_server

    server, _ = create_server()
    registered = {t.name for t in asyncio.run(server.list_tools())}
    readme = (PKG_ROOT / "README.md").read_text()

    stated = int(re.search(r"## Tools \((\d+) total\)", readme).group(1))
    # Tool rows only (the env-var table uses UPPER_CASE names).
    listed = {n for n in re.findall(r"^\| `(\w+)` \|", readme, re.M) if not n.isupper()}
    assert stated == len(registered)
    assert listed == registered


@pytest.mark.skipif(
    not (PKG_ROOT / "dist").is_dir(), reason="run `python -m build` first to check wheel contents"
)
def test_built_wheel_ships_hook_scripts():
    wheels = sorted((PKG_ROOT / "dist").glob("veriswarm_mcp-*.whl"))
    assert wheels
    names = zipfile.ZipFile(wheels[-1]).namelist()
    for required in (
        "veriswarm_mcp/hooks/activity_logger.sh",
        "veriswarm_mcp/hooks/guard_hook.py",
        "veriswarm_mcp/hooks/activity_reporter.py",
        "veriswarm_mcp/secret_rules_manifest.json",
        "veriswarm_mcp/__main__.py",
    ):
        assert required in names
