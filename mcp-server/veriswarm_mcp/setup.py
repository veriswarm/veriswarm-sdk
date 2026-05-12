#!/usr/bin/env python3
"""VeriSwarm setup CLI — configure MCP server, Guard Proxy, and hooks.

Usage:
  veriswarm-setup                    # Interactive setup
  veriswarm-setup --platform claude  # Configure for Claude Code
  veriswarm-setup --platform gemini  # Configure for Gemini CLI
  veriswarm-setup --platform codex   # Configure for OpenAI Codex CLI
  veriswarm-setup --api-key KEY      # Set API key non-interactively
  veriswarm-setup --uninstall        # Remove hooks and MCP config

Installs:
  1. VeriSwarm MCP Server (67 tools for trust scoring, Guard, Passport, Vault)
  2. Guard Proxy config (wraps other MCP servers for transparent PII interception)
  3. Guard hooks (PII protection for prompts and tool calls)
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path


# ── Platform Config Paths ────────────────────────────────────────────────

PLATFORMS = {
    "claude": {
        "name": "Claude Code",
        "settings_path": Path.home() / ".claude" / "settings.json",
        "project_settings": ".claude/settings.json",
        "hook_format": "claude",
    },
    "gemini": {
        "name": "Gemini CLI",
        "settings_path": Path.home() / ".gemini" / "settings.json",
        "project_settings": ".gemini/settings.json",
        "hook_format": "gemini",
    },
    "codex": {
        "name": "Codex CLI",
        "settings_path": Path.home() / ".codex" / "settings.json",
        "project_settings": ".codex/settings.json",
        "hook_format": "codex",
    },
}


def _find_package_dir() -> Path:
    """Find the installed veriswarm-mcp package directory."""
    return Path(__file__).parent.parent.resolve()


def _hook_script_path() -> str:
    """Get the absolute path to the guard hook script."""
    return str(Path(__file__).parent / "hooks" / "guard_hook.py")


def _activity_logger_path() -> str:
    """Get the absolute path to the fast activity logger shell script."""
    return str(Path(__file__).parent / "hooks" / "activity_logger.sh")


def _guard_proxy_dir() -> str:
    """Get the path to the guard-proxy package (sibling of mcp-server)."""
    pkg_dir = _find_package_dir()
    guard_proxy = pkg_dir.parent / "guard-proxy"
    if guard_proxy.exists():
        return str(guard_proxy)
    return ""


# ── Hook Configuration Generators ────────────────────────────────────────

def _write_env_file(api_key: str, api_url: str = "", agent_id: str = "") -> Path:
    """Write credentials to ~/.veriswarm/env (not in command line args)."""
    env_dir = Path.home() / ".veriswarm"
    env_dir.mkdir(parents=True, exist_ok=True)
    env_file = env_dir / "env"

    lines = [
        "# VeriSwarm Guard credentials",
        f"VERISWARM_API_KEY={api_key}",
    ]
    if api_url:
        lines.append(f"VERISWARM_API_URL={api_url}")
    if agent_id:
        lines.append(f"GUARD_AGENT_ID={agent_id}")

    env_file.write_text("\n".join(lines) + "\n")
    env_file.chmod(0o600)  # Owner read/write only
    return env_file


def _generate_hooks_config(hook_script: str, api_key: str, agent_id: str = "") -> dict:
    """Generate hooks configuration for Claude Code / compatible platforms.

    Two-path architecture:
    - Fast path: bash activity_logger.sh (~25ms) logs ALL tool calls
    - Slow path: python3 guard_hook.py (~200ms) scans MCP tools for PII

    PreToolUse and PostToolUse each get two hook entries. SessionStart gets one.
    UserPromptSubmit is not hooked (too many false positives on code).
    """
    logger_script = _activity_logger_path()
    pii_command = f"python3 {hook_script}"
    log_command = f"bash {logger_script}"

    return {
        "hooks": {
            "SessionStart": [
                {
                    "matcher": "",
                    "hooks": [
                        {
                            "type": "command",
                            "command": pii_command,
                            "timeout": 10,
                        }
                    ]
                }
            ],
            "PreToolUse": [
                {
                    "matcher": "",
                    "hooks": [
                        {
                            "type": "command",
                            "command": log_command,
                            "timeout": 5,
                        }
                    ]
                },
                {
                    "matcher": "^mcp__",
                    "hooks": [
                        {
                            "type": "command",
                            "command": pii_command,
                            "timeout": 10,
                        }
                    ]
                }
            ],
            "PostToolUse": [
                {
                    "matcher": "",
                    "hooks": [
                        {
                            "type": "command",
                            "command": log_command,
                            "timeout": 5,
                        }
                    ]
                },
                {
                    "matcher": "^mcp__",
                    "hooks": [
                        {
                            "type": "command",
                            "command": pii_command,
                            "timeout": 10,
                        }
                    ]
                }
            ],
        }
    }


def _generate_mcp_config(api_key: str, agent_key: str = "", api_url: str = "") -> dict:
    """Generate MCP server configuration."""
    pkg_dir = _find_package_dir()
    env = {}
    if api_url:
        env["VERISWARM_API_URL"] = api_url
    else:
        env["VERISWARM_API_URL"] = "https://api.veriswarm.ai"
    if api_key:
        env["VERISWARM_API_KEY"] = api_key
    if agent_key:
        env["VERISWARM_AGENT_KEY"] = agent_key

    return {
        "mcpServers": {
            "veriswarm": {
                "command": "python3",
                "args": ["-m", "src"],
                "cwd": str(pkg_dir),
                "env": env,
            }
        }
    }


# ── Settings File Management ─────────────────────────────────────────────

def _read_settings(path: Path) -> dict:
    """Read a JSON settings file, returning empty dict if missing."""
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {}


def _write_settings(path: Path, settings: dict) -> None:
    """Write settings to a JSON file, creating parent dirs if needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(settings, f, indent=2)
        f.write("\n")


def _merge_settings(existing: dict, new: dict) -> dict:
    """Deep merge new settings into existing, preserving existing values."""
    merged = existing.copy()
    for key, value in new.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _merge_settings(merged[key], value)
        else:
            merged[key] = value
    return merged


# ── Setup Commands ───────────────────────────────────────────────────────

def setup(platform: str, api_key: str, agent_key: str = "", api_url: str = "",
          agent_id: str = "", global_install: bool = True) -> None:
    """Run the full setup for a platform."""
    plat = PLATFORMS.get(platform)
    if not plat:
        print(f"Unknown platform: {platform}. Supported: {', '.join(PLATFORMS)}")
        sys.exit(1)

    hook_script = _hook_script_path()
    print(f"\n  VeriSwarm Guard Setup for {plat['name']}")
    print(f"  {'=' * 45}\n")

    # 0. Write credentials file
    env_file = _write_env_file(api_key, api_url, agent_id)
    print(f"  [0/3] Credentials saved to {env_file} (chmod 600)")

    # 1. MCP Server
    print("  [1/3] Configuring MCP Server...")
    mcp_config = _generate_mcp_config(api_key, agent_key, api_url)
    settings_path = plat["settings_path"]
    existing = _read_settings(settings_path)
    merged = _merge_settings(existing, mcp_config)
    _write_settings(settings_path, merged)
    print(f"         MCP server added to {settings_path}")

    # 2. Hooks
    print("  [2/3] Installing Guard hooks...")
    hooks_config = _generate_hooks_config(hook_script, api_key, agent_id)
    merged = _merge_settings(merged, hooks_config)
    _write_settings(settings_path, merged)
    print(f"         5 hooks installed (SessionStart, PreToolUse x2, PostToolUse x2)")

    # 3. Guard Proxy info
    guard_dir = _guard_proxy_dir()
    if guard_dir:
        print("  [3/3] Guard Proxy available")
        print(f"         To wrap an MCP server with Guard, add to your config:")
        print(f'         "command": "python3", "args": ["-m", "src"],')
        print(f'         "cwd": "{guard_dir}",')
        print(f'         "env": {{"GUARD_TARGET_COMMAND": "<real-server-cmd>", ...}}')
    else:
        print("  [3/3] Guard Proxy not found (optional — install guard-proxy package)")

    print(f"\n  Setup complete! Restart {plat['name']} to activate.\n")
    print("  Protection enabled:")
    print("    - All tool calls logged locally (activity_logger.sh, ~25ms)")
    print("    - MCP tool arguments scanned for PII and auto-tokenized")
    print("    - MCP tool responses scanned for PII (context warning injected)")
    print("    - Built-in tools (Read, Write, Edit, Bash, Grep) are logged but NOT scanned")
    print("    - User prompts are NOT scanned (avoids false positives on code)")
    print("    - Use rehydrate_pii tool to restore real values when needed")
    print()


def uninstall(platform: str) -> None:
    """Remove VeriSwarm hooks and MCP config."""
    plat = PLATFORMS.get(platform)
    if not plat:
        print(f"Unknown platform: {platform}")
        sys.exit(1)

    settings_path = plat["settings_path"]
    if not settings_path.exists():
        print(f"No settings found at {settings_path}")
        return

    existing = _read_settings(settings_path)
    changed = False

    if "hooks" in existing:
        for event in ["SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse"]:
            if event in existing["hooks"]:
                hooks = existing["hooks"][event]
                existing["hooks"][event] = [
                    h for h in hooks
                    if not any(
                        "guard_hook" in sub.get("command", "") or
                        "activity_logger" in sub.get("command", "")
                        for sub in h.get("hooks", [])
                    )
                ]
                if not existing["hooks"][event]:
                    del existing["hooks"][event]
                changed = True
        if not existing["hooks"]:
            del existing["hooks"]

    if "mcpServers" in existing and "veriswarm" in existing["mcpServers"]:
        del existing["mcpServers"]["veriswarm"]
        if not existing["mcpServers"]:
            del existing["mcpServers"]
        changed = True

    if changed:
        _write_settings(settings_path, existing)
        print(f"VeriSwarm removed from {settings_path}")
    else:
        print("No VeriSwarm config found to remove")


# ── CLI Entry Point ──────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="VeriSwarm Guard — install MCP server, Guard Proxy, and PII hooks"
    )
    parser.add_argument(
        "--platform", "-p",
        choices=list(PLATFORMS.keys()),
        help="Target platform (claude, gemini, codex)",
    )
    parser.add_argument("--api-key", "-k", help="VeriSwarm API key")
    parser.add_argument("--agent-key", help="VeriSwarm agent key (optional)")
    parser.add_argument("--api-url", help="VeriSwarm API URL (default: https://api.veriswarm.ai)")
    parser.add_argument("--agent-id", help="Agent ID for audit trail")
    parser.add_argument("--uninstall", action="store_true", help="Remove VeriSwarm config")

    args = parser.parse_args()

    # Interactive platform selection if not specified
    if not args.platform:
        print("\n  VeriSwarm Guard Setup")
        print("  " + "=" * 25 + "\n")
        print("  Select your platform:")
        for i, (key, plat) in enumerate(PLATFORMS.items(), 1):
            print(f"    {i}. {plat['name']}")
        print()
        try:
            choice = input("  Choice (1-3): ").strip()
            platform_keys = list(PLATFORMS.keys())
            idx = int(choice) - 1
            if 0 <= idx < len(platform_keys):
                args.platform = platform_keys[idx]
            else:
                print("Invalid choice")
                sys.exit(1)
        except (ValueError, EOFError, KeyboardInterrupt):
            print("\nSetup cancelled")
            sys.exit(1)

    if args.uninstall:
        uninstall(args.platform)
        return

    # Interactive API key if not specified
    if not args.api_key:
        try:
            args.api_key = input("\n  VeriSwarm API key: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nSetup cancelled")
            sys.exit(1)

    if not args.api_key:
        print("API key is required. Get one at https://veriswarm.ai/account")
        sys.exit(1)

    setup(
        platform=args.platform,
        api_key=args.api_key,
        agent_key=args.agent_key or "",
        api_url=args.api_url or "",
        agent_id=args.agent_id or "",
    )


if __name__ == "__main__":
    main()
