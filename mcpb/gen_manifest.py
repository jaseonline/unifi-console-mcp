"""Generate mcpb/manifest.json from the live server, so the tool list can never drift from the code.

    uv run mcpb/gen_manifest.py

Everything except `tools` is the hand-written template below; `tools` is read from the server itself.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = Path(__file__).resolve().parent / "manifest.json"

# Environment variable per user_config key. These are UNIFI_BUNDLE_* so that a blank form field can fall through to
# the user's own system variable (UNIFI_MCP_API_KEY and so on); config.py resolves form value > system variable > default.
# Fields with a system-variable fallback therefore have no default here: a default would always beat the system value.
ENV = {
    key: "UNIFI_BUNDLE_" + key.upper()
    for key in (
        "console_host",
        "api_key",
        "site_manager_api_key",
        "username",
        "password",
        "site",
        "port",
        "verify_ssl",
        "cert_sha256",
        "enable_writes",
        "write_entities",
        "download_dir",
        "journal_dir",
        "log_level",
    )
}
ENV["console_host"] = "UNIFI_BUNDLE_HOST"

USER_CONFIG = {
    "console_host": {
        "type": "string",
        "title": "Console address",
        "required": False,
        "description": "IP address or hostname of your UniFi console, for example 192.168.1.1. Leave blank to use the UNIFI_LOCAL_HOST system environment variable.",
    },
    "api_key": {
        "type": "string",
        "title": "Integration API key",
        "sensitive": True,
        "required": False,
        "description": "UniFi Network Integration API key (Network > Settings > Control Plane > Integrations). Used for the documented Integration API. Blank uses the UNIFI_MCP_API_KEY system variable.",
    },
    "site_manager_api_key": {
        "type": "string",
        "title": "Site Manager API key",
        "sensitive": True,
        "required": False,
        "description": "Cloud key from unifi.ui.com > API (not the Integration API key). Used read-only for every console on the UI account: hosts, sites, devices, ISP metrics and SD-WAN. Blank uses the UNIFI_SITE_MANAGER_API_KEY system variable; with neither, Site Manager operations are refused.",
    },
    "username": {
        "type": "string",
        "title": "Local admin username",
        "required": False,
        "description": "Blank uses UNIFI_MCP_USERNAME. Local (not cloud) admin account. Needed with the password for the controller and UniFi OS endpoints that an API key cannot reach: system log, firewall hit counts, PoE, backups and all configuration writes.",
    },
    "password": {
        "type": "string",
        "title": "Local admin password",
        "sensitive": True,
        "required": False,
        "description": "Blank uses UNIFI_MCP_PASSWORD. Stored by the host in the operating system's secure storage when entered here.",
    },
    "site": {
        "type": "string",
        "title": "Site",
        "required": False,
        "description": "UniFi site name. Blank uses UNIFI_DEFAULT_SITE, then 'default'.",
    },
    "port": {
        "type": "number",
        "title": "HTTPS port",
        "min": 1,
        "max": 65535,
        "required": False,
        "description": "HTTPS port of the console. Blank uses UNIFI_LOCAL_PORT, then 443.",
    },
    "verify_ssl": {
        "type": "string",
        "title": "Verify the console's TLS certificate",
        "required": False,
        "description": "true or false; blank uses UNIFI_LOCAL_VERIFY_SSL, then true. Consoles ship with a self-signed certificate. Leave on if you installed a trusted certificate or set a fingerprint below; turn off only on a network you trust.",
    },
    "cert_sha256": {
        "type": "string",
        "title": "Pinned certificate fingerprint (SHA-256)",
        "required": False,
        "description": "Optional. SHA-256 fingerprint of the console's certificate. When set, only that certificate is accepted, which is the safe way to use a self-signed console.",
    },
    "enable_writes": {
        "type": "string",
        "title": "Allow configuration changes",
        "required": False,
        "description": "true or false; blank uses UNIFI_CONSOLE_ENABLE_WRITES, then false (read-only). When on, typed write tools can change configuration, but only for the entities listed below and only after a preview and an explicit confirm.",
    },
    "write_entities": {
        "type": "string",
        "title": "Entities that may be changed",
        "required": False,
        "description": "Comma-separated list, for example 'wifi,network,firewall_policy'. Blank uses UNIFI_CONSOLE_WRITE_ENTITIES. Ignored unless writes are enabled; empty means nothing can be changed.",
    },
    "download_dir": {
        "type": "directory",
        "title": "Download folder",
        "required": False,
        "description": "Where backups and support files are saved. Defaults to ~/.unifi-console-mcp/downloads.",
    },
    "journal_dir": {
        "type": "directory",
        "title": "Change journal folder",
        "required": False,
        "description": "Where the audit journal of every confirmed change is kept. Defaults to ~/.unifi-console-mcp/journal.",
    },
    "log_level": {
        "type": "string",
        "title": "Log level",
        "default": "INFO",
        "required": False,
        "description": "DEBUG, INFO, WARNING, ERROR or CRITICAL. Logs go to the host's MCP log file (stderr), never to the chat.",
    },
}


def first_sentence(text: str) -> str:
    text = " ".join((text or "").split())
    m = re.match(r"(.+?[.!?])(\s|$)", text)
    return (m.group(1) if m else text)[:300]


async def live_tools() -> list[dict[str, str]]:
    os.environ.setdefault("UNIFI_LOCAL_HOST", "console.invalid")
    from mcp.client import Client

    from unifi_console_mcp.config import Settings
    from unifi_console_mcp.server import create_server

    settings = dataclasses.replace(Settings.from_env(), enable_writes=True)
    mcp, _ = create_server(settings)
    async with Client(mcp) as client:
        listed = await client.list_tools()
    return [
        {"name": t.name, "description": first_sentence(t.description or "")}
        for t in sorted(listed.tools, key=lambda t: t.name)
    ]


def build(version: str, tools: list[dict[str, str]]) -> dict:
    env = {ENV[k]: "${user_config.%s}" % k for k in USER_CONFIG}
    return {
        "manifest_version": "0.4",
        "name": "unifi-console-mcp",
        "display_name": "UniFi Console",
        "version": version,
        "description": "Read, audit and (optionally) change your UniFi Network from Claude, with a preview-then-confirm flow for every change.",
        "long_description": (
            "UniFi Console connects Claude to your own UniFi console over your local network. It covers the documented "
            "Integration API plus the controller and UniFi OS APIs: system log, firewall policy hit counts, PoE budget, "
            "switch ports, access review, backups and support files. Read tools are always safe. Configuration changes are "
            "off by default; when you turn them on, every change is previewed first and applied only after you approve it, "
            "with an audit journal and secrets always redacted. Everything runs on your computer and talks only to your console."
        ),
        "author": {"name": "jaseonline", "url": "https://github.com/jaseonline"},
        "repository": {"type": "git", "url": "https://github.com/jaseonline/unifi-console-mcp"},
        "homepage": "https://github.com/jaseonline/unifi-console-mcp",
        "documentation": "https://github.com/jaseonline/unifi-console-mcp#readme",
        "support": "https://github.com/jaseonline/unifi-console-mcp/issues",
        "license": "MIT",
        "keywords": ["unifi", "ubiquiti", "network", "firewall", "home-network", "mcp"],
        "icon": "icons/icon-light.png",
        "icons": [
            {"src": "icons/icon-light.png", "size": "512x512", "theme": "light"},
            {"src": "icons/icon-dark.png", "size": "512x512", "theme": "dark"},
        ],
        "server": {
            "type": "uv",
            "entry_point": "src/unifi_console_mcp/server.py",
            "mcp_config": {
                "command": "uv",
                "args": ["run", "--directory", "${__dirname}", "--no-dev", "unifi-console-mcp"],
                "env": env,
            },
        },
        "tools": tools,
        "tools_generated": False,
        "compatibility": {
            "claude_desktop": ">=1.0.0",
            "platforms": ["darwin", "win32", "linux"],
            "runtimes": {"python": ">=3.12"},
        },
        "user_config": USER_CONFIG,
    }


def read_version() -> str:
    m = re.search(r'__version__\s*=\s*"([^"]+)"', (ROOT / "src/unifi_console_mcp/__init__.py").read_text())
    if not m:
        raise SystemExit("cannot find __version__")
    return m.group(1)


def main() -> None:
    manifest = build(read_version(), asyncio.run(live_tools()))
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {MANIFEST} ({len(manifest['tools'])} tools, version {manifest['version']})")


if __name__ == "__main__":
    main()
