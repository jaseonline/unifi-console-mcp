"""Exercise the real MCP tools (read-only ones) against the live console, in-process.

    uv run python scripts/live_check.py

Prints each tool's result length and the first part of its output, so you can see exactly what a model
would receive. Nothing here writes to the console.
"""
from __future__ import annotations

import asyncio
import json

from mcp.client import Client

from unifi_console_mcp.config import Settings
from unifi_console_mcp.server import create_server

LIMIT = 1_400


async def main() -> None:
    settings = Settings.from_env()
    mcp, api = create_server(settings)
    basic = await api.run("listDevicesBasic")
    switch = next((d for d in basic.data if d.get("type") == "usw"), None)
    mac = switch["mac"] if switch else None

    plan = [
        ("unifi_console_session_status", {}),
        ("unifi_console_system_log", {"params": {"hours": 24, "min_severity": "LOW", "page_size": 5}}),
        ("unifi_console_system_log", {"params": {"critical_only": True, "min_severity": "LOW"}}),
        ("unifi_console_firewall_policy_hits", {"params": {"unused_only": True, "enabled_only": True, "limit": 4}}),
        ("unifi_console_access_review", {}),
        ("unifi_console_backup", {"params": {"action": "list"}}),
        ("unifi_console_call_operation", {"params": {"operation_id": "listKnownClients", "fields": ["mac", "name", "fixed_ip"], "limit": 3}}),
        ("unifi_console_list_operations", {"params": {"search": "stp", "access": "all", "limit": 5}}),
    ]
    if mac:
        plan += [
            ("unifi_console_poe_overview", {"params": {"device_mac": mac}}),
            ("unifi_console_switch_port_detail", {"params": {"device_mac": mac, "ports": [1, 2]}}),
        ]
    async with Client(mcp) as client:
        for name, args in plan:
            res = await client.call_tool(name, args)
            text = res.content[0].text
            print(f"\n=== {name} {json.dumps(args.get('params', {}))[:90]} -> {len(text)} chars"
                  f"{' (isError)' if res.is_error else ''}")
            print(text[:LIMIT] + (" ...[cut for display]" if len(text) > LIMIT else ""))
    await api.client.aclose()


asyncio.run(main())
