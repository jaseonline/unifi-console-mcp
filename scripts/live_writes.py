"""Live test of the gated safe-write and download flows against the real console.

    uv run python scripts/live_writes.py

Needs: UNIFI_CONSOLE_ENABLE_WRITES=true and the MCP account's Control Plane permission set to Admin.
It creates ONE console backup and ONE support file and saves them to the download folder
(owner-only permissions). File contents are never printed; only names, sizes and hashes.
It changes no configuration.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from mcp.client import Client

from unifi_console_mcp.config import Settings
from unifi_console_mcp.server import create_server

LIMIT = 1_200


async def main() -> None:
    settings = Settings.from_env()
    print(f"enable_writes={settings.enable_writes} download_dir={settings.download_dir}")
    mcp, api = create_server(settings)

    plan = [
        ("gate: backup create without confirm (expect refusal)", "unifi_console_backup", {"params": {"action": "create"}}),
        ("gate: download without confirm (expect refusal)", "unifi_console_backup", {"params": {"action": "download"}}),
        ("session before", "unifi_console_session_status", {}),
        ("backups before", "unifi_console_backup", {"params": {"action": "list"}}),
        ("CREATE backup", "unifi_console_backup", {"params": {"action": "create", "confirm": True}}),
        ("backups after", "unifi_console_backup", {"params": {"action": "list"}}),
        ("DOWNLOAD backup", "unifi_console_backup", {"params": {"action": "download", "confirm": True}}),
        ("SUPPORT FILE (console)", "unifi_console_support_file", {"params": {"scope": "console", "confirm": True, "wait_seconds": 180}}),
        ("access review", "unifi_console_access_review", {}),
        ("firmware updates (was 403 under View)", "unifi_console_call_operation", {"params": {"operation_id": "getFirmwareUpdates", "limit": 3}}),
        ("syslog settings (was 403 under View)", "unifi_console_call_operation", {"params": {"operation_id": "getSyslogSettings"}}),
        ("session after", "unifi_console_session_status", {}),
    ]
    async with Client(mcp) as client:
        skip = [s for s in os.environ.get("LIVE_SKIP", "").split(",") if s]
        for label, name, args in plan:
            if any(s in label for s in skip):
                print(f"\n=== {label} -> skipped (LIVE_SKIP)")
                continue
            res = await client.call_tool(name, args)
            text = res.content[0].text
            print(f"\n=== {label} -> {len(text)} chars{' (isError)' if res.is_error else ''}")
            print(text[:LIMIT] + (" ...[cut]" if len(text) > LIMIT else ""))

    d = Path(settings.download_dir)
    print("\nDownload folder:")
    for p in sorted(d.glob("*")):
        st = p.stat()
        print(f"  {p.name}  {st.st_size} bytes  mode={oct(st.st_mode & 0o777)}")
    print("client stats:", json.dumps(api.client.stats))
    await api.client.aclose()


asyncio.run(main())
