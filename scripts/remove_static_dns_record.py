"""Remove one named static DNS record through the write tool (preview, confirm, journal, read-back).

    uv run scripts/remove_static_dns_record.py <_id> <key>           # dry run: shows the preview, deletes nothing
    uv run scripts/remove_static_dns_record.py <_id> <key> --run     # deletes it

Refuses unless the record with that _id still has exactly that key. Writes are enabled for this process only.
"""
from __future__ import annotations

import asyncio
import dataclasses
import json
import sys
from typing import Any

from mcp.client import Client

from unifi_console_mcp.config import Settings
from unifi_console_mcp.entities.static_dns import SPEC
from unifi_console_mcp.server import create_server
from unifi_console_mcp.writes import WriteEngine

TOOL = "unifi_console_static_dns"


async def tool(client: Client, args: dict[str, Any]) -> dict[str, Any]:
    res = await client.call_tool(TOOL, {"params": args})
    return json.loads(res.content[0].text)


async def main(ident: str, key: str, run: bool, transport: Any = None) -> int:
    settings = dataclasses.replace(Settings.from_env(), enable_writes=True, write_entities=frozenset({"static_dns"}))
    mcp, api = create_server(settings, transport=transport)
    try:
        async with Client(mcp) as client:
            rows = await WriteEngine(api)._rows(SPEC)
            row = next((r for r in rows if r.get("_id") == ident), None)
            if row is None or row.get("key") != key:
                print(f"STOP: no record {ident} with key '{key}' (found: {row and row.get('key')!r}). Nothing was changed.")
                return 1
            pre = await tool(client, {"action": "delete", "target": ident})
            if not pre.get("ok") or pre["errors"] or pre["apply_blocked_reason"]:
                print("STOP: preview not applicable:", pre.get("error") or pre["errors"] or pre["apply_blocked_reason"])
                return 1
            print("Record:", json.dumps({k: row.get(k) for k in ("key", "record_type", "value", "enabled")}))
            print("Warnings:", pre["warnings"] or "none")
            if not run:
                print("Dry run only. Add --run to delete it.")
                return 0
            out = await tool(client, {"action": "delete", "target": ident, "confirm": True, "fingerprint": pre["fingerprint"]})
            print("Result:", json.dumps({k: out.get(k) for k in ("ok", "applied", "verified", "journal_id", "error")}))
            print("Rollback:", json.dumps(out.get("rollback")))
            return 0 if out.get("ok") and out.get("verified") else 1
    finally:
        await api.client.aclose()


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) != 2:
        sys.exit("usage: remove_static_dns_record.py <_id> <key> [--run]")
    sys.exit(asyncio.run(main(args[0], args[1], "--run" in sys.argv)))
