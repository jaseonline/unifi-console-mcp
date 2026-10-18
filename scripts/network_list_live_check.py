"""Prove the network list tool on the real console using one throwaway port list.

    uv run scripts/network_list_live_check.py            # dry run: prints the plan, touches nothing
    uv run scripts/network_list_live_check.py --run      # performs it

SAFETY
  * Goes through the real tool (preview, then confirm with the fingerprint, journal, read-back), in-process. Writes are
    enabled for THIS process only; the Claude Desktop server configuration is not changed.
  * Creates exactly one list named "zz-listcheck" (ports 58690-58699 and 58700). Nothing references it, so it is inert.
  * Existing lists are never edited or deleted. Before and after, the script compares all the other lists.
  * The delete preview reads the live firewall policies and traffic objects to see what uses the list, which proves the
    reference check against the real console. The list is deleted in a finally block, also when a step fails;
    leftovers named zz-listcheck* are removed first.
  * Journal lines go to the normal journal folder. Prints field names and short values only.
"""
from __future__ import annotations

import asyncio
import dataclasses
import json
import sys
from typing import Any

from mcp.client import Client

from unifi_console_mcp.config import Settings
from unifi_console_mcp.entities.network_list import SPEC
from unifi_console_mcp.server import create_server
from unifi_console_mcp.writes import WriteEngine

PREFIX = "zz-listcheck"
TOOL = "unifi_console_network_list"

PLAN = f"""\
1. list the existing network lists (read only) and remember them
2. create "{PREFIX}" (port list 58690-58699, 58700), preview then apply, check the read-back
3. update the description only; the diff must show only the description
4. add member 58701 and remove 58700 (the members array is replaced whole); check the diff
5. preview the delete (reads the live policies and traffic objects to see what uses the list), then apply it
6. confirm the other lists are exactly as they were"""


async def tool(client: Client, args: dict[str, Any]) -> dict[str, Any]:
    res = await client.call_tool(TOOL, {"params": args})
    return json.loads(res.content[0].text)


async def apply(client: Client, args: dict[str, Any]) -> dict[str, Any]:
    pre = await tool(client, args)
    if not pre.get("ok"):
        raise RuntimeError(f"preview failed: {pre.get('error')}")
    if pre["errors"] or pre["apply_blocked_reason"]:
        raise RuntimeError(f"preview not applicable: {pre['errors'] or pre['apply_blocked_reason']}")
    out = await tool(client, {**args, "confirm": True, "fingerprint": pre["fingerprint"]})
    if not out.get("ok"):
        raise RuntimeError(f"apply failed: {out.get('error')}")
    out["_preview"] = pre
    return out


def snapshot(rows: list[dict[str, Any]]) -> list[tuple]:
    return sorted((r["_id"], r.get("name"), r.get("group_type"), tuple(r.get("group_members") or []), r.get("description"))
                  for r in rows if not str(r.get("name", "")).startswith(PREFIX))


async def main(run: bool, transport: Any = None) -> int:
    print("Plan:\n" + PLAN)
    if not run:
        print("\nDry run only. Add --run to perform it.")
        return 0
    settings = dataclasses.replace(Settings.from_env(), enable_writes=True, write_entities=frozenset({"network_list"}))
    mcp, api = create_server(settings, transport=transport)
    engine = WriteEngine(api)
    failures = 0
    try:
        async with Client(mcp) as client:
            before = await engine._rows(SPEC)
            others_before = snapshot(before)
            print(f"\n[1] {len(before)} existing list(s); {len(others_before)} are not ours")
            for r in before:
                if str(r.get("name", "")).startswith(PREFIX):
                    out = await apply(client, {"action": "delete", "target": r["_id"]})
                    print(f"  removed leftover {r.get('name')}: verified={out['verified']}")

            created_id: str | None = None
            try:
                print("\n[2] create")
                out = await apply(client, {"action": "create", "name": PREFIX, "group_type": "port-group",
                                           "group_members": ["58690-58699", "58700"], "description": "zz test"})
                created_id = out["id"]
                print(f"  verified={out['verified']} id={created_id} rollback={out['rollback']}")
                failures += not out["verified"]

                print("\n[3] update description only")
                out = await apply(client, {"action": "update", "target": created_id, "description": "zz changed"})
                print(f"  verified={out['verified']} diff={json.dumps(out['diff'])}")
                failures += not out["verified"] or list(out["diff"]) != ["description"]

                print("\n[4] add 58701, remove 58700")
                out = await apply(client, {"action": "update", "target": created_id, "add_members": ["58701"], "remove_members": ["58700"]})
                print(f"  verified={out['verified']} diff={json.dumps(out['diff'])}")
                failures += not out["verified"] or out["diff"].get("group_members", {}).get("to") != ["58690-58699", "58701"]

                print("\n[5] delete (reference check reads the live policies and traffic objects)")
                out = await apply(client, {"action": "delete", "target": created_id})
                print(f"  used_by={out['_preview']['used_by']} verified={out['verified']}")
                failures += not out["verified"] or bool(out["_preview"]["used_by"])
                created_id = None
            except Exception as exc:  # report, then fall through to cleanup
                failures += 1
                print(f"  ERROR: {type(exc).__name__}: {exc}")
            finally:
                if created_id:
                    try:
                        out = await apply(client, {"action": "delete", "target": created_id})
                        print(f"  cleanup delete: verified={out['verified']}")
                    except Exception as exc:  # noqa: BLE001
                        failures += 1
                        print(f"  CLEANUP FAILED, remove '{PREFIX}*' by hand: {exc}")

            after = await engine._rows(SPEC)
            leftovers = [r.get("name") for r in after if str(r.get("name", "")).startswith(PREFIX)]
            print(f"\n[6] other lists unchanged: {snapshot(after) == others_before}; leftovers: {leftovers or 'none'}")
            failures += snapshot(after) != others_before or bool(leftovers)
    finally:
        await api.client.aclose()
    print("\nRESULT:", "all checks passed" if not failures else f"{failures} check(s) FAILED")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main("--run" in sys.argv)))
