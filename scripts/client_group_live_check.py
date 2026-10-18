"""Prove the client group tool on the real console using one throwaway group of made-up MAC addresses.

    uv run scripts/client_group_live_check.py            # dry run: prints the plan, touches nothing
    uv run scripts/client_group_live_check.py --run      # performs it

SAFETY
  * Goes through the real tool (preview, then confirm with the fingerprint, journal, read-back), in-process. Writes are
    enabled for THIS process only; the Claude Desktop server configuration is not changed.
  * Creates exactly one group named "zz-groupcheck" whose members are made-up, locally administered MAC addresses
    (02:00:00:...) plus, in one step, the Harmony Hub's MAC to show a known client raises no warning. No policy references
    the group, so it is inert. The Hub itself is never edited.
  * Existing groups (the Sonos group included) are never edited or deleted. Before and after, the script compares all
    the other groups member by member.
  * The delete preview reads the live firewall policies and traffic objects to see what uses the group, which proves the
    reference check against the real console. The group is deleted in a finally block, also when a step fails;
    leftovers named zz-groupcheck* are removed first.
  * Journal lines go to the normal journal folder. Prints field names and short values only.
"""
from __future__ import annotations

import asyncio
import os
import dataclasses
import json
import sys
from typing import Any

from mcp.client import Client

from unifi_console_mcp.config import Settings
from unifi_console_mcp.entities.client_group import SPEC
from unifi_console_mcp.server import create_server
from unifi_console_mcp.writes import WriteEngine

PREFIX = "zz-groupcheck"
RENAMED = PREFIX + "-renamed"
TOOL = "unifi_console_client_group"
F1, F2, F3 = "02:00:00:aa:bb:01", "02:00:00:aa:bb:02", "02:00:00:aa:bb:03"
HUB_MAC = os.environ.get("UNIFI_LIVE_CHECK_CLIENT_MAC", "02:00:00:00:00:23").lower()   # a harmless client on YOUR console

PLAN = f"""\
1. list the existing client groups (read only) and remember every one, member by member
2. create "{PREFIX}" with two made-up MACs ({F1}, {F2}); preview then apply, check the read-back (this also shows whether
   the console accepts MACs it has never seen)
3. rename it to "{RENAMED}"; the diff must show only the name
4. add {F3} and remove {F1}; the members array is sent whole; the diff must show only the members
5. add the Harmony Hub's MAC ({HUB_MAC}); the preview must not warn about it (it is a known client)
6. preview the delete (reads the live policies and traffic objects to see what uses the group), then apply it
7. confirm every other group, the Sonos group included, is exactly as it was"""


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
    return sorted((r["id"], r.get("name"), r.get("type"), tuple(r.get("members") or []))
                  for r in rows if not str(r.get("name", "")).startswith(PREFIX))


async def main(run: bool, transport: Any = None) -> int:
    print("Plan:\n" + PLAN)
    if not run:
        print("\nDry run only. Add --run to perform it.")
        return 0
    settings = dataclasses.replace(Settings.from_env(), enable_writes=True, write_entities=frozenset({"client_group"}))
    mcp, api = create_server(settings, transport=transport)
    engine = WriteEngine(api)
    failures = 0
    try:
        async with Client(mcp) as client:
            before = await engine._rows(SPEC)
            others_before = snapshot(before)
            print(f"\n[1] {len(before)} existing group(s); {len(others_before)} are not ours")
            for r in before:
                print(f"    {r.get('name')}: {len(r.get('members') or [])} member(s)")
                if str(r.get("name", "")).startswith(PREFIX):
                    out = await apply(client, {"action": "delete", "target": r["id"]})
                    print(f"  removed leftover {r.get('name')}: verified={out['verified']}")

            created_id: str | None = None
            try:
                print("\n[2] create")
                out = await apply(client, {"action": "create", "name": PREFIX, "members": [F1, F2]})
                created_id = out["id"]
                print(f"  verified={out['verified']} id={created_id} http={out['http_status']} rollback={out['rollback']}")
                failures += not out["verified"]

                print("\n[3] rename")
                out = await apply(client, {"action": "update", "target": created_id, "name": RENAMED})
                print(f"  verified={out['verified']} diff={json.dumps(out['diff'])}")
                failures += not out["verified"] or list(out["diff"]) != ["name"]

                print("\n[4] add one member, remove one")
                out = await apply(client, {"action": "update", "target": created_id, "add_members": [F3], "remove_members": [F1]})
                print(f"  verified={out['verified']} diff={json.dumps(out['diff'])}")
                failures += not out["verified"] or out["diff"].get("members", {}).get("to") != [F2, F3]

                print("\n[5] add a known client (the Harmony Hub's MAC)")
                out = await apply(client, {"action": "update", "target": created_id, "add_members": [HUB_MAC]})
                warned = [w for w in out["_preview"]["warnings"] if HUB_MAC in w]
                print(f"  verified={out['verified']} warnings about the Hub: {warned or 'none'}")
                failures += not out["verified"] or bool(warned)

                print("\n[6] delete (reference check reads the live policies and traffic objects)")
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
            print(f"\n[7] other groups unchanged: {snapshot(after) == others_before}; leftovers: {leftovers or 'none'}")
            failures += snapshot(after) != others_before or bool(leftovers)
    finally:
        await api.client.aclose()
    print("\nRESULT:", "all checks passed" if not failures else f"{failures} check(s) FAILED")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main("--run" in sys.argv)))
