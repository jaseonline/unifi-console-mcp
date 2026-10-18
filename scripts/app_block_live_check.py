"""Prove the application block tool on the real console using throwaway blocks that can never apply.

    uv run scripts/app_block_live_check.py            # dry run: prints the plan, touches nothing
    uv run scripts/app_block_live_check.py --run      # performs it

SAFETY
  * Goes through the real tool (preview, then confirm with the fingerprint, journal, read-back), in-process. Writes are
    enabled for THIS process only; the Claude Desktop server configuration is not changed.
  * Every block it creates is named "zz-appblock-check*", is for the Harmony Hub's MAC only, and has a schedule in
    January 2030 (one time, or custom dates), so the console never applies it. Nothing is switched on.
  * The console replaces the WHOLE set on every write, so before starting the script records every existing block, and in a
    finally block it puts that exact set back (existing blocks keep their ids). It compares the other blocks before and after.
  * `[]` (delete everything) is only exercised when the set was already empty, so a real block is never at risk.
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
from unifi_console_mcp.entities.app_block import SPEC
from unifi_console_mcp.server import create_server
from unifi_console_mcp.writes import WriteEngine

PREFIX = "zz-appblock-check"
TOOL = "unifi_console_app_block"
HUB = os.environ.get("UNIFI_LIVE_CHECK_CLIENT_MAC", "02:00:00:00:00:23").lower()   # a harmless client on YOUR console
APP = 1114144
ONE_TIME = {"mode": "ONE_TIME_ONLY", "date": "2030-01-01", "time_range_start": "03:00", "time_range_end": "03:05"}
CUSTOM = {"mode": "CUSTOM", "date_start": "2030-01-01", "date_end": "2030-01-02", "time_all_day": True, "repeat_on_days": ["tue"]}

PLAN = f"""\
1. read the existing blocks (read only) and remember every one
2. create "{PREFIX}" (Harmony Hub, one application, one time on 2030-01-01); stored shape and generated policy are checked
3. change its schedule to CUSTOM (2030-01-01 to 2030-01-02, all day); the diff must show only the schedule
4. rename it; the diff must show only the name
5. switch it to a category; the stale application list must be gone
6. one request with two changes (create "{PREFIX}-2" and update the first); the journal records a single write
7. replay the rollback of step 6
8. restore the original set exactly; confirm the other blocks are as they were and nothing named {PREFIX}* is left
9. if the set was empty at the start, step 8 sends [] (delete everything), which proves an empty array is accepted"""


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
    out.setdefault("verified", out.get("applied") is False)      # "already in the requested state" sends nothing and counts as fine
    return out


def fields(diff: dict[str, Any], name: str) -> list[str]:
    """The diff is keyed by block name; list the fields whose values differ inside one block."""
    old, new = diff[name].get("from") or {}, diff[name].get("to") or {}
    return sorted(k for k in set(old) | set(new) if old.get(k) != new.get(k))


def others(blocks: list[dict[str, Any]]) -> list[str]:
    return sorted(json.dumps(b, sort_keys=True) for b in blocks if not str(b.get("name", "")).startswith(PREFIX))


async def main(run: bool, transport: Any = None) -> int:
    print("Plan:\n" + PLAN)
    if not run:
        print("\nDry run only. Add --run to perform it.")
        return 0
    settings = dataclasses.replace(Settings.from_env(), enable_writes=True, write_entities=frozenset({"app_block"}))
    mcp, api = create_server(settings, transport=transport)
    engine = WriteEngine(api)
    failures = 0
    try:
        async with Client(mcp) as client:
            original = await engine._read_list("listFirewallAppBlocks")
            print(f"\n[1] {len(original)} existing block(s)")
            for b in original:
                print(f"    {b.get('name')}: {b.get('type')} {b.get('target_type')} {b.get('schedule', {}).get('mode')}")
            keep = others(original)
            leftovers = [b for b in original if str(b.get("name", "")).startswith(PREFIX)]
            if leftovers:
                print(f"  note: {len(leftovers)} leftover {PREFIX}* block(s) will be removed by the restore in step 8")
            try:
                print("\n[2] create (one time, 2030)")
                out = await apply(client, {"changes": [{"op": "create", "name": PREFIX, "clients": [HUB], "apps": [APP], "schedule": ONE_TIME}]})
                rows = await engine._read_list("listFirewallAppBlocks")
                row = next((r for r in rows if r.get("name") == PREFIX), {})
                print(f"  verified={out['verified']} keys={sorted(row)} schedule={row.get('schedule')}")
                print(f"  generated policy check: {out.get('generated_policies')}")
                failures += not out["verified"] or not row.get("_id") or others(rows) != keep

                print("\n[3] schedule -> CUSTOM")
                out = await apply(client, {"changes": [{"op": "update", "target": PREFIX, "schedule": CUSTOM}]})
                changed = fields(out["diff"], PREFIX)
                print(f"  verified={out['verified']} blocks in diff={sorted(out['diff'])} fields changed={changed}")
                failures += not out["verified"] or sorted(out["diff"]) != [PREFIX] or changed != ["schedule"]

                print("\n[4] rename")
                out = await apply(client, {"changes": [{"op": "update", "target": PREFIX, "name": PREFIX + "-r"}]})
                print(f"  verified={out['verified']} diff={sorted(out['diff'])}")
                failures += not out["verified"]

                print("\n[5] switch to a category")
                out = await apply(client, {"changes": [{"op": "update", "target": PREFIX + "-r", "categories": [6]}]})
                rows = await engine._read_list("listFirewallAppBlocks")
                row = next((r for r in rows if r.get("name") == PREFIX + "-r"), {})
                print(f"  verified={out['verified']} target_type={row.get('target_type')} app_ids={row.get('app_ids')} categories={row.get('app_category_ids')}")
                failures += not out["verified"] or row.get("app_ids") != [] or row.get("app_category_ids") != [6]

                print("\n[6] several changes, one request")
                out = await apply(client, {"changes": [
                    {"op": "create", "name": PREFIX + "-2", "clients": [HUB], "apps": [APP], "schedule": ONE_TIME},
                    {"op": "update", "target": PREFIX + "-r", "apps": [APP]}]})
                print(f"  verified={out['verified']} summary={out['summary']} journal={out['journal_id']}")
                failures += not out["verified"]
                rollback = out["rollback"]

                print("\n[7] replay the rollback")
                out = await apply(client, rollback)
                rows = await engine._read_list("listFirewallAppBlocks")
                print(f"  verified={out['verified']} names={[r.get('name') for r in rows if str(r.get('name')).startswith(PREFIX)]}")
                failures += not out["verified"]
            except Exception as exc:  # report, then fall through to the restore
                failures += 1
                print(f"  ERROR: {type(exc).__name__}: {exc}")
            finally:
                try:
                    out = await apply(client, {"replace_all": original})
                    print(f"\n[8] restored the original set: verified={out['verified']}")
                    failures += not out["verified"]
                except Exception as exc:  # noqa: BLE001
                    failures += 1
                    print(f"  RESTORE FAILED. Put these blocks back by hand: {json.dumps(original)} ({exc})")
            after = await engine._read_list("listFirewallAppBlocks")
            same_set = others(after) == keep
            left = [b.get("name") for b in after if str(b.get("name", "")).startswith(PREFIX)]
            print(f"    other blocks unchanged: {same_set}; leftovers: {left or 'none'}")
            failures += (not same_set) or bool(left and not leftovers)

            if not original:
                print("\n[9] the set was empty, so the restore in step 8 sent [] and the console accepted it")
            else:
                print("\n[9] skipped: real blocks exist, so [] is not tested here")
    finally:
        await api.client.aclose()
    print("\nRESULT:", "all checks passed" if not failures else f"{failures} check(s) FAILED")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main("--run" in sys.argv)))
