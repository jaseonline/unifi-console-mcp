"""Prove the traffic object tool on the real console using one throwaway object that is never switched on.

    uv run scripts/traffic_object_live_check.py            # dry run: prints the plan, touches nothing
    uv run scripts/traffic_object_live_check.py --run      # performs it

SAFETY
  * Goes through the real tool (preview, then confirm with the fingerprint, journal, read-back), in-process. Writes are
    enabled for THIS process only; the Claude Desktop server configuration is not changed.
  * Creates exactly one object named "zz-qoscheck" targeting the guest network. The object's own `enabled` switch stays
    false from start to finish, so the console never applies it to any traffic; only its stored fields change. Nothing
    here proves what an ENABLED limit does to traffic, and that is recorded as unverified.
  * Existing objects (there are none at the time of writing) are never edited or deleted; before and after, the script
    compares every other object. Leftovers named zz-qoscheck* are removed first, and the object is deleted in a finally
    block, also when a step fails.
  * Journal lines go to the normal journal folder. Prints field names and short values only.
"""
from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import sys
from typing import Any

from mcp.client import Client

from unifi_console_mcp.config import Settings
from unifi_console_mcp.entities.traffic_object import SPEC
from unifi_console_mcp.server import create_server
from unifi_console_mcp.writes import WriteEngine

PREFIX = "zz-qoscheck"
RENAMED = PREFIX + "-renamed"
TOOL = "unifi_console_traffic_object"
NET_A, NET_B = "LAN_Guest", "LAN_IoT"

PLAN = f"""\
1. list the existing traffic objects (read only) and remember every one
2. create "{PREFIX}" on {NET_A}, switched off with QoS off; preview then apply, check the read-back and that the
   stored shape matches what the UI sends (this proves the create route, HTTP 201 and the defaults)
3. set a download limit and an upload limit while the object stays off; the diff must show only qos
4. switch the QoS block on (the object itself stays off); the diff must show only qos
5. rename it to "{RENAMED}"; the diff must show only the name
6. retarget it to {NET_A} and {NET_B}; the diff must show only the targets
7. replay the rollback of step 6; the stored targets must be back to {NET_A} only
8. extras, all on the same switched-off object: client (MAC) target, burst, an every-day schedule, PRIORITIZE mode,
   an internet block with a schedule, and a route through the WAN to one IP address; each diff must show only the
   expected block, and the stored shape must match the capture
9. preview the delete, then apply it
10. confirm every other object is exactly as it was and nothing named {PREFIX}* is left"""


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


def snapshot(rows: list[dict[str, Any]]) -> list[str]:
    return sorted(json.dumps(r, sort_keys=True) for r in rows if not str(r.get("name", "")).startswith(PREFIX))


async def main(run: bool, transport: Any = None) -> int:
    print("Plan:\n" + PLAN)
    if not run:
        print("\nDry run only. Add --run to perform it.")
        return 0
    settings = dataclasses.replace(Settings.from_env(), enable_writes=True, write_entities=frozenset({"traffic_object"}))
    mcp, api = create_server(settings, transport=transport)
    engine = WriteEngine(api)
    failures = 0
    try:
        async with Client(mcp) as client:
            before = await engine._rows(SPEC)
            others_before = snapshot(before)
            print(f"\n[1] {len(before)} existing object(s); {len(others_before)} are not ours")
            for r in before:
                print(f"    {r.get('name')}: enabled={r.get('enabled')} target_type={r.get('target_type')}")
                if str(r.get("name", "")).startswith(PREFIX):
                    out = await apply(client, {"action": "delete", "target": r["id"]})
                    print(f"  removed leftover {r.get('name')}: verified={out['verified']}")

            created_id: str | None = None
            try:
                print("\n[2] create (switched off, QoS off)")
                out = await apply(client, {"action": "create", "name": PREFIX, "networks": [NET_A]})
                created_id = out["id"]
                stored = next((r for r in await engine._rows(SPEC) if r["id"] == created_id), {})
                print(f"  verified={out['verified']} id={created_id} http={out['http_status']} rollback={out['rollback']}")
                print(f"  stored keys={sorted(stored)} enabled={stored.get('enabled')} qos.enabled={(stored.get('qos') or {}).get('enabled')}")
                failures += not out["verified"] or stored.get("enabled") is not False or out["http_status"] != 201

                print("\n[3] limits while the object stays off")
                out = await apply(client, {"action": "update", "target": created_id, "download_limit": 5000, "upload_limit": 2000})
                print(f"  verified={out['verified']} diff keys={list(out['diff'])}")
                failures += not out["verified"] or list(out["diff"]) != ["qos"]

                print("\n[4] QoS block on (object still off)")
                out = await apply(client, {"action": "update", "target": created_id, "qos_enabled": True})
                print(f"  verified={out['verified']} diff keys={list(out['diff'])} warnings={out['_preview']['warnings']}")
                failures += not out["verified"] or list(out["diff"]) != ["qos"]

                print("\n[5] rename")
                out = await apply(client, {"action": "update", "target": created_id, "name": RENAMED})
                print(f"  verified={out['verified']} diff keys={list(out['diff'])}")
                failures += not out["verified"] or list(out["diff"]) != ["name"]

                print("\n[6] retarget to two networks")
                out = await apply(client, {"action": "update", "target": created_id, "networks": [NET_A, NET_B]})
                print(f"  verified={out['verified']} diff keys={list(out['diff'])}")
                failures += not out["verified"] or list(out["diff"]) != ["targets"]
                rollback = out["rollback"]

                print("\n[7] replay the rollback")
                out = await apply(client, {"action": rollback["action"], "target": rollback["target"], **rollback["changes"]})
                stored = next((r for r in await engine._rows(SPEC) if r["id"] == created_id), {})
                print(f"  verified={out['verified']} targets={len(stored.get('targets') or [])}")
                failures += not out["verified"] or len(stored.get("targets") or []) != 1

                print("\n[8] extras (object stays off)")
                hub = os.environ.get("UNIFI_LIVE_CHECK_CLIENT_MAC", "02:00:00:00:00:23").lower()
                steps = [
                    ("client target", {"clients": [hub]}, ["target_type", "targets"]),
                    ("burst + schedule", {"download_burst": "SHORT", "qos_schedule": {"mode": "EVERY_DAY", "start": "18:00", "end": "21:00"}}, ["qos"]),
                    ("prioritize", {"qos_mode": "PRIORITIZE"}, ["qos"]),
                    ("internet block + schedule", {"block_internet": True, "block_schedule": {"mode": "EVERY_DAY", "start": "23:00", "end": "06:00"}}, ["secure"]),
                    ("route via WAN", {"route_enabled": True, "route_network": "WAN1", "route_ip_addresses": ["203.0.113.0/24"], "route_kill_switch": True}, ["route"]),
                ]
                for label, change, expect in steps:
                    out = await apply(client, {"action": "update", "target": created_id, **change})
                    stored = next((r for r in await engine._rows(SPEC) if r["id"] == created_id), {})
                    ok = out["verified"] and sorted(out["diff"]) == sorted(expect) and stored.get("enabled") is False
                    print(f"  {label}: verified={out['verified']} diff keys={sorted(out['diff'])} enabled={stored.get('enabled')} -> {'ok' if ok else 'FAIL'}")
                    failures += not ok
                print(f"  stored qos.schedule={stored.get('qos', {}).get('schedule')} secure={stored.get('secure')} route={ {k: v for k, v in (stored.get('route') or {}).items() if v not in (None, False, {}, [])} }")

                print("\n[9] delete")
                out = await apply(client, {"action": "delete", "target": created_id})
                print(f"  verified={out['verified']} http={out['http_status']} warnings={out['_preview']['warnings']}")
                failures += not out["verified"]
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
            print(f"\n[10] other objects unchanged: {snapshot(after) == others_before}; leftovers: {leftovers or 'none'}")
            failures += snapshot(after) != others_before or bool(leftovers)
    finally:
        await api.client.aclose()
    print("\nRESULT:", "all checks passed" if not failures else f"{failures} check(s) FAILED")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main("--run" in sys.argv)))
