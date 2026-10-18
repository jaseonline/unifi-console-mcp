"""Prove the QoS rule tool on the real console using one throwaway rule that is never switched on.

    uv run scripts/qos_rule_live_check.py            # dry run: prints the plan, touches nothing
    uv run scripts/qos_rule_live_check.py --run      # performs it

SAFETY
  * Goes through the real tool (preview, then confirm with the fingerprint, journal, read-back), in-process. Writes are
    enabled for THIS process only; the Claude Desktop server configuration is not changed.
  * Creates exactly one rule named "zz-qosrule-check" for the Harmony Hub's MAC and a few application ids. The rule's own
    `enabled` switch stays false from start to finish, so the console never applies it; only its stored fields change.
    What an ENABLED rule does to traffic is not tested and is recorded as unverified.
  * Existing rules are never edited or deleted; before and after, the script compares every other rule. Leftovers named
    zz-qosrule-check* are removed first, and the rule is deleted in a finally block, also when a step fails.
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
from unifi_console_mcp.entities.qos_rule import SPEC
from unifi_console_mcp.server import create_server
from unifi_console_mcp.writes import WriteEngine

PREFIX = "zz-qosrule-check"
RENAMED = PREFIX + "-renamed"
TOOL = "unifi_console_qos_rule"
HUB = os.environ.get("UNIFI_LIVE_CHECK_CLIENT_MAC", "02:00:00:00:00:23").lower()   # a harmless client on YOUR console
APPS = [393220, 393245]
WAN = "WAN1"

PLAN = f"""\
1. list the existing QoS rules (read only) and remember every one
2. create "{PREFIX}" (PRIORITIZE, Harmony Hub, two applications, {WAN}), switched off; the stored shape must match the capture
3. change it to LIMIT 20 Mbit/s down and 5 Mbit/s up with long bursts; the diff must show only the limit fields
4. rename it to "{RENAMED}"; the diff must show only the name
5. change the applications; the diff must show only the destination
6. replay the rollback of step 5
7. back to PRIORITIZE; the limits must be gone
8. delete it through batch-delete (HTTP 204)
9. confirm every other rule is exactly as it was and nothing named {PREFIX}* is left"""


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
    settings = dataclasses.replace(Settings.from_env(), enable_writes=True, write_entities=frozenset({"qos_rule"}))
    mcp, api = create_server(settings, transport=transport)
    engine = WriteEngine(api)
    failures = 0
    try:
        async with Client(mcp) as client:
            before = await engine._rows(SPEC)
            others_before = snapshot(before)
            print(f"\n[1] {len(before)} existing rule(s); {len(others_before)} are not ours")
            for r in before:
                print(f"    {r.get('name')}: enabled={r.get('enabled')} objective={r.get('objective')}")
                if str(r.get("name", "")).startswith(PREFIX):
                    out = await apply(client, {"action": "delete", "target": r["_id"]})
                    print(f"  removed leftover {r.get('name')}: verified={out['verified']}")

            rid: str | None = None

            def stored() -> Any:
                return engine._rows(SPEC)

            try:
                print("\n[2] create (PRIORITIZE, switched off)")
                out = await apply(client, {"action": "create", "name": PREFIX, "wan_network": WAN, "source_clients": [HUB],
                                           "destination_apps": APPS, "objective": "PRIORITIZE"})
                rid = out["id"]
                row = next((r for r in await stored() if r["_id"] == rid), {})
                print(f"  verified={out['verified']} id={rid} http={out['http_status']} keys={sorted(row)} mismatches={out.get('mismatches')}")
                print(f"  stored source={row.get('source')} destination={row.get('destination')} schedule={row.get('schedule')}")
                failures += not out["verified"] or row.get("enabled") is not False or out["http_status"] != 201

                print("\n[3] LIMIT with bursts")
                out = await apply(client, {"action": "update", "target": rid, "objective": "LIMIT", "download_limit": 20000,
                                           "upload_limit": 5000, "download_burst": "LONG", "upload_burst": "LONG"})
                row = next((r for r in await stored() if r["_id"] == rid), {})
                print(f"  verified={out['verified']} diff keys={sorted(out['diff'])} stored limits={row.get('download_limit_kbps')}/{row.get('upload_limit_kbps')}")
                failures += not out["verified"] or row.get("enabled") is not False

                print("\n[4] rename")
                out = await apply(client, {"action": "update", "target": rid, "name": RENAMED})
                print(f"  verified={out['verified']} diff keys={sorted(out['diff'])}")
                failures += not out["verified"] or sorted(out["diff"]) != ["name"]

                print("\n[5] change the applications")
                out = await apply(client, {"action": "update", "target": rid, "destination_apps": [393220]})
                print(f"  verified={out['verified']} diff keys={sorted(out['diff'])}")
                failures += not out["verified"] or sorted(out["diff"]) != ["destination"]
                rollback = out["rollback"]

                print("\n[6] replay the rollback")
                out = await apply(client, {"action": rollback["action"], "target": rollback["target"], **rollback["changes"]})
                row = next((r for r in await stored() if r["_id"] == rid), {})
                print(f"  verified={out['verified']} app_ids={(row.get('destination') or {}).get('app_ids')}")
                failures += not out["verified"] or (row.get("destination") or {}).get("app_ids") != APPS

                print("\n[7] back to PRIORITIZE")
                out = await apply(client, {"action": "update", "target": rid, "objective": "PRIORITIZE"})
                row = next((r for r in await stored() if r["_id"] == rid), {})
                print(f"  verified={out['verified']} diff keys={sorted(out['diff'])} stored keys={sorted(row)}")
                failures += not out["verified"] or "download_limit_kbps" in row

                print("\n[8] delete (batch-delete)")
                out = await apply(client, {"action": "delete", "target": rid})
                print(f"  verified={out['verified']} http={out['http_status']} warnings={out['_preview']['warnings']}")
                failures += not out["verified"]
                rid = None
            except Exception as exc:  # report, then fall through to cleanup
                failures += 1
                print(f"  ERROR: {type(exc).__name__}: {exc}")
            finally:
                if rid:
                    try:
                        out = await apply(client, {"action": "delete", "target": rid})
                        print(f"  cleanup delete: verified={out['verified']}")
                    except Exception as exc:  # noqa: BLE001
                        failures += 1
                        print(f"  CLEANUP FAILED, remove '{PREFIX}*' by hand: {exc}")

            after = await engine._rows(SPEC)
            leftovers = [r.get("name") for r in after if str(r.get("name", "")).startswith(PREFIX)]
            print(f"\n[9] other rules unchanged: {snapshot(after) == others_before}; leftovers: {leftovers or 'none'}")
            failures += snapshot(after) != others_before or bool(leftovers)
    finally:
        await api.client.aclose()
    print("\nRESULT:", "all checks passed" if not failures else f"{failures} check(s) FAILED")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main("--run" in sys.argv)))
