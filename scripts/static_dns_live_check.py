"""Prove the static DNS tool on the real console using two throwaway records, then remove them.

    uv run scripts/static_dns_live_check.py            # dry run: prints the plan, touches nothing
    uv run scripts/static_dns_live_check.py --run      # performs it

SAFETY
  * Goes through the real tool (preview, then confirm with the fingerprint, journal, read-back), in-process. Writes are
    enabled for THIS process only; the Claude Desktop server configuration is not changed.
  * Creates exactly two records, both named zz-dnscheck*.example.home: an A record pointing at 192.0.2.77 (an address
    reserved for documentation, not used on any network) and a CNAME to it. Both start disabled, so nothing resolves.
    The A record is enabled for a moment to prove enable/disable; no real name is involved.
  * Existing records are never edited or deleted. Before and after, the script compares all the other records. Leftovers
    named zz-dnscheck* from an aborted run are removed first, and the new records are deleted in a finally block.
  * The record "zz.example.home" (192.0.2.100, disabled) that is on the console already is NOT ours and is left alone.
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
from unifi_console_mcp.entities.static_dns import SPEC
from unifi_console_mcp.server import create_server
from unifi_console_mcp.writes import WriteEngine

PREFIX = "zz-dnscheck"
TOOL = "unifi_console_static_dns"
A_KEY = f"{PREFIX}.example.home"
C_KEY = f"{PREFIX}-alias.example.home"

PLAN = f"""\
1. list the existing records (read only) and remember them
2. create {A_KEY} A 192.0.2.77, disabled; preview then apply, check the read-back
3. update its value to 192.0.2.78 (the console needs the whole record, so this proves the whole-object update); diff must be only the value
4. create {C_KEY} CNAME -> {A_KEY}, disabled
5. preview (not apply) deleting the A record: the preview must warn that the CNAME points at it
6. enable then disable the A record; each diff must be only `enabled`
7. delete the CNAME, then the A record; check the read-back
8. confirm the other records are exactly as they were"""


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
    return sorted((r["_id"], r.get("key"), r.get("record_type"), str(r.get("value")), bool(r.get("enabled")), r.get("ttl"))
                  for r in rows if not str(r.get("key", "")).startswith(PREFIX))


async def main(run: bool, transport: Any = None) -> int:
    print("Plan:\n" + PLAN)
    if not run:
        print("\nDry run only. Add --run to perform it.")
        return 0
    settings = dataclasses.replace(Settings.from_env(), enable_writes=True, write_entities=frozenset({"static_dns"}))
    mcp, api = create_server(settings, transport=transport)
    engine = WriteEngine(api)
    failures = 0
    made: list[str] = []
    try:
        async with Client(mcp) as client:
            before = await engine._rows(SPEC)
            others_before = snapshot(before)
            print(f"\n[1] {len(before)} existing record(s); {len(others_before)} are not ours")
            for r in before:
                if str(r.get("key", "")).startswith(PREFIX):
                    out = await apply(client, {"action": "delete", "target": r["_id"]})
                    print(f"  removed leftover {r.get('key')}: verified={out['verified']}")

            async def step(label: str, args: dict[str, Any], expect: set[str] | None = None) -> dict[str, Any]:
                nonlocal failures
                out = await apply(client, args)
                print(f"  {label}: verified={out['verified']} diff={json.dumps(out['diff'])}")
                if not out["verified"] or (expect is not None and set(out["diff"]) != expect):
                    failures += 1
                    print(f"  CHECK FAILED{'' if expect is None else f': expected a diff on exactly {sorted(expect)}'}")
                return out

            try:
                print("\n[2] create the A record (disabled)")
                out = await step("create A", {"action": "create", "record_type": "A", "key": A_KEY, "value": "192.0.2.77", "enabled": False})
                a_id = out["id"]; made.append(a_id)
                print(f"  id={a_id} rollback={out['rollback']} warnings={out['_preview']['warnings']}")

                print("\n[3] update the value (whole-object PUT)")
                await step("value", {"action": "update", "target": a_id, "value": "192.0.2.78"}, {"value"})

                print("\n[4] create the CNAME (disabled)")
                out = await step("create CNAME", {"action": "create", "record_type": "CNAME", "key": C_KEY, "value": A_KEY, "enabled": False})
                c_id = out["id"]; made.append(c_id)

                print("\n[5] preview deleting the A record (not applied)")
                pre = await tool(client, {"action": "delete", "target": a_id})
                warned = C_KEY in " ".join(pre.get("warnings", []))
                print(f"  warnings={pre.get('warnings')} applied={pre.get('applied')}")
                failures += (not warned) or bool(pre.get("applied"))

                print("\n[6] enable, then disable")
                await step("enable", {"action": "enable", "target": a_id}, {"enabled"})
                await step("disable", {"action": "disable", "target": a_id}, {"enabled"})

                print("\n[7] delete the CNAME, then the A record")
                await step("delete CNAME", {"action": "delete", "target": c_id}); made.remove(c_id)
                await step("delete A", {"action": "delete", "target": a_id}); made.remove(a_id)
            except Exception as exc:  # report, then fall through to cleanup
                failures += 1
                print(f"  ERROR: {type(exc).__name__}: {exc}")
            finally:
                for ident in list(made):
                    try:
                        out = await apply(client, {"action": "delete", "target": ident})
                        print(f"  cleanup delete {ident}: verified={out['verified']}")
                    except Exception as exc:  # noqa: BLE001
                        failures += 1
                        print(f"  CLEANUP FAILED, remove '{PREFIX}*' by hand: {exc}")

            after = await engine._rows(SPEC)
            leftovers = [r.get("key") for r in after if str(r.get("key", "")).startswith(PREFIX)]
            print(f"\n[8] other records unchanged: {snapshot(after) == others_before}; leftovers: {leftovers or 'none'}")
            failures += snapshot(after) != others_before or bool(leftovers)
    finally:
        await api.client.aclose()
    print("\nRESULT:", "all checks passed" if not failures else f"{failures} check(s) FAILED")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main("--run" in sys.argv)))
