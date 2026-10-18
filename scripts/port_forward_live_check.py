"""Prove the write framework on the real console using one throwaway, disabled port forward.

    uv run scripts/port_forward_live_check.py            # dry run: prints the plan, touches nothing
    uv run scripts/port_forward_live_check.py --run      # performs it

SAFETY
  * Goes through the real tool (preview, then confirm with the fingerprint, journal, read-back), in-process.
    Writes are enabled for THIS process only; the Claude Desktop server configuration is not changed.
  * Creates exactly one rule named "zz-pfcheck", DISABLED, forwarding to 192.0.2.15 (documentation address, nothing
    lives there). It is never enabled: the enable step is a preview only, to show the exposure warning.
  * Existing rules are never edited or deleted. Before and after, the script compares the list of other rules.
  * The rule is deleted in a finally block, also when a step fails; leftovers named zz-pfcheck* are removed first.
  * Journal lines go to the normal journal folder (UNIFI_CONSOLE_JOURNAL_DIR or ~/.unifi-console-mcp/journal).
  * Uses the same account and settings as the MCP server. Prints field names and short values only.
"""
from __future__ import annotations

import asyncio
import dataclasses
import json
import sys
from typing import Any

from mcp.client import Client

from unifi_console_mcp.config import Settings
from unifi_console_mcp.server import create_server

PREFIX = "zz-pfcheck"
TOOL = "unifi_console_port_forward"

PLAN = f"""\
1. list the existing port forwards (read only) and remember them
2. create "{PREFIX}" disabled (preview, then apply with the fingerprint) and check the read-back
3. update: rename to "{PREFIX}-renamed" and check the diff shows only the name
4. enable: PREVIEW ONLY, to show the exposure warning. It is never applied.
5. delete it (preview, then apply) and check it is gone
6. confirm the other rules are exactly as they were"""


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
    return out


async def rules(api: Any) -> list[dict[str, Any]]:
    from unifi_console_mcp.writes import WriteEngine
    from unifi_console_mcp.entities.port_forward import SPEC

    return await WriteEngine(api)._rows(SPEC)


def short(d: dict[str, Any], keys: tuple[str, ...]) -> str:
    return json.dumps({k: d.get(k) for k in keys if k in d}, default=str)


async def main(run: bool, transport: Any = None) -> int:
    print("Plan:\n" + PLAN)
    if not run:
        print("\nDry run only. Add --run to perform it.")
        return 0
    settings = dataclasses.replace(Settings.from_env(), enable_writes=True, write_entities=frozenset({"port_forward"}))
    mcp, api = create_server(settings, transport=transport)
    failures = 0
    try:
        async with Client(mcp) as client:
            before = await rules(api)
            others_before = sorted((r["_id"], r.get("name"), r.get("enabled")) for r in before if not str(r.get("name", "")).startswith(PREFIX))
            print(f"\n[1] {len(before)} existing rule(s); {len(others_before)} are not ours")

            for r in before:
                if str(r.get("name", "")).startswith(PREFIX):
                    out = await apply(client, {"action": "delete", "target": r["_id"]})
                    print(f"  removed leftover {r.get('name')}: verified={out['verified']}")

            created_id: str | None = None
            try:
                print("\n[2] create (disabled)")
                out = await apply(client, {"action": "create", "name": PREFIX, "dst_port": "58699", "fwd": "192.0.2.15"})
                created_id = out["id"]
                print(f"  verified={out['verified']} id={created_id} rollback={out['rollback']}")
                failures += not out["verified"]

                print("\n[3] rename")
                out = await apply(client, {"action": "update", "target": created_id, "name": f"{PREFIX}-renamed"})
                print(f"  verified={out['verified']} diff={json.dumps(out['diff'])}")
                failures += not out["verified"] or list(out["diff"]) != ["name"]

                print("\n[4] enable: preview only, NOT applied")
                pre = await tool(client, {"action": "enable", "target": created_id})
                print(f"  applied={pre['applied']} warnings={len(pre['warnings'])}")
                for w in pre["warnings"]:
                    print(f"   - {w[:140]}")
                failures += pre["applied"] or not pre["warnings"]

                print("\n[5] delete")
                out = await apply(client, {"action": "delete", "target": created_id})
                print(f"  verified={out['verified']}")
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

            after = await rules(api)
            others_after = sorted((r["_id"], r.get("name"), r.get("enabled")) for r in after if not str(r.get("name", "")).startswith(PREFIX))
            leftovers = [r.get("name") for r in after if str(r.get("name", "")).startswith(PREFIX)]
            print(f"\n[6] other rules unchanged: {others_before == others_after}; leftovers: {leftovers or 'none'}")
            failures += others_before != others_after or bool(leftovers)
    finally:
        await api.client.aclose()
    print("\nRESULT:", "all checks passed" if not failures else f"{failures} check(s) FAILED")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main("--run" in sys.argv)))
