"""Prove the DoH tool on the real console: a harmless change and back, then the automatic restore.

    uv run scripts/doh_live_check.py            # dry run: prints the plan, touches nothing
    uv run scripts/doh_live_check.py --run      # performs it

SAFETY
  * Goes through the real tool (preview, then confirm with the fingerprint and an approval note, journal, read-back),
    in-process. Writes are enabled for THIS process only; the Claude Desktop configuration is not changed.
  * Only the DoH group changes, and only by ADDING Google's two resolvers to the list that is already in use (Cloudflare stays
    first and stays selected), then putting the exact original back. DNS keeps working throughout. It stops unless DoH is
    already in manual mode. SSL inspection and everything else are never touched.
  * The tool tests DNS through the gateway before and after each change. Step 5 uses the test switch
    UNIFI_CONSOLE_DNS_PROBE_FORCE_FAIL (this process only) to make the probe report a failure after the change, which proves the
    automatic restore with a perfectly healthy resolver: the change is made, the probe "fails", the original values come back.
  * A finally block restores the original values if anything ends in another state. If even that fails it prints the exact
    commands (scripts/doh_restore.py --run, or the UI).
  * Prints state, resolver names and short values only.
"""
from __future__ import annotations

import asyncio
import dataclasses
import json
import sys
from typing import Any

from mcp.client import Client

from unifi_console_mcp.config import Settings
from unifi_console_mcp.entities.doh import SPEC
from unifi_console_mcp.server import create_server
from unifi_console_mcp.writes import WriteEngine

TOOL = "unifi_console_doh"
NOTE = "doh live check, approved in chat 2026-10-18 (claude/unifi-console-doh-plan-2026-10-18.md)"
EXTRA = ["google", "google-ipv6"]

PLAN = """\
1. read the DoH group and run the DNS probe (read only); stop unless the state is manual
2. preview three bad requests (an unknown resolver, a bad custom stamp, names without the mode); all must be refused
3. add google and google-ipv6 to the existing list: preview, confirm; check the read-back and the probe after
4. put the exact original list back: preview, confirm; check the read-back
5. repeat step 3 with the probe forced to fail: the tool must put the original back by itself (auto_restored)
6. read the group again: it must equal the original, byte for byte"""


async def tool(client: Client, args: dict[str, Any]) -> dict[str, Any]:
    res = await client.call_tool(TOOL, {"params": args})
    return json.loads(res.content[0].text)


async def apply(client: Client, args: dict[str, Any]) -> dict[str, Any]:
    pre = await tool(client, {**args, "approval_note": NOTE})
    if not pre.get("ok"):
        raise RuntimeError(f"preview failed: {pre.get('error')}")
    if pre["errors"] or pre["apply_blocked_reason"]:
        raise RuntimeError(f"preview not applicable: {pre['errors'] or pre['apply_blocked_reason']}")
    out = await tool(client, {**args, "confirm": True, "fingerprint": pre["fingerprint"], "approval_note": NOTE})
    if not out.get("ok"):
        raise RuntimeError(f"apply failed: {out.get('error')}")
    out["_preview"] = pre
    return out


def pick(group: dict[str, Any]) -> dict[str, Any]:
    return {k: group.get(k) for k in ("_id", "key", "state", "server_names", "custom_servers")}


async def with_client(settings: Settings, transport: Any, fn: Any) -> Any:
    mcp, api = create_server(settings, transport=transport)
    try:
        async with Client(mcp) as client:
            return await fn(client, WriteEngine(api))
    finally:
        await api.client.aclose()


async def main(run: bool, transport: Any = None) -> int:
    print("Plan:\n" + PLAN)
    if not run:
        print("\nDry run only. Add --run to perform it.")
        return 0
    base = dataclasses.replace(Settings.from_env(), enable_writes=True, write_entities=frozenset({"doh"}))
    failures = 0
    original: dict[str, Any] = {}

    async def baseline(client: Client, engine: WriteEngine) -> dict[str, Any]:
        rows = await engine._rows(SPEC)
        return pick(rows[0])

    original = await with_client(base, transport, baseline)
    print(f"\n[1] original: {json.dumps(original)}")
    if original["state"] != "manual" or not original["server_names"]:
        print("STOP: DoH is not in manual mode with resolvers selected, so this check does not apply. Nothing was changed.")
        return 1
    extended = original["server_names"] + [n for n in EXTRA if n not in original["server_names"]]
    if extended == original["server_names"]:
        print("STOP: the Google resolvers are already selected; nothing to add for the check. Nothing was changed.")
        return 1
    restore_args = {"state": "manual", "server_names": original["server_names"]}
    change_args = {"state": "manual", "server_names": extended}

    async def steps(client: Client, engine: WriteEngine) -> int:
        bad = 0
        pre = await tool(client, {"state": "manual", "server_names": ["nosuch-resolver"]})
        probe_before = pre.get("guard", {}).get("check_before")
        print(f"    DNS probe before any change: {probe_before}")
        bad += probe_before != "ok"

        print("\n[2] refusals")
        cases = [
            ({"state": "manual", "server_names": ["nosuch-resolver"]}, "not a resolver"),
            ({"state": "custom", "custom_servers": [{"server_name": "x", "sdns_stamp": "https://example.com"}]}, "sdns://"),
            ({"state": "off", "server_names": ["google"]}, "only applies when state is manual"),
        ]
        for args, needle in cases:
            res = await client.call_tool(TOOL, {"params": args})
            text = res.content[0].text
            ok = needle in text
            print(f"  {needle!r}: {'refused' if ok else 'NOT refused: ' + text[:120]}")
            bad += not ok

        print("\n[3] add google and google-ipv6")
        out = await apply(client, change_args)
        print(f"  applied={out['applied']} verified={out['verified']} guard={json.dumps(out.get('guard'))} diff={json.dumps(out['diff'])}")
        bad += not (out["applied"] and out["verified"] and out["guard"].get("probe_after") == "ok" and list(out["diff"]) == ["server_names"])

        print("\n[4] put the original back")
        out = await apply(client, restore_args)
        print(f"  applied={out['applied']} verified={out['verified']} guard={json.dumps(out.get('guard'))}")
        bad += not (out["applied"] and out["verified"])
        return bad

    async def forced(client: Client, engine: WriteEngine) -> int:
        print("\n[5] the same change with the probe forced to fail")
        out = await apply(client, change_args)
        g = out.get("guard") or {}
        print(f"  applied={out['applied']} auto_restored={g.get('auto_restored')} restore_verified={g.get('restore_verified')} "
              f"probe_after_restore={g.get('probe_after_restore')}")
        return int(not (out["applied"] is False and g.get("auto_restored") and g.get("restore_verified")
                        and g.get("probe_after_restore") == "ok"))

    async def cleanup(client: Client, engine: WriteEngine) -> dict[str, Any]:
        now = pick((await engine._rows(SPEC))[0])
        if now != original:
            print(f"  state differs from the original, restoring: {json.dumps(now)}")
            try:
                await apply(client, restore_args)
            except Exception as exc:  # noqa: BLE001
                print(f"  RESTORE FAILED: {exc}\n  Run: uv run scripts/doh_restore.py --run   (or set it back in the UI)")
            now = pick((await engine._rows(SPEC))[0])
        return now

    try:
        failures += await with_client(base, transport, steps)
        failures += await with_client(dataclasses.replace(base, dns_probe_force_fail=True), transport, forced)
    except Exception as exc:  # noqa: BLE001 - report (an ExceptionGroup is unpacked), then restore below
        failures += 1
        inner = list(getattr(exc, "exceptions", None) or [exc])
        print("  ERROR: " + "; ".join(f"{type(e).__name__}: {e}" for e in inner))
    finally:
        print("\n[6] final state")
        final = await with_client(base, transport, cleanup)
        same = final == original
        print(f"  equals the original: {same}")
        failures += not same
    print("\nRESULT:", "all checks passed" if not failures else f"{failures} check(s) FAILED")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main("--run" in sys.argv)))
