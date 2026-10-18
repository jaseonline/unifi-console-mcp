"""Prove the switch port tool on the real console, using only two unused (link down) ports of Switch 16 PoE.

    uv run scripts/switch_port_live_check.py            # dry run: prints the plan, touches nothing
    uv run scripts/switch_port_live_check.py --run      # performs it

SAFETY
  * Goes through the real tool (preview, then confirm with fingerprint and approval note, journal, read-back), in-process.
    Writes are enabled for THIS process only; the Claude Desktop configuration is not changed.
  * Stops unless the two test ports exist, have no link and are classified "unused", the add port has no saved settings and
    the edit port has some.
  * Only those two ports are ever changed: a name on the add port (then reset) and isolation on the edit port (then back).
    Every refusal case is a preview only. The final state of every device's port_overrides is compared with a snapshot
    taken at the start.
  * Step 6 uses UNIFI_CONSOLE_DNS_PROBE_FORCE_FAIL (this process only) to make the health guard report a failure after the
    change, which proves the automatic restore without any real outage.
  * A finally block puts both ports back if anything was left changed.
"""
from __future__ import annotations

import asyncio
import dataclasses
import json
import sys
from typing import Any

from mcp.client import Client

from unifi_console_mcp.config import Settings
from unifi_console_mcp.entities.switch_port import SPEC, classify
from unifi_console_mcp.server import create_server
from unifi_console_mcp.writes import WriteEngine

TOOL = "unifi_console_switch_port"
NOTE = "switch port live check, approved in chat 2026-10-18 (claude/unifi-console-switch-port-plan-2026-10-18.md)"
SWITCH = "Switch 16 PoE"
ADD_PORT, EDIT_PORT = 12, 14                    # unused, link down; 12 has no saved settings, 14 has
UPLINK_PORT, AP_PORT, CONSOLE_PORT = 1, 6, 8    # refusal previews only
TEST_NAME = "zz-portcheck"

PLAN = f"""\
1. snapshot every device's port_overrides; check that {SWITCH} ports {ADD_PORT} and {EDIT_PORT} are unused (no link) and
   that {ADD_PORT} has no saved settings (read only)
2. preview five bad requests (native VLAN on the console port {CONSOLE_PORT}, PoE off on the AP port {AP_PORT}, isolation on the
   uplink port {UPLINK_PORT}, unknown port 99, an out-of-range storm rate); all must be refused
3. rename port {ADD_PORT} (adds a saved-settings entry), then reset it (removes it): check each read-back and that no other port moved
4. switch isolation on for port {EDIT_PORT}, then off again: the diff must show only isolation
5. switch isolation on for port {EDIT_PORT} with the health guard forced to fail: the tool must put it back by itself
6. compare every device's port_overrides with the snapshot from step 1"""


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


def snapshot(rows: list[dict[str, Any]]) -> dict[str, str]:
    return {str(r["_id"]): json.dumps(sorted(r.get("port_overrides") or [], key=lambda e: e.get("port_idx", 0)), sort_keys=True)
            for r in rows if r.get("type") == "usw"}


async def with_client(settings: Settings, transport: Any, fn: Any) -> Any:
    mcp, api = create_server(settings, transport=transport)
    try:
        async with Client(mcp) as client:
            return await fn(client, WriteEngine(api))
    finally:
        await api.client.aclose()


def find(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    return next((r for r in rows if r.get("name") == SWITCH and r.get("type") == "usw"), None)


def entry(row: dict[str, Any], idx: int) -> dict[str, Any] | None:
    return next((e for e in row.get("port_overrides") or [] if e.get("port_idx") == idx), None)


async def main(run: bool, transport: Any = None) -> int:
    print("Plan:\n" + PLAN)
    if not run:
        print("\nDry run only. Add --run to perform it.")
        return 0
    base = dataclasses.replace(Settings.from_env(), enable_writes=True, write_entities=frozenset({"switch_port"}))
    failures = 0
    state: dict[str, Any] = {}

    async def baseline(client: Client, engine: WriteEngine) -> int:
        rows = await engine._rows(SPEC)
        sw = find(rows)
        print("\n[1] baseline")
        if sw is None:
            print(f"STOP: no switch called {SWITCH!r}. Nothing was changed.")
            return 1
        ctx = await engine._context(SPEC)
        import socket
        try:
            console_ip = socket.gethostbyname(engine.api.settings.host)
        except OSError:
            console_ip = None
        others = [r for r in rows if r["_id"] != sw["_id"]]
        for idx in (ADD_PORT, EDIT_PORT):
            row = next((p for p in sw.get("port_table") or [] if p.get("port_idx") == idx), None)
            kind, what = classify(sw, idx, others, ctx.get("clients", []), console_ip) if row else ("missing", "no such port")
            print(f"    port {idx}: {kind} ({what})")
            if kind != "unused":
                print(f"STOP: port {idx} must be unused (no link). Nothing was changed.")
                return 1
        if entry(sw, ADD_PORT) is not None or entry(sw, EDIT_PORT) is None:
            print(f"STOP: port {ADD_PORT} must have no saved settings and port {EDIT_PORT} must have some. Nothing was changed.")
            return 1
        state.update(snap=snapshot(rows), sw_id=sw["_id"], edit0=entry(sw, EDIT_PORT))
        basic = await engine._read_list("listDevicesBasic")
        down = [d.get("name") or d.get("mac") for d in basic if d.get("adopted", True) and d.get("state") != 1]
        print(f"    {len(state['snap'])} switches snapshotted; devices not connected now: {down or 'none'}")
        return 0

    stop = await with_client(base, transport, baseline)
    if stop:
        return 1
    ref = {"target": SWITCH}

    async def steps(client: Client, engine: WriteEngine) -> int:
        bad = 0
        print("\n[2] refusals")
        cases: list[tuple[dict[str, Any], str]] = [
            ({"port": CONSOLE_PORT, "native_network": "LAN_IoT"}, "Infrastructure stop"),
            ({"port": AP_PORT, "poe_mode": "off"}, "Infrastructure stop"),
            ({"port": UPLINK_PORT, "isolation": True}, "Infrastructure stop"),
            ({"port": 99, "name": "x"}, "no port 99"),
            ({"port": EDIT_PORT, "storm_control": {"unicast": {"rate": 0}}}, "whole number"),
        ]
        for args, needle in cases:
            pre = await tool(client, {**ref, **args})
            text = json.dumps(pre)
            ok = needle in text and (not pre.get("ok") or bool(pre.get("errors")))
            print(f"  port {args['port']} {needle!r}: {'refused' if ok else 'NOT refused: ' + text[:160]}")
            bad += not ok

        print(f"\n[3] rename port {ADD_PORT}, then reset it")
        out = await apply(client, {**ref, "port": ADD_PORT, "name": TEST_NAME})
        sw = find(await engine._rows(SPEC))
        print(f"  rename: applied={out['applied']} verified={out['verified']} entry={'present' if entry(sw, ADD_PORT) else 'MISSING'}")
        bad += not (out["applied"] and out["verified"] and entry(sw, ADD_PORT) and entry(sw, ADD_PORT)["name"] == TEST_NAME
                    and "guard" in out and out["guard"].get("probe_after") == "ok")
        out = await apply(client, {**ref, "port": ADD_PORT, "reset": True})
        sw = find(await engine._rows(SPEC))
        print(f"  reset: applied={out['applied']} verified={out['verified']} entry={'still present' if entry(sw, ADD_PORT) else 'gone'}")
        bad += not (out["applied"] and out["verified"] and entry(sw, ADD_PORT) is None)

        print(f"\n[4] isolation on, then off, for port {EDIT_PORT}")
        was = bool(state["edit0"].get("isolation"))
        out = await apply(client, {**ref, "port": EDIT_PORT, "isolation": not was})
        print(f"  on: verified={out['verified']} diff={json.dumps(out['diff'])}")
        bad += not (out["verified"] and set(out["diff"]) == {"isolation"})
        out = await apply(client, {**ref, "port": EDIT_PORT, "isolation": was})
        print(f"  off: verified={out['verified']} diff={json.dumps(out['diff'])}")
        bad += not (out["verified"] and set(out["diff"]) == {"isolation"})
        return bad

    async def forced(client: Client, engine: WriteEngine) -> int:
        print(f"\n[5] isolation on for port {EDIT_PORT} with the health guard forced to fail")
        was = bool(state["edit0"].get("isolation"))
        out = await apply(client, {**ref, "port": EDIT_PORT, "isolation": not was})
        g = out.get("guard") or {}
        now = entry(find(await engine._rows(SPEC)), EDIT_PORT)
        print(f"  applied={out['applied']} auto_restored={g.get('auto_restored')} restore_verified={g.get('restore_verified')} "
              f"probe_after_restore={g.get('probe_after_restore')} isolation_now={now.get('isolation')}")
        return int(not (out["applied"] is False and g.get("auto_restored") and g.get("restore_verified")
                        and g.get("probe_after_restore") == "ok" and bool(now.get("isolation")) == was))

    async def finish(client: Client, engine: WriteEngine) -> list[dict[str, Any]]:
        sw = find(await engine._rows(SPEC))
        e12, e14 = entry(sw, ADD_PORT), entry(sw, EDIT_PORT)
        if e12 is not None:
            print(f"\n  cleanup: port {ADD_PORT} still has an entry; resetting it")
            try:
                await apply(client, {**ref, "port": ADD_PORT, "reset": True})
            except Exception as exc:  # noqa: BLE001
                print(f"  RESET FAILED for port {ADD_PORT}: {exc}\n  Fix it in the UI: {SWITCH}, port {ADD_PORT}, remove any override.")
        was = bool(state["edit0"].get("isolation"))
        if e14 is not None and bool(e14.get("isolation")) != was:
            print(f"\n  cleanup: port {EDIT_PORT} isolation is not as found; putting it back")
            try:
                await apply(client, {**ref, "port": EDIT_PORT, "isolation": was})
            except Exception as exc:  # noqa: BLE001
                print(f"  RESTORE FAILED for port {EDIT_PORT}: {exc}\n  Fix it in the UI: {SWITCH}, port {EDIT_PORT}, isolation {was}.")
        return await engine._rows(SPEC)

    try:
        failures += await with_client(base, transport, steps)
        failures += await with_client(dataclasses.replace(base, dns_probe_force_fail=True), transport, forced)
    except Exception as exc:  # noqa: BLE001 - report (an ExceptionGroup is unpacked), then clean up below
        failures += 1
        inner = list(getattr(exc, "exceptions", None) or [exc])
        while inner and hasattr(inner[0], "exceptions"):
            inner = list(inner[0].exceptions)
        print("  ERROR: " + "; ".join(f"{type(e).__name__}: {e}" for e in inner))
    finally:
        final_rows = await with_client(base, transport, finish)
        print("\n[6] compare with the snapshot")
        final = snapshot(final_rows)
        changed = sorted(k for k in set(final) | set(state["snap"]) if final.get(k) != state["snap"].get(k))
        print(f"  switches before={len(state['snap'])} after={len(final)} changed={changed}")
        failures += bool(changed)
    print("\nRESULT:", "all checks passed" if not failures else f"{failures} check(s) FAILED")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main("--run" in sys.argv)))
