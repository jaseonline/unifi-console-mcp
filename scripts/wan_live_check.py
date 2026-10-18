"""Prove the WAN tool on the real console, using one harmless setting (`report_wan_event`) on the real WAN.

    uv run scripts/wan_live_check.py            # dry run: prints the plan, touches nothing
    uv run scripts/wan_live_check.py --run      # performs it

SAFETY
  * Goes through the real tool (preview, then confirm with fingerprint and approval note, journal, read-back, safety net),
    in-process. Writes are enabled for THIS process only; the Claude Desktop configuration is not changed.
  * Stops before changing anything unless: there is exactly one WAN, the gateway is connected, the WAN reports ok, the internet
    probe and DNS work, and every adopted device is connected.
  * The only field ever changed is `report_wan_event` (whether the console raises WAN events). It carries no traffic, but every
    save makes the gateway re-provision (about 20 seconds) and the internet may drop briefly. Run it when nobody is on a call.
  * One step runs with the safety net forced to fail, which proves the automatic restore.
  * A finally block puts `report_wan_event` back to its original value if anything left it changed.
"""
from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
import sys
import time
from typing import Any

from mcp.client import Client

from unifi_console_mcp.config import Settings
from unifi_console_mcp.dnsprobe import run_probe
from unifi_console_mcp.entities.wan import GATEWAY_TYPES, SPEC, _internet_ok
from unifi_console_mcp.server import create_server
from unifi_console_mcp.writes import VOLATILE, WriteEngine

TOOL = "unifi_console_wan"
NOTE = "WAN live check, approved in chat 2026-10-18 (claude/unifi-console-wan-plan-2026-10-18.md)"

PLAN = """\
1. snapshot every network (WAN included), SSID and switch port setting; check there is exactly one WAN, the gateway is connected,
   the WAN reports ok, the internet probe and DNS work and every adopted device is connected (read only)
2. preview refusals: an identity change without the acknowledgement, a manual DNS preference with no server, a LAN network aimed at
   the WAN tool, delete and disable of the WAN through the network tool, an unknown field, a create; all must be refused
3. flip report_wan_event on the real WAN with the safety net on: the gateway re-provisions, comes back, every device stays connected,
   the WAN reports ok, the internet and DNS work (about 20 to 40 seconds)
4. flip it back, same checks
5. flip it again with the safety net forced to fail: the tool must put it back by itself and check again
6. compare every network, SSID and switch port setting with the snapshot from step 1"""


async def tool(client: Client, args: dict[str, Any], name: str = TOOL) -> dict[str, Any]:
    res = await client.call_tool(name, {"params": args})
    text = res.content[0].text
    try:
        return json.loads(text)
    except ValueError:
        return {"ok": False, "error": text}


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


def _h(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()[:12]


async def snapshot(engine: WriteEngine) -> dict[str, dict[str, str]]:
    nets = {str(r["_id"]): _h({k: v for k, v in r.items() if k not in VOLATILE}) for r in await engine._rows(SPEC)}
    wlans = {str(r["_id"]): _h(r) for r in await engine._read_list("listWlanConfigLegacy")}
    ports = {str(r["_id"]): _h(sorted(r.get("port_overrides") or [], key=lambda e: e.get("port_idx", 0)))
             for r in await engine._read_list("listDevicesDetailed") if r.get("type") == "usw"}
    return {"networks": nets, "ssids": wlans, "switch ports": ports}


async def with_client(settings: Settings, transport: Any, fn: Any) -> Any:
    mcp, api = create_server(settings, transport=transport)
    try:
        async with Client(mcp) as client:
            return await fn(client, WriteEngine(api))
    finally:
        await api.client.aclose()


async def the_wan(engine: WriteEngine) -> dict[str, Any] | None:
    wans = [r for r in await engine._rows(SPEC) if r.get("purpose") == "wan"]
    return wans[0] if len(wans) == 1 else None


async def gateway(engine: WriteEngine) -> dict[str, Any]:
    rows = await engine._read_list("listDevicesDetailed")
    return next((r for r in rows if r.get("type") in GATEWAY_TYPES), {})


async def main(run: bool, transport: Any = None) -> int:
    print("Plan:\n" + PLAN)
    if not run:
        print("\nDry run only. Add --run to perform it.")
        return 0
    base = dataclasses.replace(Settings.from_env(), enable_writes=True, write_entities=frozenset({"wan", "network"}))
    state: dict[str, Any] = {}

    async def baseline(client: Client, engine: WriteEngine) -> int:
        rows = await engine._rows(SPEC)
        wans = [r for r in rows if r.get("purpose") == "wan"]
        print(f"\n[1] baseline: {len(rows)} networks, {len(wans)} WAN")
        problems = []
        if len(wans) != 1:
            problems.append(f"expected exactly one WAN, found {len(wans)}")
        gw = await gateway(engine)
        if gw.get("state") != 1:
            problems.append("the gateway is not connected")
        down = [str(d.get("name") or d.get("mac")) for d in await engine._read_list("listDevicesBasic") if d.get("adopted", True) and d.get("state") != 1]
        if down:
            problems.append("devices not connected: " + ", ".join(down))
        for h in await engine._read_list("getSiteHealth"):
            if h.get("subsystem") == "wan" and str(h.get("status")) != "ok":
                problems.append(f"the WAN reports {h.get('status')}")
        if not await _internet_ok():
            problems.append("the internet probe fails")
        probe = await run_probe(engine, window=6.0, attempts=3)
        if probe:
            problems.append(f"DNS probe failed: {probe}")
        if problems:
            print("STOP: " + "; ".join(problems) + ". Nothing was changed.")
            return 1
        wan = wans[0]
        state.update(snap=await snapshot(engine), name=wan["name"], original=bool(wan.get("report_wan_event")), prov=gw.get("provisioned_at"))
        print(f"    {wan['name']}: report_wan_event={state['original']}; gateway provisioned_at={state['prov']}; internet, DNS and all devices ok")
        return 0

    if await with_client(base, transport, baseline):
        return 1
    failures = 0
    name, original = state["name"], state["original"]

    async def refusals(client: Client, engine: WriteEngine) -> int:
        bad = 0
        print("\n[2] refusals (previews only)")
        cases: list[tuple[str, str, dict[str, Any], str]] = [
            ("identity without acknowledgement", TOOL, {"target": name, "mac_override_enabled": False}, "Identity stop"),
            ("manual DNS with no server", TOOL, {"target": name, "dns_preference": "manual"}, "first server"),
            ("a LAN network on the WAN tool", TOOL, {"target": "LAN_Private", "report_wan_event": True}, "unifi_console_network"),
            ("delete the WAN (network tool)", "unifi_console_network", {"action": "delete", "target": name}, "cannot be deleted"),
            ("disable the WAN (network tool)", "unifi_console_network", {"action": "disable", "target": name}, "unifi_console_wan"),
            ("unknown field", TOOL, {"target": name, "x_uplink_password": "a"}, "Extra inputs"),
            ("create", TOOL, {"action": "create", "target": name}, "update"),
        ]
        for label, tool_name, args, needle in cases:
            pre = await tool(client, args, tool_name)
            text = json.dumps(pre)
            ok = needle in text and (not pre.get("ok") or bool(pre.get("errors")))
            print(f"  {label}: {'refused' if ok else 'NOT refused: ' + text[:160]}")
            bad += not ok
        return bad

    async def flip(client: Client, engine: WriteEngine, want: bool, label: str) -> int:
        print(f"\n{label}")
        t0 = time.monotonic()
        out = await apply(client, {"target": name, "report_wan_event": want})
        took = time.monotonic() - t0
        now = await the_wan(engine)
        gw = await gateway(engine)
        g = out.get("guard") or {}
        print(f"  applied={out['applied']} verified={out['verified']} report_wan_event={now and now.get('report_wan_event')} guard={g.get('probe_after')} "
              f"gateway_state={gw.get('state')} provisioned_at={gw.get('provisioned_at')} took={took:.0f}s diff={json.dumps(out['diff'])}")
        return int(not (out["applied"] and out["verified"] and g.get("probe_after") == "ok" and now and bool(now.get("report_wan_event")) is want
                        and gw.get("state") == 1 and set(out["diff"]) == {"report_wan_event"}))

    async def forced(client: Client, engine: WriteEngine) -> int:
        print("\n[5] flip with the safety net forced to fail")
        t0 = time.monotonic()
        out = await apply(client, {"target": name, "report_wan_event": not original})
        g = out.get("guard") or {}
        now = await the_wan(engine)
        gw = await gateway(engine)
        print(f"  applied={out['applied']} auto_restored={g.get('auto_restored')} restore_verified={g.get('restore_verified')} "
              f"probe_after_restore={g.get('probe_after_restore')} report_wan_event_now={now and now.get('report_wan_event')} "
              f"gateway_state={gw.get('state')} took={time.monotonic() - t0:.0f}s")
        return int(not (out["applied"] is False and g.get("auto_restored") and g.get("restore_verified") and g.get("probe_after_restore") == "ok"
                        and now and bool(now.get("report_wan_event")) is original and gw.get("state") == 1))

    async def finish(client: Client, engine: WriteEngine) -> dict[str, dict[str, str]]:
        now = await the_wan(engine)
        if now is not None and bool(now.get("report_wan_event")) is not original:
            print(f"\n  cleanup: report_wan_event is {now.get('report_wan_event')}; putting it back to {original}")
            try:
                await apply(client, {"target": name, "report_wan_event": original})
            except Exception as exc:  # noqa: BLE001
                print(f"  RESTORE FAILED: {exc}\n  Set the WAN event reporting back by hand in the UI (Settings, Internet).")
        return await snapshot(engine)

    try:
        failures += await with_client(base, transport, refusals)
        failures += await with_client(base, transport, lambda c, e: flip(c, e, not original, f"[3] flip report_wan_event to {not original} (safety net on)"))
        failures += await with_client(base, transport, lambda c, e: flip(c, e, original, f"[4] flip it back to {original}"))
        failures += await with_client(dataclasses.replace(base, dns_probe_force_fail=True), transport, forced)
    except Exception as exc:  # noqa: BLE001 - report (an ExceptionGroup is unpacked), then clean up below
        failures += 1
        inner = list(getattr(exc, "exceptions", None) or [exc])
        while inner and hasattr(inner[0], "exceptions"):
            inner = list(inner[0].exceptions)
        print("  ERROR: " + "; ".join(f"{type(e).__name__}: {e}" for e in inner))
    finally:
        final = await with_client(base, transport, finish)
        print("\n[6] compare with the snapshot")
        for kind, before in state["snap"].items():
            changed = sorted(k for k in set(final[kind]) | set(before) if final[kind].get(k) != before.get(k))
            print(f"  {kind}: before={len(before)} after={len(final[kind])} changed={changed}")
            failures += bool(changed)
    print("\nRESULT:", "all checks passed" if not failures else f"{failures} check(s) FAILED")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main("--run" in sys.argv)))
