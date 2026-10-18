"""Prove the network tool on the real console, using one throwaway VLAN in the empty Dmz zone.

    uv run scripts/network_live_check.py            # dry run: prints the plan, touches nothing
    uv run scripts/network_live_check.py --run      # performs it

SAFETY
  * Goes through the real tool (preview, then confirm with fingerprint and approval note, journal, read-back, safety net),
    in-process. Writes are enabled for THIS process only; the Claude Desktop configuration is not changed.
  * Stops before changing anything unless: no network called zz-netcheck exists, VLAN 3999 and 10.199.99.0/24 are free, the Dmz
    zone exists and has no networks, and DNS works through the gateway.
  * Only zz-netcheck is ever created, changed or deleted. The real networks, SSIDs and switch port settings are previewed in
    refusal cases only, and compared with a snapshot taken at the start.
  * One step runs with the safety net forced to fail, which proves the automatic restore without any real outage.
  * A finally block deletes zz-netcheck if anything left it behind.
"""
from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
import sys
from typing import Any

from mcp.client import Client

from unifi_console_mcp.config import Settings
from unifi_console_mcp.dnsprobe import run_probe
from unifi_console_mcp.entities.network import SPEC
from unifi_console_mcp.server import create_server
from unifi_console_mcp.writes import VOLATILE, WriteEngine

TOOL = "unifi_console_network"
NOTE = "network live check, approved in chat 2026-10-18 (claude/unifi-console-network-plan-2026-10-18.md)"
NAME, VLAN, SUBNET, ZONE = "zz-netcheck", 3999, "10.199.99.1/24", "Dmz"
NEW = {"action": "create", "name": NAME, "vlan": VLAN, "subnet": SUBNET, "zone": ZONE}

PLAN = f"""\
1. snapshot every network, SSID and switch port setting; check that {NAME!r}, VLAN {VLAN} and {SUBNET} are free, that the {ZONE}
   zone has no networks, and that DNS works through the gateway (read only)
2. preview refusals against the real networks (delete LAN_Private, disable LAN_Private, disable and delete a network that SSIDs or
   ports use, a VLAN clash, an overlapping subnet); all must be refused
3. create {NAME!r} in {ZONE}: it must be stored DISABLED (no safety net runs for a disabled network)
4. change its DHCP range and lease (still disabled)
5. enable it, then disable it (each runs the safety net: devices stay connected, DNS works)
6. enable it with the safety net forced to fail: the tool must put it back by itself
7. delete it
8. compare every network, SSID and switch port setting with the snapshot from step 1"""


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


def _h(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()[:12]


async def snapshot(engine: WriteEngine) -> dict[str, dict[str, str]]:
    nets = {str(r["_id"]): _h({k: v for k, v in r.items() if k not in VOLATILE}) for r in await engine._rows(SPEC) if r.get("name") != NAME}
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


def find(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    return next((r for r in rows if r.get("name") == NAME), None)


async def main(run: bool, transport: Any = None) -> int:
    print("Plan:\n" + PLAN)
    if not run:
        print("\nDry run only. Add --run to perform it.")
        return 0
    base = dataclasses.replace(Settings.from_env(), enable_writes=True, write_entities=frozenset({"network"}))
    state: dict[str, Any] = {}

    async def baseline(client: Client, engine: WriteEngine) -> int:
        rows = await engine._rows(SPEC)
        ctx = await engine._context(SPEC)
        print(f"\n[1] baseline: {len([r for r in rows if r.get('purpose') != 'wan'])} LAN networks: "
              f"{', '.join(sorted(str(r.get('name')) for r in rows))}")
        problems = []
        if find(rows):
            problems.append(f"a network called {NAME!r} already exists")
        if any(r.get("vlan") == VLAN for r in rows):
            problems.append(f"VLAN {VLAN} is in use")
        if any(r.get("ip_subnet", "").startswith("10.199.99.") for r in rows):
            problems.append(f"{SUBNET} is in use")
        zone = next((z for z in ctx.get("zones", []) if str(z.get("name")).lower() == ZONE.lower()), None)
        if zone is None:
            problems.append(f"no {ZONE} zone")
        elif zone.get("network_ids"):
            problems.append(f"the {ZONE} zone is not empty")
        probe = await run_probe(engine, window=6.0, attempts=3)
        if probe:
            problems.append(f"DNS probe failed: {probe}")
        if problems:
            print("STOP: " + "; ".join(problems) + ". Nothing was changed.")
            return 1
        state["snap"] = await snapshot(engine)
        state["clash"] = next(r for r in rows if r.get("vlan") and r.get("purpose") == "corporate" and r.get("name") != "LAN_Private")
        print("    snapshot: " + ", ".join(f"{len(v)} {k}" for k, v in state["snap"].items()) + "; DNS probe ok")
        return 0

    if await with_client(base, transport, baseline):
        return 1
    failures = 0

    async def steps(client: Client, engine: WriteEngine) -> int:
        bad = 0
        clash = state["clash"]
        print("\n[2] refusals (previews only)")
        cases: list[tuple[str, dict[str, Any], str]] = [
            ("delete LAN_Private", {"action": "delete", "target": "LAN_Private"}, "cannot be deleted"),
            ("disable LAN_Private", {"action": "disable", "target": "LAN_Private"}, "Infrastructure stop"),
            ("disable LAN_Sonos", {"action": "disable", "target": "LAN_Sonos"}, "Disconnect stop"),
            ("delete LAN_Sonos", {"action": "delete", "target": "LAN_Sonos"}, "In use"),
            ("VLAN clash", {**NEW, "vlan": clash["vlan"]}, f"VLAN {clash['vlan']} is already used"),
            ("subnet overlap", {**NEW, "subnet": clash["ip_subnet"].rsplit(".", 1)[0] + ".9/24"}, "overlaps"),
        ]
        for label, args, needle in cases:
            pre = await tool(client, args)
            text = json.dumps(pre)
            ok = needle in text and (not pre.get("ok") or bool(pre.get("errors")))
            print(f"  {label}: {'refused' if ok else 'NOT refused: ' + text[:160]}")
            bad += not ok

        print(f"\n[3] create {NAME} (must be stored disabled)")
        out = await apply(client, NEW)
        row = find(await engine._rows(SPEC))
        print(f"  applied={out['applied']} verified={out['verified']} enabled={row and row.get('enabled')} zone_ok={bool(row) and row.get('firewall_zone_id') is not None} "
              f"guard={'present' if 'guard' in out else 'none'}")
        bad += not (out["applied"] and out["verified"] and row and row.get("enabled") is False and "guard" not in out)
        if not row:
            return bad + 1

        print("\n[4] change the DHCP range and lease")
        out = await apply(client, {"action": "update", "target": NAME, "dhcp_start": "10.199.99.20", "dhcp_stop": "10.199.99.200", "dhcp_lease_seconds": 43200})
        print(f"  verified={out['verified']} diff={json.dumps(out['diff'])}")
        bad += not (out["verified"] and set(out["diff"]) == {"dhcpd_start", "dhcpd_stop", "dhcpd_leasetime"})

        print("\n[5] enable, then disable (safety net on)")
        for action, want in (("enable", True), ("disable", False)):
            out = await apply(client, {"action": action, "target": NAME})
            now = find(await engine._rows(SPEC))
            print(f"  {action}: verified={out['verified']} enabled={now and now.get('enabled')} guard={out.get('guard')}")
            bad += not (out["verified"] and now and now.get("enabled") is want and (out.get("guard") or {}).get("probe_after") == "ok")
        return bad

    async def forced(client: Client, engine: WriteEngine) -> int:
        print("\n[6] enable with the safety net forced to fail")
        out = await apply(client, {"action": "enable", "target": NAME})
        g = out.get("guard") or {}
        now = find(await engine._rows(SPEC))
        print(f"  applied={out['applied']} auto_restored={g.get('auto_restored')} restore_verified={g.get('restore_verified')} "
              f"probe_after_restore={g.get('probe_after_restore')} enabled_now={now and now.get('enabled')}")
        return int(not (out["applied"] is False and g.get("auto_restored") and g.get("restore_verified") and now and now.get("enabled") is False))

    async def delete(client: Client, engine: WriteEngine) -> int:
        print("\n[7] delete")
        out = await apply(client, {"action": "delete", "target": NAME})
        gone = find(await engine._rows(SPEC)) is None
        print(f"  applied={out['applied']} verified={out['verified']} gone={gone}")
        return int(not (out["applied"] and out["verified"] and gone))

    async def finish(client: Client, engine: WriteEngine) -> dict[str, dict[str, str]]:
        row = find(await engine._rows(SPEC))
        if row is not None:
            print(f"\n  cleanup: {NAME} still exists; deleting it")
            try:
                await apply(client, {"action": "delete", "target": NAME, "acknowledge_disconnect": True})
            except Exception as exc:  # noqa: BLE001
                print(f"  DELETE FAILED: {exc}\n  Remove the network {NAME!r} in the UI (Settings, Networks).")
        return await snapshot(engine)

    try:
        failures += await with_client(base, transport, steps)
        failures += await with_client(dataclasses.replace(base, dns_probe_force_fail=True), transport, forced)
        failures += await with_client(base, transport, delete)
    except Exception as exc:  # noqa: BLE001 - report (an ExceptionGroup is unpacked), then clean up below
        failures += 1
        inner = list(getattr(exc, "exceptions", None) or [exc])
        while inner and hasattr(inner[0], "exceptions"):
            inner = list(inner[0].exceptions)
        print("  ERROR: " + "; ".join(f"{type(e).__name__}: {e}" for e in inner))
    finally:
        final = await with_client(base, transport, finish)
        print("\n[8] compare with the snapshot")
        for kind, before in state["snap"].items():
            changed = sorted(k for k in set(final[kind]) | set(before) if final[kind].get(k) != before.get(k))
            print(f"  {kind}: before={len(before)} after={len(final[kind])} changed={changed}")
            failures += bool(changed)
    print("\nRESULT:", "all checks passed" if not failures else f"{failures} check(s) FAILED")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main("--run" in sys.argv)))
