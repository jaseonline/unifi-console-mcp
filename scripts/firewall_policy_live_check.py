"""Prove the firewall policy tool on the real console, using only the Dmz -> Vpn zone pair (no networks in either zone).

    uv run scripts/firewall_policy_live_check.py            # dry run: prints the plan, touches nothing
    uv run scripts/firewall_policy_live_check.py --run      # performs it

SAFETY
  * Goes through the real tool (preview, then confirm with fingerprint and approval note, journal, read-back), in-process.
    Writes are enabled for THIS process only; the Claude Desktop configuration is not changed.
  * Stops unless the Dmz and Vpn zones both exist and contain no networks: then no traffic can ever match a policy between
    them, so even an enabled throwaway policy changes nothing on the network.
  * Only policies named zz-fwcheck-* are created, edited, moved and deleted. Real policies are never touched; the final
    state is compared with a snapshot of every policy taken at the start (hit counters ignored).
  * Step 7 uses UNIFI_CONSOLE_DNS_PROBE_FORCE_FAIL (this process only) to make the DNS probe report a failure after enabling,
    which proves the automatic restore for this entity without any real outage.
  * A finally block deletes any leftover zz-fwcheck-* policy.
"""
from __future__ import annotations

import asyncio
import dataclasses
import json
import sys
from typing import Any

from mcp.client import Client

from unifi_console_mcp.config import Settings
from unifi_console_mcp.dnsprobe import run_probe
from unifi_console_mcp.entities.firewall_policy import SPEC
from unifi_console_mcp.server import create_server
from unifi_console_mcp.writes import WriteEngine

TOOL = "unifi_console_firewall_policy"
NOTE = "firewall policy live check, approved in chat 2026-10-18 (claude/unifi-console-firewall-policy-plan-2026-10-18.md)"
A, B = "zz-fwcheck-a", "zz-fwcheck-b"
VOLATILE = ("hits", "last_hit")

PLAN = """\
1. snapshot every policy; check that Dmz and Vpn have no networks; run the DNS probe (read only)
2. preview five bad requests (a system policy, a "(Return)" policy, an External ALLOW that matches everything, an unknown zone,
   a bad port); all must be refused
3. create zz-fwcheck-a in Dmz -> Vpn (ALLOW tcp 65000, switched off): check the read-back
4. edit its description and logging: the diff must show only those two
5. enable it, then disable it (batch endpoint): check each read-back and the probe
6. create zz-fwcheck-b; move it first, then last (reorder endpoint): check the order each time
7. enable zz-fwcheck-a with the probe forced to fail: the tool must switch it back off by itself (auto_restored)
8. delete both (batch-delete endpoint)
9. compare every policy with the snapshot from step 1"""


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
    return {str(r["_id"]): json.dumps({k: v for k, v in r.items() if k not in VOLATILE}, sort_keys=True) for r in rows}


async def with_client(settings: Settings, transport: Any, fn: Any) -> Any:
    mcp, api = create_server(settings, transport=transport)
    try:
        async with Client(mcp) as client:
            return await fn(client, WriteEngine(api))
    finally:
        await api.client.aclose()


def mine(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [r for r in rows if str(r.get("name", "")).startswith("zz-fwcheck-")]


def order(rows: list[dict[str, Any]], z_src: str, z_dst: str) -> list[str]:
    g = [r for r in rows if not r.get("predefined") and r["source"]["zone_id"] == z_src and r["destination"]["zone_id"] == z_dst]
    return [str(r["name"]) for r in sorted(g, key=lambda r: r["index"])]


async def main(run: bool, transport: Any = None) -> int:
    print("Plan:\n" + PLAN)
    if not run:
        print("\nDry run only. Add --run to perform it.")
        return 0
    base = dataclasses.replace(Settings.from_env(), enable_writes=True, write_entities=frozenset({"firewall_policy"}))
    failures = 0
    state: dict[str, Any] = {}

    async def baseline(client: Client, engine: WriteEngine) -> int:
        rows = await engine._rows(SPEC)
        zones = await engine._read_list("listFirewallZones")
        by = {z["name"]: z for z in zones}
        print("\n[1] baseline")
        if "Dmz" not in by or "Vpn" not in by or by["Dmz"].get("network_ids") or by["Vpn"].get("network_ids"):
            print("STOP: Dmz and Vpn must both exist and have no networks. Nothing was changed.")
            return 1
        if mine(rows):
            print("STOP: zz-fwcheck-* policies already exist. Delete them first. Nothing was changed.")
            return 1
        state.update(snap=snapshot(rows), dmz=by["Dmz"]["_id"], vpn=by["Vpn"]["_id"], rows=rows)
        probe = await run_probe(engine, window=5.0)
        print(f"    {len(rows)} policies; Dmz and Vpn have no networks; DNS probe: {probe or 'ok'}")
        return int(probe is not None)

    stop = await with_client(base, transport, baseline)
    if stop:
        return 1
    dmz, vpn, rows0 = state["dmz"], state["vpn"], state["rows"]
    a_args = {"name": A, "policy_action": "ALLOW", "protocol": "tcp", "allow_return": False, "logging": False,
              "source": {"zone": "Dmz"}, "destination": {"zone": "Vpn", "ports": "65000"}}
    b_args = {**a_args, "name": B}

    async def steps(client: Client, engine: WriteEngine) -> int:
        bad = 0
        print("\n[2] refusals")
        sysrow = next((r for r in rows0 if r.get("predefined") and r["source"]["zone_id"] == dmz and r["destination"]["zone_id"] == vpn), None)
        ret = next((r for r in rows0 if r.get("origin_type") == "custom_firewall_rule"), None)
        cases: list[tuple[dict[str, Any], str]] = [
            ({"action": "update", "target": (sysrow or {}).get("_id", "x"), "description": "x"}, "system-defined"),
            ({"action": "update", "target": (ret or {}).get("_id", "x"), "description": "x"}, "system-defined"),
            ({"action": "create", "name": "zz-fwcheck-open", "policy_action": "ALLOW", "enabled": True,
              "source": {"zone": "External"}, "destination": {"zone": "Internal"}}, "Exposure stop"),
            ({"action": "create", "name": "zz-fwcheck-x", "source": {"zone": "Nowhere"}, "destination": {"zone": "Vpn"}}, "not a zone"),
            ({"action": "create", **{**a_args, "name": "zz-fwcheck-x", "destination": {"zone": "Vpn", "ports": "99999"}}}, "ports"),
        ]
        for args, needle in cases:
            res = await client.call_tool(TOOL, {"params": args})
            text = res.content[0].text
            ok = needle in text
            print(f"  {needle!r}: {'refused' if ok else 'NOT refused: ' + text[:140]}")
            bad += not ok
        if sysrow is None or ret is None:
            print("  (no system policy in Dmz -> Vpn, or no \"(Return)\" policy, to test against)")
            bad += 1

        print("\n[3] create a")
        out = await apply(client, {"action": "create", **a_args})
        print(f"  applied={out['applied']} verified={out['verified']} http={out['http_status']} id={out['id']}")
        bad += not (out["applied"] and out["verified"] and "guard" not in out)

        print("\n[4] edit description and logging")
        out = await apply(client, {"action": "update", "target": A, "description": "live check", "logging": True})
        print(f"  verified={out['verified']} diff={json.dumps(out['diff'])}")
        bad += not (out["verified"] and set(out["diff"]) == {"description", "logging"})

        print("\n[5] enable, then disable")
        out = await apply(client, {"action": "enable", "target": A})
        print(f"  enable: verified={out['verified']} guard={json.dumps(out.get('guard'))}")
        bad += not (out["verified"] and out["guard"].get("probe_after") == "ok")
        out = await apply(client, {"action": "disable", "target": A})
        print(f"  disable: verified={out['verified']} guard={json.dumps(out.get('guard'))}")
        bad += not out["verified"]

        print("\n[6] create b, move it first then last")
        out = await apply(client, {"action": "create", **b_args})
        bad += not out["verified"]
        for pos in ("first", "last"):
            out = await apply(client, {"action": "move", "target": B, "position": pos})
            now = order(await engine._rows(SPEC), dmz, vpn)
            print(f"  move {pos}: verified={out['verified']} order={now}")
            mine_now = [n for n in now if n in (A, B)]
            want = [B, A] if pos == "first" else [A, B]
            edge = (now[0] == B) if pos == "first" else (now[-1] == B)
            bad += not (out["verified"] and mine_now == want and edge)
        return bad

    async def forced(client: Client, engine: WriteEngine) -> int:
        print("\n[7] enable a with the probe forced to fail")
        out = await apply(client, {"action": "enable", "target": A})
        g = out.get("guard") or {}
        now = next(r for r in await engine._rows(SPEC) if r["name"] == A)
        print(f"  applied={out['applied']} auto_restored={g.get('auto_restored')} restore_verified={g.get('restore_verified')} "
              f"probe_after_restore={g.get('probe_after_restore')} enabled_now={now['enabled']}")
        return int(not (out["applied"] is False and g.get("auto_restored") and g.get("restore_verified")
                        and g.get("probe_after_restore") == "ok" and now["enabled"] is False))

    async def finish(client: Client, engine: WriteEngine) -> list[dict[str, Any]]:
        print("\n[8] delete both")
        for name in (A, B):
            if any(r["name"] == name for r in await engine._rows(SPEC)):
                try:
                    out = await apply(client, {"action": "delete", "target": name})
                    print(f"  {name}: applied={out['applied']} verified={out['verified']}")
                except Exception as exc:  # noqa: BLE001
                    print(f"  DELETE FAILED for {name}: {exc}\n  Delete it in the UI: Settings > Policy Table, zone pair Dmz -> Vpn.")
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
        print("\n[9] compare with the snapshot")
        final = snapshot(final_rows)
        gone = sorted(set(state["snap"]) - set(final))
        added = sorted(set(final) - set(state["snap"]))
        changed = sorted(k for k in set(final) & set(state["snap"]) if final[k] != state["snap"][k])
        print(f"  policies before={len(state['snap'])} after={len(final)} missing={gone} extra={added} changed={changed}")
        failures += bool(gone or added or changed)
    print("\nRESULT:", "all checks passed" if not failures else f"{failures} check(s) FAILED")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main("--run" in sys.argv)))
