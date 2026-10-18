"""Prove the Wi-Fi tool on the real console, using one throwaway SSID that is never enabled for more than a few seconds.

    uv run scripts/wifi_live_check.py            # dry run: prints the plan, touches nothing
    uv run scripts/wifi_live_check.py --run      # performs it

SAFETY
  * Goes through the real tool (preview, then confirm with fingerprint and approval note, journal, read-back), in-process.
    Writes are enabled for THIS process only; the Claude Desktop configuration is not changed.
  * Only the throwaway SSID `zz-wificheck` is ever created, changed or deleted. It is created DISABLED on LAN_Private with a
    random passphrase held only in this process's environment (never printed), enabled for a few seconds, then deleted.
    The real SSIDs are previewed in refusal cases only, and compared with a snapshot taken at the start.
  * Stops before changing anything if an SSID called zz-wificheck already exists or LAN_Private cannot be found.
  * A finally block deletes the throwaway SSID if anything left it behind.
"""
from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
import os
import secrets
import sys
from typing import Any

from mcp.client import Client

from unifi_console_mcp.config import Settings
from unifi_console_mcp.entities.wifi import SPEC
from unifi_console_mcp.server import create_server
from unifi_console_mcp.writes import VOLATILE, WriteEngine

TOOL = "unifi_console_wifi"
NOTE = "wifi live check, approved in chat 2026-10-18 (claude/unifi-console-wifi-plan-2026-10-18.md)"
NAME, NETWORK = "zz-wificheck", "LAN_Private"
ENV_A, ENV_B = "UNIFI_WIFI_CHECK_A", "UNIFI_WIFI_CHECK_B"
LIVE_SECONDS = 5

PLAN = f"""\
1. snapshot every SSID; check that {NAME!r} does not exist and {NETWORK!r} does (read only)
2. preview bad requests (open without acknowledgement, unknown network, duplicate name, missing passphrase variable,
   existing WPA SSID to open); all must be refused
3. create {NAME!r} on {NETWORK}, WPA2, random passphrase from a process-only variable: it must be stored DISABLED
4. hide the SSID and show it again; change the passphrase (write-only, so only applied is checked)
5. enable it, wait {LIVE_SECONDS} seconds, disable it
6. delete it
7. compare every real SSID with the snapshot from step 1"""


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
    """A hash per SSID (secrets included in the hash only), so nothing sensitive is printed."""
    return {str(r["_id"]): hashlib.sha256(json.dumps({k: v for k, v in r.items() if k not in VOLATILE}, sort_keys=True).encode()).hexdigest()[:12]
            for r in rows if r.get("name") != NAME}


async def with_client(settings: Settings, transport: Any, fn: Any) -> Any:
    mcp, api = create_server(settings, transport=transport)
    try:
        async with Client(mcp) as client:
            return await fn(client, WriteEngine(api))
    finally:
        await api.client.aclose()


def find(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    return next((r for r in rows if r.get("name") == NAME), None)


async def main(run: bool, transport: Any = None, pause: float = LIVE_SECONDS) -> int:
    print("Plan:\n" + PLAN)
    if not run:
        print("\nDry run only. Add --run to perform it.")
        return 0
    os.environ[ENV_A], os.environ[ENV_B] = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    base = dataclasses.replace(Settings.from_env(), enable_writes=True, write_entities=frozenset({"wifi"}))
    state: dict[str, Any] = {}

    async def baseline(client: Client, engine: WriteEngine) -> int:
        rows = await engine._rows(SPEC)
        ctx = await engine._context(SPEC)
        print(f"\n[1] baseline: {len(rows)} SSIDs: {', '.join(sorted(str(r.get('name')) for r in rows))}")
        if find(rows):
            print(f"STOP: an SSID called {NAME!r} already exists. Nothing was changed.")
            return 1
        if not any(n.get("name") == NETWORK and n.get("purpose") != "wan" for n in ctx.get("networks", [])):
            print(f"STOP: no network called {NETWORK!r}. Nothing was changed.")
            return 1
        state["snap"] = snapshot(rows)
        return 0

    if await with_client(base, transport, baseline):
        return 1
    failures = 0
    good = {"network": NETWORK, "security": "wpa2", "passphrase_env": ENV_A}

    async def steps(client: Client, engine: WriteEngine) -> int:
        bad = 0
        print("\n[2] refusals (previews only)")
        cases: list[tuple[str, dict[str, Any], str]] = [
            ("open without acknowledgement", {"action": "create", "name": NAME, "network": NETWORK, "security": "open"}, "Open security stop"),
            ("unknown network", {"action": "create", "name": NAME, **{**good, "network": "No Such Network"}}, "not a network"),
            ("duplicate name", {"action": "create", "name": "ExampleNet", **good}, "already called"),
            ("missing variable", {"action": "create", "name": NAME, **{**good, "passphrase_env": "UNIFI_WIFI_NOT_SET_ANYWHERE"}}, "is not set"),
            ("wpa to open", {"action": "update", "target": "ExampleNet", "security": "open"}, "not offered"),
        ]
        for label, args, needle in cases:
            pre = await tool(client, args)
            text = json.dumps(pre)
            ok = needle in text and (not pre.get("ok") or bool(pre.get("errors")))
            print(f"  {label}: {'refused' if ok else 'NOT refused: ' + text[:160]}")
            bad += not ok

        print(f"\n[3] create {NAME} (must be stored disabled)")
        out = await apply(client, {"action": "create", "name": NAME, **good})
        row = find(await engine._rows(SPEC))
        print(f"  applied={out['applied']} verified={out['verified']} enabled={row and row.get('enabled')} "
              f"network_ok={bool(row) and row.get('networkconf_id') is not None} secrets_not_verified={out.get('secret_fields_not_verified')}")
        bad += not (out["applied"] and out["verified"] and row and row.get("enabled") is False and row.get("security") == "wpapsk")
        if not row:
            return bad + 1

        print("\n[4] hide and show; change the passphrase")
        for want in (True, False):
            out = await apply(client, {"action": "update", "target": NAME, "hide_ssid": want})
            print(f"  hide_ssid={want}: verified={out['verified']} diff={json.dumps(out['diff'])}")
            bad += not (out["verified"] and set(out["diff"]) == {"hide_ssid"})
        out = await apply(client, {"action": "update", "target": NAME, "passphrase_env": ENV_B})
        print(f"  passphrase: applied={out['applied']} secret_fields_not_verified={out.get('secret_fields_not_verified')}")
        bad += not (out["applied"] and "x_passphrase" in (out.get("secret_fields_not_verified") or []))

        print(f"\n[5] enable for {pause:g} seconds, then disable")
        out = await apply(client, {"action": "enable", "target": NAME})
        now = find(await engine._rows(SPEC))
        print(f"  enable: verified={out['verified']} enabled={now and now.get('enabled')}")
        bad += not (out["verified"] and now and now.get("enabled") is True)
        await asyncio.sleep(pause)
        out = await apply(client, {"action": "disable", "target": NAME})
        now = find(await engine._rows(SPEC))
        print(f"  disable: verified={out['verified']} enabled={now and now.get('enabled')}")
        bad += not (out["verified"] and now and now.get("enabled") is False)

        print("\n[6] delete")
        out = await apply(client, {"action": "delete", "target": NAME})
        gone = find(await engine._rows(SPEC)) is None
        print(f"  applied={out['applied']} verified={out['verified']} gone={gone}")
        bad += not (out["applied"] and out["verified"] and gone)
        return bad

    async def finish(client: Client, engine: WriteEngine) -> list[dict[str, Any]]:
        row = find(await engine._rows(SPEC))
        if row is not None:
            print(f"\n  cleanup: {NAME} still exists; deleting it")
            try:
                await apply(client, {"action": "delete", "target": NAME, "acknowledge_disconnect": True})
            except Exception as exc:  # noqa: BLE001
                print(f"  DELETE FAILED: {exc}\n  Remove the SSID {NAME!r} in the UI (Settings, WiFi).")
        return await engine._rows(SPEC)

    try:
        failures += await with_client(base, transport, steps)
    except Exception as exc:  # noqa: BLE001 - report (an ExceptionGroup is unpacked), then clean up below
        failures += 1
        inner = list(getattr(exc, "exceptions", None) or [exc])
        while inner and hasattr(inner[0], "exceptions"):
            inner = list(inner[0].exceptions)
        print("  ERROR: " + "; ".join(f"{type(e).__name__}: {e}" for e in inner))
    finally:
        final_rows = await with_client(base, transport, finish)
        print("\n[7] compare the real SSIDs with the snapshot")
        final = snapshot(final_rows)
        changed = sorted(k for k in set(final) | set(state["snap"]) if final.get(k) != state["snap"].get(k))
        print(f"  SSIDs before={len(state['snap'])} after={len(final)} changed={changed}")
        failures += bool(changed)
        for name in (ENV_A, ENV_B):
            os.environ.pop(name, None)
    print("\nRESULT:", "all checks passed" if not failures else f"{failures} check(s) FAILED")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main("--run" in sys.argv)))
