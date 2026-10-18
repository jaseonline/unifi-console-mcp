"""Prove the 2026-10-18 additions on the real console, each one reversible.

    uv run scripts/gap_closure_live_check.py                                   # dry run: prints the plan, touches nothing
    uv run scripts/gap_closure_live_check.py --run                             # IPv6 list, port forward source limit, syslog, retention, logging levels
    uv run scripts/gap_closure_live_check.py --run --client-mac AA:BB:..       # also block then unblock that client
    uv run scripts/gap_closure_live_check.py --run --reconnect-mac AA:BB:..    # also kick that connected wireless client once
    uv run scripts/gap_closure_live_check.py --run --include-doh               # also DoH Auto, then the original state back

SAFETY
  * Goes through the real tools (preview, confirm with the fingerprint, journal, read-back), in-process. Writes are enabled for
    THIS process only; the Claude Desktop server configuration is not changed.
  * Creates only "zz-gapcheck*" objects: an IPv6 list, and a port forward that stays DISABLED (so nothing is exposed). Both are
    deleted in a finally block, and leftovers are removed first.
  * Syslog: switches `debug` on and then back to the original value. The destination is never touched.
  * Data retention: raises the 5-minute statistics retention by one hour and puts the original value back. Nothing is shortened
    below the original. Skipped unless the group is in manual mode.
  * Logging levels: sets sdn to debug and then back to auto/warn (the console's defaults; the current levels cannot be read).
  * Clients: the named client is blocked and unblocked in a finally block; pick one that is not essential. Forget is never run.
  * DoH Auto (tier C, only with --include-doh): runs through the tool's DNS safety net, then restores the original state.
  * Dynamic DNS update is not run live: the real Cloudflare entry has never been touched. Prints names and short values only.
"""
from __future__ import annotations

import asyncio
import dataclasses
import json
import sys
from typing import Any

from mcp.client import Client

from unifi_console_mcp.config import Settings
from unifi_console_mcp.entities import doh, network_list, port_forward, site_settings
from unifi_console_mcp.server import create_server
from unifi_console_mcp.writes import WriteEngine

PREFIX = "zz-gapcheck"
NOTE = "gap closure live check, approved in chat 2026-10-18"
ENTITIES = frozenset({"network_list", "port_forward", "syslog", "data_retention", "logging_levels", "client", "doh"})

PLAN = f"""\
1. IPv6 list: create "{PREFIX}-v6" (two members), add one member, delete; check read-backs
2. port forward: create "{PREFIX}-pf" DISABLED with source limiting (142.250.0.0/15), check the stored src fields, delete
3. syslog: debug on, then back to the original value (the destination is not touched)
4. data retention (manual mode only): 5-minute hours +1, then the original back; the Maps key never appears
5. logging levels: sdn debug, then the console's defaults (auto, warn)
6. optional --client-mac: block then unblock that client (read back each time)
7. optional --reconnect-mac: kick that connected wireless client once
8. optional --include-doh: DoH Auto, then the original state back (tier C, behind the DNS safety net)"""


async def call(client: Client, tool: str, args: dict[str, Any]) -> dict[str, Any]:
    res = await client.call_tool(tool, {"params": args})
    return json.loads(res.content[0].text)


async def apply(client: Client, tool: str, args: dict[str, Any], note: str | None = None) -> dict[str, Any]:
    extra = {"approval_note": note} if note else {}
    pre = await call(client, tool, {**args, **extra})
    if not pre.get("ok"):
        raise RuntimeError(f"preview failed: {pre.get('error')}")
    if pre["errors"] or pre["apply_blocked_reason"]:
        raise RuntimeError(f"preview not applicable: {pre['errors'] or pre['apply_blocked_reason']}")
    out = await call(client, tool, {**args, **extra, "confirm": True, "fingerprint": pre["fingerprint"]})
    if not out.get("ok"):
        raise RuntimeError(f"apply failed: {out.get('error')}")
    out["_preview"] = pre
    return out


def show(label: str, out: dict[str, Any]) -> bool:
    ok = out.get("verified") is not False
    print(f"  {label}: applied={out.get('applied')} verified={out.get('verified')} journal={out.get('journal_id')}")
    return ok


async def lists_section(client: Client, engine: WriteEngine) -> int:
    print("\n[1] IPv6 network list")
    tool, fails, new_id = "unifi_console_network_list", 0, None
    for r in await engine._rows(network_list.SPEC):
        if str(r.get("name", "")).startswith(PREFIX):
            show(f"removed leftover {r['name']}", await apply(client, tool, {"action": "delete", "target": r["_id"]}))
    try:
        out = await apply(client, tool, {"action": "create", "name": f"{PREFIX}-v6", "group_type": "ipv6-address-group",
                                         "group_members": ["2001:db8::1", "2001:db8:1::/48"]})
        new_id = out["id"]
        fails += not show("create", out)
        out = await apply(client, tool, {"action": "update", "target": new_id, "add_members": ["2001:db8::2"]})
        fails += not show("add member", out)
        stored = next(r for r in await engine._rows(network_list.SPEC) if r["_id"] == new_id)
        fails += stored["group_members"] != ["2001:db8::1", "2001:db8:1::/48", "2001:db8::2"]
        out = await apply(client, tool, {"action": "delete", "target": new_id})
        new_id = None
        fails += not show("delete", out)
    finally:
        if new_id:
            try:
                show("cleanup delete", await apply(client, tool, {"action": "delete", "target": new_id}))
            except Exception as exc:  # noqa: BLE001
                fails += 1
                print(f"  CLEANUP FAILED, delete '{PREFIX}-v6' by hand: {exc}")
    return fails


async def portfwd_section(client: Client, engine: WriteEngine) -> int:
    print("\n[2] port forward source limiting (rule stays disabled)")
    tool, fails, new_id = "unifi_console_port_forward", 0, None
    for r in await engine._rows(port_forward.SPEC):
        if str(r.get("name", "")).startswith(PREFIX):
            show(f"removed leftover {r['name']}", await apply(client, tool, {"action": "delete", "target": r["_id"]}))
    try:
        out = await apply(client, tool, {"action": "create", "name": f"{PREFIX}-pf", "dst_port": "58699", "fwd": "10.88.1.15",
                                         "fwd_port": "58699", "proto": "tcp", "src_limiting_enabled": True, "src": "142.250.0.0/15",
                                         "log": False})
        new_id = out["id"]
        fails += not show("create", out)
        stored = next(r for r in await engine._rows(port_forward.SPEC) if r["_id"] == new_id)
        good = (stored.get("enabled") is False and stored.get("src") == "142.250.0.0/15"
                and stored.get("src_limiting_enabled") is True and stored.get("src_limiting_type") == "ip")
        print(f"  stored: enabled={stored.get('enabled')} src={stored.get('src')} limiting={stored.get('src_limiting_enabled')} "
              f"type={stored.get('src_limiting_type')}")
        fails += not good
        out = await apply(client, tool, {"action": "delete", "target": new_id})
        new_id = None
        fails += not show("delete", out)
    finally:
        if new_id:
            try:
                show("cleanup delete", await apply(client, tool, {"action": "delete", "target": new_id}))
            except Exception as exc:  # noqa: BLE001
                fails += 1
                print(f"  CLEANUP FAILED, delete '{PREFIX}-pf' by hand: {exc}")
    return fails


async def syslog_section(client: Client, engine: WriteEngine) -> int:
    print("\n[3] syslog debug flag")
    tool, fails = "unifi_console_syslog", 0
    original = (await engine._rows(site_settings.SYSLOG_SPEC))[0]
    flag = bool(original.get("debug"))
    try:
        out = await apply(client, tool, {"debug": not flag})
        fails += not show(f"debug -> {not flag}", out)
    finally:
        out = await apply(client, tool, {"debug": flag})
        fails += not show(f"debug back to {flag}", out)
    after = (await engine._rows(site_settings.SYSLOG_SPEC))[0]
    same = {k: v for k, v in after.items()} == {k: v for k, v in original.items()}
    print(f"  group equals the original: {same}")
    return fails + (not same)


async def retention_section(client: Client, engine: WriteEngine) -> int:
    print("\n[4] data retention (5-minute hours +1, then back)")
    tool, fails = "unifi_console_data_retention", 0
    key = site_settings.HOURS[0]
    original = (await engine._rows(site_settings.RETENTION_SPEC))[0]
    if original.get("data_retention_setting_preference") != "manual":
        print("  skipped: the group is not in manual mode")
        return 0
    base = original[key]
    try:
        out = await apply(client, tool, {"hours_5minutes": base + 1})
        fails += not show(f"{base} -> {base + 1}", out)
        text = json.dumps(out)
        fails += "AIza" in text
    finally:
        out = await apply(client, tool, {"hours_5minutes": base})
        fails += not show(f"back to {base}", out)
    after = (await engine._rows(site_settings.RETENTION_SPEC))[0]
    same = after == original
    print(f"  group equals the original (the Maps key included): {same}")
    return fails + (not same)


async def logging_section(client: Client, engine: WriteEngine) -> int:
    print("\n[5] logging levels (sdn debug, then defaults)")
    tool, fails = "unifi_console_logging_levels", 0
    try:
        out = await apply(client, tool, {"sdn": "debug"})
        print(f"  requests_sent={out.get('requests_sent')} verified={out.get('verified')}")
        fails += out.get("requests_sent") != 5
    finally:
        out = await apply(client, tool, {})
        print(f"  defaults restored: requests_sent={out.get('requests_sent')}")
        fails += out.get("requests_sent") != 5
    return fails


async def client_section(client: Client, mac: str) -> int:
    print(f"\n[6] block then unblock {mac}")
    tool, fails, blocked = "unifi_console_client_command", 0, False
    try:
        out = await apply(client, tool, {"command": "block", "target": mac})
        blocked = True
        fails += not (show("block", out) and out.get("verified") is True)
    finally:
        if blocked:
            out = await apply(client, tool, {"command": "unblock", "target": mac})
            fails += not (show("unblock", out) and out.get("verified") is True)
    return fails


async def reconnect_section(client: Client, mac: str) -> int:
    print(f"\n[7] reconnect {mac}")
    out = await apply(client, "unifi_console_client_command", {"command": "reconnect", "target": mac})
    print(f"  applied={out.get('applied')} http={out.get('http_status')} journal={out.get('journal_id')}")
    return 0 if out.get("applied") else 1


async def doh_section(client: Client, engine: WriteEngine) -> int:
    print("\n[8] DoH Auto and back")
    tool, fails = "unifi_console_doh", 0
    original = (await engine._rows(doh.SPEC))[0]
    keep = {k: original[k] for k in ("state", "server_names", "custom_servers")}
    print(f"  original state: {keep['state']}")
    changed = False
    try:
        out = await apply(client, tool, {"state": "auto"}, NOTE)
        changed = out.get("applied", False)
        fails += not show("auto", out)
        fails += bool(out.get("attention"))
    finally:
        if changed:
            out = await apply(client, tool, keep, NOTE)
            fails += not show("original back", out)
    after = (await engine._rows(doh.SPEC))[0]
    same = {k: after[k] for k in keep} == keep
    print(f"  group equals the original: {same}")
    return fails + (not same)


def arg(name: str) -> str | None:
    return sys.argv[sys.argv.index(name) + 1] if name in sys.argv and sys.argv.index(name) + 1 < len(sys.argv) else None


async def main(run: bool, transport: Any = None, *, client_mac: str | None = None, reconnect_mac: str | None = None,
               include_doh: bool = False) -> int:
    print("Plan:\n" + PLAN)
    if not run:
        print("\nDry run only. Add --run to perform it.")
        return 0
    settings = dataclasses.replace(Settings.from_env(), enable_writes=True, write_entities=ENTITIES)
    mcp, api = create_server(settings, transport=transport)
    engine = WriteEngine(api)
    failures = 0
    try:
        async with Client(mcp) as client:
            steps = [lists_section(client, engine), portfwd_section(client, engine), syslog_section(client, engine),
                     retention_section(client, engine), logging_section(client, engine)]
            if client_mac:
                steps.append(client_section(client, client_mac))
            if reconnect_mac:
                steps.append(reconnect_section(client, reconnect_mac))
            if include_doh:
                steps.append(doh_section(client, engine))
            for step in steps:
                try:
                    failures += await step
                except Exception as exc:  # noqa: BLE001 - report and carry on with the next section
                    failures += 1
                    print(f"  ERROR: {type(exc).__name__}: {exc}")
    finally:
        await api.client.aclose()
    print("\nRESULT:", "all checks passed" if not failures else f"{failures} check(s) FAILED")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main("--run" in sys.argv, client_mac=arg("--client-mac"), reconnect_mac=arg("--reconnect-mac"),
                              include_doh="--include-doh" in sys.argv)))
