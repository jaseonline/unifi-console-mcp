"""Read-only live probe of the console. Prints shapes and timings only, never values.

    uv run python scripts/probe.py

Purpose: answer the open questions in the spec (session lifetime, CSRF rotation, response sizes,
permission gaps) and check that the gap endpoints behave as the spec says. It performs one login and
GET / read-only POST requests only.
"""

from __future__ import annotations

import asyncio
import json
import time

from unifi_console_mcp.client import UniFiClient, UniFiError
from unifi_console_mcp.config import Settings
from unifi_console_mcp.registry import Registry


def shape(data, depth: int = 0) -> str:
    if isinstance(data, list):
        inner = shape(data[0], depth + 1) if data else "empty"
        return f"list[{len(data)}] of {inner}"
    if isinstance(data, dict):
        keys = list(data)
        shown = ",".join(keys[:14]) + ("..." if len(keys) > 14 else "")
        return f"object({len(keys)} keys: {shown})"
    return type(data).__name__


async def call(client: UniFiClient, reg: Registry, s: Settings, op_id: str, *, path=None, query=None, body=None):
    op = reg.get(op_id)
    started = time.perf_counter()
    try:
        resp = await client.request(
            op.method, op.build_path(path or {}, s.site), params=query, json_body=body,
            needs_session=op.needs_session, send_body=body is not None,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"{op_id:36} ERROR {type(exc).__name__}: {str(exc)[:120]}")
        return None
    ms = int((time.perf_counter() - started) * 1000)
    parsed = None
    desc = ""
    if resp.content and "json" in resp.headers.get("content-type", ""):
        parsed = resp.json()
        inner = parsed.get("data") if isinstance(parsed, dict) and "meta" in parsed else parsed
        desc = shape(inner)
    elif resp.content:
        desc = f"{resp.headers.get('content-type', '?')} {len(resp.content)}B"
    print(f"{op_id:36} HTTP {resp.status_code} {ms:5}ms {len(resp.content):8}B  {desc}")
    return parsed


async def main() -> None:
    s = Settings.from_env()
    reg = Registry(s.spec_path)
    client = UniFiClient(s)
    print(f"Console {s.host}:{s.port} site={s.site} verify_ssl={s.verify_ssl} spec={reg.spec_version}")
    try:
        await client.login()
    except UniFiError as exc:
        print(f"LOGIN FAILED: {exc}")
        return
    info = client.session_info()
    print("Session:", json.dumps({k: v for k, v in info.items() if k not in ("last_login_at",)}))

    me = await call(client, reg, s, "getCurrentUser")
    if isinstance(me, dict):
        user = me.get("data") or {}
        perms = user.get("permissions") or {}
        print("  account:", user.get("username"), "| local-only:", user.get("only_local_account"),
              "| network.management:", perms.get("network.management"),
              "| other permission keys:", sorted(k for k in perms if k != "network.management")[:12])
    sysinfo = await call(client, reg, s, "getSysInfo")
    if isinstance(sysinfo, dict) and sysinfo.get("data"):
        print("  controller version:", sysinfo["data"][0].get("version"), "build:", sysinfo["data"][0].get("build"))

    now = int(time.time() * 1000)
    log_body = {"searchText": "", "type": "GENERAL", "severities": ["MEDIUM", "HIGH", "VERY_HIGH"],
                "timestampFrom": now - 24 * 3_600_000, "timestampTo": now, "pageNumber": 0, "pageSize": 5,
                "clientDeviceMacs": [], "adminIds": []}
    log = await call(client, reg, s, "querySystemLogAll", body=log_body)
    if isinstance(log, dict):
        print("  system log total:", log.get("total_element_count"), "pages:", log.get("total_page_count"),
              "| entry keys:", sorted((log.get("data") or [{}])[0].keys()))
    await call(client, reg, s, "querySystemLog", body={"searchText": "", "severities": ["HIGH", "VERY_HIGH"]})
    await call(client, reg, s, "getSystemLogFilterData", body={"type": "GENERAL", "timestampFrom": now - 86_400_000, "timestampTo": now})

    pol = await call(client, reg, s, "listFirewallPoliciesWithHits")
    if isinstance(pol, list):
        user_pol = [p for p in pol if not p.get("predefined")]
        print(f"  policies: {len(pol)} total, {len(user_pol)} user-defined, "
              f"{sum(1 for p in user_pol if not p.get('hits'))} user policies with zero hits")
    await call(client, reg, s, "listFirewallZones")
    await call(client, reg, s, "getTopology")
    await call(client, reg, s, "listPowerSupervisors")
    await call(client, reg, s, "listPortAnomalies")

    basic = await call(client, reg, s, "listDevicesBasic")
    devices = (basic or {}).get("data") if isinstance(basic, dict) else None
    switch = next((d for d in devices or [] if d.get("type") == "usw"), None)
    if switch:
        mac = switch["mac"]
        print("  probing first switch (model:", switch.get("model"), ")")
        detail = await call(client, reg, s, "getDeviceDetail", path={"mac": mac})
        if isinstance(detail, dict) and detail.get("data"):
            dev = detail["data"][0]
            port = (dev.get("port_table") or [{}])[0]
            print("  device top-level keys with stp_/lldp_:", sorted(k for k in dev if k.startswith(("stp_", "lldp_"))))
            print("  port_table[0] stp/poe/error keys:",
                  sorted(k for k in port if k.startswith(("stp_", "poe_")) or "error" in k or "link_down" in k))
            print("  x_ secret-bearing keys present on device record:", sorted(k for k in dev if k.startswith("x_")))
        await call(client, reg, s, "getPoeInfo", query={"mac": mac})
    else:
        print("  no switch found in listDevicesBasic")

    for op_id, extra in [("listConsoleAdmins", {"query": {"page_size": 100}}), ("listRoles", {}), ("listApiKeys", {}),
                         ("listConsoleBackups", {}), ("getFirmwareUpdates", {}), ("getSyslogSettings", {}),
                         ("listAlarmRules", {}), ("getTrafficByApplication", {}), ("listWanSlaMonitors", {})]:
        await call(client, reg, s, op_id, **extra)

    final = client.session_info()
    print("Session after probe:", json.dumps({k: v for k, v in final.items() if k != "last_login_at"}))
    await client.aclose()


asyncio.run(main())
