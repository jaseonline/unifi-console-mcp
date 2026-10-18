"""Read-only probe of candidate endpoints that are not yet in the bundled spec.

    uv run python scripts/probe_endpoints.py

For each candidate it records HTTP status, timing, size and the response *shape* (key names and value types,
plus a few values for enum-like keys such as type/status/severity). It never records other values. Results are
written to probe_out/endpoints.json (git-ignored) and a summary is printed.

Only GET requests and a handful of POST *queries* (IPS events, rogue APs, system-log count, stat/event) are sent.
Nothing here changes configuration. One login is used.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any

from unifi_console_mcp.client import UniFiClient, UniFiError
from unifi_console_mcp.config import Settings

ENUM_KEYS = {"type", "status", "state", "mode", "category", "severity", "action", "direction", "protocol",
             "origin", "key", "version", "subsystem", "kind", "enabled"}
OUT = Path(__file__).resolve().parent.parent / "probe_out" / "endpoints.json"


def shape(value: Any, key: str = "", depth: int = 0) -> Any:
    if depth > 5:
        return "..."
    if isinstance(value, dict):
        return {k: shape(v, k, depth + 1) for k, v in list(value.items())[:60]}
    if isinstance(value, list):
        if not value:
            return ["len=0"]
        samples = value[:40]
        if all(isinstance(x, dict) for x in samples):
            merged: dict[str, Any] = {}
            for item in samples:  # union of keys across items, so optional fields show up
                for k, v in item.items():
                    merged.setdefault(k, shape(v, k, depth + 1))
            return [f"len={len(value)}", merged]
        return [f"len={len(value)}", shape(value[0], key, depth + 1)]
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if value is None:
        return "null"
    if isinstance(value, str):
        if key.lower() in ENUM_KEYS and len(value) <= 32:
            return f"str e.g. {value!r}"
        return "str"
    return type(value).__name__


async def hit(client: UniFiClient, results: list[dict], label: str, method: str, path: str,
              body: Any = None, query: dict | None = None) -> Any:
    started = time.perf_counter()
    rec: dict[str, Any] = {"label": label, "method": method, "path": path}
    if body is not None:
        rec["body_keys"] = sorted(body) if isinstance(body, dict) else type(body).__name__
    try:
        resp = await client.request(method, path, params=query, json_body=body, send_body=body is not None)
    except Exception as exc:  # noqa: BLE001
        rec.update(error=f"{type(exc).__name__}: {str(exc)[:160]}")
        results.append(rec)
        print(f"{label:34} {method:4} ERROR {rec['error']}")
        return None
    ms = int((time.perf_counter() - started) * 1000)
    rec.update(http=resp.status_code, ms=ms, bytes=len(resp.content), content_type=resp.headers.get("content-type", ""))
    parsed = None
    if resp.content and "json" in rec["content_type"]:
        try:
            parsed = resp.json()
            rec["shape"] = shape(parsed)
        except ValueError:
            rec["note"] = "invalid json"
    elif resp.content:
        rec["note"] = "non-json body"
        if resp.status_code >= 400:
            rec["error_text"] = resp.text[:200]
    if resp.status_code >= 400 and isinstance(parsed, dict):
        rec["error_text"] = json.dumps({k: v for k, v in parsed.items() if k in ("code", "codeS", "msg", "message", "meta")})[:300]
    results.append(rec)
    print(f"{label:34} {method:4} HTTP {resp.status_code} {ms:5}ms {len(resp.content):8}B")
    return parsed


def first(parsed: Any, key: str) -> Any:
    items = parsed.get("data") if isinstance(parsed, dict) else parsed
    if isinstance(items, list) and items and isinstance(items[0], dict):
        return items[0].get(key)
    return None


async def main() -> None:
    s = Settings.from_env()
    client = UniFiClient(s)
    results: list[dict] = []
    try:
        await client.login()
    except UniFiError as exc:
        print(f"LOGIN FAILED: {exc}")
        return
    v1 = f"/proxy/network/api/s/{s.site}"
    v2 = f"/proxy/network/v2/api/site/{s.site}"
    now = int(time.time() * 1000)
    day = 24 * 3600 * 1000

    # ---- v1 reads
    await hit(client, results, "fwupdate latest-version", "GET", f"{v1}/stat/fwupdate/latest-version")
    await hit(client, results, "self sites", "GET", "/proxy/network/api/self/sites")
    await hit(client, results, "self sites (site-scoped)", "GET", f"{v1}/self/sites")
    await hit(client, results, "stat admin", "GET", "/proxy/network/api/stat/admin")
    await hit(client, results, "stat admin (site-scoped)", "GET", f"{v1}/stat/admin")
    await hit(client, results, "dynamicdns", "GET", f"{v1}/rest/dynamicdns")
    await hit(client, results, "stat routing", "GET", f"{v1}/stat/routing")
    await hit(client, results, "stat status (site)", "GET", f"{v1}/stat/status")
    await hit(client, results, "status (network root)", "GET", "/proxy/network/status")
    await hit(client, results, "stat voucher", "GET", f"{v1}/stat/voucher")

    users = await hit(client, results, "rest user (for a mac)", "GET", f"{v1}/rest/user")
    mac = first(users, "mac")
    if mac:
        await hit(client, results, "stat user/{mac}", "GET", f"{v1}/stat/user/{mac}")
    devices = await hit(client, results, "stat device (for an AP)", "GET", f"{v1}/stat/device-basic")
    ap = None
    items = devices.get("data") if isinstance(devices, dict) else None
    if isinstance(items, list):
        ap = next((d.get("mac") for d in items if isinstance(d, dict) and d.get("type") == "uap"), None)
    if ap:
        await hit(client, results, "stat spectrum-scan/{ap}", "GET", f"{v1}/stat/spectrum-scan/{ap}")

    # ---- v1 read-only POST queries (bodies are guesses; each attempt is recorded)
    for i, body in enumerate(({"start": now - day, "end": now, "_limit": 5},
                              {"_limit": 5}), 1):
        await hit(client, results, f"ips event (body {i})", "POST", f"{v1}/stat/ips/event", body)
    for i, body in enumerate(({"within": 24, "_limit": 5}, {}), 1):
        await hit(client, results, f"rogueap (body {i})", "POST", f"{v1}/stat/rogueap", body)
    await hit(client, results, "stat event GET (spec)", "GET", f"{v1}/stat/event", query={"_limit": 3})
    await hit(client, results, "stat event POST (sirkirby)", "POST", f"{v1}/stat/event", {"_limit": 3})

    # ---- v2 reads
    for name in ("acl-rules", "cybersecure/summary", "nat", "network-members-groups", "qos-rules",
                 "settings/ips/available-categories", "static-dns", "traffic-flow-latest-statistics",
                 "firewall/zones", "firewall/zone"):
        parsed = await hit(client, results, f"v2 {name}", "GET", f"{v2}/{name}")
        if name == "network-members-groups":
            gid = first(parsed, "id") or first(parsed, "_id")
            if gid:
                await hit(client, results, "v2 network-members-group/{id}", "GET", f"{v2}/network-members-group/{gid}")

    base = {"searchText": "", "type": "GENERAL", "timestampFrom": now - 7 * day, "timestampTo": now,
            "severities": ["LOW", "MEDIUM", "HIGH", "VERY_HIGH"], "clientDeviceMacs": [], "adminIds": []}
    await hit(client, results, "system-log/count (body 1)", "POST", f"{v2}/system-log/count", base)
    await hit(client, results, "system-log/count (body 2)", "POST", f"{v2}/system-log/count",
              {"timestampFrom": now - 7 * day, "timestampTo": now})

    await client.aclose()
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps({"controller_site": s.site, "client_stats": client.stats, "results": results},
                              indent=1), encoding="utf-8")
    print(f"\nWrote {OUT} ({len(results)} probes). client stats: {json.dumps(client.stats)}")


async def round2() -> None:
    """Endpoints that answered 400 without parameters in round 1 (parameters taken from the upstream client code)."""
    s = Settings.from_env()
    client = UniFiClient(s)
    results: list[dict] = []
    await client.login()
    v2 = f"/proxy/network/v2/api/site/{s.site}"
    for period in ("DAY", "WEEK"):
        await hit(client, results, f"cybersecure/summary {period}", "GET", f"{v2}/cybersecure/summary", query={"period": period})
    await hit(client, results, "traffic-flow-latest-statistics", "GET", f"{v2}/traffic-flow-latest-statistics",
              query={"period": "DAY", "top": 5})
    await client.aclose()
    out = OUT.with_name("endpoints_round2.json")
    out.write_text(json.dumps({"results": results}, indent=1), encoding="utf-8")
    print(f"Wrote {out}")


if __name__ == "__main__":
    import sys

    asyncio.run(round2() if "round2" in sys.argv[1:] else main())
