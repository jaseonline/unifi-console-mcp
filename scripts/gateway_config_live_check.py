"""Exercise unifi_console_gateway_config against the live console, in-process.

    uv run python scripts/gateway_config_live_check.py            # reuse the newest support file (up to 7 days old)
    uv run python scripts/gateway_config_live_check.py --refresh  # build a fresh bundle first (about 90 s)

Prints the policy-drift verdict, the firewall field-type check and the WAN's DHCPv6-PD request, then scans the
full output for anything secret-shaped. Nothing here changes configuration; --refresh creates a support file.
"""
from __future__ import annotations

import asyncio
import json
import re
import sys

from mcp.client import Client

from unifi_console_mcp.config import Settings
from unifi_console_mcp.server import create_server

SECRET_SHAPES = re.compile(r"sdns://(?!\[redacted\])|-----BEGIN|\"(x_[a-z_]+|password|token|privateKey)\":\s*\"(?!\[redacted\])")


async def main() -> None:
    refresh = "--refresh" in sys.argv
    mcp, api = create_server(Settings.from_env())
    args = {"params": {"refresh": refresh, "confirm": refresh, "max_age_minutes": 10_080, "firewall_chain": "WAN_LOCAL"}}
    async with Client(mcp) as client:
        res = await client.call_tool("unifi_console_gateway_config", args)
        text = res.content[0].text
    await api.client.aclose()
    out = json.loads(text)
    if not out.get("ok"):
        print("FAILED:", out.get("error"))
        return
    data = out["data"]
    drift = data.get("policy_drift", {})
    print(f"source: {data['source']}  ({len(text)} chars{', cut' if out.get('meta') else ''})")
    print("summary:", json.dumps({k: data["summary"].get(k) for k in ("inform", "controller_now", "config_version")}))
    print("drift:", json.dumps({k: drift.get(k) for k in ("in_sync", "custom_enabled", "custom_matched",
                                                          "predefined_missing_on_gateway")}))
    for key in ("missing_on_gateway", "predefined_missing_on_gateway", "disabled_but_on_gateway", "mismatches", "orphan_rules"):
        for row in drift.get(key, []):
            print(f"  {key}: {json.dumps(row)[:200]}")
    fw = data.get("firewall", {})
    print("mixed_type_fields:", fw.get("mixed_type_fields"), " log:", fw.get("field_types", {}).get("log"))
    wan = next((i for i in data.get("interfaces", []) if (i.get("status") or {}).get("comment") == "WAN"), {})
    print("WAN ipv6:", wan.get("ipv6"), " WAN_LOCAL rules:", len(fw.get("chain_rules", [])))
    hits = SECRET_SHAPES.findall(text)
    print("secret-shaped strings:", len(hits) if hits else "none")


asyncio.run(main())
