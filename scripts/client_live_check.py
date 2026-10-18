"""Prove the client tool on the real console using one client, the Harmony Hub, and put it back exactly as it was.

    uv run scripts/client_live_check.py                        # dry run: prints the plan, touches nothing
    uv run scripts/client_live_check.py --run                  # note, name and Local DNS record; restores them
    uv run scripts/client_live_check.py --run --with-fixed-ip  # also moves the fixed IP to a spare address and back

SAFETY
  * Goes through the real tool (preview, then confirm with the fingerprint, journal, read-back), in-process. Writes are
    enabled for THIS process only; the Claude Desktop server configuration is not changed.
  * Touches only the client with MAC 02:00:00:00:00:23 and only when it is still called "Harmony Hub". Every other client
    is compared before and after.
  * The original values of name, note, noted, fixed IP and Local DNS record are recorded first and restored in a finally
    block, also when a step fails. The script ends by checking the Hub has exactly those values again.
  * The fixed-IP step picks a spare address in the Hub's own subnet, below the DHCP pool, that no known client owns and
    no active client uses. A fixed IP only takes effect when the Hub next renews its lease, and it is put back first.
  * Journal lines go to the normal journal folder. Prints field names and short values only.
"""
from __future__ import annotations

import asyncio
import os
import dataclasses
import ipaddress
import json
import sys
from typing import Any

from mcp.client import Client

from unifi_console_mcp.config import Settings
from unifi_console_mcp.entities.client import FIELDS, LIVE, SPEC
from unifi_console_mcp.server import create_server
from unifi_console_mcp.writes import WriteEngine

HUB_MAC = os.environ.get("UNIFI_LIVE_CHECK_CLIENT_MAC", "02:00:00:00:00:23").lower()   # a harmless client on YOUR console
HUB_NAME = "Harmony Hub"
TOOL = "unifi_console_client"
TEST_NOTE = "zz live check"
TEST_NAME = "Harmony Hub (zz-check)"
TEST_DNS = "zz-hubcheck.example.home"
WATCHED = FIELDS + ("blocked", "usergroup_id", "fixed_ap_enabled", "virtual_network_override_enabled", "virtual_network_override_id")

PLAN = f"""\
1. read the Hub (MAC {HUB_MAC}, must still be called "{HUB_NAME}") and remember name, note, noted, fixed IP and Local DNS record
2. note -> "{TEST_NOTE}"; the diff must show only the note
3. name -> "{TEST_NAME}"; the diff must show only the name
4. Local DNS record -> {TEST_DNS}; the diff must show the record and its enabled flag
5. (only with --with-fixed-ip) fixed IP -> a spare address in the Hub's subnet below the DHCP pool, then check the read-back
6. restore every value to what was recorded in step 1 and check the Hub is exactly as it was
7. confirm every other client is unchanged"""


async def tool(client: Client, args: dict[str, Any]) -> dict[str, Any]:
    res = await client.call_tool(TOOL, {"params": args})
    return json.loads(res.content[0].text)


async def apply(client: Client, args: dict[str, Any]) -> dict[str, Any]:
    pre = await tool(client, args)
    if not pre.get("ok"):
        raise RuntimeError(f"preview failed: {pre.get('error')}")
    if pre["errors"] or pre["apply_blocked_reason"]:
        raise RuntimeError(f"preview not applicable: {pre['errors'] or pre['apply_blocked_reason']}")
    out = await tool(client, {**args, "confirm": True, "fingerprint": pre["fingerprint"]})
    if not out.get("ok"):
        raise RuntimeError(f"apply failed: {out.get('error')}")
    out["_preview"] = pre
    return out


def watched(row: dict[str, Any]) -> dict[str, Any]:
    return {k: row.get(k) for k in WATCHED if k not in LIVE}


def others(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(r.get("mac")): watched(r) for r in rows if str(r.get("mac")).lower() != HUB_MAC}


def spare_address(hub: dict[str, Any], clients: list[dict[str, Any]], active: list[dict[str, Any]],
                  networks: list[dict[str, Any]]) -> str | None:
    ip = ipaddress.IPv4Address(hub["fixed_ip"])
    net = next((n for n in networks if n.get("ip_subnet") and ip in ipaddress.IPv4Network(n["ip_subnet"], strict=False)), None)
    if net is None:
        return None
    network = ipaddress.IPv4Network(net["ip_subnet"], strict=False)
    pool_start = ipaddress.IPv4Address(net["dhcpd_start"]) if net.get("dhcpd_start") else network.broadcast_address
    used = {str(r.get("fixed_ip")) for r in clients if r.get("use_fixedip")} | {str(r.get("ip")) for r in active}
    gateway = ipaddress.IPv4Interface(net["ip_subnet"]).ip
    for host in sorted(network.hosts(), reverse=True):
        if host < pool_start and host != gateway and str(host) not in used and host != ip:
            return str(host)
    return None


async def main(run: bool, with_fixed_ip: bool = False, transport: Any = None) -> int:
    print("Plan:\n" + PLAN)
    if not run:
        print("\nDry run only. Add --run to perform it.")
        return 0
    settings = dataclasses.replace(Settings.from_env(), enable_writes=True, write_entities=frozenset({"client"}))
    mcp, api = create_server(settings, transport=transport)
    engine = WriteEngine(api)
    failures = 0
    try:
        async with Client(mcp) as client:
            rows = await engine._rows(SPEC)
            hub = next((r for r in rows if str(r.get("mac")).lower() == HUB_MAC), None)
            if hub is None or hub.get("name") != HUB_NAME:
                print(f"\nSTOP: no client {HUB_MAC} called '{HUB_NAME}' (found: {hub and hub.get('name')!r}). Nothing was changed.")
                return 1
            original = {k: hub.get(k) for k in FIELDS}
            others_before = others(rows)
            print(f"\n[1] Hub {hub['_id']}: " + json.dumps({k: original[k] for k in FIELDS}))
            print(f"    {len(others_before)} other client(s) recorded")
            if not hub.get("use_fixedip") or not hub.get("fixed_ip"):
                print("STOP: the Hub has no fixed IP stored, so there is nothing safe to restore against."); return 1

            async def step(label: str, args: dict[str, Any], expect: set[str]) -> dict[str, Any] | None:
                nonlocal failures
                out = await apply(client, {"target": HUB_MAC, **args})
                got = set(out["diff"])
                print(f"  {label}: verified={out['verified']} diff={json.dumps(out['diff'])}")
                if not out["verified"] or got != expect:
                    failures += 1
                    print(f"  CHECK FAILED: expected a diff on exactly {sorted(expect)}")
                return out

            try:
                print("\n[2] note");  await step("note", {"note": TEST_NOTE}, {"note"})
                print("\n[3] name");  await step("name", {"name": TEST_NAME}, {"name"})
                print("\n[4] Local DNS record")
                await step("dns", {"local_dns_record": TEST_DNS}, {"local_dns_record", "local_dns_record_enabled"})
                if with_fixed_ip:
                    print("\n[5] fixed IP")
                    spare = spare_address(hub, rows, await engine._read_list("listActiveClientsLegacy"),
                                          await engine._read_list("listNetworkConfig"))
                    if spare is None:
                        failures += 1
                        print("  no spare address found; step skipped")
                    else:
                        print(f"  spare address: {spare} (original {original['fixed_ip']})")
                        await step("fixed ip", {"fixed_ip": spare}, {"fixed_ip"})
                else:
                    print("\n[5] fixed IP: skipped (run with --with-fixed-ip to include it)")
            except Exception as exc:  # report, then fall through to the restore
                failures += 1
                print(f"  ERROR: {type(exc).__name__}: {exc}")
            finally:
                print("\n[6] restore")
                try:
                    now = next(r for r in await engine._rows(SPEC) if str(r.get("mac")).lower() == HUB_MAC)
                    back = {k: original[k] for k in FIELDS if original[k] is not None and now.get(k) != original[k]}
                    # a record that was empty is restored with the record text; the tool then switches it off
                    if "local_dns_record_enabled" in back and "local_dns_record" in back:
                        back.pop("local_dns_record_enabled")
                    if back:
                        out = await apply(client, {"target": HUB_MAC, **back})
                        print(f"  restored {sorted(back)}: verified={out['verified']}")
                        failures += not out["verified"]
                    else:
                        print("  nothing to restore")
                except Exception as exc:  # noqa: BLE001
                    failures += 1
                    print(f"  RESTORE FAILED, put the Hub back by hand ({json.dumps(original)}): {exc}")

            after = await engine._rows(SPEC)
            hub_after = next((r for r in after if str(r.get("mac")).lower() == HUB_MAC), {})
            exact = all(hub_after.get(k) == original[k] for k in FIELDS if original[k] is not None)
            changed = sorted(m for m, v in others(after).items() if others_before.get(m) != v)
            print(f"\n[7] Hub back to its original values: {exact}; other clients unchanged: {not changed} {changed or ''}")
            failures += (not exact) or bool(changed)
    finally:
        await api.client.aclose()
    print("\nRESULT:", "all checks passed" if not failures else f"{failures} check(s) FAILED")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main("--run" in sys.argv, "--with-fixed-ip" in sys.argv)))
