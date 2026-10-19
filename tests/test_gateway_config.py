from __future__ import annotations

import contextlib
import dataclasses
import io
import json
import os
import tarfile
import time

import httpx
import pytest
from mcp.client import Client

from unifi_console_mcp import gateway_config as g
from unifi_console_mcp.server import create_server

GW_MAC = "02:00:00:00:00:71"
ROOT = "support-ab12-1700000000000"

# The support-file sanitiser's damage, reproduced: an unterminated masked string and an unquoted masked value.
BROKEN_UNIFI_NETWORK = '''      "unifiNetwork" : {
        "enabled" : true,
        "token" : "**REDACTED-TOKEN**",
        "controllerURL" : "**REDACTED-URL**
        "informURL" : **REDACTED-URL**
      },'''


def _udapi(rules: list[dict], *, log_obj: bool = False) -> dict:
    return {
        "interfaces": [
            {"identification": {"id": "eth1", "type": "ethernet"}, "status": {"enabled": True, "comment": "WAN"},
             "ipv6": {"dhcp6PDRequestEnabled": True, "dhcp6PDRequestSize": 56}},
            {"identification": {"id": "wg0", "type": "wireguard"}, "wireguard": {"privateKey": "WGSECRET"}},
        ],
        "services": {
            "dnsForwarder": {"enabled": True},
            "dohProxy": {"enabled": True, "instances": [{"servers": [{"server": "sdns://AgcAAAPRIVATE"}]}]},
            "dpi": {"enabled": True, "dpiModule": {"fingerprinting": {"wifiListener": {"key": "DPISECRET"}}}},
            "sshServer": {"enabled": True, "password": "SSHSECRET"},
            "snmpAgent": {"community": "SNMPSECRET"},
        },
        "system": {"hostname": "GatewayLite", "timezone": "Europe/London", "users": [{"name": "ui", "password": "HASH"}]},
        "version": 48, "versionDetail": {"firewall/filter": 7},
        "firewall/filter": [
            {"config": {"name": "WAN_LOCAL", "policy": "DROP"}, "rules": rules},
            {"config": {"name": "LAN_IN", "policy": "ACCEPT"}, "rules": [
                {"id": 1, "target": "ACCEPT", "log": {"enabled": True} if log_obj else False}]},
            {"config": {"name": "DMZ_IN", "policy": "ACCEPT"}, "rules": []},
        ],
        "firewall/sets": [{"identification": {"name": "ALL_IPV4"}, "entries": ["10.0.0.0/8", "192.168.0.0/16"]},
                          {"identification": {"name": "policy_src_net_1"}, "entries": ["10.0.0.0/8"]}],
    }


RULES = [
    {"id": 30004, "target": "ACCEPT", "description": "[WAN_LOCAL]Allow Link-Local DHCPv6", "log": False,
     "ipVersion": "v6only", "triggerTag": {"id": "pre-dhcp6", "type": "PREDEF_FW_RULE"}, "originId": "pre-dhcp6"},
    {"id": 10000, "target": "ACCEPT", "description": "Allow Xbox", "log": False, "ipVersion": "v6only",
     "triggerTag": {"id": "cust-xbox", "type": "FIREWALL_POLICY"}, "originId": "cust-xbox"},
    {"id": 10001, "target": "ACCEPT", "description": "Old rule", "log": True, "ipVersion": "both",
     "triggerTag": {"id": "cust-disabled", "type": "FIREWALL_POLICY"}, "originId": "cust-disabled"},
    {"id": 10002, "target": "DROP", "description": "Deleted on controller", "ipVersion": "both",
     "triggerTag": {"id": "cust-gone", "type": "FIREWALL_POLICY"}, "originId": "cust-gone"},
    {"id": 10003, "target": "DROP", "description": "Block IoT", "log": False, "ipVersion": "both", "originId": "cust-logged"},
]
POLICIES = [
    {"_id": "pre-1", "origin_id": "pre-dhcp6", "name": "Allow Link-Local DHCPv6", "enabled": True, "predefined": True, "action": "ALLOW", "ip_version": "IPV6"},
    {"_id": "pre-default", "origin_id": "pre-default", "name": "Block All Traffic", "enabled": True, "predefined": True, "action": "BLOCK", "ip_version": "BOTH"},
    {"_id": "cust-xbox", "name": "Allow Xbox", "enabled": True, "predefined": False, "action": "ALLOW", "ip_version": "IPV6", "logging": False},
    {"_id": "cust-disabled", "name": "Old rule", "enabled": False, "predefined": False, "action": "ALLOW", "ip_version": "BOTH"},
    {"_id": "cust-missing", "name": "Allow Sonos", "enabled": True, "predefined": False, "action": "ALLOW", "ip_version": "IPV4"},
    {"_id": "cust-logged", "name": "Block IoT", "enabled": True, "predefined": False, "action": "BLOCK", "ip_version": "BOTH", "logging": True},
]


def _system_cfg(udapi: dict) -> str:
    text = json.dumps({"udapi": udapi, "ubntconf": []}, indent=2, separators=(",", " : "))
    return text.replace('"services" : {', '"services" : {\n' + BROKEN_UNIFI_NETWORK, 1)


def build_bundle(path, udapi: dict | None = None) -> None:
    files = {
        f"{ROOT}/unifi/devices/uxg/{GW_MAC.replace(':', '-')}/system.cfg": _system_cfg(udapi or _udapi(RULES)),
        f"{ROOT}/unifi/devices/uxg/{GW_MAC.replace(':', '-')}/last.inform": json.dumps(
            {"model": "UXG", "version": "5.1.26", "cfgversion": "aaaa", "state": 1, "serial": "SERIALSECRET"}),
        f"{ROOT}/unifi/devices/usw/02-00-00-00-00-72/system.cfg": "mgmt.is_default=false\nusers.1.password=SWSECRET\n",
        f"{ROOT}/system/network/ip6tables-save": "*filter\n",
    }
    with tarfile.open(path, "w:gz") as tar:
        for name, text in files.items():
            raw = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            tar.addfile(info, io.BytesIO(raw))


def test_repair_json_mends_sanitiser_damage():
    with pytest.raises(json.JSONDecodeError):
        json.loads("{\n" + BROKEN_UNIFI_NETWORK.rstrip(",") + "\n}")
    fixed = json.loads(g.repair_json("{\n" + BROKEN_UNIFI_NETWORK.rstrip(",") + "\n}"))
    assert fixed["unifiNetwork"]["informURL"] == "**REDACTED-URL**" and fixed["unifiNetwork"]["enabled"] is True


def test_load_gateways_skips_switch_configs(tmp_path):
    build_bundle(tmp_path / f"{ROOT}.tgz")
    gws = g.load_gateways(tmp_path / f"{ROOT}.tgz")
    assert [(x.mac, x.device_type) for x in gws] == [(GW_MAC, "uxg")]
    assert gws[0].inform["cfgversion"] == "aaaa" and gws[0].udapi["version"] == 48


def test_views_never_carry_secrets():
    udapi = _udapi(RULES)
    out = json.dumps([g.interfaces_view(udapi), g.services_view(udapi), g.firewall_view(udapi, "WAN_LOCAL"),
                      g.summary_view(g.GatewayFiles(GW_MAC, "uxg", udapi, {"serial": "SERIALSECRET", "model": "UXG"}))])
    for secret in ("WGSECRET", "DPISECRET", "SSHSECRET", "SNMPSECRET", "HASH", "PRIVATE", "SERIALSECRET"):
        assert secret not in out, secret
    services = g.services_view(udapi)
    assert services["services_omitted"] == ["snmpAgent", "sshServer"]
    assert services["services"]["dohProxy"]["instances"][0]["servers"][0]["server"] == "sdns://[redacted]"
    wan = g.interfaces_view(udapi)[0]
    assert wan["ipv6"] == {"dhcp6PDRequestEnabled": True, "dhcp6PDRequestSize": 56}


def test_firewall_view_counts_and_flags_mixed_types():
    fw = g.firewall_view(_udapi(RULES), "wan_local")
    assert fw["chains"]["WAN_LOCAL"] == {"policy": "DROP", "rules": 5, "from_policies": 5}
    assert fw["empty_chains"] == ["DMZ_IN"] and fw["sets"] == [{"name": "ALL_IPV4", "description": None, "entries": 2}]
    assert fw["policy_sets"] == 1
    assert fw["mixed_type_fields"] == [] and len(fw["chain_rules"]) == 5
    mixed = g.firewall_view(_udapi(RULES, log_obj=True))
    assert mixed["mixed_type_fields"] == ["log"] and mixed["field_types"]["log"] == {"bool": 4, "object": 1, "absent": 1}


def test_compare_policies_finds_each_kind_of_drift():
    drift = g.compare_policies(POLICIES, _udapi(RULES))
    assert [m["name"] for m in drift["missing_on_gateway"]] == ["Allow Sonos"]
    assert [d["name"] for d in drift["disabled_but_on_gateway"]] == ["Old rule"]
    assert drift["mismatches"] == [{"name": "Block IoT", "id": "cust-logged", "action": "BLOCK", "field": "logging",
                                    "controller": True, "gateway": False}]
    assert [o["description"] for o in drift["orphan_rules"]] == ["Deleted on controller"]
    assert drift["custom_enabled"] == 3 and drift["custom_matched"] == 2
    assert [m["name"] for m in drift["predefined_missing_on_gateway"]] == ["Block All Traffic"] and drift["in_sync"] is False


def test_compare_policies_in_sync_and_action_mismatch():
    rules = [{"id": 1, "target": "ACCEPT", "ipVersion": "v4only", "originId": "p"}]
    ok = g.compare_policies([{"_id": "p", "enabled": True, "action": "ALLOW", "ip_version": "IPV4"}], _udapi(rules))
    assert ok["in_sync"] is True
    bad = g.compare_policies([{"_id": "p", "enabled": True, "action": "BLOCK", "ip_version": "BOTH"}], _udapi(rules))
    assert {m["field"] for m in bad["mismatches"]} == {"action", "ip_version"}


# ------------------------------------------------------------------ tool
@pytest.fixture
def open_session(settings, console):
    @contextlib.asynccontextmanager
    async def opener():
        mcp, api = create_server(dataclasses.replace(settings, enable_writes=True), transport=httpx.MockTransport(console))
        try:
            async with Client(mcp) as client:
                yield client, console, api
        finally:
            await api.client.aclose()

    return opener


async def _call(client, args):
    res = await client.call_tool("unifi_console_gateway_config", {"params": args})
    assert not res.is_error, res
    return json.loads(res.content[0].text)


async def test_tool_reuses_latest_bundle_and_reports_drift(open_session, settings):
    settings.download_dir.mkdir(parents=True)
    build_bundle(settings.download_dir / f"{ROOT}.tgz")
    async with open_session() as (client, console, _):
        console.routes[("GET", "/proxy/network/v2/api/site/default/firewall-policies")] = POLICIES
        console.routes[("GET", f"/proxy/network/api/s/default/stat/device/{GW_MAC}")] = {
            "meta": {"rc": "ok"}, "data": [{"cfgversion": "bbbb", "state": 1, "x_authkey": "AUTHSECRET"}]}
        out = await _call(client, {"firewall_chain": "WAN_LOCAL"})
        data = out["data"]
        assert out["ok"] is True and data["source"]["file"] == f"{ROOT}.tgz"
        assert data["summary"]["inform"]["cfgversion"] == "aaaa" and data["summary"]["controller_now"]["cfgversion"] == "bbbb"
        assert [m["name"] for m in data["policy_drift"]["missing_on_gateway"]] == ["Allow Sonos"]
        assert len(data["firewall"]["chain_rules"]) == 5 and "services_omitted" in data
        dumped = json.dumps(out)
        for secret in ("TOKEN", "AUTHSECRET", "WGSECRET", "DPISECRET", "SSHSECRET", "SNMPSECRET", "SWSECRET", "SERIALSECRET"):
            assert secret not in dumped, secret
        assert not any(r.method == "POST" and "support" in r.url.path for r in console.requests)  # nothing generated


async def test_tool_sections_limit_calls(open_session, settings):
    settings.download_dir.mkdir(parents=True)
    build_bundle(settings.download_dir / f"{ROOT}.tgz")
    async with open_session() as (client, console, _):
        out = await _call(client, {"sections": ["interfaces"]})
        assert set(out["data"]) == {"source", "interfaces"} and not console.requests


async def test_tool_refuses_stale_bundle_without_refresh(open_session, settings):
    settings.download_dir.mkdir(parents=True)
    path = settings.download_dir / f"{ROOT}.tgz"
    build_bundle(path)
    old = time.time() - 3 * 3600
    os.utime(path, (old, old))
    async with open_session() as (client, console, _):
        out = await _call(client, {"max_age_minutes": 60})
        assert out["ok"] is False and "refresh=true" in out["error"] and not console.requests
        refused = await _call(client, {"refresh": True})
        assert refused["ok"] is False and "confirm=true" in refused["error"]
