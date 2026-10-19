from __future__ import annotations

import contextlib
import dataclasses
import json

import httpx
import pytest
from mcp.client import Client

from unifi_console_mcp.server import create_server

EXPECTED = {
    "unifi_console_list_operations", "unifi_console_describe_operation", "unifi_console_call_operation",
    "unifi_console_session_status", "unifi_console_system_log", "unifi_console_firewall_policy_hits",
    "unifi_console_poe_overview", "unifi_console_switch_port_detail", "unifi_console_backup",
    "unifi_console_support_file", "unifi_console_gateway_config", "unifi_console_access_review", "unifi_console_port_forward", "unifi_console_network_list", "unifi_console_client", "unifi_console_static_dns", "unifi_console_client_group", "unifi_console_dynamic_dns", "unifi_console_traffic_object", "unifi_console_doh", "unifi_console_firewall_policy", "unifi_console_switch_port", "unifi_console_wifi", "unifi_console_network", "unifi_console_wan", "unifi_console_client_command", "unifi_console_syslog", "unifi_console_data_retention", "unifi_console_logging_levels", "unifi_console_qos_rule", "unifi_console_app_block", "unifi_console_device",
}
SITE = "/proxy/network/v2/api/site/default"
MAC = "aa:bb:cc:dd:ee:ff"


async def call(client, name, args=None):
    res = await client.call_tool(name, args or {})
    assert not res.is_error, res
    return json.loads(res.content[0].text)


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


async def test_tool_list_and_annotations(open_session):
    async with open_session() as (client, _, _):
        tools = {t.name: t for t in (await client.list_tools()).tools}
        assert set(tools) == EXPECTED
        writers = {"unifi_console_call_operation", "unifi_console_backup", "unifi_console_support_file", "unifi_console_gateway_config", "unifi_console_port_forward", "unifi_console_network_list", "unifi_console_client", "unifi_console_static_dns", "unifi_console_client_group", "unifi_console_dynamic_dns", "unifi_console_traffic_object", "unifi_console_doh", "unifi_console_firewall_policy", "unifi_console_switch_port", "unifi_console_wifi", "unifi_console_network", "unifi_console_wan", "unifi_console_client_command", "unifi_console_syslog", "unifi_console_data_retention", "unifi_console_logging_levels", "unifi_console_qos_rule", "unifi_console_app_block", "unifi_console_device"}
        for name in EXPECTED - writers:
            assert tools[name].annotations.read_only_hint is True, name
        assert tools["unifi_console_port_forward"].annotations.destructive_hint is True
        assert all(t.description and len(t.description) > 40 for t in tools.values())


async def test_list_and_describe_do_not_touch_the_console(open_session):
    async with open_session() as (client, console, _):
        out = await call(client, "unifi_console_list_operations", {"params": {"search": "system log", "access": "all"}})
        ids = {o["operation_id"] for o in out["operations"]}
        assert {"querySystemLogAll", "querySystemLog"} <= ids
        desc = await call(client, "unifi_console_describe_operation", {"params": {"operation_id": "querySystemLogAll"}})
        assert desc["access"] == "read" and desc["body_schema"]
        bad = await call(client, "unifi_console_describe_operation", {"params": {"operation_id": "zzzz"}})
        assert bad["ok"] is False and "unifi_console_list_operations" in bad["error"]
        assert not console.requests


async def test_system_log_fills_templates_and_builds_body(open_session):
    async with open_session() as (client, console, _):
        entry = {"id": "1", "timestamp": 1792205209266, "severity": "HIGH", "category": "UNIFI_ETHERNET_PORTS",
                 "subcategory": "SECURITY_FIREWALL", "event": "BPDU_GUARD_TRIGGERED", "target": "DEVICE",
                 "title_raw": "BPDU guard on {DEVICE}", "message_raw": "Port {PORT} shut down",
                 "parameters": {"DEVICE": {"name": "Office Switch"}, "PORT": {"name": "Port 5"}}}
        seen = {}

        def handler(request):
            seen["body"] = json.loads(request.content)
            return httpx.Response(200, json={"data": [entry], "page_number": 0, "total_element_count": 1, "total_page_count": 1})

        console.routes[("POST", f"{SITE}/system-log/all")] = handler
        out = await call(client, "unifi_console_system_log", {"params": {"hours": 6, "min_severity": "HIGH", "client_mac": MAC.upper()}})
        row = out["data"][0]
        assert row["title"] == "BPDU guard on Office Switch" and row["message"] == "Port Port 5 shut down"
        assert row["time"].endswith("Z") and out["log_page"]["total"] == 1
        body = seen["body"]
        assert body["severities"] == ["HIGH", "VERY_HIGH"] and body["clientDeviceMacs"] == [MAC]
        assert body["timestampTo"] - body["timestampFrom"] == 6 * 3_600_000


async def test_firewall_hits_sorts_and_filters(open_session):
    async with open_session() as (client, console, _):
        console.routes[("GET", f"{SITE}/firewall-policies")] = [
            {"_id": "a", "name": "Allow IoT DNS", "hits": 500, "index": 1, "enabled": True, "predefined": False, "action": "ALLOW", "source": {"zone_id": "z1"}, "destination": {"zone_id": "z2"}},
            {"_id": "b", "name": "Old rule", "hits": 0, "index": 2, "enabled": True, "predefined": False, "action": "BLOCK", "last_hit": None},
            {"_id": "c", "name": "System", "hits": 9, "index": 3, "predefined": True},
        ]
        console.routes[("GET", f"{SITE}/firewall/zone")] = [{"_id": "z1", "name": "IoT"}, {"_id": "z2", "name": "Internal"}]
        out = await call(client, "unifi_console_firewall_policy_hits", {"params": {}})
        assert [r["name"] for r in out["data"]] == ["Old rule", "Allow IoT DNS"]  # unused first, predefined hidden
        assert out["data"][1]["source_zone"] == "IoT"
        unused = await call(client, "unifi_console_firewall_policy_hits", {"params": {"unused_only": True}})
        assert [r["name"] for r in unused["data"]] == ["Old rule"]


async def test_switch_port_detail_trims_and_redacts(open_session):
    async with open_session() as (client, console, _):
        big = {"name": "Switch", "model": "USW", "version": "7.0", "x_authkey": "SECRET", "stp_priority": "32768",
               "port_table": [{"port_idx": 1, "up": True, "stp_state": "forwarding", "stp_role": "designated",
                               "rx_errors": 2, "poe_power": "3.2", "junk": "x" * 1000, "x_aes_gcm": "SECRET"},
                              {"port_idx": 2, "up": False, "stp_state": "disabled"}]}
        console.routes[("GET", f"/proxy/network/api/s/default/stat/device/{MAC}")] = {"meta": {"rc": "ok"}, "data": [big]}
        out = await call(client, "unifi_console_switch_port_detail", {"params": {"device_mac": MAC, "ports": [1]}})
        port = out["data"]["ports"][0]
        assert port["stp_state"] == "forwarding" and port["rx_errors"] == 2 and "junk" not in port
        assert len(out["data"]["ports"]) == 1 and out["data"]["stp"] == {"stp_priority": "32768"}
        assert "SECRET" not in json.dumps(out)


async def test_backup_create_and_download_gating(open_session):
    async with open_session() as (client, console, _):
        refused = await call(client, "unifi_console_backup", {"params": {"action": "create"}})
        assert refused["ok"] is False and "confirm=true" in refused["error"]
        console.routes[("POST", "/api/backup/now")] = lambda r: httpx.Response(204)
        ok = await call(client, "unifi_console_backup", {"params": {"action": "create", "confirm": True}})
        assert ok["ok"] is True
        console.routes[("GET", "/api/backup/download")] = lambda r: httpx.Response(200, content=b"x" * 10, headers={"filename": "b.unifi"})
        dl = await call(client, "unifi_console_backup", {"params": {"action": "download", "target": "network", "confirm": True}})
        assert dl["saved_file"]["bytes"] == 10 and console.requests[-1].url.params["target"] == "network"


async def test_support_file_console_polls_until_ready(open_session, monkeypatch):
    async with open_session() as (client, console, api):
        monkeypatch.setattr("unifi_console_mcp.tools_curated.asyncio.sleep", lambda s: _noop())
        calls = {"n": 0}

        def download(request):
            calls["n"] += 1
            return httpx.Response(404, json={}) if calls["n"] < 3 else httpx.Response(200, content=b"tgz", headers={"content-disposition": 'attachment; filename="support-ab12-1.tgz"'})

        console.routes[("POST", "/api/support/file/generate")] = lambda r: httpx.Response(200, json={})
        console.routes[("GET", "/api/support/file/download")] = download
        out = await call(client, "unifi_console_support_file", {"params": {"scope": "console", "confirm": True, "wait_seconds": 60}})
        assert out["saved_file"]["path"].endswith("support-ab12-1.tgz") and calls["n"] == 3


async def _noop():
    return None


async def test_session_status_reports_lifetime_without_secrets(open_session):
    async with open_session() as (client, console, _):
        console.routes[("GET", "/proxy/users/api/v2/user/self")] = {"data": {"username": "mcp", "roles": ["r"], "only_local_account": True,
                                                                              "permissions": {"network.management": ["admin"], "system.management.location": ["readonly"]}}}
        console.routes[("GET", "/proxy/network/api/s/default/stat/sysinfo")] = {"meta": {"rc": "ok"}, "data": [{"version": "11.0.81", "hostname": "cloudkey"}]}
        out = await call(client, "unifi_console_session_status")
        assert out["controller"]["version"] == "11.0.81" and out["account"]["network_management"] == ["admin"]
        assert out["session"]["token_lifetime_s"] == 3600 and out["server"]["tls_verification"] == "on"
        dumped = json.dumps(out)
        assert '"pw"' not in dumped and "csrf-jwt" not in dumped and "csrf-1" not in dumped and "TOKEN" not in dumped


async def test_call_operation_blocks_config_write_without_network_call(open_session):
    async with open_session() as (client, console, _):
        out = await call(client, "unifi_console_call_operation", {"params": {"operation_id": "updateSiteSetting", "path_params": {"key": "mgmt"}, "body": {}, "confirm": True}})
        assert out["ok"] is False and "does not expose configuration writes" in out["error"]
        assert not console.requests


async def test_call_operation_large_result_is_cut_with_hint(open_session):
    async with open_session() as (client, console, _):
        console.routes[("GET", "/proxy/network/api/s/default/rest/user")] = {"meta": {"rc": "ok"}, "data": [{"mac": f"m{i}", "name": "n" * 200} for i in range(1000)]}
        out = await call(client, "unifi_console_call_operation", {"params": {"operation_id": "listKnownClients", "fields": ["mac"], "limit": 5}})
        assert out["meta"]["total"] == 1000 and len(out["data"]) == 5 and out["meta"]["next_offset"] == 5


async def test_access_review_returns_partial_results_when_one_section_denied(open_session):
    async with open_session() as (client, console, _):
        console.routes[("GET", "/proxy/users/api/v2/users/admin/uos")] = {"code": 0, "codeS": "SUCCESS", "data": [{"username": "a", "x_password": "p"}]}
        console.routes[("GET", "/proxy/users/api/v2/custom_roles")] = {"code": 0, "codeS": "SUCCESS", "data": [{"name": "r", "users_count": 1}]}
        console.routes[("GET", "/proxy/users/api/v2/keys")] = {"code": -17, "codeS": "CODE_UNAUTHORIZED", "msg": "no"}
        out = await call(client, "unifi_console_access_review")
        assert out["ok"] is True and out["data"]["admins"] == [{"username": "a"}] and out["data"]["roles"][0]["name"] == "r"
        assert "api_keys" not in out["data"] and "CODE_UNAUTHORIZED" in out["data"]["unavailable"]["api_keys"]
