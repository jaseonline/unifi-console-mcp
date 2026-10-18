from __future__ import annotations

import dataclasses
import json

import httpx
import pytest

from unifi_console_mcp.api import Api
from unifi_console_mcp.client import AuthError, UniFiClient, UniFiError
from unifi_console_mcp.redact import fit, redact
from unifi_console_mcp.registry import DOWNLOADS, READ_ONLY_POSTS, SAFE_WRITES, Registry


@pytest.fixture(scope="module")
def registry() -> Registry:
    return Registry()


# ---------------------------------------------------------------- registry
def test_registry_covers_undocumented_apis(registry):
    tags = {o.tag.split(" · ")[0] for o in registry.all()}
    assert {"Controller", "UniFi OS"} <= tags
    assert "Cloud" not in tags
    assert len(registry.all()) > 150


def test_policy_ids_exist_in_spec(registry):
    """Drift guard: every operationId named in the access policy must still exist in the spec."""
    for op_id in READ_ONLY_POSTS | SAFE_WRITES | DOWNLOADS:
        registry.get(op_id)


def test_no_destructive_operation_is_callable(registry):
    for op in registry.all():
        if op.destructive:
            assert op.access in ("blocked", "safe_write"), op.operation_id


def test_every_write_is_blocked_unless_allowlisted(registry):
    for op in registry.all():
        if op.method in ("PUT", "DELETE", "PATCH"):
            assert op.access == "blocked", op.operation_id


def test_build_path_defaults_site_and_quotes(registry):
    op = registry.get("getDeviceDetail")
    assert op.build_path({"mac": "aa:bb:cc:dd:ee:ff"}, "default") == "/proxy/network/api/s/default/stat/device/aa%3Abb%3Acc%3Add%3Aee%3Aff"
    with pytest.raises(ValueError):
        op.build_path({}, "default")


def test_unknown_operation_suggests(registry):
    with pytest.raises(KeyError) as exc:
        registry.get("systemlog")
    assert "querySystemLog" in str(exc.value)


# ----------------------------------------------------------------- redact
def test_redact_removes_x_fields_and_secrets():
    data = {"name": "ap", "x_passphrase": "hunter2", "nested": [{"x_authkey": "abc", "ok": 1}],
            "wifi_password": "p", "empty": {"x_aes_gcm": ""}, "key": "mgmt"}
    out = redact(data)
    assert out["x_passphrase"] == "[redacted]" and out["wifi_password"] == "[redacted]"
    assert out["nested"][0]["x_authkey"] == "[redacted]"
    assert out["key"] == "mgmt" and out["name"] == "ap"
    assert "hunter2" not in json.dumps(out)


def test_fit_truncates_lists_on_item_boundaries():
    items = [{"i": i, "pad": "x" * 100} for i in range(500)]
    text, meta = fit(items, 5_000)
    assert len(text) <= 5_000 and meta["truncated"] and meta["total"] == 500
    assert json.loads(text)[-1]["i"] == meta["returned"] - 1
    assert meta["next_offset"] == meta["returned"]


# ----------------------------------------------------------------- client
async def test_login_get_post_and_csrf(settings, console):
    console.routes[("GET", "/x")] = {"a": 1}
    console.routes[("POST", "/y")] = {"b": 2}
    client = UniFiClient(settings, transport=httpx.MockTransport(console))
    r = await client.request("GET", "/x")
    assert r.json() == {"a": 1} and console.logins == 1
    assert "x-csrf-token" not in console.requests[-1].headers
    await client.request("POST", "/y", send_body=True, json_body={})
    assert console.requests[-1].headers["x-csrf-token"] == "csrf-1"
    await client.request("POST", "/y", send_body=True, json_body={})
    assert console.requests[-1].headers["x-csrf-token"] == "csrf-2"  # rotated
    info = client.session_info()
    assert info["csrf_rotations"] == 1 and info["token_lifetime_s"] == 3600
    assert "TOKEN" not in json.dumps(info)
    await client.aclose()


async def test_relogin_once_on_401(settings, console):
    console.routes[("GET", "/x")] = {"a": 1}
    client = UniFiClient(settings, transport=httpx.MockTransport(console))
    await client.request("GET", "/x")
    console.expire_next = True
    r = await client.request("GET", "/x")
    assert r.status_code == 200 and console.logins == 2
    assert client.session_info()["relogins_after_401"] == 1
    await client.aclose()


async def test_login_failure_backoff_protects_account(settings, console):
    console.login_status = 401
    client = UniFiClient(settings, transport=httpx.MockTransport(console))
    for _ in range(2):
        with pytest.raises(AuthError, match="Wrong username or password"):
            await client.request("GET", "/x")
    with pytest.raises(AuthError, match="paused to avoid locking"):
        await client.request("GET", "/x")
    assert console.logins == 2  # third attempt never reached the console
    await client.aclose()


async def test_literal_null_body_is_sent(settings, console):
    console.routes[("POST", "/n")] = {}
    client = UniFiClient(settings, transport=httpx.MockTransport(console))
    await client.request("POST", "/n", send_body=True, json_body=None)
    assert console.requests[-1].content == b"null"
    await client.aclose()


# -------------------------------------------------------------------- api
def make_api(settings, console, registry):
    client = UniFiClient(settings, transport=httpx.MockTransport(console))
    return Api(settings, registry, client)


async def test_config_write_is_refused(settings, console, registry):
    api = make_api(settings, console, registry)
    with pytest.raises(UniFiError, match="changes configuration"):
        await api.run("updateSiteSetting", path_params={"key": "lcm"}, body={"a": 1}, confirm=True)
    assert not console.requests  # refused before any network call


async def test_safe_write_needs_flag_and_confirm(settings, console, registry):
    api = make_api(settings, console, registry)
    with pytest.raises(UniFiError, match="Writes are disabled"):
        await api.run("createConsoleBackup", query={"destination": "local"}, confirm=True)
    on = dataclasses.replace(settings, enable_writes=True)
    api = make_api(on, console, registry)
    with pytest.raises(UniFiError, match="confirm=true"):
        await api.run("createConsoleBackup", query={"destination": "local"})
    console.routes[("POST", "/api/backup/now")] = lambda r: httpx.Response(204)
    res = await api.run("createConsoleBackup", query={"destination": "local"}, confirm=True)
    assert res.status == 204 and console.requests[-1].content == b""


async def test_read_only_post_runs_and_redacts(settings, console, registry):
    api = make_api(settings, console, registry)
    console.routes[("POST", "/proxy/network/v2/api/site/default/system-log/critical")] = [{"x_secret": "s", "event": "E"}]
    res = await api.run("querySystemLog", body={"severities": ["HIGH"]})
    assert res.data == [{"x_secret": "[redacted]", "event": "E"}]


async def test_download_saves_to_disk_and_requires_confirm(settings, console, registry):
    api = make_api(settings, console, registry)
    with pytest.raises(UniFiError, match="confirm=true"):
        await api.run("downloadBackup")
    console.routes[("GET", "/api/backup/download")] = lambda r: httpx.Response(
        200, content=b"BACKUPBYTES", headers={"filename": "unifi_os_backup_1_abc.unifi", "content-type": "application/octet-stream"})
    res = await api.run("downloadBackup", confirm=True)
    assert res.download.path.read_bytes() == b"BACKUPBYTES"
    text = api.render(res)
    assert "BACKUPBYTES" not in text and "unifi_os_backup_1_abc.unifi" in text


async def test_403_message_points_at_permissions(settings, console, registry):
    api = make_api(settings, console, registry)
    console.routes[("GET", "/proxy/users/api/v2/keys")] = lambda r: httpx.Response(403, json={})
    with pytest.raises(UniFiError, match="Control Plane = Admin"):
        await api.run("listApiKeys")


async def test_error_inside_http_200_envelope_is_surfaced(settings, console, registry):
    api = make_api(settings, console, registry)
    console.routes[("GET", "/proxy/users/api/v2/keys")] = {"code": 403, "codeS": "NO_PERMISSION", "msg": "denied", "error": {}}
    with pytest.raises(UniFiError, match="NO_PERMISSION.*Control Plane"):
        await api.run("listApiKeys")
    console.routes[("GET", "/proxy/users/api/v2/keys")] = {"code": 0, "codeS": "SUCCESS", "msg": "success", "data": [{"id": "k"}]}
    res = await api.run("listApiKeys")
    assert res.data == [{"id": "k"}]


def test_legacy_env_names_still_read(monkeypatch):
    """UNIFI_EXT_* (pre-rename) is a fallback; UNIFI_CONSOLE_* wins when both are set."""
    from unifi_console_mcp.config import Settings

    monkeypatch.setenv("UNIFI_LOCAL_HOST", "console.test")
    monkeypatch.delenv("UNIFI_CONSOLE_ENABLE_WRITES", raising=False)
    monkeypatch.setenv("UNIFI_EXT_ENABLE_WRITES", "true")
    assert Settings.from_env().enable_writes is True
    monkeypatch.setenv("UNIFI_CONSOLE_ENABLE_WRITES", "false")
    assert Settings.from_env().enable_writes is False


def test_probed_read_endpoints_are_reads():
    """Operations added from the 2026-10-17 live probe must be readable, and the POST queries must not need writes."""
    from unifi_console_mcp.registry import Registry

    reg = Registry()
    ids = ["getSelfSites", "listDynamicDns", "listActiveRoutes", "listHotspotVouchers", "getClientRecord",
           "getSpectrumScan", "listRogueAps", "listMacAclRules", "listNatRules", "listQosRules", "listStaticDns",
           "listNetworkMemberGroups", "getNetworkMemberGroup", "listIpsCategories", "getTrafficFlowStatistics",
           "getCyberSecureSummary", "getSystemLogCount"]
    for op_id in ids:
        assert reg.get(op_id).access == "read", op_id
    assert reg.get("listRogueAps").method == "POST"
    assert reg.get("getSystemLogCount").method == "POST"


def test_har_derived_reads_are_reads():
    from unifi_console_mcp.registry import Registry

    reg = Registry()
    ids = [
        "listTrafficPolicyObjects", "listPortForwardStats", "listStaticDnsDevices", "getPortAnomaliesForPort",
        "getDohAvailableServerNames", "getDohDefaults", "getIpsSuricataSettings", "getIpsAdvancedFilteringDefaults",
        "getSslInspectionSetting", "getSslInspectionSettingDefaults", "listSslInspectionCertificates",
        "getActiveSslInspectionCertificate", "getClient24hrSatisfaction", "getClientApStats",
        "getClientConnectionLog", "listDeviceWirelessLinks", "listPowerSupervisorLinks",
        "listDeviceReplacementCandidates", "listFirewallAppBlocks", "listContentFilteringCategories",
        "getFirewallPolicyDefaults", "getFirewallZoneDefaults", "getGlobalSwitchSettingDefaults",
        "getPortMacTables", "queryPortSystemLogs",
    ]
    for i in ids:
        assert reg.get(i).access == "read", i
    assert reg.get("getPortMacTables").method == "POST"
    assert reg.get("queryPortSystemLogs").method == "POST"


def test_second_har_reads_are_reads():
    from unifi_console_mcp.registry import Registry

    reg = Registry()
    for i in ["listDdnsServices", "getWanDefaults", "getWanLoadBalancingConfiguration", "getWanLoadBalancingStatus",
              "getWlanDefaults", "getWlanCapabilities", "listVpnConnections", "getControllerFirewallPolicy"]:
        assert reg.get(i).access == "read", i
