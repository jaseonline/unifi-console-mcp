"""Wi-Fi networks through the write framework: create disabled, whole-object edits, disconnect and open-security stops, secrets."""
from __future__ import annotations

import contextlib
import copy
import dataclasses
import json
import uuid

import httpx
import pytest
from mcp.client import Client

from conftest import make_jwt
from test_writes import Wrapped
from unifi_console_mcp.server import create_server

API = "/proxy/network/api/s/default"
WLANS, NETS, STA = f"{API}/rest/wlanconf", f"{API}/rest/networkconf", f"{API}/stat/sta"
GROUPS = "/proxy/network/v2/api/site/default/apgroups"
TOOL = "unifi_console_wifi"
NOTE = "plan claude/unifi-console-wifi-plan-2026-10-18.md, approved in chat"
N_PRIV, N_IOT, N_SON, N_WAN = "n-priv", "n-iot", "n-son", "n-wan"
GROUP = "grp-all"
SECRET = "correct-horse-battery"
OLD_PW = "old-passphrase-1"


def wlan(_id, name, net, **kw):
    base = {"_id": _id, "site_id": "s", "name": name, "enabled": True, "security": "wpapsk", "wpa_mode": "wpa2", "wpa3_support": False,
            "wpa3_transition": False, "x_passphrase": OLD_PW, "x_iapp_key": "iapp-secret", "networkconf_id": net, "usergroup_id": "ug1",
            "is_guest": False, "hide_ssid": False, "l2_isolation": False, "wlan_bands": ["2g", "5g"], "pmf_mode": "disabled",
            "ap_group_mode": "all", "ap_group_ids": [GROUP], "minrate_ng_enabled": False}
    return {**base, **kw}


def rows():
    return [wlan("w-main", "ExampleNet", N_PRIV), wlan("w-iot", "ExampleNet_IoT", N_IOT), wlan("w-son", "ExampleNet_Sonos", N_SON),
            wlan("w-apple", "apple", N_PRIV, security="open", x_passphrase="", is_guest=True, wlan_bands=["5g"])]


class FakeWifi:
    def __init__(self) -> None:
        self.rows = rows()
        self.log: list[tuple[str, str, object]] = []
        self.clients = [{"mac": "c1", "name": "Sonos Playbar", "essid": "ExampleNet_Sonos"}, {"mac": "c2", "hostname": "bulb", "essid": "ExampleNet_IoT"}]
        self.alter = None   # fn(row) applied to the stored row on PUT, to simulate the console changing something else

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        wrap = lambda x: {"meta": {"rc": "ok"}, "data": x}  # noqa: E731
        if path == "/api/auth/login":
            return httpx.Response(200, json={}, headers={"set-cookie": f"TOKEN={make_jwt()}; Path=/", "x-csrf-token": "c"})
        if method == "GET":
            if path == WLANS:
                return httpx.Response(200, json=wrap(copy.deepcopy(self.rows)))
            if path == NETS:
                return httpx.Response(200, json=wrap([
                    {"_id": N_PRIV, "name": "LAN_Private", "purpose": "corporate"}, {"_id": N_IOT, "name": "LAN_IoT", "purpose": "corporate"},
                    {"_id": N_SON, "name": "LAN_Sonos", "purpose": "corporate"}, {"_id": N_WAN, "name": "Internet", "purpose": "wan"}]))
            if path == STA:
                return httpx.Response(200, json=wrap(self.clients))
            if path == GROUPS:
                return httpx.Response(200, json=[{"_id": GROUP, "name": "All APs"}])
            return httpx.Response(404, json={})
        body = json.loads(request.content) if request.content else None
        self.log.append((method, path, body))
        if method == "POST" and path == WLANS:
            assert "_id" not in body
            row = {**body, "_id": uuid.uuid4().hex[:24], "site_id": "s"}
            self.rows.append(row)
            return httpx.Response(200, json=wrap([row]))
        if path.startswith(WLANS + "/"):
            ident = path.rsplit("/", 1)[1]
            i = next(i for i, r in enumerate(self.rows) if r["_id"] == ident)
            if method == "PUT":
                assert body["_id"] == ident and "x_passphrase" in body
                self.rows[i] = self.alter({**body}) if self.alter else {**body}
                return httpx.Response(200, json=wrap([self.rows[i]]))
            if method == "DELETE":
                del self.rows[i]
                return httpx.Response(200, json=wrap([]))
        return httpx.Response(404, json={})

    def writes(self):
        return [e for e in self.log if "login" not in e[1]]

    def by_name(self, name):
        return next(r for r in self.rows if r["name"] == name)


@pytest.fixture
def make_session(settings, tmp_path, monkeypatch):
    monkeypatch.setenv("UNIFI_WIFI_TEST", SECRET)
    monkeypatch.setenv("UNIFI_WIFI_SHORT", "short")

    @contextlib.asynccontextmanager
    async def opener(net, *, entities=frozenset({"wifi"}), writes=True):
        s = dataclasses.replace(settings, enable_writes=writes, write_entities=entities, journal_dir=tmp_path / "journal")
        mcp, api = create_server(s, transport=httpx.MockTransport(net))
        try:
            async with Client(mcp) as client:
                yield Wrapped(client), tmp_path / "journal"
        finally:
            await api.client.aclose()
    return opener


async def raw(c, args):
    return (await c.call_tool(TOOL, args)).content[0].text


async def call(c, args):
    res = await c.call_tool(TOOL, args)
    assert not res.is_error, res
    return json.loads(res.content[0].text)


async def apply(c, args, note=NOTE):
    pre = await call(c, args)
    assert pre.get("ok") and not pre["errors"], pre
    return pre, await call(c, {**args, "confirm": True, "fingerprint": pre["fingerprint"], "approval_note": note})


def journal_text(path):
    return "".join(p.read_text() for p in path.glob("*.jsonl")) if path.exists() else ""


# ------------------------------------------------------------------------------------------------ create
async def test_create_is_disabled_wpa2_on_the_named_network_and_the_passphrase_never_appears(make_session):
    net = FakeWifi()
    async with make_session(net) as (c, journal):
        pre, out = await apply(c, {"action": "create", "name": "zz-test", "network": "LAN_Private", "security": "wpa2", "passphrase_env": "UNIFI_WIFI_TEST"})
        text = json.dumps(pre) + json.dumps(out) + journal_text(journal)
    assert SECRET not in text and "UNIFI_WIFI_TEST" not in json.dumps(out)
    _, path, body = net.writes()[0]
    assert path == WLANS and body["enabled"] is False and body["x_passphrase"] == SECRET
    assert body["networkconf_id"] == N_PRIV and body["ap_group_ids"] == [GROUP] and body["ap_group_mode"] == "all"
    assert body["usergroup_id"] == "ug1" and body["wpa3_support"] is False and body["pmf_mode"] == "disabled"
    assert out["applied"] and out["verified"] and "x_passphrase" in out["secret_fields_not_verified"]
    assert out["rollback"]["arguments"]["action"] == "delete"


async def test_create_needs_network_security_and_a_passphrase_variable(make_session):
    net = FakeWifi()
    async with make_session(net) as (c, _):
        for args, word in (({"name": "x", "security": "wpa2", "passphrase_env": "UNIFI_WIFI_TEST"}, "network"),
                           ({"name": "x", "network": "LAN_Private", "passphrase_env": "UNIFI_WIFI_TEST"}, "security"),
                           ({"name": "x", "network": "LAN_Private", "security": "wpa2"}, "passphrase_env"),
                           ({"name": "x", "network": "Nope", "security": "wpa2", "passphrase_env": "UNIFI_WIFI_TEST"}, "not a network"),
                           ({"name": "x", "network": "Internet", "security": "wpa2", "passphrase_env": "UNIFI_WIFI_TEST"}, "not a network")):
            assert word in await raw(c, {"action": "create", **args})
    assert not net.writes()


async def test_passphrase_variable_must_be_named_set_and_long_enough(make_session):
    net = FakeWifi()
    base = {"action": "create", "name": "x", "network": "LAN_Private", "security": "wpa2"}
    async with make_session(net) as (c, _):
        assert "must be the name of an environment variable" in await raw(c, {**base, "passphrase_env": "HOME"})
        assert "is not set" in await raw(c, {**base, "passphrase_env": "UNIFI_WIFI_MISSING"})
        pre = await call(c, {**base, "passphrase_env": "UNIFI_WIFI_SHORT"})
        assert any("8 to 63" in e for e in pre["errors"]) and "short" not in json.dumps(pre)
    assert not net.writes()


async def test_open_ssid_needs_its_own_acknowledgement_and_takes_no_passphrase(make_session):
    net = FakeWifi()
    args = {"action": "create", "name": "portal", "network": "LAN_Private", "security": "open", "guest": True}
    async with make_session(net) as (c, _):
        pre = await call(c, args)
        assert any("Open security stop" in e for e in pre["errors"])
        assert "takes no passphrase" in await raw(c, {**args, "passphrase_env": "UNIFI_WIFI_TEST"})
        _, out = await apply(c, {**args, "acknowledge_open": True})
    assert out["applied"] and net.by_name("portal")["security"] == "open" and "x_passphrase" not in net.writes()[0][2]


async def test_duplicate_name_and_oversize_name_are_refused(make_session):
    net = FakeWifi()
    base = {"action": "create", "network": "LAN_Private", "security": "wpa2", "passphrase_env": "UNIFI_WIFI_TEST"}
    async with make_session(net) as (c, _):
        assert any("already called" in e for e in (await call(c, {**base, "name": "ExampleNet"}))["errors"])
        assert any("1 to 32" in e for e in (await call(c, {**base, "name": "x" * 33}))["errors"])


async def test_wpa3_only_warns(make_session):
    net = FakeWifi()
    async with make_session(net) as (c, _):
        pre = await call(c, {"action": "create", "name": "w3", "network": "LAN_Private", "security": "wpa3", "passphrase_env": "UNIFI_WIFI_TEST"})
    assert any("WPA3-only" in w for w in pre["warnings"]) and pre["after"]["pmf_mode"] == "required"


# ------------------------------------------------------------------------------------------------ update
async def test_edit_sends_the_whole_object_with_secrets_unchanged_and_nothing_else_moves(make_session):
    net = FakeWifi()
    before = copy.deepcopy(net.rows)
    async with make_session(net) as (c, _):
        pre, out = await apply(c, {"action": "update", "target": "ExampleNet", "l2_isolation": True})
    body = net.writes()[0][2]
    assert body["x_passphrase"] == OLD_PW and body["x_iapp_key"] == "iapp-secret" and body["l2_isolation"] is True
    assert {k: v for k, v in body.items() if k != "l2_isolation"} == {k: v for k, v in before[0].items() if k != "l2_isolation"}
    assert set(pre["diff"]) == {"l2_isolation"} and out["verified"]
    assert net.rows[1:] == before[1:]
    assert OLD_PW not in json.dumps(pre) + json.dumps(out)


async def test_changes_that_drop_clients_are_refused_until_acknowledged_and_name_the_clients(make_session):
    net = FakeWifi()
    async with make_session(net) as (c, _):
        pre = await call(c, {"action": "update", "target": "ExampleNet_Sonos", "hide_ssid": True})
        assert any("Disconnect stop" in e for e in pre["errors"]) and any("Sonos Playbar" in w for w in pre["warnings"])
        refused = await raw(c, {"action": "update", "target": "ExampleNet_Sonos", "hide_ssid": True, "confirm": True,
                                "fingerprint": pre["fingerprint"], "approval_note": NOTE})
        assert "Refused" in refused and not net.writes()
        _, out = await apply(c, {"action": "update", "target": "ExampleNet_Sonos", "hide_ssid": True, "acknowledge_disconnect": True})
    assert out["applied"] and net.by_name("ExampleNet_Sonos")["hide_ssid"] is True


async def test_an_ssid_with_no_clients_needs_no_acknowledgement(make_session):
    net = FakeWifi()
    net.clients = []
    async with make_session(net) as (c, _):
        pre, out = await apply(c, {"action": "update", "target": "ExampleNet_Sonos", "name": "ExampleNet_Sonos2"})
    assert out["applied"] and any("reconnect" in w for w in pre["warnings"])


async def test_passphrase_change_is_applied_not_verified_and_rollback_says_re_enter(make_session):
    net = FakeWifi()
    net.clients = []
    async with make_session(net) as (c, journal):
        pre, out = await apply(c, {"action": "update", "target": "ExampleNet_IoT", "passphrase_env": "UNIFI_WIFI_TEST"})
        text = json.dumps(pre) + json.dumps(out) + journal_text(journal)
    assert net.by_name("ExampleNet_IoT")["x_passphrase"] == SECRET
    assert SECRET not in text and OLD_PW not in text
    assert "x_passphrase" in out["secret_fields_not_verified"] and "re-enter" in out["rollback"]["note"]


async def test_moving_to_another_network_warns_and_needs_the_acknowledgement_with_clients(make_session):
    net = FakeWifi()
    async with make_session(net) as (c, _):
        pre = await call(c, {"action": "update", "target": "ExampleNet_IoT", "network": "LAN_Private"})
        assert any("Clients move from network LAN_IoT to LAN_Private" in w for w in pre["warnings"])
        assert any("Disconnect stop" in e for e in pre["errors"])


async def test_switching_an_existing_wpa_ssid_to_open_is_not_offered(make_session):
    async with make_session(FakeWifi()) as (c, _):
        assert "not offered" in await raw(c, {"action": "update", "target": "ExampleNet", "security": "open"})


async def test_enabled_is_not_an_update_field_and_unknown_target_is_refused(make_session):
    async with make_session(FakeWifi()) as (c, _):
        assert "enable or disable action" in await raw(c, {"action": "update", "target": "ExampleNet", "enabled": False})
        assert "No SSID" in await raw(c, {"action": "update", "target": "Nope", "hide_ssid": True})


async def test_other_ssids_changing_is_reported_as_a_mismatch(make_session):
    net = FakeWifi()
    net.clients = []

    def alter(row):
        net.rows[1]["hide_ssid"] = True
        return row
    net.alter = alter
    async with make_session(net) as (c, _):
        _, out = await apply(c, {"action": "update", "target": "ExampleNet", "l2_isolation": True})
    assert not out["verified"] and any("ExampleNet_IoT" in m["field"] for m in out["mismatches"])


# ------------------------------------------------------------------------------------------------ enable, disable, delete
async def test_disable_needs_the_acknowledgement_when_clients_are_on_it_and_enable_does_not(make_session):
    net = FakeWifi()
    async with make_session(net) as (c, _):
        pre = await call(c, {"action": "disable", "target": "ExampleNet_IoT"})
        assert any("Disconnect stop" in e for e in pre["errors"])
        _, out = await apply(c, {"action": "disable", "target": "ExampleNet_IoT", "acknowledge_disconnect": True})
        assert net.by_name("ExampleNet_IoT")["enabled"] is False and out["rollback"]["arguments"]["action"] == "enable"
        _, out2 = await apply(c, {"action": "enable", "target": "ExampleNet_IoT"})
    assert net.by_name("ExampleNet_IoT")["enabled"] is True and out2["verified"]


async def test_delete_is_refused_with_clients_and_applies_when_acknowledged_or_empty(make_session):
    net = FakeWifi()
    async with make_session(net) as (c, _):
        pre = await call(c, {"action": "delete", "target": "ExampleNet_Sonos"})
        assert any("Disconnect stop" in e for e in pre["errors"])
        _, out = await apply(c, {"action": "delete", "target": "ExampleNet_Sonos", "acknowledge_disconnect": True})
        assert out["applied"] and all(r["name"] != "ExampleNet_Sonos" for r in net.rows)
        assert "passphrase" in out["rollback"]["note"]
        _, out2 = await apply(c, {"action": "delete", "target": "apple"})
    assert out2["applied"] and len(net.rows) == 2


async def test_delete_and_enable_take_no_field_values(make_session):
    async with make_session(FakeWifi()) as (c, _):
        assert "takes no field values" in await raw(c, {"action": "delete", "target": "ExampleNet", "hide_ssid": True})
        assert "takes no field values" in await raw(c, {"action": "enable", "target": "ExampleNet", "name": "x"})


# ------------------------------------------------------------------------------------------------ gates and routing
async def test_gates_stale_fingerprint_and_tier_c_note(make_session):
    net = FakeWifi()
    net.clients = []
    args = {"action": "update", "target": "ExampleNet", "l2_isolation": True}
    async with make_session(net, writes=False) as (c, _):
        pre = await call(c, args)
        assert "Writes are disabled" in pre["apply_blocked_reason"]
    async with make_session(net, entities=frozenset({"port_forward"})) as (c, _):
        assert "not enabled for writes" in (await call(c, args))["apply_blocked_reason"]
    async with make_session(net) as (c, _):
        pre = await call(c, args)
        assert "approval_note" in await raw(c, {**args, "confirm": True, "fingerprint": pre["fingerprint"]})
        net.by_name("ExampleNet")["hide_ssid"] = True
        assert "differs from the preview" in await raw(c, {**args, "confirm": True, "fingerprint": pre["fingerprint"], "approval_note": NOTE})
    assert not net.writes()


async def test_generic_tool_refuses_the_wlanconf_writes_and_names_the_typed_tool(make_session):
    net = FakeWifi()
    async with make_session(net) as (c, _):
        for op, extra in (("deleteWlanConfig", {"path_params": {"id": "w-main"}}), ("createWlanConfig", {"body": {"name": "x"}}),
                          ("updateWlanConfig", {"path_params": {"id": "w-main"}, "body": {"name": "x"}})):
            res = await c.call_tool("unifi_console_call_operation", {"operation_id": op, "confirm": True, **extra})
            assert TOOL in res.content[0].text
    assert net.writes() == []
