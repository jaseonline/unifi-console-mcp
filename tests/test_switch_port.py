"""Switch port settings through the write framework: whole port_overrides array, one port per call, protections, health guard."""
from __future__ import annotations

import contextlib
import copy
import dataclasses
import json

import httpx
import pytest
from mcp.client import Client

from conftest import make_jwt
from test_writes import Wrapped
from unifi_console_mcp.server import create_server

API = "/proxy/network/api/s/default"
DEVICES, BASIC, NETS, STA = f"{API}/stat/device", f"{API}/stat/device-basic", f"{API}/rest/networkconf", f"{API}/stat/sta"
TOOL = "unifi_console_switch_port"
NOTE = "plan claude/unifi-console-switch-port-plan-2026-10-18.md, approved in chat"
N_PRIV, N_IOT, N_SON = "n-priv", "n-iot", "n-son"
SW, SW_MAC = "sw-a", "aa:00:00:00:00:01"
GW_MAC, AP_MAC = "aa:00:00:00:00:10", "aa:00:00:00:00:20"


def entry(idx, **kw):
    base = {"port_idx": idx, "name": f"Port {idx}", "forward": "all", "native_networkconf_id": N_PRIV, "isolation": False,
            "poe_mode": "auto", "stp_port_mode": True, "flow_control_enabled": True, "autoneg": True, "lldpmed_enabled": True}
    return {**base, **kw}


def overrides():
    return [
        entry(1, name="Gateway", poe_mode="off", stp_edge_state="auto"),
        entry(2, name="Sonos Playbar", native_networkconf_id=N_SON, stormctrl_bcast_enabled=True, stormctrl_bcast_rate="300",
              stormctrl_type="rate"),
        entry(3, name="AP", link_debounce_auto=True),
        entry(4, name="Cloud Key"),
        entry(5, name="spare"),
        entry(7, name="odd", forward="customize", excluded_networkconf_ids=[N_IOT], dot1x_ctrl="force_authorized", port_security_enabled=False),
    ]


def port_table():
    rows = []
    for i in range(1, 9):
        rows.append({"port_idx": i, "name": f"Port {i}", "up": i in (1, 2, 3, 4), "is_uplink": i == 1, "poe_caps": 0 if i == 1 else 7,
                     "poe_enable": i in (3, 4), "poe_power": "6.5" if i in (3, 4) else "0.00"})
    return rows


def switch():
    return {"_id": SW, "mac": SW_MAC, "name": "Switch A", "type": "usw", "model": "USL16P", "state": 1, "adopted": True,
            "config_network": {"ip": "192.168.1.3"}, "stp_priority": "4096", "port_overrides": overrides(), "port_table": port_table(),
            "uplink": {"port_idx": 1, "type": "wire", "uplink_mac": GW_MAC, "uplink_device_name": "Gateway"}}


def devices():
    return [
        switch(),
        {"_id": "gw", "mac": GW_MAC, "name": "Gateway", "type": "ugw", "state": 1, "adopted": True, "uplink": {}},
        {"_id": "ap", "mac": AP_MAC, "name": "AP Pro", "type": "uap", "state": 1, "adopted": True,
         "uplink": {"uplink_mac": SW_MAC, "uplink_remote_port": 3, "type": "wire"}},
    ]


class FakeSwitchNet:
    def __init__(self) -> None:
        self.devs = devices()
        self.log: list[tuple[str, str, object]] = []
        self.mutate = None                  # fn(overrides) -> overrides, applied on every PUT (a console that alters other entries)
        self.ap_down_on_put = False
        self.fail_after = None
        self.n_writes = 0

    def sw(self):
        return self.devs[0]

    def ov(self):
        return copy.deepcopy(self.sw()["port_overrides"])

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        if path == "/api/auth/login":
            return httpx.Response(200, json={}, headers={"set-cookie": f"TOKEN={make_jwt()}; Path=/", "x-csrf-token": "c"})
        wrap = lambda x: {"meta": {"rc": "ok"}, "data": x}  # noqa: E731
        if method == "GET":
            if path == DEVICES:
                return httpx.Response(200, json=wrap(copy.deepcopy(self.devs)))
            if path == BASIC:
                return httpx.Response(200, json=wrap([{k: d[k] for k in ("mac", "name", "type", "state", "adopted")} for d in self.devs]))
            if path == NETS:
                return httpx.Response(200, json=wrap([
                    {"_id": N_PRIV, "name": "LAN_Private", "purpose": "corporate", "ip_subnet": "192.168.1.1/24"},
                    {"_id": N_IOT, "name": "LAN_IoT", "purpose": "corporate", "ip_subnet": "10.88.1.1/24"},
                    {"_id": N_SON, "name": "LAN_Sonos", "purpose": "corporate", "ip_subnet": "10.88.2.1/24"}]))
            if path == STA:
                return httpx.Response(200, json=wrap([
                    {"mac": "c1", "name": "Sonos Playbar", "sw_mac": SW_MAC, "sw_port": 2, "ip": "10.88.2.5"},
                    {"mac": "c2", "name": "Cloud Key Gen2 Plus", "sw_mac": SW_MAC, "sw_port": 4, "ip": "127.0.0.1"}]))
            return httpx.Response(404, json={})
        body = json.loads(request.content) if request.content else None
        self.log.append((method, path, body))
        self.n_writes += 1
        if self.fail_after is not None and self.n_writes > self.fail_after:
            return httpx.Response(500, json={"message": "boom"})
        if method == "PUT" and path == f"{API}/rest/device/{SW}":
            assert set(body) == {"port_overrides"}, body
            arr = copy.deepcopy(body["port_overrides"])
            self.sw()["port_overrides"] = self.mutate(arr) if self.mutate else arr
            if self.ap_down_on_put and self.n_writes == 1:
                self.devs[2]["state"] = 0
            return httpx.Response(200, json=wrap([self.sw()]))
        return httpx.Response(404, json={})

    def writes(self):
        return [e for e in self.log if "login" not in e[1]]


@pytest.fixture
def make_session(settings, tmp_path, monkeypatch):
    monkeypatch.setattr("unifi_console_mcp.entities.switch_port.socket.gethostbyname", lambda host: "127.0.0.1")

    @contextlib.asynccontextmanager
    async def opener(net, *, entities=frozenset({"switch_port"}), writes=True, force_fail=False):
        s = dataclasses.replace(settings, enable_writes=writes, write_entities=entities, journal_dir=tmp_path / "journal",
                                dns_probe_window=1.0, dns_probe_force_fail=force_fail)
        mcp, api = create_server(s, transport=httpx.MockTransport(net))
        try:
            async with Client(mcp) as client:
                yield Wrapped(client)
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


def ent(arr, idx):
    return next((e for e in arr if e["port_idx"] == idx), None)


def untouched(before, after, *ports):
    for e in before:
        if e["port_idx"] not in ports:
            assert ent(after, e["port_idx"]) == e


# ------------------------------------------------------------------------------------------------ add, edit, reset
async def test_rename_a_port_without_an_entry_adds_one_and_sends_everything_else_unchanged(make_session):
    net = FakeSwitchNet()
    before = net.ov()
    async with make_session(net) as c:
        pre, out = await apply(c, {"target": "Switch A", "port": 6, "name": "Spare 6"})
    assert pre["request"]["body_fields"] == ["port_overrides"]
    assert pre["after"]["name"] == "Spare 6" and pre["before"] is None
    assert any("no saved settings yet" in w for w in pre["warnings"])
    sent = net.writes()[0][2]["port_overrides"]
    untouched(before, sent, 6)
    new = ent(sent, 6)
    assert new["name"] == "Spare 6" and new["native_networkconf_id"] == N_PRIV and new["poe_mode"] == "auto"
    assert out["applied"] and out["verified"] and out["guard"]["probe_after"] == "ok"
    untouched(before, net.ov(), 6)
    assert out["rollback"]["arguments"] == {"action": "update", "target": "Switch A", "port": 6, "reset": True}


async def test_edit_an_uneven_entry_changes_only_the_asked_fields(make_session):
    net = FakeSwitchNet()
    before = net.ov()
    async with make_session(net) as c:
        pre, out = await apply(c, {"target": SW_MAC, "port": 5, "isolation": True, "bpdu_guard": True})
    assert pre["diff"] and set(pre["diff"]) == {"isolation", "stp_bpdu_guard_enabled"}
    now = net.ov()
    untouched(before, now, 5)
    assert ent(now, 5)["isolation"] is True and ent(now, 5)["stp_bpdu_guard_enabled"] is True
    assert out["verified"] and out["rollback"]["arguments"]["isolation"] is False


async def test_reset_removes_an_untouched_entry_only(make_session):
    net = FakeSwitchNet()
    async with make_session(net) as c:
        await apply(c, {"target": "Switch A", "port": 6, "name": "x"})
        _, out = await apply(c, {"target": "Switch A", "port": 6, "reset": True})
        assert ent(net.ov(), 6) is None and out["verified"]
        refused = await raw(c, {"target": "Switch A", "port": 7, "reset": True})
        assert "beyond what this tool creates" in refused
        assert "no saved settings" in await raw(c, {"target": "Switch A", "port": 8, "reset": True})
        assert "reset takes no other fields" in await raw(c, {"target": "Switch A", "port": 6, "reset": True, "name": "q"})


async def test_storm_control_and_native_network_by_name(make_session):
    net = FakeSwitchNet()
    async with make_session(net) as c:
        await apply(c, {"target": "Switch A", "port": 5, "native_network": "LAN_IoT",
                        "storm_control": {"unicast": {"enabled": True, "rate": 500}}})
    e = ent(net.ov(), 5)
    assert e["native_networkconf_id"] == N_IOT and e["stormctrl_ucast_enabled"] is True and e["stormctrl_ucast_rate"] == 500


async def test_blocked_networks_need_customize_mode(make_session):
    net = FakeSwitchNet()
    async with make_session(net) as c:
        assert "customize" in await raw(c, {"target": "Switch A", "port": 5, "blocked_networks": ["LAN_IoT"]})
        await apply(c, {"target": "Switch A", "port": 7, "blocked_networks": ["LAN_IoT", "LAN_Sonos"]})
        assert "not a network" in await raw(c, {"target": "Switch A", "port": 7, "blocked_networks": ["nope"]})
    assert ent(net.ov(), 7)["excluded_networkconf_ids"] == [N_IOT, N_SON]


# ------------------------------------------------------------------------------------------------ validation
@pytest.mark.parametrize("args,text", [
    ({"port": 99, "name": "x"}, "no port 99"),
    ({"port": 1, "poe_mode": "off", "acknowledge_infrastructure": True}, "not a PoE port"),
    ({"port": 5, "native_network": "nope"}, "not a network"),
    ({"port": 5, "storm_control": {"unicast": {"rate": 0}}}, "whole number"),
    ({"port": 5, "storm_control": {"unicast": {"rate": 10**9}}}, "whole number"),
    ({"port": 5}, "Nothing to change"),
    ({"port": 5, "name": " "}, "1 to 64"),
])
async def test_bad_requests_are_refused(make_session, args, text):
    net = FakeSwitchNet()
    async with make_session(net) as c:
        assert text in await raw(c, {"target": "Switch A", **args})
    assert net.writes() == []


async def test_target_must_be_a_switch(make_session):
    net = FakeSwitchNet()
    async with make_session(net) as c:
        assert "not a switch" in await raw(c, {"target": "Gateway", "port": 1, "name": "x"})
        assert "No switch" in await raw(c, {"target": "nope", "port": 1, "name": "x"})
        assert "Extra inputs" in await raw(c, {"target": "Switch A", "port": 5, "stp_edge": True})


# ------------------------------------------------------------------------------------------------ protections
@pytest.mark.parametrize("port,what", [(1, "uplink"), (3, "AP Pro"), (4, "console")])
async def test_risky_fields_on_infrastructure_ports_are_refused_unless_acknowledged(make_session, port, what):
    net = FakeSwitchNet()
    async with make_session(net) as c:
        for args in ({"poe_mode": "off"} if port != 1 else {"isolation": True}, {"native_network": "LAN_IoT"}, {"bpdu_guard": True},
                     {"storm_control": {"broadcast": {"enabled": True}}}):
            pre = await call(c, {"target": "Switch A", "port": port, **args})
            assert any("Infrastructure stop" in e and what in e for e in pre["errors"]), (port, args, pre["errors"])
            assert "Infrastructure stop" in await raw(c, {"target": "Switch A", "port": port, **args, "confirm": True,
                                                          "fingerprint": pre["fingerprint"], "approval_note": NOTE})
    assert net.writes() == []


async def test_name_is_always_allowed_and_acknowledgement_unlocks_the_rest(make_session):
    net = FakeSwitchNet()
    async with make_session(net) as c:
        pre, out = await apply(c, {"target": "Switch A", "port": 1, "name": "Gateway link"})
        assert out["verified"] and ent(net.ov(), 1)["name"] == "Gateway link"
        pre, out = await apply(c, {"target": "Switch A", "port": 3, "isolation": True, "acknowledge_infrastructure": True})
        assert any("Acknowledged" in w for w in pre["warnings"]) and out["verified"]


async def test_client_port_warnings(make_session):
    net = FakeSwitchNet()
    async with make_session(net) as c:
        pre = await call(c, {"target": "Switch A", "port": 2, "poe_mode": "off", "native_network": "LAN_IoT"})
    text = " ".join(pre["warnings"])
    assert not pre["errors"] and "Sonos Playbar" in text and "native VLAN moves from LAN_Sonos to LAN_IoT" in text
    assert "client" in pre["warnings"][0]


async def test_poe_off_on_a_port_drawing_power_is_warned(make_session):
    net = FakeSwitchNet()
    net.sw()["port_table"][1]["poe_enable"], net.sw()["port_table"][1]["poe_power"] = True, "9.1"
    async with make_session(net) as c:
        pre = await call(c, {"target": "Switch A", "port": 2, "poe_mode": "off"})
    assert any("9.1 W" in w for w in pre["warnings"])


# ------------------------------------------------------------------------------------------------ verification and safety net
async def test_verification_catches_a_console_that_alters_other_entries(make_session):
    net = FakeSwitchNet()
    net.mutate = lambda arr: [e for e in arr if e["port_idx"] != 5]
    async with make_session(net) as c:
        _, out = await apply(c, {"target": "Switch A", "port": 6, "name": "x"})
    assert out["verified"] is False and "attention" in out
    assert any(m["field"].startswith("port 5") for m in out["mismatches"])


async def test_health_guard_failure_restores_the_previous_array_once(make_session):
    net = FakeSwitchNet()
    net.ap_down_on_put = True
    before = net.ov()
    async with make_session(net) as c:
        _, out = await apply(c, {"target": "Switch A", "port": 6, "name": "x"})
    assert out["applied"] is False and out["guard"]["auto_restored"] and out["guard"]["restore_verified"]
    assert "AP Pro" in out["guard"]["probe_after"]
    assert net.ov() == before
    assert len(net.writes()) == 2


async def test_forced_failure_switch_proves_the_restore(make_session):
    net = FakeSwitchNet()
    before = net.ov()
    async with make_session(net, force_fail=True) as c:
        _, out = await apply(c, {"target": "Switch A", "port": 5, "isolation": True})
    assert out["applied"] is False and out["guard"]["auto_restored"] and net.ov() == before
    assert "forced failure" in out["guard"]["probe_after"]


async def test_failed_restore_is_reported_loudly(make_session):
    net = FakeSwitchNet()
    net.ap_down_on_put = True
    net.fail_after = 1
    async with make_session(net) as c:
        _, out = await apply(c, {"target": "Switch A", "port": 6, "name": "x"})
    assert out["guard"].get("restore_error") and "restore failed" in out["attention"]


async def test_a_device_already_down_is_not_blamed(make_session):
    net = FakeSwitchNet()
    net.devs[2]["state"] = 0
    async with make_session(net) as c:
        _, out = await apply(c, {"target": "Switch A", "port": 6, "name": "x"})
    assert out["applied"] and out["guard"]["probe_after"] == "ok"


# ------------------------------------------------------------------------------------------------ gates
async def test_gates_and_stale_fingerprint(make_session):
    net = FakeSwitchNet()
    args = {"target": "Switch A", "port": 6, "name": "x"}
    async with make_session(net, writes=False) as c:
        assert (await call(c, args))["apply_blocked_reason"]
    async with make_session(net, entities=frozenset({"port_forward"})) as c:
        pre = await call(c, args)
        assert "not enabled for writes" in await raw(c, {**args, "confirm": True, "fingerprint": pre["fingerprint"], "approval_note": NOTE})
    async with make_session(net) as c:
        pre = await call(c, args)
        assert "approval_note" in await raw(c, {**args, "confirm": True, "fingerprint": pre["fingerprint"]})
        net.sw()["port_overrides"].append(entry(8, name="changed meanwhile"))
        assert "differs from the preview" in await raw(c, {**args, "confirm": True, "fingerprint": pre["fingerprint"], "approval_note": NOTE})
    assert net.writes() == []


async def test_no_change_sends_nothing(make_session):
    net = FakeSwitchNet()
    async with make_session(net) as c:
        out = await call(c, {"target": "Switch A", "port": 5, "name": "spare"})
        assert out["note"].startswith("Already")
    assert net.writes() == []


async def test_generic_tool_refuses_the_device_settings_write(make_session):
    net = FakeSwitchNet()
    async with make_session(net) as c:
        res = await c.call_tool("unifi_console_call_operation", {"operation_id": "updateDeviceSettings", "confirm": True,
                                                                  "path_params": {"id": SW}, "body": {"port_overrides": []}})
    assert TOOL in res.content[0].text and net.writes() == []
