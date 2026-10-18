"""unifi_console_device: locate, restart, disable, enable, update, adopt and remove (fake console, nothing real is touched)."""
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
from unifi_console_mcp.client import UniFiError
from unifi_console_mcp.entities import device as dev
from unifi_console_mcp.server import create_server

API = "/proxy/network/api/s/default"
TOOL = "unifi_console_device"
PRIVATE, IOT = "5a1c0000-0000-4000-8000-0000000000a1", "5a1c0000-0000-4000-8000-0000000000a2"
NETS = [{"_id": PRIVATE, "name": "LAN_Private", "purpose": "corporate"}, {"_id": IOT, "name": "LAN_IoT", "purpose": "corporate"},
        {"_id": "wan1", "name": "Internet", "purpose": "wan"}]
AP, SW, GW, NEW = "02:00:00:00:00:41", "02:00:00:00:00:42", "02:00:00:00:00:43", "02:00:00:00:00:44"


def rows():
    return [
        {"_id": "id-ap", "mac": AP, "name": "AP-Lounge", "type": "uap", "model": "U6", "ip": "192.168.1.20", "state": 1, "adopted": True,
         "uptime": 5000, "num_sta": 3, "uplink": {"uplink_mac": SW}, "mgmt_network_id": PRIVATE, "led_override": "default",
         "config_network": {"type": "dhcp", "bonding_enabled": False}, "x_authkey": "SECRET-KEY", "syslog_key": "SECRET-SYSLOG"},
        {"_id": "id-sw", "mac": SW, "name": "Switch-Core", "type": "usw", "model": "USW8", "ip": "192.168.1.4", "state": 1, "adopted": True,
         "uptime": 90000, "stp_priority": "8192", "mgmt_network_id": PRIVATE, "uplink": {"uplink_mac": GW},
         "port_table": [{"port_idx": 1, "poe_enable": True, "poe_power": "6.5"}, {"port_idx": 2, "poe_enable": False}],
         "config_network": {"type": "static", "ip": "192.168.1.4", "netmask": "255.255.255.0", "gateway": "192.168.1.1",
                            "dns1": "192.168.1.1", "dns2": "", "bonding_enabled": False}, "x_authkey": "SECRET-KEY-2"},
        {"_id": "id-gw", "mac": GW, "name": "Gateway", "type": "ugw", "model": "UXG", "ip": "192.168.1.1", "state": 1, "adopted": True,
         "uptime": 200000, "uplink": {}, "config_network": {"type": "static", "ip": "192.168.1.1"}},
    ]


class FakeDevices:
    def __init__(self, *, restart_works=True, pending=True) -> None:
        self.rows = rows()
        self.pending = [{"_id": "id-new", "mac": NEW, "name": "New AP", "type": "uap", "adopted": False, "state": 2}] if pending else []
        self.restart_works = restart_works
        self.log: list[tuple[str, str, object]] = []

    def basic(self):
        keys = ("_id", "mac", "name", "type", "adopted", "state", "disabled")
        return [{k: r[k] for k in keys if k in r} for r in self.rows] + copy.deepcopy(self.pending)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        if path == "/api/auth/login":
            return httpx.Response(200, json={}, headers={"set-cookie": f"TOKEN={make_jwt()}; Path=/", "x-csrf-token": "c"})
        body = json.loads(request.content) if request.content else None
        self.log.append((method, path, body))
        ok = lambda data: httpx.Response(200, json={"meta": {"rc": "ok"}, "data": data})  # noqa: E731
        if path == API + "/stat/device":
            return ok(copy.deepcopy(self.rows))
        if path == API + "/stat/device-basic":
            return ok(self.basic())
        if path == API + "/rest/networkconf":
            return ok(NETS)
        if path.startswith(API + "/rest/device/") and method == "PUT":
            row = next((r for r in self.rows if r["_id"] == path.rsplit("/", 1)[1]), None)
            if row is None:
                return httpx.Response(404, json={})
            row.update(body)
            return ok([copy.deepcopy(row)])
        if path == API + "/cmd/devmgr":
            row = next((r for r in self.rows if r["mac"] == body.get("mac")), None)
            if body["cmd"] in ("set-locate", "unset-locate") and row is not None:
                row["locating"] = body["cmd"] == "set-locate"
            elif body["cmd"] == "restart" and row is not None and self.restart_works:
                row["uptime"] = 12
            elif body["cmd"] == "adopt":
                p = next((x for x in self.pending if x["mac"] == body["mac"]), None)
                if p:
                    self.pending.remove(p)
                    self.rows.append({**p, "adopted": True, "state": 1, "_id": "id-new-2", "uptime": 3})
            return ok([])
        if path == API + "/cmd/sitemgr":
            for r in [r for r in self.rows if r["mac"] in body["macs"]]:       # a forgotten device waits to be adopted, with defaults
                self.pending.append({"_id": "id-pend-" + r["_id"], "mac": r["mac"], "name": r.get("model"), "type": r["type"],
                                     "adopted": False, "state": 2})
            self.rows = [r for r in self.rows if r["mac"] not in body["macs"]]
            return ok([])
        return httpx.Response(404, json={})

    def writes(self):
        return [e for e in self.log if e[0] in ("POST", "PUT", "DELETE") and "login" not in e[1]]


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    async def fast(_seconds: float) -> None:
        return None
    monkeypatch.setattr(dev, "_sleep", fast)


@pytest.fixture
def make_session(settings, tmp_path):
    @contextlib.asynccontextmanager
    async def opener(net: FakeDevices, *, entities=frozenset({"device"})):
        s = dataclasses.replace(settings, enable_writes=True, write_entities=entities, journal_dir=tmp_path / "journal")
        mcp, api = create_server(s, transport=httpx.MockTransport(net))
        try:
            async with Client(mcp) as client:
                yield Wrapped(client)
        finally:
            await api.client.aclose()
    return opener


async def call(c, params):
    res = await c.call_tool(TOOL, params)
    assert not res.is_error, res
    return json.loads(res.content[0].text)


async def apply(c, params, **extra):
    pre = await call(c, params)
    assert pre.get("ok") and not pre["errors"], pre
    out = await call(c, {**params, "confirm": True, "fingerprint": pre["fingerprint"], **extra})
    return pre, out


# ------------------------------------------------------------------------------------------ locate
async def test_locate_needs_no_fingerprint_and_is_read_back(make_session):
    net = FakeDevices()
    async with make_session(net) as c:
        pre = await call(c, {"action": "locate", "target": "AP-Lounge"})
        assert pre["tier"] == "A" and net.writes() == []
        out = await call(c, {"action": "locate", "target": "AP-Lounge", "confirm": True})
        assert out["applied"] and out["verified"] is True and out["rollback"]["arguments"]["action"] == "unlocate"
        assert net.writes() == [("POST", API + "/cmd/devmgr", {"mac": AP, "cmd": "set-locate"})]
        again = await call(c, {"action": "locate", "target": AP})
        assert again["note"].startswith("Already")


async def test_gates_apply_to_locate_too(make_session):
    async with make_session(FakeDevices(), entities=frozenset({"client"})) as c:
        res = await c.call_tool(TOOL, {"action": "locate", "target": "AP-Lounge", "confirm": True})
        assert "not enabled for writes" in res.content[0].text


# ------------------------------------------------------------------------------------------ update
async def test_rename_sends_only_the_changed_field(make_session):
    net = FakeDevices()
    async with make_session(net) as c:
        pre, out = await apply(c, {"action": "update", "target": "AP-Lounge", "name": "AP-Lounge2"})
        assert pre["tier"] == "B" and pre["request"]["body"] == {"name": "AP-Lounge2"}
        assert out["verified"] is True
        assert net.writes() == [("PUT", API + "/rest/device/id-ap", {"name": "AP-Lounge2"})]
        assert out["rollback"]["arguments"] == {"action": "update", "target": AP, "name": "AP-Lounge"}


async def test_management_network_and_ip_are_tier_c(make_session):
    net = FakeDevices()
    async with make_session(net) as c:
        params = {"action": "update", "target": "Switch-Core", "management_network": "LAN_IoT", "ip": "192.168.1.5"}
        pre = await call(c, params)
        assert pre["tier"] == "C" and pre["errors"] == []
        res = await c.call_tool(TOOL, {**params, "confirm": True, "fingerprint": pre["fingerprint"]})
        assert "tier C" in res.content[0].text and net.writes() == []
        out = await call(c, {**params, "confirm": True, "fingerprint": pre["fingerprint"], "approval_note": "plan 18 Oct"})
        assert out["verified"] is True
        (_m, _p, body), = net.writes()
        assert body["mgmt_network_id"] == IOT and body["config_network"]["ip"] == "192.168.1.5"
        assert body["config_network"]["gateway"] == "192.168.1.1" and "name" not in body


@pytest.mark.parametrize("fields, text", [
    ({"ip": "192.168.1.9", "gateway": "10.0.0.1"}, "do not fit the subnet"),
    ({"ip": "192.168.1.1"}, "already used by Gateway"),
    ({"management_network": "Internet"}, "not a network on this console"),
    ({"stp_priority": 100}, "multiple of 4096"),
    ({"name": ""}, "1 to 64 characters"),
])
async def test_bad_updates_are_refused(make_session, fields, text):
    net = FakeDevices()
    async with make_session(net) as c:
        pre = await call(c, {"action": "update", "target": "Switch-Core", **fields})
        assert text in " ".join(pre["errors"]), pre
        res = await c.call_tool(TOOL, {"action": "update", "target": "Switch-Core", **fields, "confirm": True, "fingerprint": pre["fingerprint"],
                                       "approval_note": "x"})
        assert "Refused" in res.content[0].text and net.writes() == []


async def test_stp_priority_only_on_a_switch(make_session):
    async with make_session(FakeDevices()) as c:
        pre = await call(c, {"action": "update", "target": "AP-Lounge", "stp_priority": 4096})
        assert "only applies to a switch" in " ".join(pre["errors"])


async def test_unchanged_update_sends_nothing(make_session):
    net = FakeDevices()
    async with make_session(net) as c:
        pre = await call(c, {"action": "update", "target": "AP-Lounge", "name": "AP-Lounge"})
        assert pre["note"].startswith("Already")
        out = await call(c, {"action": "update", "target": "AP-Lounge", "name": "AP-Lounge", "confirm": True, "fingerprint": pre["fingerprint"]})
        assert out["applied"] is False and net.writes() == []


# ------------------------------------------------------------------------------------------ disable and enable
async def test_disable_is_tier_c_then_enable_restores(make_session):
    net = FakeDevices()
    async with make_session(net) as c:
        pre = await call(c, {"action": "disable", "target": "AP-Lounge"})
        assert pre["tier"] == "C" and any("wireless client" in w for w in pre["warnings"])
        out = await call(c, {"action": "disable", "target": "AP-Lounge", "confirm": True, "fingerprint": pre["fingerprint"], "approval_note": "ok"})
        assert out["verified"] is True and out["rollback"]["arguments"]["action"] == "enable"
        assert net.writes() == [("PUT", API + "/rest/device/id-ap", {"disabled": True})]
        pre2, out2 = await apply(c, {"action": "enable", "target": "AP-Lounge"})
        assert pre2["tier"] == "B" and out2["verified"] is True
        assert net.writes()[-1] == ("PUT", API + "/rest/device/id-ap", {"disabled": False})


# ------------------------------------------------------------------------------------------ restart
async def test_restart_leaf_ap_is_tier_b_and_seen_coming_back(make_session):
    net = FakeDevices()
    async with make_session(net) as c:
        pre, out = await apply(c, {"action": "restart", "target": "AP-Lounge"})
        assert pre["tier"] == "B" and out["verified"] is True and out["rollback"] is None
        assert net.writes() == [("POST", API + "/cmd/devmgr", {"mac": AP, "reboot_type": "hard", "cmd": "restart"})]


async def test_restart_switch_is_tier_c_and_lists_what_it_takes_down(make_session):
    net = FakeDevices()
    async with make_session(net) as c:
        pre = await call(c, {"action": "restart", "target": "Switch-Core"})
        assert pre["tier"] == "C" and pre["dependents"]["downlinks"] == ["AP-Lounge"] and pre["dependents"]["poe_ports"] == 1
        assert any("AP-Lounge" in w for w in pre["warnings"])
        res = await c.call_tool(TOOL, {"action": "restart", "target": "Switch-Core", "confirm": True, "fingerprint": pre["fingerprint"]})
        assert "tier C" in res.content[0].text and net.writes() == []


async def test_restart_that_is_not_seen_returns_is_reported(make_session):
    net = FakeDevices(restart_works=False)
    async with make_session(net) as c:
        _pre, out = await apply(c, {"action": "restart", "target": "AP-Lounge"}, wait_seconds=10)
        assert out["verified"] is False and "attention" in out and out["mismatches"][0]["field"] == "(device)"


# ------------------------------------------------------------------------------------------ adopt and remove
async def test_adopt_a_pending_device(make_session):
    net = FakeDevices()
    async with make_session(net) as c:
        pre, out = await apply(c, {"action": "adopt", "target": NEW})
        assert pre["tier"] == "B" and out["verified"] is True and out["new_id"] == "id-new-2"
        assert net.writes() == [("POST", API + "/cmd/devmgr", {"mac": NEW, "client": "web", "cmd": "adopt"})]
        assert out["rollback"]["arguments"]["action"] == "remove"


@pytest.mark.parametrize("target, text", [(AP, "already adopted"), ("02:00:00:00:00:99", "does not list a device")])
async def test_adopt_refuses_unknown_or_adopted_devices(make_session, target, text):
    async with make_session(FakeDevices()) as c:
        pre = await call(c, {"action": "adopt", "target": target})
        assert text in " ".join(pre["errors"])


async def test_adopt_needs_a_mac(make_session):
    async with make_session(FakeDevices()) as c:
        res = await c.call_tool(TOOL, {"action": "adopt", "target": "New AP"})
        assert "MAC address" in res.content[0].text


async def test_remove_needs_note_and_acknowledgement(make_session):
    net = FakeDevices()
    async with make_session(net) as c:
        params = {"action": "remove", "target": "AP-Lounge"}
        pre = await call(c, params)
        assert pre["tier"] == "C" and any("cannot be undone" in w for w in pre["warnings"])
        base = {**params, "confirm": True, "fingerprint": pre["fingerprint"]}
        assert "tier C" in (await c.call_tool(TOOL, base)).content[0].text
        assert "acknowledge_removal" in (await c.call_tool(TOOL, {**base, "approval_note": "ok"})).content[0].text
        assert net.writes() == []
        out = await call(c, {**base, "approval_note": "ok", "acknowledge_removal": True})
        assert out["verified"] is True and out["rollback"] is None
        assert net.writes() == [("POST", API + "/cmd/sitemgr", {"macs": [AP], "cmd": "delete-device"})]


# ------------------------------------------------------------------------------------------ safety
async def test_stale_preview_is_refused(make_session):
    net = FakeDevices()
    async with make_session(net) as c:
        pre = await call(c, {"action": "update", "target": "AP-Lounge", "name": "A"})
        net.rows[0]["name"] = "Renamed elsewhere"
        res = await c.call_tool(TOOL, {"action": "update", "target": "AP-Lounge", "name": "A", "confirm": True, "fingerprint": pre["fingerprint"]})
        assert "differs from the preview" in res.content[0].text or "No device" in res.content[0].text
        assert net.writes() == []


async def test_secrets_never_appear_in_output_or_journal(make_session, tmp_path):
    net = FakeDevices()
    async with make_session(net) as c:
        pre, out = await apply(c, {"action": "update", "target": "AP-Lounge", "name": "AP-X"})
        text = json.dumps([pre, out])
    journal = "".join(p.read_text() for p in (tmp_path / "journal").glob("*.jsonl"))
    for secret in ("SECRET-KEY", "SECRET-SYSLOG"):
        assert secret not in text and secret not in journal
    assert "attempt" in journal


async def test_unknown_field_is_rejected(make_session):
    async with make_session(FakeDevices()) as c:
        res = await c.call_tool(TOOL, {"action": "update", "target": "AP-Lounge", "x_authkey": "no"})
        assert res.is_error or "extra" in res.content[0].text.lower()


# ------------------------------------------------------------------------------------------ pure planning
def test_the_console_device_is_refused_except_locate():
    rs = rows()
    rs[0]["ip"] = "192.168.1.2"
    for action in ("restart", "disable", "remove"):
        plan = dev.build_plan(action, "AP-Lounge", {}, rs, [], [], "192.168.1.2")
        assert any("running the console" in e for e in plan.errors)
    assert dev.build_plan("locate", "AP-Lounge", {}, rs, [], [], "192.168.1.2").errors == []


def test_gateway_changes_are_tier_c():
    plan = dev.build_plan("update", "Gateway", {"name": "GW"}, rows(), [], [], None)
    assert plan.tier == "C" and any("re-provisions" in w for w in plan.warnings)
    assert dev.build_plan("restart", "Gateway", {}, rows(), [], [], None).tier == "C"


def test_target_resolution_by_id_mac_and_name():
    for ref in ("id-ap", AP, AP.upper().replace(":", "-"), "AP-Lounge"):
        assert dev.build_plan("locate", ref, {}, rows(), [], [], None).mac == AP
    with pytest.raises(UniFiError):
        dev.build_plan("locate", "nothing", {}, rows(), [], [], None)
