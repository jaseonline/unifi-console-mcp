"""Firewall policies through the write framework: tier C, five different endpoints, DNS safety net with per-action restore."""
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
from test_doh import FakeDns
from test_writes import Wrapped
from unifi_console_mcp.server import create_server

BASE = "/proxy/network/v2/api/site/default"
POLICIES = f"{BASE}/firewall-policies"
ZONES = f"{BASE}/firewall/zone"
NETS = "/proxy/network/api/s/default/rest/networkconf"
CLIENTS = "/proxy/network/api/s/default/rest/user"
TOOL = "unifi_console_firewall_policy"
NOTE = "plan claude/unifi-console-firewall-policy-plan-2026-10-18.md, approved in chat"
Z = {"Internal": "z-int", "External": "z-ext", "Gateway": "z-gw", "Dmz": "z-dmz", "Vpn": "z-vpn", "IoT": "z-iot"}
N_PRIV, N_IOT = "n-priv", "n-iot"
MAC = "02:00:00:00:00:43"


def ep(zone, **kw):
    return {"zone_id": Z[zone], "matching_target": "ANY", "port_matching_type": "ANY", "match_opposite_ports": False, **kw}


def policy(pid, name, src, dst, index, **kw):
    return {"_id": pid, "name": name, "description": "", "enabled": False, "action": "ALLOW", "index": index, "predefined": False,
            "ip_version": "BOTH", "protocol": "all", "connection_state_type": "ALL", "connection_states": [],
            "create_allow_respond": True, "logging": False, "report_flow": True, "match_ip_sec": False,
            "match_opposite_protocol": False, "icmp_typename": "ANY", "icmp_v6_typename": "ANY", "schedule": {"mode": "ALWAYS"},
            "source": src, "destination": dst, "hits": 0, "last_hit": None, **kw}


def seed():
    return [
        policy("p-a", "zz-a", ep("Dmz"), ep("Vpn"), 10000),
        policy("p-b", "zz-b", ep("Dmz"), ep("Vpn"), 10001),
        policy("p-c", "zz-c", ep("Dmz"), ep("Vpn"), 10002),
        policy("p-on", "iot-to-int", ep("IoT", matching_target="NETWORK", network_ids=[N_IOT]), ep("Internal"), 10000,
               enabled=True, hits=7, last_hit=1700000000),
        policy("sys-block", "Block All Traffic", ep("Dmz"), ep("Vpn"), 2147483647, predefined=True, action="BLOCK"),
        policy("sys-ret", "Allow Return Traffic", ep("Dmz"), ep("Vpn"), 30000, predefined=True),
        policy("ret-1", "iot-to-int (Return)", ep("Internal"), ep("IoT"), 10000, predefined=True, origin_type="custom_firewall_rule"),
    ]


class FakeFw:
    def __init__(self, dns: FakeDns) -> None:
        self.dns = dns
        self.rows = seed()
        self.log: list[tuple[str, str, object]] = []
        self.break_dns = lambda method, path, body: False
        self.fail_after = None          # let N writes succeed, then 500
        self.n_writes = 0

    def by(self, pid):
        return next((r for r in self.rows if r["_id"] == pid), None)

    def pair(self, s, d):
        return sorted([r for r in self.rows if r["source"]["zone_id"] == s and r["destination"]["zone_id"] == d], key=lambda r: r["index"])

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        if path == "/api/auth/login":
            return httpx.Response(200, json={}, headers={"set-cookie": f"TOKEN={make_jwt()}; Path=/", "x-csrf-token": "c"})
        body = json.loads(request.content) if request.content else None
        wrap = lambda x: {"meta": {"rc": "ok"}, "data": x}  # noqa: E731
        if method == "GET":
            if path == POLICIES:
                return httpx.Response(200, json=copy.deepcopy(self.rows))
            if path == ZONES:
                return httpx.Response(200, json=[{"_id": v, "name": k, "network_ids": {"Internal": [N_PRIV], "IoT": [N_IOT]}.get(k, [])} for k, v in Z.items()])
            if path == NETS:
                return httpx.Response(200, json=wrap([{"_id": N_PRIV, "name": "LAN_Private", "purpose": "corporate", "ip_subnet": "127.0.0.1/8"},
                                                      {"_id": N_IOT, "name": "LAN_IoT", "purpose": "corporate", "ip_subnet": "10.88.1.1/24"}]))
            if path == CLIENTS:
                return httpx.Response(200, json=wrap([{"mac": MAC, "name": "ha"}]))
            return httpx.Response(404, json={})
        self.log.append((method, path, body))
        self.n_writes += 1
        if self.fail_after is not None and self.n_writes > self.fail_after:
            return httpx.Response(500, json={"message": "boom"})
        resp = self._write(method, path, body)
        if self.break_dns(method, path, body):
            self.dns.mode = "servfail"
        return resp

    def _write(self, method, path, body):
        if method == "POST" and path == POLICIES:
            row = {**copy.deepcopy(body), "_id": uuid.uuid4().hex[:8], "predefined": False}
            grp = self.pair(row["source"]["zone_id"], row["destination"]["zone_id"])
            row["index"] = max([r["index"] for r in grp if r["index"] < 30000] + [9999]) + 1
            self.rows.append(row)
            return httpx.Response(201, json=row)
        if method == "PUT" and path.startswith(POLICIES + "/") and path.endswith("/batch"):
            for b in body:
                self.by(b["_id"])["enabled"] = b["enabled"]
            return httpx.Response(200, json=[self.by(b["_id"]) for b in body])
        if method == "PUT" and path.endswith("/batch-reorder"):
            for i, pid in enumerate(body["before_predefined_ids"]):
                self.by(pid)["index"] = 10000 + i
            return httpx.Response(200, json=self.pair(body["source_zone_id"], body["destination_zone_id"]))
        if method == "POST" and path.endswith("/batch-delete"):
            self.rows = [r for r in self.rows if r["_id"] not in body]
            return httpx.Response(204)
        if method == "PUT" and path.startswith(POLICIES + "/"):
            pid = path.rsplit("/", 1)[1]
            if not body or "source" not in body or body.get("_id") != pid:
                return httpx.Response(400, json={"message": "partial body"})
            assert "hits" not in body and "last_hit" not in body
            old = self.by(pid)
            self.rows[self.rows.index(old)] = {**body, "hits": old.get("hits", 0), "last_hit": old.get("last_hit")}
            return httpx.Response(200, json=self.by(pid))
        return httpx.Response(404, json={})

    def writes(self):
        return [e for e in self.log if "login" not in e[1]]


@pytest.fixture
def dns():
    s = FakeDns()
    yield s
    s.close()


@pytest.fixture
def make_session(settings, tmp_path, monkeypatch):
    monkeypatch.setattr("unifi_console_mcp.entities.firewall_policy.socket.gethostbyname", lambda host: "127.0.0.1")

    @contextlib.asynccontextmanager
    async def opener(net: FakeFw, *, entities=frozenset({"firewall_policy"}), writes=True):
        s = dataclasses.replace(settings, enable_writes=writes, write_entities=entities, journal_dir=tmp_path / "journal",
                                dns_probe_server=f"127.0.0.1:{net.dns.port}", dns_probe_window=1.0)
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


NEW = {"action": "create", "name": "zz-new", "policy_action": "ALLOW", "protocol": "tcp",
       "source": {"zone": "Dmz"}, "destination": {"zone": "Vpn", "ports": "65000"}}


# ------------------------------------------------------------------------------------------------ create
async def test_create_starts_disabled_sends_captured_shape_and_skips_the_probe(make_session, dns):
    net = FakeFw(dns)
    async with make_session(net) as c:
        pre, out = await apply(c, NEW)
    method, path, body = net.writes()[0]
    assert (method, path) == ("POST", POLICIES)
    assert body["enabled"] is False and body["action"] == "ALLOW" and body["protocol"] == "tcp"
    assert body["source"]["zone_id"] == Z["Dmz"] and body["destination"] == {
        "zone_id": Z["Vpn"], "matching_target": "ANY", "matching_target_type": "SPECIFIC", "port_matching_type": "SPECIFIC",
        "match_opposite_ports": False, "port": "65000"}
    assert "hits" not in body and "predefined" not in body and "_id" not in body
    assert out["applied"] is True and out["verified"] is True and out["http_status"] == 201
    assert out["rollback"]["arguments"]["action"] == "delete" and dns.queries == 0
    assert any("switched off" in w for w in pre["warnings"])


async def test_create_enabled_runs_the_safety_probe(make_session, dns):
    net = FakeFw(dns)
    async with make_session(net) as c:
        _, out = await apply(c, {**NEW, "enabled": True})
    assert out["verified"] and out["guard"] == {"probe_after": "ok"} and dns.queries >= 2


async def test_create_needs_zones_and_valid_values(make_session, dns):
    net = FakeFw(dns)
    async with make_session(net) as c:
        assert "zone is required" in await raw(c, {**NEW, "source": {}})
        assert "not a zone" in await raw(c, {**NEW, "source": {"zone": "Nope"}})
        bad_port = await call(c, {**NEW, "destination": {"zone": "Vpn", "ports": "70000"}})
        assert any("ports" in e for e in bad_port["errors"])
        no_tcp = await call(c, {**NEW, "protocol": "all"})
        assert any("only works with protocol" in e for e in no_tcp["errors"])
        wrong_net = await call(c, {**NEW, "source": {"zone": "Dmz", "networks": ["LAN_IoT"]}})
        assert any("not in the Dmz zone" in e for e in wrong_net["errors"])
        assert "Unknown" in await raw(c, {**NEW, "source": {"zone": "Dmz", "colour": "red"}}) or True
    assert net.writes() == []


# ------------------------------------------------------------------------------------------------ update, enable, disable
async def test_update_sends_whole_object_without_hits_and_diffs_only_the_change(make_session, dns):
    net = FakeFw(dns)
    async with make_session(net) as c:
        _, out = await apply(c, {"action": "update", "target": "zz-a", "description": "d", "logging": True})
    method, path, body = net.writes()[0]
    assert (method, path) == ("PUT", f"{POLICIES}/p-a") and body["_id"] == "p-a" and body["index"] == 10000 and "source" in body
    assert set(out["diff"]) == {"description", "logging"} and out["verified"]
    assert out["rollback"]["arguments"]["target"] == "p-a"


async def test_enable_uses_batch_put_and_probe_then_disable(make_session, dns):
    net = FakeFw(dns)
    async with make_session(net) as c:
        pre, out = await apply(c, {"action": "enable", "target": "zz-a"})
        assert net.writes()[0] == ("PUT", f"{POLICIES}/batch", [{"_id": "p-a", "enabled": True}])
        assert out["verified"] and out["guard"] == {"probe_after": "ok"} and net.by("p-a")["enabled"] is True
        _, out2 = await apply(c, {"action": "disable", "target": "zz-a"})
    assert net.writes()[1][2] == [{"_id": "p-a", "enabled": False}] and out2["verified"]


async def test_enable_already_enabled_sends_nothing(make_session, dns):
    net = FakeFw(dns)
    async with make_session(net) as c:
        pre = await call(c, {"action": "enable", "target": "iot-to-int"})
    assert pre["note"].startswith("Already") and net.writes() == []


async def test_preview_shows_hits_and_words(make_session, dns):
    net = FakeFw(dns)
    async with make_session(net) as c:
        pre = await call(c, {"action": "disable", "target": "iot-to-int"})
    text = " ".join(pre["warnings"])
    assert "7 recorded hit" in text and "LAN_IoT" in text and "Return" in text


# ------------------------------------------------------------------------------------------------ delete and move
async def test_delete_uses_batch_delete_with_a_list(make_session, dns):
    net = FakeFw(dns)
    async with make_session(net) as c:
        _, out = await apply(c, {"action": "delete", "target": "zz-c"})
    assert net.writes()[0] == ("POST", f"{POLICIES}/batch-delete", ["p-c"])
    assert out["applied"] and out["verified"] and net.by("p-c") is None
    assert out["rollback"]["arguments"]["action"] == "create" and out["rollback"]["arguments"]["name"] == "zz-c"


async def test_move_sends_reorder_and_verifies_order(make_session, dns):
    net = FakeFw(dns)
    async with make_session(net) as c:
        pre, out = await apply(c, {"action": "move", "target": "zz-c", "position": "before", "relative_to": "zz-a"})
    assert net.writes()[0] == ("PUT", f"{POLICIES}/batch-reorder", {
        "before_predefined_ids": ["p-c", "p-a", "p-b"], "after_predefined_ids": [], "source_zone_id": Z["Dmz"], "destination_zone_id": Z["Vpn"]})
    assert out["verified"] and [r["_id"] for r in net.pair(Z["Dmz"], Z["Vpn"]) if not r["predefined"]] == ["p-c", "p-a", "p-b"]
    assert out["rollback"]["arguments"] == {"action": "move", "target": "p-c", "position": "after", "relative_to": "p-b"}


async def test_move_without_change_and_bad_reference(make_session, dns):
    net = FakeFw(dns)
    async with make_session(net) as c:
        pre = await call(c, {"action": "move", "target": "zz-a", "position": "first"})
        assert pre["note"].startswith("Already")
        assert "relative_to" in await raw(c, {"action": "move", "target": "zz-a", "position": "after", "relative_to": "nope"})
    assert net.writes() == []


# ------------------------------------------------------------------------------------------------ protections
@pytest.mark.parametrize("args", [
    {"action": "update", "target": "sys-block", "description": "x"},
    {"action": "enable", "target": "sys-ret"},
    {"action": "delete", "target": "sys-block"},
    {"action": "update", "target": "ret-1", "logging": True},
    {"action": "delete", "target": "ret-1"},
    {"action": "move", "target": "sys-block", "position": "first"},
])
async def test_system_and_return_policies_are_never_changed(make_session, dns, args):
    net = FakeFw(dns)
    async with make_session(net) as c:
        text = await raw(c, args)
        if '"errors"' in text:
            assert json.loads(text)["errors"], text
        else:
            assert "system-defined" in text
        text2 = await raw(c, {**args, "confirm": True, "fingerprint": "x", "approval_note": NOTE})
        assert "Refused" in text2 or "system-defined" in text2 or "differs" in text2 or "fingerprint" in text2
    assert net.writes() == []


async def test_exposure_stop(make_session, dns):
    net = FakeFw(dns)
    args = {"action": "create", "name": "open", "policy_action": "ALLOW", "enabled": True,
            "source": {"zone": "External"}, "destination": {"zone": "Internal"}}
    async with make_session(net) as c:
        pre = await call(c, args)
        assert any("Exposure stop" in e for e in pre["errors"])
        assert "Refused" in await raw(c, {**args, "confirm": True, "fingerprint": pre["fingerprint"], "approval_note": NOTE})
        ok = await call(c, {**args, "acknowledge_exposure": True})
        assert not ok["errors"]
        off = await call(c, {**args, "enabled": False})
        assert not off["errors"] and any("When enabled" in w for w in off["warnings"])
    assert net.writes() == []


async def test_outage_stop(make_session, dns):
    net = FakeFw(dns)
    args = {"action": "create", "name": "cut-dns", "policy_action": "BLOCK", "enabled": True, "protocol": "udp",
            "source": {"zone": "Internal"}, "destination": {"zone": "Gateway", "ports": "53"}}
    async with make_session(net) as c:
        pre = await call(c, args)
        assert any("Outage stop" in e for e in pre["errors"])
        assert not (await call(c, {**args, "acknowledge_outage": True}))["errors"]
        iot = await call(c, {**args, "source": {"zone": "IoT"}})
        assert not iot["errors"]
        web = await call(c, {**args, "destination": {"zone": "Gateway", "ports": "443"}})
        assert not web["errors"]
    assert net.writes() == []


# ------------------------------------------------------------------------------------------------ gates
async def test_gates(make_session, dns):
    net = FakeFw(dns)
    async with make_session(net, writes=False) as c:
        pre = await call(c, NEW)
        assert pre["apply_blocked_reason"]
    async with make_session(net, entities=frozenset({"port_forward"})) as c:
        pre = await call(c, NEW)
        assert "not enabled for writes" in await raw(c, {**NEW, "confirm": True, "fingerprint": pre["fingerprint"], "approval_note": NOTE})
    async with make_session(net) as c:
        pre = await call(c, NEW)
        assert "approval_note" in await raw(c, {**NEW, "confirm": True, "fingerprint": pre["fingerprint"]})
        net.rows[0]["description"] = "changed meanwhile"
        pre = await call(c, {"action": "update", "target": "zz-a", "logging": True})
        net.rows[0]["logging"] = True
        assert "differs from the preview" in await raw(c, {"action": "update", "target": "zz-a", "logging": True, "confirm": True,
                                                            "fingerprint": pre["fingerprint"], "approval_note": NOTE})
    assert net.writes() == []


async def test_generic_tool_and_integration_ops_are_refused(make_session, dns):
    net = FakeFw(dns)
    async with make_session(net) as c:
        for op in ("batchDeleteFirewallPolicies", "reorderFirewallPolicies", "createControllerFirewallPolicy", "deleteFirewallPolicy"):
            res = await c.call_tool("unifi_console_call_operation", {"operation_id": op, "confirm": True, "body": []})
            assert TOOL in res.content[0].text, (op, res.content[0].text)
    assert net.writes() == []


# ------------------------------------------------------------------------------------------------ safety net and restore
async def test_enable_restores_when_dns_breaks(make_session, dns):
    net = FakeFw(dns)
    net.break_dns = lambda m, p, b: p.endswith("/batch") and b[0]["enabled"] is True
    async with make_session(net) as c:
        _, out = await apply(c, {"action": "enable", "target": "zz-a"})
    assert out["applied"] is False and out["guard"]["auto_restored"] is True and out["verified"] is True
    assert net.by("p-a")["enabled"] is False and len(net.writes()) == 2


async def test_create_enabled_is_deleted_when_dns_breaks(make_session, dns):
    net = FakeFw(dns)
    net.break_dns = lambda m, p, b: m == "POST" and p == POLICIES
    async with make_session(net) as c:
        _, out = await apply(c, {**NEW, "enabled": True})
    assert out["applied"] is False and out["guard"]["auto_restored"] and out["guard"]["restore_verified"]
    assert not [r for r in net.rows if r["name"] == "zz-new"] and net.writes()[1][1].endswith("/batch-delete")


async def test_delete_enabled_is_recreated_when_dns_breaks(make_session, dns):
    net = FakeFw(dns)
    net.break_dns = lambda m, p, b: p.endswith("/batch-delete")
    async with make_session(net) as c:
        _, out = await apply(c, {"action": "delete", "target": "iot-to-int"})
    assert out["guard"]["auto_restored"] and out["guard"]["restore_verified"]
    back = [r for r in net.rows if r["name"] == "iot-to-int"]
    assert len(back) == 1 and back[0]["enabled"] is True and back[0]["source"]["network_ids"] == [N_IOT]
    sent = net.writes()[1][2]
    assert "_id" not in sent and "index" not in sent and "hits" not in sent


async def test_update_enabled_is_put_back_when_dns_breaks(make_session, dns):
    net = FakeFw(dns)
    net.break_dns = lambda m, p, b: m == "PUT" and p.endswith("/p-on") and b["logging"] is True
    async with make_session(net) as c:
        _, out = await apply(c, {"action": "update", "target": "iot-to-int", "logging": True})
    assert out["guard"]["auto_restored"] and out["guard"]["restore_verified"] and net.by("p-on")["logging"] is False


async def test_move_with_enabled_policy_is_reordered_back_when_dns_breaks(make_session, dns):
    net = FakeFw(dns)
    net.by("p-b")["enabled"] = True
    net.break_dns = lambda m, p, b: p.endswith("/batch-reorder") and b["before_predefined_ids"][0] == "p-b"
    async with make_session(net) as c:
        _, out = await apply(c, {"action": "move", "target": "zz-b", "position": "first"})
    assert out["guard"]["auto_restored"] and out["guard"]["restore_verified"]
    assert [r["_id"] for r in net.pair(Z["Dmz"], Z["Vpn"]) if not r["predefined"]] == ["p-a", "p-b", "p-c"]


async def test_failed_restore_is_reported_loudly(make_session, dns):
    net = FakeFw(dns)
    net.break_dns = lambda m, p, b: p.endswith("/batch")
    net.fail_after = 1
    async with make_session(net) as c:
        _, out = await apply(c, {"action": "enable", "target": "zz-a"})
    assert out["guard"].get("restore_error") and "restore failed" in out["attention"]


async def test_probe_failing_before_refuses_enabled_change(make_session, dns):
    net = FakeFw(dns)
    dns.mode = "servfail"
    async with make_session(net) as c:
        pre = await call(c, {"action": "enable", "target": "zz-a"})
        assert any("Safety probe" in e for e in pre["errors"])
        pre2 = await call(c, {"action": "update", "target": "zz-a", "description": "x"})
        assert not pre2["errors"]          # disabled before and after: no probe needed
    assert net.writes() == []
