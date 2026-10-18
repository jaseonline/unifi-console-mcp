"""WAN settings through the write framework: allowlist, identity gate, gateway re-provision wait, safety net, automatic restore."""
from __future__ import annotations

import contextlib
import copy
import dataclasses
import json

import httpx
import pytest
from mcp.client import Client

from conftest import make_jwt
from test_doh import FakeDns
from test_network import API, BASIC, DEVS, NETS, FakeNet, networks
from test_writes import Wrapped
from unifi_console_mcp.entities import wan as wan_mod
from unifi_console_mcp.server import create_server

HEALTH = f"{API}/stat/health"
TOOL = "unifi_console_wan"
NOTE = "plan claude/unifi-console-wan-plan-2026-10-18.md, approved in chat"
N_WAN = "n-wan"
SECRET = "UPLINK-SECRET-VALUE"


def wan_row():
    return {"_id": N_WAN, "site_id": "s", "name": "WAN1", "enabled": True, "purpose": "wan", "attr_no_delete": True,
            "attr_hidden_id": "WAN", "external_id": "x-wan", "wan_networkgroup": "WAN", "wan_type": "dhcp", "wan_type_v6": "dhcpv6",
            "wan_vlan": 2, "wan_vlan_enabled": False, "mac_override": "02:00:00:00:00:41", "mac_override_enabled": True,
            "wan_dhcpv6_pd_size": 56, "wan_dhcpv6_pd_size_auto": False, "wan_provider_capabilities": {"upload_kilobits_per_second": 1000000,
            "download_kilobits_per_second": 1000000}, "wan_smartq_enabled": False, "wan_dns_preference": "auto",
            "wan_ipv6_dns_preference": "auto", "wan_failover_priority": 1, "wan_load_balance_type": "weighted", "wan_load_balance_weight": 99,
            "report_wan_event": False, "wan_dhcp_cos": 0, "wan_dhcpv6_cos": 0, "firewall_zone_id": "z-wan", "uplink_identity": "",
            "x_uplink_password": SECRET, "routing_table_id": 201}


class FakeWan(FakeNet):
    def __init__(self, dns: FakeDns) -> None:
        super().__init__(dns)
        self.rows = [r for r in networks() if r["purpose"] != "wan"] + [wan_row()]
        self.gw = {"_id": "gw", "mac": "aa:00:00:00:00:99", "name": "Gateway", "type": "uxg", "state": 1, "adopted": True,
                   "config_network": {"ip": "192.168.1.1"}, "provisioned_at": 100}
        self.devs.append(self.gw)
        self.wan_status = "ok"
        self.internet = True
        self.reprov_reads = 2           # polls during which the gateway shows 'provisioning' after a write
        self.pending = 0
        self.stuck_until_second_put = False
        self.puts: list[dict] = []
        self.after_put = None           # fn(self, n) run after the nth WAN PUT

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        wrap = lambda x: {"meta": {"rc": "ok"}, "data": x}  # noqa: E731
        if method == "GET" and path == HEALTH:
            return httpx.Response(200, json=wrap([{"subsystem": "wan", "status": self.wan_status}, {"subsystem": "lan", "status": "ok"}]))
        if method == "GET" and path in (BASIC, DEVS):
            if self.pending > 0:
                self.pending -= 1
                if self.pending == 0 and not self.stuck_until_second_put:
                    self.gw["state"], self.gw["provisioned_at"] = 1, self.gw["provisioned_at"] + 1
        if method == "PUT" and path == f"{NETS}/{N_WAN}":
            body = json.loads(request.content)
            self.log.append((method, path, body))
            assert body["_id"] == N_WAN and "site_id" not in body and "attr_no_delete" not in body and "attr_hidden_id" not in body
            i = next(i for i, r in enumerate(self.rows) if r["_id"] == N_WAN)
            self.rows[i] = {**body, "site_id": "s", "attr_no_delete": True, "attr_hidden_id": "WAN"}
            self.puts.append(body)
            self.gw["state"] = 5
            self.pending = self.reprov_reads
            if len(self.puts) >= 2:
                self.stuck_until_second_put = False
            if self.after_put:
                self.after_put(self, len(self.puts))
            return httpx.Response(200, json=wrap([self.rows[i]]))
        return super().__call__(request)

    def wan(self):
        return next(r for r in self.rows if r["_id"] == N_WAN)


@pytest.fixture
def dns():
    s = FakeDns()
    yield s
    s.close()


@pytest.fixture
def make_session(settings, tmp_path, monkeypatch):
    @contextlib.asynccontextmanager
    async def opener(fake, *, entities=frozenset({"wan", "network"}), writes=True, force_fail=False):
        monkeypatch.setattr(wan_mod, "_tcp_ok", lambda host, port, timeout: fake.internet)
        s = dataclasses.replace(settings, enable_writes=writes, write_entities=entities, journal_dir=tmp_path / "journal",
                                dns_probe_server=f"127.0.0.1:{fake.dns.port}", dns_probe_window=1.0, dns_probe_force_fail=force_fail)
        mcp, api = create_server(s, transport=httpx.MockTransport(fake))
        try:
            async with Client(mcp) as client:
                yield Wrapped(client)
        finally:
            await api.client.aclose()
    return opener


async def raw(c, args, tool=TOOL):
    res = await c.call_tool(tool, args)
    return res.content[0].text


async def call(c, args):
    res = await c.call_tool(TOOL, args)
    assert not res.is_error, res
    return json.loads(res.content[0].text)


async def apply(c, args, note=NOTE):
    pre = await call(c, args)
    assert pre.get("ok") and not pre["errors"], pre
    return pre, await call(c, {**args, "confirm": True, "fingerprint": pre["fingerprint"], "approval_note": note})


FLIP = {"target": "WAN1", "report_wan_event": True}


# ------------------------------------------------------------------------------------------------ happy path
async def test_preview_changes_nothing_and_runs_the_checks_before(make_session, dns):
    fake = FakeWan(dns)
    async with make_session(fake) as c:
        pre = await call(c, FLIP)
    assert pre["preview"] and set(pre["diff"]) == {"report_wan_event"} and pre["guard"]["check_before"] == "ok"
    assert any("re-provisions" in w for w in pre["warnings"]) and not fake.puts


async def test_apply_sends_the_whole_object_waits_for_the_gateway_and_verifies(make_session, dns):
    fake = FakeWan(dns)
    start = copy.deepcopy(fake.wan())
    async with make_session(fake) as c:
        pre, out = await apply(c, FLIP)
    body = fake.puts[0]
    assert body["report_wan_event"] is True and body["x_uplink_password"] == SECRET
    assert {k: v for k, v in body.items() if k != "report_wan_event"} == {k: v for k, v in start.items()
                                                                           if k not in ("site_id", "attr_no_delete", "attr_hidden_id", "report_wan_event")}
    assert out["applied"] and out["verified"] and out["guard"]["probe_after"] == "ok"
    assert fake.gw["state"] == 1 and fake.gw["provisioned_at"] == 101
    assert out["rollback"]["arguments"] == {"action": "update", "target": N_WAN, "report_wan_event": False}


async def test_provider_speeds_merge_into_the_nested_object(make_session, dns):
    fake = FakeWan(dns)
    async with make_session(fake) as c:
        pre, out = await apply(c, {"target": "WAN1", "download_kbps": 900000})
    assert fake.wan()["wan_provider_capabilities"] == {"upload_kilobits_per_second": 1000000, "download_kilobits_per_second": 900000}
    assert out["verified"] and out["rollback"]["arguments"]["download_kbps"] == 1000000


async def test_dns_manual_servers_and_other_allowlisted_fields(make_session, dns):
    fake = FakeWan(dns)
    async with make_session(fake) as c:
        _, out = await apply(c, {"target": "WAN1", "dns_preference": "manual", "dns1": "1.1.1.1", "dns2": "9.9.9.9",
                                 "smart_queues": True, "pd_size": 60, "load_balance_weight": 50, "dhcp_cos": 3})
    w = fake.wan()
    assert (w["wan_dns_preference"], w["wan_dns1"], w["wan_dns2"], w["wan_smartq_enabled"], w["wan_dhcpv6_pd_size"]) == ("manual", "1.1.1.1", "9.9.9.9", True, 60)
    assert out["verified"] and w["wan_load_balance_weight"] == 50 and w["wan_dhcp_cos"] == 3


async def test_the_secret_is_never_echoed_or_journalled(make_session, dns, tmp_path):
    fake = FakeWan(dns)
    async with make_session(fake) as c:
        pre = await raw(c, FLIP)
        _, out = await apply(c, FLIP)
    assert SECRET not in pre and SECRET not in json.dumps(out)
    assert SECRET not in "".join(p.read_text() for p in (tmp_path / "journal").glob("*.jsonl"))


async def test_no_change_sends_nothing(make_session, dns):
    fake = FakeWan(dns)
    async with make_session(fake) as c:
        pre = await call(c, {"target": "WAN1", "report_wan_event": False})
        out = await call(c, {"target": "WAN1", "report_wan_event": False, "confirm": True, "fingerprint": pre["fingerprint"], "approval_note": NOTE})
    assert out["applied"] is False and not fake.puts


# ------------------------------------------------------------------------------------------------ validation
async def test_bad_values_are_refused(make_session, dns):
    fake = FakeWan(dns)
    cases = (({"dns_preference": "manual"}, "first server"), ({"dns_preference": "manual", "dns1": "nope"}, "IPv4"),
             ({"dns1": "1.1.1.1"}, "preference is manual"), ({"ipv6_dns_preference": "manual", "ipv6_dns1": "1.1.1.1"}, "IPv6"),
             ({"download_kbps": 0}, "kilobits"), ({"pd_size": 40}, "48 to 64"), ({"dhcp_cos": 9}, "0 to 7"),
             ({"failover_priority": 0}, "1 to 99"), ({"load_balance_weight": 101}, "1 to 100"))
    async with make_session(fake) as c:
        for change, word in cases:
            assert word in await raw(c, {"target": "WAN1", **change}), change
    assert not fake.puts


async def test_unknown_fields_and_other_actions_do_not_exist(make_session, dns):
    async with make_session(FakeWan(dns)) as c:
        for args in ({"target": "WAN1", "x_uplink_password": "a"}, {"target": "WAN1", "firewall_zone_id": "z"},
                     {"target": "WAN1", "name": "x"}, {"target": "WAN1", "enabled": False},
                     {"action": "delete", "target": "WAN1"}, {"action": "create", "target": "x"},
                     {"target": "WAN1", "type": "pppoe"}):
            res = await c.call_tool(TOOL, args)
            assert res.is_error or '"ok":false' in res.content[0].text.replace(" ", ""), args


async def test_a_lan_network_is_refused_and_pointed_at_the_network_tool(make_session, dns):
    async with make_session(FakeWan(dns)) as c:
        assert "unifi_console_network" in await raw(c, {"target": "LAN_Sonos", "report_wan_event": True})


async def test_the_network_tool_refuses_the_wan_and_names_this_one(make_session, dns):
    fake = FakeWan(dns)
    async with make_session(fake) as c:
        text = await raw(c, {"action": "update", "target": "WAN1", "name": "x"}, tool="unifi_console_network")
        assert "unifi_console_wan" in text
        assert "cannot be deleted" in await raw(c, {"action": "delete", "target": "WAN1"}, tool="unifi_console_network")
        pre = json.loads(await raw(c, {"action": "disable", "target": "WAN1"}, tool="unifi_console_network"))
        assert any("unifi_console_wan" in e for e in pre["errors"])
        refused = await raw(c, {"action": "disable", "target": "WAN1", "confirm": True, "fingerprint": pre["fingerprint"], "approval_note": NOTE},
                            tool="unifi_console_network")
        assert "Refused" in refused and "unifi_console_wan" in refused
    assert not fake.puts


# ------------------------------------------------------------------------------------------------ identity
async def test_identity_fields_need_the_acknowledgement(make_session, dns):
    fake = FakeWan(dns)
    args = {"target": "WAN1", "mac_override_enabled": False}
    async with make_session(fake) as c:
        pre = await call(c, args)
        assert any("Identity stop" in e for e in pre["errors"]) and any("ISP session" in w for w in pre["warnings"])
        _, out = await apply(c, {**args, "acknowledge_identity": True})
    assert out["applied"] and fake.wan()["mac_override_enabled"] is False
    assert out["rollback"]["arguments"]["acknowledge_identity"] is True


async def test_identity_values_are_checked(make_session, dns):
    async with make_session(FakeWan(dns)) as c:
        for change, word in (({"mac_override": "zz"}, "MAC address"), ({"vlan": 5000}, "1 to 4094"), ({"type_v6": "disabled", "mac_override": "bad"}, "MAC")):
            assert word in await raw(c, {"target": "WAN1", "acknowledge_identity": True, **change}), change


# ------------------------------------------------------------------------------------------------ gates
async def test_gates_block_apply(make_session, dns):
    fake = FakeWan(dns)
    async with make_session(fake, writes=False) as c:
        pre = await call(c, FLIP)
        assert "Writes are disabled" in await raw(c, {**FLIP, "confirm": True, "fingerprint": pre["fingerprint"], "approval_note": NOTE})
    async with make_session(fake, entities=frozenset({"network"})) as c:
        pre = await call(c, FLIP)
        assert "not enabled for writes" in await raw(c, {**FLIP, "confirm": True, "fingerprint": pre["fingerprint"], "approval_note": NOTE})
    async with make_session(fake) as c:
        pre = await call(c, FLIP)
        assert "approval_note" in await raw(c, {**FLIP, "confirm": True, "fingerprint": pre["fingerprint"]})
        assert "fingerprint" in await raw(c, {**FLIP, "confirm": True, "approval_note": NOTE})
    assert not fake.puts


# ------------------------------------------------------------------------------------------------ safety net
async def test_checks_before_refuse_when_the_wan_is_already_unhealthy(make_session, dns):
    for attr, value, word in (("wan_status", "unknown", "WAN reports"), ("internet", False, "internet probe")):
        fake = FakeWan(dns)
        setattr(fake, attr, value)
        async with make_session(fake) as c:
            pre = await call(c, FLIP)
            assert any(word in e for e in pre["errors"])
            assert word in await raw(c, {**FLIP, "confirm": True, "fingerprint": pre["fingerprint"], "approval_note": NOTE})
        assert not fake.puts


async def test_a_gateway_that_is_not_connected_before_refuses(make_session, dns):
    fake = FakeWan(dns)
    fake.gw["state"] = 0
    async with make_session(fake) as c:
        pre = await call(c, FLIP)
    assert any("gateway is not connected" in e for e in pre["errors"])


async def test_forced_failure_restores_automatically_and_checks_again(make_session, dns):
    fake = FakeWan(dns)
    start = copy.deepcopy(fake.wan())
    async with make_session(fake, force_fail=True) as c:
        _, out = await apply(c, FLIP)
    assert len(fake.puts) == 2 and fake.wan() == start
    assert out["applied"] is False and out["guard"]["auto_restored"] and out["guard"]["restore_verified"]
    assert out["guard"]["probe_after_restore"] == "ok" and "put back" in out["attention"]


async def test_internet_lost_after_the_change_restores(make_session, dns):
    fake = FakeWan(dns)
    fake.after_put = lambda f, n: setattr(f, "internet", n >= 2)         # dies after the change, returns after the restore
    start = copy.deepcopy(fake.wan())
    async with make_session(fake) as c:
        _, out = await apply(c, FLIP)
    assert fake.wan() == start and out["guard"]["auto_restored"] and out["guard"]["restore_verified"]
    assert "internet probe" in out["guard"]["probe_after"] and out["guard"]["probe_after_restore"] == "ok"


async def test_wan_unhealthy_after_the_change_restores(make_session, dns):
    fake = FakeWan(dns)
    fake.after_put = lambda f, n: setattr(f, "wan_status", "unknown" if n == 1 else "ok")
    async with make_session(fake) as c:
        _, out = await apply(c, FLIP)
    assert out["guard"]["auto_restored"] and "WAN reports" in out["guard"]["probe_after"] and fake.wan()["report_wan_event"] is False


async def test_a_gateway_that_never_comes_back_restores(make_session, dns):
    fake = FakeWan(dns)
    fake.stuck_until_second_put = True
    async with make_session(fake) as c:
        _, out = await apply(c, FLIP)
    assert out["guard"]["auto_restored"] and "not connected" in out["guard"]["probe_after"] and len(fake.puts) == 2


async def test_the_guard_waits_for_the_reprovision(make_session, dns):
    fake = FakeWan(dns)
    fake.reprov_reads = 4
    async with make_session(fake) as c:
        _, out = await apply(c, FLIP)
    assert out["guard"]["probe_after"] == "ok" and len(fake.puts) == 1 and fake.gw["state"] == 1


async def test_a_device_that_drops_off_restores(make_session, dns):
    fake = FakeWan(dns)

    def drop(f, n):
        if n == 1:
            next(d for d in f.devs if d["_id"] == "ap")["state"] = 0
        else:
            next(d for d in f.devs if d["_id"] == "ap")["state"] = 1
    fake.after_put = drop
    async with make_session(fake) as c:
        _, out = await apply(c, FLIP)
    assert out["guard"]["auto_restored"] and "AP Pro" in out["guard"]["probe_after"]
