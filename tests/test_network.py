"""Networks and VLANs through the write framework: create disabled, whole-object edits, group enable/disable, protections, safety net."""
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

API = "/proxy/network/api/s/default"
V2 = "/proxy/network/v2/api/site/default"
NETS, GROUP, WLANS, DEVS, BASIC, STA, USER, FWD = (f"{API}/rest/networkconf", f"{API}/group/networkconf", f"{API}/rest/wlanconf",
                                                  f"{API}/stat/device", f"{API}/stat/device-basic", f"{API}/stat/sta", f"{API}/rest/user", f"{API}/rest/portforward")
ZONES, DNS, POLICIES, OBJECTS = f"{V2}/firewall/zone", f"{V2}/static-dns", f"{V2}/firewall-policies", f"{V2}/object-oriented-network-configs"
TOOL = "unifi_console_network"
NOTE = "plan claude/unifi-console-network-plan-2026-10-18.md, approved in chat"
Z_INT, Z_IOT, Z_SON, Z_GUEST, Z_DMZ, Z_EXT = "z-int", "z-iot", "z-son", "z-guest", "z-dmz", "z-ext"
N_PRIV, N_IOT, N_SON, N_GUEST, N_WAN = "n-priv", "n-iot", "n-son", "n-guest", "n-wan"


def net(_id, name, vlan, subnet, zone, **kw):
    base = {"_id": _id, "site_id": "s", "name": name, "enabled": True, "purpose": "corporate", "vlan_enabled": vlan is not None, "ip_subnet": subnet,
            "networkgroup": "LAN", "dhcpd_enabled": True, "dhcpd_start": subnet.replace(".1/24", ".100"),
            "dhcpd_stop": subnet.replace(".1/24", ".254"), "dhcpd_leasetime": 86400, "dhcpd_dns_enabled": False, "dhcpd_ip_1": subnet.split("/")[0],
            "dhcpd_ip_2": "", "dhcpd_ip_3": "", "domain_name": "", "internet_access_enabled": True, "network_isolation_enabled": False,
            "igmp_snooping": False, "dhcpguard_enabled": False, "firewall_zone_id": zone, "external_id": "x-" + _id, "mdns_enabled": False,
            "dpi_enabled": False, "ipv6_setting_preference": "auto"}
    if vlan is not None:
        base["vlan"] = vlan
    return {**base, **kw}


def networks():
    return [net(N_PRIV, "LAN_Private", None, "192.168.1.1/24", Z_INT, attr_no_delete=True), net(N_IOT, "LAN_IoT", 88, "10.88.1.1/24", Z_IOT),
            net(N_SON, "LAN_Sonos", 22, "10.22.1.1/24", Z_SON, igmp_snooping=True), net(N_GUEST, "LAN_Guest", 11, "10.11.1.1/24", Z_GUEST, purpose="guest"),
            {"_id": N_WAN, "name": "WAN1", "purpose": "wan", "enabled": True, "attr_no_delete": True, "firewall_zone_id": "z-wan"}]


class FakeNet:
    def __init__(self, dns: FakeDns) -> None:
        self.dns = dns
        self.rows = networks()
        self.log: list[tuple[str, str, object]] = []
        self.devs = [
            {"_id": "sw", "mac": "aa:00:00:00:00:01", "name": "Switch A", "type": "usw", "state": 1, "adopted": True,
             "config_network": {"ip": "192.168.1.3"}, "port_overrides": [{"port_idx": 2, "native_networkconf_id": N_SON, "name": "Sonos Playbar"},
                                                                          {"port_idx": 5, "native_networkconf_id": N_PRIV}]},
            {"_id": "ap", "mac": "aa:00:00:00:00:20", "name": "AP Pro", "type": "uap", "state": 1, "adopted": True, "config_network": {"ip": "192.168.1.4"}}]
        self.wlans = [{"_id": "w-iot", "name": "ExampleNet_IoT", "networkconf_id": N_IOT}, {"_id": "w-main", "name": "ExampleNet", "networkconf_id": N_PRIV}]
        self.clients = [{"mac": "c1", "name": "Sonos Playbar", "ip": "10.22.1.50"}, {"mac": "c2", "name": "Cloud Key", "ip": "192.168.1.2"}]
        self.known = [{"mac": "c3", "name": "Harmony Hub", "use_fixedip": True, "fixed_ip": "10.88.1.23"}]
        self.static = [{"_id": "d1", "key": "hub.example.home", "record_type": "A", "value": "10.88.1.23", "enabled": True}]
        self.forwards: list[dict] = []
        self.drop_on_write = None      # fn(self) run on each write (simulate a device falling off)
        self.alter = None

    def zones(self):
        ids = {Z_INT: "Internal", Z_IOT: "IoT", Z_SON: "Sonos", Z_GUEST: "Guest", Z_DMZ: "Dmz", Z_EXT: "External"}
        return [{"_id": z, "name": n, "zone_key": n.lower(), "network_ids": [r["_id"] for r in self.rows if r.get("firewall_zone_id") == z]} for z, n in ids.items()]

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        wrap = lambda x: {"meta": {"rc": "ok"}, "data": x}  # noqa: E731
        if path == "/api/auth/login":
            return httpx.Response(200, json={}, headers={"set-cookie": f"TOKEN={make_jwt()}; Path=/", "x-csrf-token": "c"})
        if method == "GET":
            table = {NETS: wrap(self.rows), ZONES: self.zones(), WLANS: wrap(self.wlans), DEVS: wrap(self.devs),
                     BASIC: wrap([{k: d[k] for k in ("mac", "name", "type", "state", "adopted")} for d in self.devs]), STA: wrap(self.clients),
                     USER: wrap(self.known), DNS: self.static, FWD: wrap(self.forwards), POLICIES: [], OBJECTS: []}
            return httpx.Response(200, json=copy.deepcopy(table[path])) if path in table else httpx.Response(404, json={})
        body = json.loads(request.content) if request.content else None
        self.log.append((method, path, body))
        if self.drop_on_write:
            self.drop_on_write(self)
        if method == "POST" and path == NETS:
            assert "_id" not in body and body["firewall_zone_id"]
            row = {**body, "_id": uuid.uuid4().hex[:12], "site_id": "s", "external_id": "x", "mdns_enabled": False, "dpi_enabled": False}
            self.rows.append(row)
            return httpx.Response(200, json=wrap([row]))
        if method == "PUT" and path == GROUP:
            for i in body["id"]:
                next(r for r in self.rows if r["_id"] == i).update(body["data"])
            return httpx.Response(200, json=wrap([{i: wrap([next(r for r in self.rows if r["_id"] == i)]) for i in body["id"]}]))
        if path.startswith(NETS + "/"):
            ident = path.rsplit("/", 1)[1]
            i = next(i for i, r in enumerate(self.rows) if r["_id"] == ident)
            if method == "PUT":
                assert body["_id"] == ident and "ip_subnet" in body and "site_id" not in body
                self.rows[i] = self.alter({**body}) if self.alter else {**body, "site_id": "s"}
                return httpx.Response(200, json=wrap([self.rows[i]]))
            if method == "DELETE":
                del self.rows[i]
                return httpx.Response(200, json=wrap([]))
        return httpx.Response(404, json={})

    def writes(self):
        return [e for e in self.log if "login" not in e[1]]

    def by(self, name):
        return next(r for r in self.rows if r["name"] == name)


@pytest.fixture
def dns():
    s = FakeDns()
    yield s
    s.close()


@pytest.fixture
def make_session(settings, tmp_path, monkeypatch):
    monkeypatch.setattr("unifi_console_mcp.entities.network.socket.gethostbyname", lambda host: "192.168.1.2")

    @contextlib.asynccontextmanager
    async def opener(fake, *, entities=frozenset({"network"}), writes=True, force_fail=False):
        s = dataclasses.replace(settings, enable_writes=writes, write_entities=entities, journal_dir=tmp_path / "journal",
                                dns_probe_server=f"127.0.0.1:{fake.dns.port}", dns_probe_window=1.0, dns_probe_force_fail=force_fail)
        mcp, api = create_server(s, transport=httpx.MockTransport(fake))
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


NEW = {"action": "create", "name": "zz-net", "vlan": 3999, "subnet": "10.199.99.1/24", "zone": "Dmz"}


# ------------------------------------------------------------------------------------------------ create
async def test_create_is_disabled_in_the_named_zone_with_the_captured_shape_and_skips_the_probe(make_session, dns):
    fake = FakeNet(dns)
    async with make_session(fake) as c:
        pre, out = await apply(c, NEW)
    _, path, body = fake.writes()[0]
    assert path == NETS and body["enabled"] is False and body["firewall_zone_id"] == Z_DMZ and body["purpose"] == "corporate"
    assert body["vlan"] == 3999 and body["vlan_enabled"] is True and body["ip_subnet"] == "10.199.99.1/24" and body["networkgroup"] == "LAN"
    assert body["dhcpd_start"] == "10.199.99.6" and body["dhcpd_stop"] == "10.199.99.254" and body["dhcpd_ip_1"] == "10.199.99.1"
    assert "_id" not in body and len(body) == 53
    assert out["applied"] and out["verified"] and "guard" not in out and dns.queries == 0
    assert out["rollback"]["arguments"]["action"] == "delete"


async def test_create_validation_refuses_clashes_and_bad_values(make_session, dns):
    fake = FakeNet(dns)
    async with make_session(fake) as c:
        for change, word in (({"vlan": 88}, "VLAN 88 is already used"), ({"subnet": "10.88.1.5/24"}, "overlaps"), ({"subnet": "8.8.8.1/24"}, "private"),
                             ({"subnet": "10.5.0.1/31", "dhcp_start": "10.5.0.1", "dhcp_stop": "10.5.0.1"}, "16 to 30"), ({"subnet": "10.5.0.0/24"}, "gateway address"), ({"name": "lan_iot"}, "already called"),
                             ({"vlan": 5000}, "1 to 4094"), ({"zone": "External"}, "External"), ({"dhcp_start": "10.199.99.1", "dhcp_stop": "10.199.99.50"}, "gateway"),
                             ({"dhcp_start": "10.1.1.5", "dhcp_stop": "10.1.1.9"}, "not inside"), ({"dhcp_lease_seconds": 5}, "dhcp_lease_seconds"),
                             ({"dhcp_dns": ["not-an-ip"]}, "not an IPv4")):
            text = await raw(c, {**NEW, **change})
            assert word in text, (change, text[:300])
        assert "unknown" in (await raw(c, {**NEW, "zone": "Nowhere"})).lower() or "not a firewall zone" in await raw(c, {**NEW, "zone": "Nowhere"})
        for need in ("name", "vlan", "subnet", "zone"):
            assert f"create needs {need}" in await raw(c, {k: v for k, v in NEW.items() if k != need})
    assert not fake.writes()


async def test_create_enabled_runs_the_safety_net(make_session, dns):
    fake = FakeNet(dns)
    async with make_session(fake) as c:
        pre, out = await apply(c, {**NEW, "enabled": True})
    assert any("Enabled on creation" in w for w in pre["warnings"])
    assert out["verified"] and out["guard"]["probe_after"] == "ok" and dns.queries >= 2


async def test_small_subnet_needs_an_explicit_dhcp_range(make_session, dns):
    async with make_session(FakeNet(dns)) as c:
        assert "dhcp_start and dhcp_stop" in await raw(c, {**NEW, "subnet": "10.199.99.1/28"})


# ------------------------------------------------------------------------------------------------ update
async def test_edit_sends_the_whole_object_as_read_and_nothing_else_moves(make_session, dns):
    fake = FakeNet(dns)
    await_before = copy.deepcopy(fake.rows)
    async with make_session(fake) as c:
        pre, out = await apply(c, {"action": "update", "target": "LAN_Sonos", "dhcp_lease_seconds": 43200, "acknowledge_disconnect": True})
    body = fake.writes()[0][2]
    want = {k: v for k, v in await_before[2].items() if k not in ("site_id", "attr_no_delete")}
    assert {k: v for k, v in body.items() if k != "dhcpd_leasetime"} == {k: v for k, v in want.items() if k != "dhcpd_leasetime"}
    assert body["dhcpd_leasetime"] == 43200 and set(pre["diff"]) == {"dhcpd_leasetime"} and out["verified"]
    assert fake.rows[:2] == await_before[:2] and fake.rows[3:] == await_before[3:]
    assert out["guard"]["probe_after"] == "ok"


async def test_a_non_disruptive_edit_of_a_disabled_network_needs_no_acknowledgement_and_no_probe(make_session, dns):
    fake = FakeNet(dns)
    async with make_session(fake) as c:
        await apply(c, NEW)
        _, out = await apply(c, {"action": "update", "target": "zz-net", "dhcp_start": "10.199.99.20"})
    assert out["verified"] and "guard" not in out and dns.queries == 0


async def test_disruptive_edit_is_refused_with_clients_until_acknowledged_and_names_them(make_session, dns):
    fake = FakeNet(dns)
    async with make_session(fake) as c:
        args = {"action": "update", "target": "LAN_Sonos", "internet_access": False}
        pre = await call(c, args)
        assert any("Disconnect stop" in e for e in pre["errors"]) and any("Sonos Playbar" in w for w in pre["warnings"])
        assert any("SSIDs" not in w and "switch ports Switch A port 2" in w for w in pre["warnings"])
        _, out = await apply(c, {**args, "acknowledge_disconnect": True})
    assert out["applied"] and fake.by("LAN_Sonos")["internet_access_enabled"] is False


async def test_subnet_change_needs_a_new_dhcp_range_and_warns_about_pointers_into_the_old_range(make_session, dns):
    fake = FakeNet(dns)
    async with make_session(fake) as c:
        pre = await call(c, {"action": "update", "target": "LAN_IoT", "subnet": "10.77.1.1/24", "acknowledge_disconnect": True})
        assert any("not inside" in e for e in pre["errors"])
        pre = await call(c, {"action": "update", "target": "LAN_IoT", "subnet": "10.77.1.1/24", "dhcp_start": "10.77.1.100",
                             "dhcp_stop": "10.77.1.254", "acknowledge_disconnect": True})
        assert not pre["errors"] and pre["after"]["dhcpd_ip_1"] == "10.77.1.1"
        text = " ".join(pre["warnings"])
        assert "fixed IPs" in text and "Harmony Hub" in text and "static DNS records" in text and "NOT rewritten" in text


async def test_enabled_is_not_an_update_field_and_wan_is_refused(make_session, dns):
    async with make_session(FakeNet(dns)) as c:
        assert "enable or disable action" in await raw(c, {"action": "update", "target": "LAN_IoT", "enabled": False})
        assert "only handles corporate and guest" in await raw(c, {"action": "update", "target": "WAN1", "name": "x"})
        pre = await call(c, {"action": "disable", "target": "WAN1"})
        assert any("only corporate and guest" in e for e in pre["errors"])


async def test_dhcp_dns_servers_set_the_flag_and_slots(make_session, dns):
    fake = FakeNet(dns)
    async with make_session(fake) as c:
        await apply(c, NEW)
        pre, out = await apply(c, {"action": "update", "target": "zz-net", "dhcp_dns": ["1.1.1.1", "9.9.9.9"]})
        b = fake.by("zz-net")
        assert b["dhcpd_dns_enabled"] is True and (b["dhcpd_dns_1"], b["dhcpd_dns_2"], b["dhcpd_dns_3"], b["dhcpd_dns_4"]) == ("1.1.1.1", "9.9.9.9", "", "")
        assert b["dhcpd_ip_1"] == "10.199.99.1"  # the gateway slot is not a DNS slot
        # dropping the second server (the LAN_Guest case) leaves only the first
        pre, out = await apply(c, {"action": "update", "target": "zz-net", "dhcp_dns": ["1.1.1.1"]})
        b = fake.by("zz-net")
        assert (b["dhcpd_dns_1"], b["dhcpd_dns_2"]) == ("1.1.1.1", "") and out["verified"]
        await apply(c, {"action": "update", "target": "zz-net", "dhcp_dns": []})
    assert fake.by("zz-net")["dhcpd_dns_enabled"] is False


# ------------------------------------------------------------------------------------------------ infrastructure
async def test_the_network_holding_the_console_is_protected(make_session, dns):
    fake = FakeNet(dns)
    async with make_session(fake) as c:
        assert "cannot be deleted" in await raw(c, {"action": "delete", "target": "LAN_Private"})
        for args in ({"action": "disable", "target": "LAN_Private"}, {"action": "update", "target": "LAN_Private", "dhcp_enabled": False}):
            pre = await call(c, args)
            assert any("Infrastructure stop" in e for e in pre["errors"]), (args, pre["errors"])
        ok = await call(c, {"action": "update", "target": "LAN_Private", "domain_name": "example.home"})
        assert not any("Infrastructure" in e for e in ok["errors"])
        ack = await call(c, {"action": "update", "target": "LAN_Private", "dhcp_enabled": False, "acknowledge_infrastructure": True, "acknowledge_disconnect": True})
        assert not any("Infrastructure" in e for e in ack["errors"]) and any("cut the session" in w for w in ack["warnings"])
    assert not fake.writes()


# ------------------------------------------------------------------------------------------------ enable, disable, delete
async def test_disable_and_enable_use_the_group_endpoint_with_the_safety_net(make_session, dns):
    fake = FakeNet(dns)
    async with make_session(fake) as c:
        await apply(c, NEW)
        fake.log.clear()
        _, out = await apply(c, {"action": "enable", "target": "zz-net"})
        assert fake.writes()[0][1] == GROUP and fake.writes()[0][2] == {"id": [fake.by("zz-net")["_id"]], "data": {"enabled": True}}
        assert out["verified"] and out["guard"]["probe_after"] == "ok" and out["rollback"]["arguments"]["action"] == "disable"
        _, out = await apply(c, {"action": "disable", "target": "zz-net"})
    assert fake.by("zz-net")["enabled"] is False and out["verified"]


async def test_disable_with_users_needs_the_acknowledgement(make_session, dns):
    async with make_session(FakeNet(dns)) as c:
        pre = await call(c, {"action": "disable", "target": "LAN_IoT"})
        assert any("Disconnect stop" in e for e in pre["errors"]) and any("SSIDs ExampleNet_IoT" in w for w in pre["warnings"])


async def test_delete_is_refused_while_an_ssid_or_port_uses_it_and_applies_when_unused(make_session, dns):
    fake = FakeNet(dns)
    async with make_session(fake) as c:
        for target, who in (("LAN_IoT", "ExampleNet_IoT"), ("LAN_Sonos", "Switch A port 2")):
            pre = await call(c, {"action": "delete", "target": target})
            assert any("In use" in e and who in e for e in pre["errors"])
        await apply(c, NEW)
        pre, out = await apply(c, {"action": "delete", "target": "zz-net"})
    assert out["applied"] and all(r["name"] != "zz-net" for r in fake.rows)
    assert "new id" in " ".join(pre["warnings"]) and out["rollback"]["arguments"]["action"] == "create"


async def test_delete_with_clients_on_an_unused_network_needs_the_acknowledgement(make_session, dns):
    fake = FakeNet(dns)
    fake.wlans, fake.devs[0]["port_overrides"] = [], []
    async with make_session(fake) as c:
        pre = await call(c, {"action": "delete", "target": "LAN_Sonos"})
        assert any("Disconnect stop" in e for e in pre["errors"]) and not any("In use" in e for e in pre["errors"])


# ------------------------------------------------------------------------------------------------ safety net
async def test_forced_failure_restores_an_edit(make_session, dns):
    fake = FakeNet(dns)
    before = copy.deepcopy(fake.by("LAN_Sonos"))
    async with make_session(fake, force_fail=True) as c:
        _, out = await apply(c, {"action": "update", "target": "LAN_Sonos", "dhcp_lease_seconds": 43200, "acknowledge_disconnect": True})
    assert out["applied"] is False and out["guard"]["auto_restored"] and out["guard"]["restore_verified"]
    assert fake.by("LAN_Sonos")["dhcpd_leasetime"] == before["dhcpd_leasetime"]


async def test_forced_failure_restores_enable_create_and_delete(make_session, dns):
    fake = FakeNet(dns)
    async with make_session(fake) as c:
        await apply(c, NEW)
    async with make_session(fake, force_fail=True) as c:
        _, out = await apply(c, {"action": "enable", "target": "zz-net"})
        assert out["applied"] is False and out["guard"]["restore_verified"] and fake.by("zz-net")["enabled"] is False
        _, out = await apply(c, {**NEW, "name": "zz-two", "vlan": 3998, "subnet": "10.199.98.1/24", "enabled": True})
        assert out["applied"] is False and out["guard"]["restore_verified"] and all(r["name"] != "zz-two" for r in fake.rows)


async def test_forced_failure_restores_a_deleted_enabled_network(make_session, dns):
    fake = FakeNet(dns)
    fake.wlans, fake.devs[0]["port_overrides"], fake.clients = [], [], []
    async with make_session(fake, force_fail=True) as c:
        _, out = await apply(c, {"action": "delete", "target": "LAN_Sonos"})
    assert out["applied"] is False and out["guard"]["restore_verified"] and fake.by("LAN_Sonos")["vlan"] == 22


async def test_a_device_dropping_off_triggers_the_restore(make_session, dns):
    fake = FakeNet(dns)
    fake.drop_on_write = lambda f: f.devs[1].update(state=0) if f.devs[1]["state"] == 1 else None
    async with make_session(fake) as c:
        _, out = await apply(c, {"action": "update", "target": "LAN_Sonos", "dhcp_lease_seconds": 43200, "acknowledge_disconnect": True})
    assert out["applied"] is False and "AP Pro" in out["guard"]["probe_after"]


async def test_dns_failing_before_refuses_a_change_to_an_enabled_network(make_session, dns):
    fake = FakeNet(dns)
    dns.mode = "silent"
    async with make_session(fake) as c:
        pre = await call(c, {"action": "update", "target": "LAN_Sonos", "dhcp_lease_seconds": 43200, "acknowledge_disconnect": True})
    assert any("Safety probe" in e for e in pre["errors"])


async def test_other_networks_changing_is_reported_as_a_mismatch(make_session, dns):
    fake = FakeNet(dns)

    def alter(row):
        fake.by("LAN_IoT")["igmp_snooping"] = True
        return row
    fake.alter = alter
    async with make_session(fake) as c:
        await apply(c, NEW)
        _, out = await apply(c, {"action": "update", "target": "zz-net", "dhcp_start": "10.199.99.20"})
    assert not out["verified"] and any("LAN_IoT" in m["field"] for m in out["mismatches"])


# ------------------------------------------------------------------------------------------------ gates and routing
async def test_gates_stale_fingerprint_and_tier_c_note(make_session, dns):
    fake = FakeNet(dns)
    args = {"action": "update", "target": "LAN_Sonos", "dhcp_lease_seconds": 43200, "acknowledge_disconnect": True}
    async with make_session(fake, writes=False) as c:
        assert "Writes are disabled" in (await call(c, args))["apply_blocked_reason"]
    async with make_session(fake, entities=frozenset({"wifi"})) as c:
        assert "not enabled for writes" in (await call(c, args))["apply_blocked_reason"]
    async with make_session(fake) as c:
        pre = await call(c, args)
        assert "approval_note" in await raw(c, {**args, "confirm": True, "fingerprint": pre["fingerprint"]})
        fake.by("LAN_Sonos")["domain_name"] = "x.test"
        assert "differs from the preview" in await raw(c, {**args, "confirm": True, "fingerprint": pre["fingerprint"], "approval_note": NOTE})
    assert not fake.writes()


async def test_delete_and_enable_take_no_field_values(make_session, dns):
    async with make_session(FakeNet(dns)) as c:
        assert "takes no field values" in await raw(c, {"action": "delete", "target": "LAN_IoT", "name": "x"})
        assert "takes no target" in await raw(c, {**NEW, "target": "LAN_IoT"})


async def test_generic_tool_refuses_the_networkconf_writes_and_names_the_typed_tool(make_session, dns):
    fake = FakeNet(dns)
    async with make_session(fake) as c:
        for op, extra in (("createNetworkConfig", {"body": {"name": "x"}}), ("updateNetworkConfig", {"path_params": {"id": N_IOT}, "body": {"name": "x"}}),
                          ("deleteNetworkConfig", {"path_params": {"id": N_IOT}}), ("updateNetworkConfigGroup", {"body": {"id": [N_IOT], "data": {"enabled": False}}}),
                          ("deleteNetwork", {"path_params": {"networkId": N_IOT}})):
            res = await c.call_tool("unifi_console_call_operation", {"operation_id": op, "confirm": True, **extra})
            assert TOOL in res.content[0].text, (op, res.content[0].text)
    assert fake.writes() == []
