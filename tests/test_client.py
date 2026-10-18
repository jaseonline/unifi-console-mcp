"""Client edits through the write framework: partial bodies, fixed-IP and DNS checks against networks, active clients and static DNS."""
from __future__ import annotations

import contextlib
import dataclasses
import json

import httpx
import pytest
from mcp.client import Client

from conftest import make_jwt
from test_writes import Wrapped
from unifi_console_mcp.server import create_server

BASE = "/proxy/network/api/s/default"
USER = BASE + "/rest/user"
NETS = BASE + "/rest/networkconf"
STA = BASE + "/stat/sta"
SDNS = "/proxy/network/v2/api/site/default/static-dns"
TOOL = "unifi_console_client"

IOT = "98fba899-f53a-4e3d-b257-5b8e2e594189"
PRIVATE = "095fd156-f0dc-4b35-a83c-ec96b7bb2805"
NETWORKS = [
    {"_id": IOT, "name": "LAN_IoT", "purpose": "corporate", "ip_subnet": "10.88.1.1/24", "dhcpd_enabled": True,
     "dhcpd_start": "10.88.1.100", "dhcpd_stop": "10.88.1.254", "vlan": 88},
    {"_id": PRIVATE, "name": "LAN_Private", "purpose": "corporate", "ip_subnet": "192.168.1.1/24", "dhcpd_enabled": True,
     "dhcpd_start": "192.168.1.100", "dhcpd_stop": "192.168.1.254"},
    {"_id": "wan", "name": "WAN1", "purpose": "wan"},
]
HUB = {"_id": "a7f05407-6185-4d13-ab47-a28b6634417f", "mac": "02:00:00:00:00:23", "name": "Harmony Hub", "noted": True, "note": "",
       "use_fixedip": True, "fixed_ip": "10.88.1.23", "local_dns_record": "", "local_dns_record_enabled": False,
       "network_id": "619a71194dd76504c6e23246", "last_connection_network_id": IOT, "last_seen": 1, "last_ip": "10.88.1.23",
       "blocked": False, "usergroup_id": "", "site_id": "s"}
ECHO = {"_id": "echo-id", "mac": "02:00:00:00:00:42", "name": "Amazon Echo", "noted": True, "use_fixedip": True, "fixed_ip": "10.88.1.44",
        "local_dns_record": "echo.example.home", "local_dns_record_enabled": True, "last_connection_network_id": IOT}
NEW = {"_id": "new-id", "mac": "aa:bb:cc:dd:ee:01", "noted": False, "use_fixedip": False, "last_connection_network_id": IOT}


class FakeClients:
    def __init__(self) -> None:
        self.items = {r["_id"]: dict(r) for r in (HUB, ECHO, NEW)}
        self.active = [{"mac": ECHO["mac"], "ip": "10.88.1.44", "name": "Amazon Echo"},
                       {"mac": "11:22:33:44:55:66", "ip": "10.88.1.60", "hostname": "xbox"}]
        self.static_dns = [{"_id": "s1", "key": "mycloud.example.home", "record_type": "A", "enabled": True, "value": "192.168.1.10"}]
        self.networks = [dict(n) for n in NETWORKS]
        self.networks_status = 200
        self.ignore_put = False
        self.fail_put_at: int | None = None     # the Nth PUT answers HTTP 500
        self.puts = 0
        self.log: list[tuple[str, str, dict | None]] = []
        self.bodies: list[dict] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        if path == "/api/auth/login":
            return httpx.Response(200, json={}, headers={"set-cookie": f"TOKEN={make_jwt()}; Path=/", "x-csrf-token": "c"})
        body = json.loads(request.content) if request.content else None
        self.log.append((method, path, body))
        wrap = lambda x: {"meta": {"rc": "ok"}, "data": x}  # noqa: E731
        if path == USER and method == "GET":
            return httpx.Response(200, json=wrap(list(self.items.values())))
        if path == NETS:
            return httpx.Response(self.networks_status, json=wrap(self.networks))
        if path == STA:
            return httpx.Response(200, json=wrap(self.active))
        if path == SDNS:
            return httpx.Response(200, json=self.static_dns)
        if path.startswith(USER + "/") and method == "PUT":
            ident = path.rsplit("/", 1)[1]
            self.puts += 1
            if self.fail_put_at == self.puts:
                return httpx.Response(500, json={"message": "boom"})
            self.bodies.append(body)
            if not self.ignore_put:
                self.items[ident] = {**self.items[ident], **body}
            return httpx.Response(200, json=wrap([self.items[ident]]))
        return httpx.Response(404, json={})

    def writes(self):
        return [e for e in self.log if e[0] in ("POST", "PUT", "DELETE") and "login" not in e[1]]


@pytest.fixture
def make_session(settings, tmp_path):
    @contextlib.asynccontextmanager
    async def opener(net: FakeClients, *, writes: bool = True, entities=frozenset({"client"})):
        s = dataclasses.replace(settings, enable_writes=writes, write_entities=entities, journal_dir=tmp_path / "journal")
        mcp, api = create_server(s, transport=httpx.MockTransport(net))
        try:
            async with Client(mcp) as client:
                yield Wrapped(client)
        finally:
            await api.client.aclose()
    return opener


async def call(c, args):
    res = await c.call_tool(TOOL, args)
    assert not res.is_error, res
    return json.loads(res.content[0].text)


async def apply(c, args):
    pre = await call(c, args)
    assert pre.get("ok") and not pre["errors"], pre
    return pre, await call(c, {**args, "confirm": True, "fingerprint": pre["fingerprint"]})


async def test_rename_sends_only_the_name_and_verifies(make_session):
    net = FakeClients()
    async with make_session(net) as c:
        pre, out = await apply(c, {"target": "Harmony Hub", "name": "Harmony Hub 2"})
    assert pre["request"]["method"] == "PUT" and pre["request"]["body_style"] == "changed fields only"
    assert net.bodies == [{"name": "Harmony Hub 2"}]
    assert out["verified"] and list(out["diff"]) == ["name"]
    assert out["rollback"]["changes"] == {"name": "Harmony Hub"}
    assert net.items[HUB["_id"]]["fixed_ip"] == "10.88.1.23"


@pytest.mark.parametrize("target", ["02:00:00:00:00:23", "02-00-00-00-00-23", HUB["_id"], "Harmony Hub"])
async def test_a_client_can_be_addressed_by_mac_id_or_name(make_session, target):
    async with make_session(FakeClients()) as c:
        pre = await call(c, {"target": target, "note": "x"})
    assert pre["id"] == HUB["_id"]


async def test_setting_a_note_on_an_unnoted_client_also_sets_noted(make_session):
    net = FakeClients()
    async with make_session(net) as c:
        pre, out = await apply(c, {"target": NEW["mac"], "note": "spare"})
    assert net.bodies == [{"note": "spare", "noted": True}]
    assert out["verified"] and out["rollback"]["changes"] == {"note": "", "noted": False}


async def test_move_fixed_ip_inside_the_network_sends_only_the_address(make_session):
    net = FakeClients()
    async with make_session(net) as c:
        pre, out = await apply(c, {"target": "Harmony Hub", "fixed_ip": "10.88.1.24"})
    assert net.bodies == [{"fixed_ip": "10.88.1.24"}]
    assert out["verified"] and out["rollback"]["changes"] == {"fixed_ip": "10.88.1.23"}
    assert "stale" not in json.dumps(pre["warnings"])


async def test_fixed_ip_on_a_client_without_one_turns_it_on(make_session):
    net = FakeClients()
    async with make_session(net) as c:
        pre, out = await apply(c, {"target": NEW["mac"], "fixed_ip": "10.88.1.90"})
    assert net.bodies == [{"use_fixedip": True, "fixed_ip": "10.88.1.90"}]
    assert out["verified"] and out["rollback"]["changes"]["use_fixedip"] is False


@pytest.mark.parametrize("ip,needle", [
    ("10.88.1.44", "already the fixed IP of 'Amazon Echo'"),
    ("10.88.1.60", "in use right now"),
    ("10.88.1.1", "gateway address"),
    ("10.88.1.0", "network or broadcast"),
    ("10.88.1.255", "network or broadcast"),
    ("172.16.0.5", "not inside any of the console's LAN subnets"),
    ("10.88.1.300", "not an IPv4 address"),
])
async def test_bad_fixed_ips_are_refused(make_session, ip, needle):
    net = FakeClients()
    async with make_session(net) as c:
        pre = await call(c, {"target": "Harmony Hub", "fixed_ip": ip})
        assert needle in " ".join(pre["errors"]), pre
        out = await call(c, {"target": "Harmony Hub", "fixed_ip": ip, "confirm": True, "fingerprint": pre["fingerprint"]})
    assert "Refused" in out["error"] and net.writes() == []


async def test_fixed_ip_in_the_dhcp_pool_warns_and_other_network_warns(make_session):
    async with make_session(FakeClients()) as c:
        pool = await call(c, {"target": "Harmony Hub", "fixed_ip": "10.88.1.150"})
        other = await call(c, {"target": "Harmony Hub", "fixed_ip": "192.168.1.30"})
    assert not pool["errors"] and "DHCP pool" in " ".join(pool["warnings"])
    assert not other["errors"] and "last used LAN_IoT" in " ".join(other["warnings"])


async def test_a_clients_own_address_is_not_a_conflict(make_session):
    net = FakeClients()
    net.active.append({"mac": HUB["mac"], "ip": "10.88.1.23", "name": "Harmony Hub"})
    async with make_session(net) as c:
        pre = await call(c, {"target": "Harmony Hub", "name": "Hub"})
        moved = await call(c, {"target": "Harmony Hub", "fixed_ip": "10.88.1.23"})
    assert not pre["errors"] and moved["note"].startswith("Already")


async def test_local_dns_record_is_lowercased_and_enabled(make_session):
    net = FakeClients()
    async with make_session(net) as c:
        pre, out = await apply(c, {"target": "Harmony Hub", "local_dns_record": "Hub.Example.Home"})
    assert net.bodies == [{"local_dns_record": "hub.example.home", "local_dns_record_enabled": True}]
    assert out["verified"] and out["rollback"]["changes"] == {"local_dns_record": "", "local_dns_record_enabled": False}


async def test_clearing_the_dns_record_disables_it(make_session):
    net = FakeClients()
    async with make_session(net) as c:
        pre, out = await apply(c, {"target": "Amazon Echo", "local_dns_record": ""})
    assert net.bodies == [{"local_dns_record": "", "local_dns_record_enabled": False}] and out["verified"]


@pytest.mark.parametrize("record,needle", [
    ("echo.example.home", "already the Local DNS record of 'Amazon Echo'"),
    ("mycloud.example.home", "static DNS A record"),
    ("bad_name.example.home", "not a valid DNS name"),
    ("-x.example.home", "not a valid DNS name"),
])
async def test_bad_dns_records_are_refused(make_session, record, needle):
    async with make_session(FakeClients()) as c:
        pre = await call(c, {"target": "Harmony Hub", "local_dns_record": record})
    assert needle in " ".join(pre["errors"]), pre


async def test_dns_record_without_fixed_ip_warns(make_session):
    async with make_session(FakeClients()) as c:
        pre = await call(c, {"target": NEW["mac"], "local_dns_record": "spare.example.home"})
    assert not pre["errors"] and "no fixed IP" in " ".join(pre["warnings"])


@pytest.mark.parametrize("args,needle", [
    ({"use_fixedip": True}, "needs a fixed_ip"),
    ({"fixed_ip": " "}, "cannot be empty"),
    ({"local_dns_record_enabled": True}, "needs a local_dns_record"),
])
async def test_incomplete_requests_are_refused(make_session, args, needle):
    async with make_session(FakeClients()) as c:
        res = await c.call_tool(TOOL, {"target": NEW["mac"], **args})
    assert needle in res.content[0].text


async def test_nothing_to_change_is_an_error(make_session):
    async with make_session(FakeClients()) as c:
        res = await call(c, {"target": "Harmony Hub"})
    assert res["ok"] is False and "Nothing to change" in res["error"]


async def test_noop_sends_nothing(make_session):
    net = FakeClients()
    async with make_session(net) as c:
        pre = await call(c, {"target": "Harmony Hub", "name": "Harmony Hub"})
        assert pre["note"].startswith("Already")
        out = await call(c, {"target": "Harmony Hub", "name": "Harmony Hub", "confirm": True, "fingerprint": pre["fingerprint"]})
    assert out["applied"] is False and net.writes() == []


async def test_a_client_that_keeps_talking_does_not_make_the_preview_stale(make_session):
    net = FakeClients()
    async with make_session(net) as c:
        pre = await call(c, {"target": "Harmony Hub", "note": "n"})
        net.items[HUB["_id"]].update(last_seen=99, last_ip="10.88.1.23", disconnect_timestamp=5)
        out = await call(c, {"target": "Harmony Hub", "note": "n", "confirm": True, "fingerprint": pre["fingerprint"]})
    assert out["applied"] and out["verified"]


async def test_a_real_change_between_preview_and_apply_is_refused(make_session):
    net = FakeClients()
    async with make_session(net) as c:
        pre = await call(c, {"target": "Harmony Hub", "note": "n"})
        net.items[HUB["_id"]]["fixed_ip"] = "10.88.1.77"
        res = await c.call_tool(TOOL, {"target": "Harmony Hub", "note": "n", "confirm": True, "fingerprint": pre["fingerprint"]})
    assert "differs from the preview" in res.content[0].text and net.writes() == []


async def test_preview_works_with_writes_off_and_says_why(make_session):
    net = FakeClients()
    async with make_session(net, writes=False) as c:
        pre = await call(c, {"target": "Harmony Hub", "note": "n"})
        res = await c.call_tool(TOOL, {"target": "Harmony Hub", "note": "n", "confirm": True, "fingerprint": pre["fingerprint"]})
    assert "UNIFI_CONSOLE_ENABLE_WRITES" in pre["apply_blocked_reason"] and net.writes() == []
    assert "UNIFI_CONSOLE_ENABLE_WRITES" in res.content[0].text


async def test_entity_must_be_listed(make_session):
    async with make_session(FakeClients(), entities=frozenset({"port_forward"})) as c:
        pre = await call(c, {"target": "Harmony Hub", "note": "n"})
    assert "UNIFI_CONSOLE_WRITE_ENTITIES" in pre["apply_blocked_reason"]


async def test_failed_check_read_blocks_everything(make_session):
    net = FakeClients()
    net.networks_status = 500
    async with make_session(net) as c:
        res = await c.call_tool(TOOL, {"target": "Harmony Hub", "note": "n"})
    assert "Could not read networks" in res.content[0].text and net.writes() == []


async def test_silent_failure_is_reported_not_retried(make_session):
    net = FakeClients()
    net.ignore_put = True
    async with make_session(net) as c:
        pre, out = await apply(c, {"target": "Harmony Hub", "note": "n"})
    assert out["verified"] is False and out["mismatches"][0]["field"] == "note" and len(net.writes()) == 1


async def test_unknown_client_and_ambiguous_name(make_session):
    net = FakeClients()
    net.items["dup"] = {**ECHO, "_id": "dup", "mac": "aa:aa:aa:aa:aa:aa"}
    async with make_session(net) as c:
        missing = await c.call_tool(TOOL, {"target": "nope", "note": "n"})
        dup = await c.call_tool(TOOL, {"target": "Amazon Echo", "note": "n"})
    assert "No client" in missing.content[0].text and "2 clients are called" in dup.content[0].text


async def test_generic_tool_points_to_the_typed_one(make_session):
    async with make_session(FakeClients()) as c:
        res = await c.client.call_tool("unifi_console_call_operation", {"params": {
            "operation_id": "updateKnownClient", "path_params": {"id": HUB["_id"]}, "body": {"name": "x"}}})
    assert "unifi_console_client" in res.content[0].text
