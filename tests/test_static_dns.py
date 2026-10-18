"""Static DNS records through the write framework: whole-object v2 updates, duplicates, the CNAME rule, client clashes."""
from __future__ import annotations

import contextlib
import dataclasses
import json
import uuid

import httpx
import pytest
from mcp.client import Client

from conftest import make_jwt
from test_writes import Wrapped
from unifi_console_mcp.server import create_server

SDNS = "/proxy/network/v2/api/site/default/static-dns"
USER = "/proxy/network/api/s/default/rest/user"
NETS = "/proxy/network/api/s/default/rest/networkconf"
TOOL = "unifi_console_static_dns"
REQUIRED = {"record_type", "key", "value", "enabled"}


def rec(ident, key, rtype, value, enabled=True, **extra):
    return {"_id": ident, "enabled": enabled, "key": key, "record_type": rtype, "value": value, "ttl": 0, "port": 0,
            "priority": 0, "weight": 0, **extra}


NAS = rec("nas-id", "nas.example.home", "A", "192.168.1.10")
ALIAS = rec("alias-id", "files.example.home", "CNAME", "nas.example.home")
V6 = rec("v6-id", "nas.example.home", "AAAA", "fe80::200:c0ff:fe33:ec44")
OFF = rec("off-id", "old.example.home", "A", "192.0.2.100", enabled=False)


class FakeDns:
    def __init__(self, items=(NAS, ALIAS, V6, OFF)) -> None:
        self.items = {r["_id"]: dict(r) for r in items}
        self.clients = [{"mac": "aa:aa:aa:aa:aa:01", "name": "Home Assistant", "local_dns_record": "ha.example.home",
                         "local_dns_record_enabled": True}]
        self.networks = [{"_id": "n1", "name": "LAN_Private", "purpose": "corporate", "ip_subnet": "192.168.1.1/24"}]
        self.ignore_put = False
        self.no_id_in_reply = False
        self.log: list[tuple[str, str, dict | None]] = []
        self.bodies: list[dict] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        if path == "/api/auth/login":
            return httpx.Response(200, json={}, headers={"set-cookie": f"TOKEN={make_jwt()}; Path=/", "x-csrf-token": "c"})
        body = json.loads(request.content) if request.content else None
        self.log.append((method, path, body))
        wrap = lambda x: {"meta": {"rc": "ok"}, "data": x}  # noqa: E731
        if path == USER:
            return httpx.Response(200, json=wrap(self.clients))
        if path == NETS:
            return httpx.Response(200, json=wrap(self.networks))
        if path == SDNS and method == "GET":
            return httpx.Response(200, json=list(self.items.values()))
        if path == SDNS and method == "POST":
            self.bodies.append(body)
            new = {"ttl": 0, "port": 0, "priority": 0, "weight": 0, **body, "_id": uuid.uuid4().hex[:12]}
            self.items[new["_id"]] = new
            return httpx.Response(200, json={} if self.no_id_in_reply else new)
        if path.startswith(SDNS + "/"):
            ident = path.rsplit("/", 1)[1]
            if method == "PUT":
                if not REQUIRED <= set(body):                       # the real console rejects a partial body
                    return httpx.Response(400, json={"errorCode": 400, "message": "Validation failed"})
                self.bodies.append(body)
                if not self.ignore_put:
                    self.items[ident] = {**self.items[ident], **body}
                return httpx.Response(200, json=self.items[ident])
            if method == "DELETE":
                self.items.pop(ident, None)
                return httpx.Response(200, json={})
        return httpx.Response(404, json={})

    def writes(self):
        return [e for e in self.log if e[0] in ("POST", "PUT", "DELETE") and "login" not in e[1]]


@pytest.fixture
def make_session(settings, tmp_path):
    @contextlib.asynccontextmanager
    async def opener(net: FakeDns, *, entities=frozenset({"static_dns"})):
        s = dataclasses.replace(settings, enable_writes=True, write_entities=entities, journal_dir=tmp_path / "journal")
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


NEW = {"action": "create", "record_type": "A", "key": "Test.example.home.", "value": "192.168.1.77"}


async def test_create_sends_the_four_captured_keys_and_verifies(make_session):
    net = FakeDns()
    async with make_session(net) as c:
        pre, out = await apply(c, NEW)
    assert net.bodies == [{"enabled": True, "record_type": "A", "key": "test.example.home", "value": "192.168.1.77"}]
    assert out["verified"] and out["rollback"] == {"action": "delete", "target": out["id"]}


async def test_create_finds_the_record_when_the_reply_has_no_id(make_session):
    net = FakeDns()
    net.no_id_in_reply = True
    async with make_session(net) as c:
        pre, out = await apply(c, {**NEW, "key": "nas.example.home", "record_type": "AAAA", "value": "fd00::1"})
    assert out["verified"] and out["id"]            # two records share the name; the sent values pick the right one


async def test_update_sends_the_whole_record(make_session):
    net = FakeDns()
    async with make_session(net) as c:
        pre, out = await apply(c, {"action": "update", "target": "nas-id", "value": "192.168.1.11"})
    assert pre["request"]["body_style"] == "whole object"
    assert net.bodies == [{**NAS, "value": "192.168.1.11"}]
    assert out["verified"] and list(out["diff"]) == ["value"] and out["rollback"]["changes"] == {"value": "192.168.1.10"}


async def test_enable_and_disable_use_the_whole_record(make_session):
    net = FakeDns()
    async with make_session(net) as c:
        _, on = await apply(c, {"action": "enable", "target": "off-id"})
        _, off = await apply(c, {"action": "disable", "target": "off-id"})
    assert [b["enabled"] for b in net.bodies] == [True, False] and all(REQUIRED <= set(b) for b in net.bodies)
    assert on["verified"] and off["verified"]


async def test_delete_removes_and_rollback_recreates(make_session):
    net = FakeDns()
    async with make_session(net) as c:
        pre, out = await apply(c, {"action": "delete", "target": "off-id"})
    assert out["verified"] and "off-id" not in net.items
    assert out["rollback"]["action"] == "create" and out["rollback"]["changes"]["key"] == "old.example.home"


async def test_a_name_shared_by_two_records_needs_the_id(make_session):
    async with make_session(FakeDns()) as c:
        res = await c.call_tool(TOOL, {"action": "disable", "target": "nas.example.home"})
        ok = await call(c, {"action": "disable", "target": "nas-id"})
    assert "2 static DNS records are called" in res.content[0].text and ok["id"] == "nas-id"


@pytest.mark.parametrize("args,needle", [
    ({"key": "nas.example.home", "value": "192.168.1.10"}, "identical A record"),
    ({"record_type": "CNAME", "key": "nas.example.home", "value": "x.example.home"}, "already has a A record"),
    ({"key": "files.example.home"}, "already has a CNAME record"),
    ({"key": "ha.example.home"}, "already publishes"),
    ({"key": "*.example.home"}, "Wildcard"),
    ({"key": "bad name.example.home"}, "not a valid DNS name"),
    ({"value": "999.1.1.1"}, "needs an IPv4 address"),
    ({"record_type": "AAAA", "value": "192.168.1.1"}, "needs an IPv6 address"),
    ({"record_type": "SRV", "key": "_sip._tcp.example.home", "value": "pbx.example.home"}, "needs a port"),
    ({"priority": 5}, "only applies to MX and SRV"),
    ({"ttl": -1}, "ttl must be"),
])
async def test_bad_records_are_refused(make_session, args, needle):
    net = FakeDns()
    base = {"action": "create", "record_type": "A", "key": "new.example.home", "value": "192.168.1.50", **args}
    async with make_session(net) as c:
        pre = await call(c, base)
        assert needle in " ".join(pre["errors"]), pre
        res = await c.call_tool(TOOL, {**base, "confirm": True, "fingerprint": pre["fingerprint"]})
    assert "Refused" in res.content[0].text and net.writes() == []


async def test_warnings_for_public_names_outside_the_lan_and_twin_records(make_session):
    async with make_session(FakeDns()) as c:
        public = await call(c, {**NEW, "key": "www.example.com"})
        outside = await call(c, {**NEW, "value": "10.9.9.9"})
        twin = await call(c, {**NEW, "key": "nas.example.home", "value": "192.168.1.99"})
    assert not public["errors"] and "outside example.home" in " ".join(public["warnings"])
    assert "not inside any of your LAN subnets" in " ".join(outside["warnings"])
    assert "already has 1 enabled A" in " ".join(twin["warnings"])


async def test_changing_or_removing_a_record_a_cname_points_at_warns(make_session):
    async with make_session(FakeDns()) as c:
        gone = await call(c, {"action": "delete", "target": "nas-id"})
        off = await call(c, {"action": "disable", "target": "nas-id"})
        rename = await call(c, {"action": "update", "target": "nas-id", "key": "nas2.example.home"})
    for out in (gone, off, rename):
        assert "files.example.home" in " ".join(out["warnings"]), out


async def test_type_cannot_change(make_session):
    async with make_session(FakeDns()) as c:
        res = await c.call_tool(TOOL, {"action": "update", "target": "nas-id", "record_type": "TXT"})
    assert "cannot be changed" in res.content[0].text


async def test_existing_odd_records_can_still_be_toggled(make_session):
    odd = rec("odd-id", "mycloud", "CNAME", "device-local-1435d109.remotewd.com")
    async with make_session(FakeDns((odd,))) as c:
        pre, out = await apply(c, {"action": "disable", "target": "mycloud"})
    assert out["verified"]


async def test_aaaa_values_are_written_in_compressed_form(make_session):
    net = FakeDns()
    async with make_session(net) as c:
        pre, out = await apply(c, {"action": "create", "record_type": "AAAA", "key": "v6.example.home",
                                   "value": "FD00:0000:0000:0000:0000:0000:0000:0001"})
    assert net.bodies[0]["value"] == "fd00::1" and out["verified"]


async def test_silent_failure_is_reported(make_session):
    net = FakeDns()
    net.ignore_put = True
    async with make_session(net) as c:
        pre, out = await apply(c, {"action": "update", "target": "nas-id", "value": "192.168.1.12"})
    assert out["verified"] is False and out["mismatches"][0]["field"] == "value"


async def test_entity_must_be_listed_and_generic_tool_redirects(make_session):
    async with make_session(FakeDns(), entities=frozenset({"client"})) as c:
        pre = await call(c, NEW)
        res = await c.client.call_tool("unifi_console_call_operation", {"params": {
            "operation_id": "updateStaticDns", "path_params": {"id": "nas-id"}, "body": {"value": "1.1.1.1"}}})
    assert "UNIFI_CONSOLE_WRITE_ENTITIES" in pre["apply_blocked_reason"]
    assert "unifi_console_static_dns" in res.content[0].text


async def test_incomplete_create_and_field_values_on_toggle_are_rejected(make_session):
    async with make_session(FakeDns()) as c:
        a = await call(c, {"action": "create", "key": "x.example.home"})
        b = await call(c, {"action": "disable", "target": "nas-id", "value": "1.1.1.1"})
    assert not a["ok"] and "needs record_type" in a["error"] and not b["ok"]
