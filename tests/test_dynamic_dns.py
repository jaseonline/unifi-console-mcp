"""Dynamic DNS through the write framework: create, update and delete, and a token that never leaves the server."""
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

DDNS = "/proxy/network/api/s/default/rest/dynamicdns"
SERVICES = "/proxy/network/v2/api/site/default/wan/ddns"
TOOL = "unifi_console_dynamic_dns"
TOKEN = "fake-ddns-value-for-tests"
REAL = {"_id": "real-id", "interface": "wan", "service": "cloudflare", "server": "", "host_name": "unifi.example.home",
        "login": "example.home", "x_password": "[console-hidden]", "site_id": "s"}


class FakeDdns:
    def __init__(self, items=(REAL,)) -> None:
        self.items = {r["_id"]: dict(r) for r in items}
        self.ignore_post = False
        self.log: list[tuple[str, str, dict | None]] = []
        self.bodies: list[dict] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        if path == "/api/auth/login":
            return httpx.Response(200, json={}, headers={"set-cookie": f"TOKEN={make_jwt()}; Path=/", "x-csrf-token": "c"})
        body = json.loads(request.content) if request.content else None
        self.log.append((method, path, body))
        wrap = lambda x: {"meta": {"rc": "ok"}, "data": x}  # noqa: E731
        if path == SERVICES:
            return httpx.Response(200, json={"ddns": ["cloudflare", "noip", "duckdns", "custom"]})
        if path == DDNS and method == "GET":
            return httpx.Response(200, json=wrap([{k: v for k, v in r.items()} for r in self.items.values()]))
        if path == DDNS and method == "POST":
            self.bodies.append(body)
            new = {**body, "_id": uuid.uuid4().hex[:12], "site_id": "s"}
            if not self.ignore_post:
                self.items[new["_id"]] = new
            return httpx.Response(200, json=wrap([{**new, "x_password": "[console-hidden]"}]))
        if path.startswith(DDNS + "/") and method == "PUT":
            self.bodies.append(body)
            ident = path.rsplit("/", 1)[1]
            if ident not in self.items or set(body) != {"service", "host_name", "interface", "login", "x_password", "server"}:
                return httpx.Response(400, json={"meta": {"rc": "error", "msg": "api.err.Invalid"}, "data": []})
            if not self.ignore_post:
                self.items[ident] = {**body, "_id": ident, "site_id": "s"}
            return httpx.Response(200, json=wrap([{**self.items[ident], "x_password": "[console-hidden]"}]))
        if path.startswith(DDNS + "/") and method == "DELETE":
            self.items.pop(path.rsplit("/", 1)[1], None)
            return httpx.Response(200, json=wrap([]))
        return httpx.Response(404, json={})

    def writes(self):
        return [e for e in self.log if e[0] in ("POST", "PUT", "DELETE") and "login" not in e[1]]


@pytest.fixture
def make_session(settings, tmp_path, monkeypatch):
    monkeypatch.setenv("UNIFI_DDNS_TEST", TOKEN)

    @contextlib.asynccontextmanager
    async def opener(net: FakeDdns, *, entities=frozenset({"dynamic_dns"})):
        s = dataclasses.replace(settings, enable_writes=True, write_entities=entities, journal_dir=tmp_path / "journal")
        mcp, api = create_server(s, transport=httpx.MockTransport(net))
        try:
            async with Client(mcp) as client:
                yield Wrapped(client)
        finally:
            await api.client.aclose()
    return opener


async def raw(c, args):
    res = await c.call_tool(TOOL, args)
    return res.content[0].text


async def call(c, args):
    res = await c.call_tool(TOOL, args)
    assert not res.is_error, res
    return json.loads(res.content[0].text)


async def apply(c, args):
    pre = await call(c, args)
    assert pre.get("ok") and not pre["errors"], pre
    return pre, await call(c, {**args, "confirm": True, "fingerprint": pre["fingerprint"]})


NEW = {"action": "create", "service": "noip", "host_name": "ZZ-Test.Example.com.", "interface": "wan2",
       "login": "zz-user", "token_env": "UNIFI_DDNS_TEST"}


async def test_create_sends_the_six_captured_keys_and_never_exposes_the_token(make_session, tmp_path):
    net = FakeDdns()
    async with make_session(net) as c:
        pre_text = await raw(c, NEW)
        pre = json.loads(pre_text)
        out_text = await raw(c, {**NEW, "confirm": True, "fingerprint": pre["fingerprint"]})
    out = json.loads(out_text)
    assert net.bodies == [{"service": "noip", "host_name": "zz-test.example.com", "interface": "wan2", "login": "zz-user",
                           "server": "", "x_password": TOKEN}]
    assert out["verified"] is True and out["secret_fields_not_verified"] == ["x_password"]
    assert out["rollback"] == {"action": "delete", "target": out["id"]}
    journal = "".join(p.read_text() for p in (tmp_path / "journal").glob("*.jsonl"))
    for text in (pre_text, out_text, journal):
        assert TOKEN not in text
    assert "[redacted]" in journal or "x_password" in journal


async def test_a_preview_changes_when_the_token_changes(make_session, monkeypatch):
    async with make_session(FakeDdns()) as c:
        pre = await call(c, NEW)
        monkeypatch.setenv("UNIFI_DDNS_TEST", TOKEN + "-rotated")
        res = await raw(c, {**NEW, "confirm": True, "fingerprint": pre["fingerprint"]})
    assert "differs from the preview" in res


@pytest.mark.parametrize("name,needle", [
    ("UNIFI_CONSOLE_PASSWORD", "starting with UNIFI_DDNS_"),
    ("PATH", "starting with UNIFI_DDNS_"),
    ("UNIFI_DDNS_MISSING", "is not set"),
])
async def test_only_ddns_environment_variables_are_read(make_session, monkeypatch, name, needle):
    monkeypatch.setenv("UNIFI_CONSOLE_PASSWORD", "admin-secret-pw")
    net = FakeDdns()
    async with make_session(net) as c:
        text = await raw(c, {**NEW, "token_env": name})
    assert needle in text and "admin-secret-pw" not in text and net.writes() == []


async def test_create_needs_every_field(make_session):
    async with make_session(FakeDdns()) as c:
        text = await raw(c, {"action": "create", "service": "noip", "host_name": "a.example.com"})
    assert "create needs interface, login, token_env" in text


@pytest.mark.parametrize("args,needle", [
    ({"service": "nosuch"}, "not a service this console offers"),
    ({"host_name": "nodots"}, "not a valid host name"),
    ({"host_name": "bad name.example.com"}, "not a valid host name"),
    ({"interface": "eth0"}, "interface must be"),
    ({"service": "custom"}, "needs a server"),
    ({"host_name": "unifi.example.home", "interface": "wan"}, "already exists"),
])
async def test_bad_entries_are_refused(make_session, args, needle):
    net = FakeDdns()
    base = {**NEW, **args}
    async with make_session(net) as c:
        pre = await call(c, base)
        assert needle in " ".join(pre["errors"]), pre
        res = await raw(c, {**base, "confirm": True, "fingerprint": pre["fingerprint"]})
    assert "Refused" in res and net.writes() == []


async def test_warnings_for_a_second_entry_on_a_wan_and_a_server_on_a_normal_service(make_session):
    async with make_session(FakeDdns()) as c:
        second = await call(c, {**NEW, "interface": "wan"})
        server = await call(c, {**NEW, "server": "update.example.com"})
    assert not second["errors"] and "already has 1 Dynamic DNS entry" in " ".join(second["warnings"])
    assert "sends this token to noip" in " ".join(second["warnings"])
    assert "normally leaves it empty" in " ".join(server["warnings"])


UPD = {"action": "update", "target": "unifi.example.home", "token_env": "UNIFI_DDNS_TEST"}


async def test_update_sends_the_six_keys_keeps_the_id_and_never_exposes_the_token(make_session, tmp_path):
    net = FakeDdns()
    async with make_session(net) as c:
        args = {**UPD, "login": "example.home", "server": ""}
        pre_text = await raw(c, {**UPD, "interface": "wan"})
        pre = json.loads(pre_text)
        out_text = await raw(c, {**UPD, "interface": "wan", "confirm": True, "fingerprint": pre["fingerprint"]})
    out = json.loads(out_text)
    assert net.bodies == [{"service": "cloudflare", "host_name": "unifi.example.home", "interface": "wan",
                           "login": "example.home", "server": "", "x_password": TOKEN}]
    assert out["verified"] is True and out["id"] == "real-id" and set(net.items) == {"real-id"}
    assert out["secret_fields_not_verified"] == ["x_password"]
    assert "console-hidden" not in out_text
    journal = "".join(p.read_text() for p in (tmp_path / "journal").glob("*.jsonl"))
    for text in (pre_text, out_text, journal):
        assert TOKEN not in text
    assert "replaced by the one in the environment variable" in " ".join(pre["warnings"])
    assert args


async def test_update_changes_a_field_and_warns_when_the_record_moves(make_session):
    net = FakeDdns()
    async with make_session(net) as c:
        pre, out = await apply(c, {**UPD, "host_name": "other.example.home"})
    assert "Changing host_name" in " ".join(pre["warnings"])
    assert out["verified"] is True and net.items["real-id"]["host_name"] == "other.example.home"
    assert "host_name" in out["diff"] and "other.example.home" in json.dumps(out["diff"]["host_name"])
    assert out["rollback"]["action"] == "update" and out["rollback"]["changes"]["host_name"] == "unifi.example.home"
    assert "re-enter" in out["rollback"]["note"]


async def test_update_needs_a_target_and_the_token(make_session):
    net = FakeDdns()
    async with make_session(net) as c:
        no_token = await raw(c, {"action": "update", "target": "real-id", "login": "x"})
        no_target = await raw(c, {"action": "update", "token_env": "UNIFI_DDNS_TEST", "login": "x"})
        discard = await raw(c, {**UPD, "discard_token": True})
    assert "update needs token_env" in no_token and "update needs a target" in no_target and "only applies to delete" in discard
    assert net.writes() == []


async def test_update_is_validated_like_a_create(make_session):
    net = FakeDdns([REAL, {**REAL, "_id": "second", "host_name": "second.example.home"}])
    async with make_session(net) as c:
        clash = await call(c, {**UPD, "host_name": "second.example.home"})
        bad = await call(c, {**UPD, "service": "nosuch", "interface": "eth0"})
        res = await raw(c, {**UPD, "host_name": "second.example.home", "confirm": True, "fingerprint": clash["fingerprint"]})
    assert "already exists" in " ".join(clash["errors"])
    assert "not a service" in " ".join(bad["errors"]) and "interface must be" in " ".join(bad["errors"])
    assert "Refused" in res and net.writes() == []


async def test_an_update_the_console_silently_drops_is_reported(make_session):
    net = FakeDdns()
    net.ignore_post = True
    async with make_session(net) as c:
        _, out = await apply(c, {**UPD, "login": "someone-else"})
    assert out["verified"] is False and net.items["real-id"]["login"] == "example.home" and TOKEN not in json.dumps(out)


async def test_delete_warns_needs_acknowledgement_and_rolls_back_without_the_token(make_session, tmp_path):
    net = FakeDdns()
    async with make_session(net) as c:
        pre = await call(c, {"action": "delete", "target": "unifi.example.home"})
        refused = await raw(c, {"action": "delete", "target": "real-id", "confirm": True, "fingerprint": pre["fingerprint"]})
        assert "discard_token=true" in refused and net.writes() == []
        out = await call(c, {"action": "delete", "target": "real-id", "confirm": True, "fingerprint": pre["fingerprint"],
                             "discard_token": True})
    assert "discards its stored token" in " ".join(pre["warnings"])
    assert out["verified"] is True and "real-id" not in net.items
    rb = out["rollback"]
    assert rb["action"] == "create" and "x_password" not in rb["changes"] and "re-enter" in rb["note"]
    assert rb["changes"]["host_name"] == "unifi.example.home"
    assert "console-hidden" not in json.dumps(out)


async def test_discard_token_is_only_for_delete_and_delete_takes_no_fields(make_session):
    async with make_session(FakeDdns()) as c:
        a = await raw(c, {**NEW, "discard_token": True})
        b = await raw(c, {"action": "delete", "target": "real-id", "login": "x"})
    assert "only applies to delete" in a and "delete takes no field values" in b


async def test_an_entry_the_console_silently_drops_is_reported(make_session):
    net = FakeDdns()
    net.ignore_post = True
    async with make_session(net) as c:
        _, out = await apply(c, NEW)
    assert out["verified"] is False and out["mismatches"][0]["field"] == "(object)" and TOKEN not in json.dumps(out)


async def test_entity_switch_and_previews_when_writes_are_off(make_session):
    net = FakeDdns()
    async with make_session(net, entities=frozenset({"port_forward"})) as c:
        pre = await call(c, NEW)
        res = await raw(c, {**NEW, "confirm": True, "fingerprint": pre["fingerprint"]})
    assert "not enabled for writes" in pre["apply_blocked_reason"] and "not enabled for writes" in res and net.writes() == []


async def test_the_generic_tool_refuses_and_names_the_typed_one(settings, tmp_path):
    net = FakeDdns()
    mcp, api = create_server(dataclasses.replace(settings, enable_writes=True, write_entities=frozenset({"dynamic_dns"}),
                                                 journal_dir=tmp_path / "journal"), transport=httpx.MockTransport(net))
    try:
        async with Client(mcp) as c:
            res = await c.call_tool("unifi_console_call_operation", {"params": {
                "operation_id": "deleteDynamicDns", "path_params": {"id": "real-id"}, "confirm": True}})
            text = json.loads(res.content[0].text)["error"]
            res = await c.call_tool("unifi_console_call_operation", {"params": {
                "operation_id": "updateDynamicDns", "path_params": {"id": "real-id"}, "body": {"login": "x"}, "confirm": True}})
            text2 = json.loads(res.content[0].text)["error"]
    finally:
        await api.client.aclose()
    assert "unifi_console_dynamic_dns" in text and "unifi_console_dynamic_dns" in text2 and net.writes() == []
