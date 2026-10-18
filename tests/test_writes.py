"""Write framework, exercised through the port forward entity against an in-memory console."""
from __future__ import annotations

import contextlib
import dataclasses
import json
import uuid

import httpx
import pytest
from mcp.client import Client

from conftest import make_jwt
from unifi_console_mcp.server import create_server

PF = "/proxy/network/api/s/default/rest/portforward"
TOOL = "unifi_console_port_forward"
REAL = {"_id": "real1", "site_id": "s", "name": "Plex", "enabled": True, "pfwd_interface": "wan", "destination_ip": "any",
        "destination_ips": [], "dst_port": "32400", "fwd": "10.88.1.20", "fwd_port": "32400", "proto": "tcp",
        "src_limiting_enabled": False, "log": True}


class FakePortForwards:
    def __init__(self, with_real: bool = False) -> None:
        self.items: dict[str, dict] = {"real1": dict(REAL)} if with_real else {}
        self.log: list[tuple[str, str, dict | None]] = []
        self.ignore_put = False        # accept the write but store nothing (silent failure)
        self.reject_post = False       # HTTP 200 with meta.rc == error
        self.bodies: list[dict] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        if path == "/api/auth/login":
            return httpx.Response(200, json={}, headers={"set-cookie": f"TOKEN={make_jwt()}; Path=/", "x-csrf-token": "c"})
        body = json.loads(request.content) if request.content else None
        self.log.append((method, path, body))
        wrap = lambda x: {"meta": {"rc": "ok"}, "data": x}  # noqa: E731
        if path == PF and method == "GET":
            return httpx.Response(200, json=wrap(list(self.items.values())))
        if path == PF and method == "POST":
            if self.reject_post:
                return httpx.Response(200, json={"meta": {"rc": "error", "msg": "api.err.Invalid"}, "data": []})
            new = {**body, "_id": uuid.uuid4().hex[:8], "site_id": "s"}
            self.items[new["_id"]] = new
            self.bodies.append(body)
            return httpx.Response(200, json=wrap([new]))
        if path.startswith(PF + "/"):
            ident = path.rsplit("/", 1)[1]
            if method == "PUT":
                self.bodies.append(body)
                if not self.ignore_put:
                    self.items[ident] = {**self.items[ident], **body}
                return httpx.Response(200, json=wrap([self.items[ident]]))
            if method == "DELETE":
                self.items.pop(ident, None)
                return httpx.Response(200, json=wrap([]))
        return httpx.Response(404, json={})

    def writes(self) -> list[tuple[str, str, dict | None]]:
        return [e for e in self.log if e[0] in ("POST", "PUT", "DELETE") and "login" not in e[1]]


@pytest.fixture
def make_session(settings, tmp_path):
    @contextlib.asynccontextmanager
    async def opener(net: FakePortForwards, *, writes: bool = True, entities: frozenset[str] = frozenset({"port_forward"})):
        s = dataclasses.replace(settings, enable_writes=writes, write_entities=entities, journal_dir=tmp_path / "journal")
        mcp, api = create_server(s, transport=httpx.MockTransport(net))
        try:
            async with Client(mcp) as client:
                yield Wrapped(client)
        finally:
            await api.client.aclose()

    return opener


class Wrapped:
    """The tools take a single `params` object; tests pass the fields directly."""

    def __init__(self, client) -> None:
        self.client = client

    async def call_tool(self, name, args):
        return await self.client.call_tool(name, {"params": args})


async def call(client, args):
    res = await client.call_tool(TOOL, args)
    assert not res.is_error, res
    return json.loads(res.content[0].text)


NEW = {"action": "create", "name": "zz-test", "dst_port": "58699", "fwd": "192.0.2.15"}


def journal(tmp_path):
    lines = []
    for f in sorted((tmp_path / "journal").glob("*.jsonl")):
        lines += [json.loads(x) for x in f.read_text().splitlines()]
    return lines


async def test_preview_sends_nothing_and_creates_disabled(make_session):
    net = FakePortForwards()
    async with make_session(net) as c:
        out = await call(c, NEW)
    assert net.writes() == []
    assert out["preview"] and out["applied"] is False
    assert out["after"]["enabled"] is False and out["after"]["fwd_port"] == "58699"
    assert out["request"]["body_style"] == "changed fields only"
    assert out["apply_blocked_reason"] is None and out["fingerprint"]


async def test_preview_works_when_writes_disabled_and_says_why(make_session):
    net = FakePortForwards()
    async with make_session(net, writes=False) as c:
        out = await call(c, NEW)
    assert "UNIFI_CONSOLE_ENABLE_WRITES" in out["apply_blocked_reason"]
    assert net.writes() == []


async def test_apply_refused_when_writes_disabled_or_entity_not_listed(make_session):
    for kwargs, needle in (({"writes": False}, "ENABLE_WRITES"), ({"entities": frozenset()}, "UNIFI_CONSOLE_WRITE_ENTITIES")):
        net = FakePortForwards()
        async with make_session(net, **kwargs) as c:
            fp = (await call(c, NEW))["fingerprint"]
            res = await c.call_tool(TOOL, {**NEW, "confirm": True, "fingerprint": fp})
        assert needle in json.loads(res.content[0].text)["error"]
        assert net.writes() == []


async def test_confirm_needs_the_preview_fingerprint(make_session):
    net = FakePortForwards()
    async with make_session(net) as c:
        missing = json.loads((await c.call_tool(TOOL, {**NEW, "confirm": True})).content[0].text)
        wrong = json.loads((await c.call_tool(TOOL, {**NEW, "confirm": True, "fingerprint": "deadbeef"})).content[0].text)
        changed = json.loads((await c.call_tool(TOOL, {**NEW, "dst_port": "58698", "confirm": True,
                                                      "fingerprint": (await call(c, NEW))["fingerprint"]})).content[0].text)
    assert "fingerprint" in missing["error"] and "differs" in wrong["error"] and "differs" in changed["error"]
    assert net.writes() == []


async def test_create_apply_verifies_journals_and_gives_rollback(make_session, tmp_path):
    net = FakePortForwards()
    async with make_session(net) as c:
        fp = (await call(c, NEW))["fingerprint"]
        out = await call(c, {**NEW, "confirm": True, "fingerprint": fp})
    assert out["applied"] and out["verified"] is True
    assert out["rollback"] == {"action": "delete", "target": out["id"]}
    (created,) = net.items.values()
    assert created["enabled"] is False and created["name"] == "zz-test" and created["log"] is True
    assert set(net.bodies[0]) == {"enabled", "name", "pfwd_interface", "destination_ip", "destination_ips", "dst_port",
                                  "fwd", "fwd_port", "proto", "src_limiting_enabled", "log"}   # the 11 verified keys
    events = [e["event"] for e in journal(tmp_path)]
    assert events == ["attempt", "result"]


async def test_stale_preview_is_refused(make_session):
    net = FakePortForwards(with_real=True)
    async with make_session(net) as c:
        args = {"action": "update", "target": "Plex", "name": "Plex2"}
        fp = (await call(c, args))["fingerprint"]
        net.items["real1"]["fwd"] = "10.88.1.99"           # someone changes it in the UI meanwhile
        res = json.loads((await c.call_tool(TOOL, {**args, "confirm": True, "fingerprint": fp})).content[0].text)
    assert "differs from the preview" in res["error"]
    assert net.writes() == []


async def test_update_sends_only_changed_fields_and_diffs_them(make_session):
    net = FakePortForwards(with_real=True)
    async with make_session(net) as c:
        args = {"action": "update", "target": "real1", "name": "Plex Media"}
        pre = await call(c, args)
        assert pre["diff"] == {"name": {"from": "Plex", "to": "Plex Media"}}
        out = await call(c, {**args, "confirm": True, "fingerprint": pre["fingerprint"]})
    assert net.bodies == [{"name": "Plex Media"}]
    assert out["verified"] and out["diff"] == {"name": {"from": "Plex", "to": "Plex Media"}}
    assert out["rollback"] == {"action": "update", "target": "real1", "changes": {"name": "Plex"}}
    assert net.items["real1"]["dst_port"] == "32400"           # untouched fields survive


async def test_enable_warns_about_exposure_and_overlap_is_an_error(make_session):
    net = FakePortForwards(with_real=True)
    async with make_session(net) as c:
        net.items["x"] = {**REAL, "_id": "x", "name": "zz-test", "enabled": False, "dst_port": "32400"}
        out = await call(c, {"action": "enable", "target": "x"})
        assert any("overlaps 'Plex'" in e for e in out["errors"])
        assert out["apply_blocked_reason"]
        net.items["x"]["dst_port"] = "58699"
        ok = await call(c, {"action": "enable", "target": "x"})
        assert ok["errors"] == []
        assert any("exposes tcp port 58699" in w for w in ok["warnings"])
        res = json.loads((await c.call_tool(TOOL, {"action": "enable", "target": "x", "confirm": True,
                                                  "fingerprint": ok["fingerprint"]})).content[0].text)
    assert res["verified"] and net.items["x"]["enabled"] is True


async def test_silent_failure_is_reported_not_retried(make_session):
    net = FakePortForwards(with_real=True)
    net.ignore_put = True
    async with make_session(net) as c:
        args = {"action": "update", "target": "real1", "name": "Plex Media"}
        fp = (await call(c, args))["fingerprint"]
        out = await call(c, {**args, "confirm": True, "fingerprint": fp})
    assert out["verified"] is False
    assert out["mismatches"] == [{"field": "name", "requested": "Plex Media", "stored": "Plex"}]
    assert sum(1 for m, _, _ in net.writes() if m == "PUT") == 1


async def test_console_error_inside_http_200_is_an_error(make_session, tmp_path):
    net = FakePortForwards()
    net.reject_post = True
    async with make_session(net) as c:
        fp = (await call(c, NEW))["fingerprint"]
        res = json.loads((await c.call_tool(TOOL, {**NEW, "confirm": True, "fingerprint": fp})).content[0].text)
    assert "api.err.Invalid" in res["error"]
    assert [e["event"] for e in journal(tmp_path)] == ["attempt", "failed"]


async def test_delete_and_its_rollback(make_session):
    net = FakePortForwards(with_real=True)
    async with make_session(net) as c:
        args = {"action": "delete", "target": "Plex"}
        pre = await call(c, args)
        assert pre["after"] is None
        out = await call(c, {**args, "confirm": True, "fingerprint": pre["fingerprint"]})
    assert out["verified"] and "real1" not in net.items
    assert out["rollback"]["action"] == "create" and out["rollback"]["changes"]["name"] == "Plex"
    assert "_id" not in out["rollback"]["changes"] and "site_id" not in out["rollback"]["changes"]


@pytest.mark.parametrize("args,needle", [
    ({**NEW, "dst_port": "0"}, "dst_port"),
    ({**NEW, "dst_port": "70000"}, "dst_port"),
    ({**NEW, "dst_port": "100-200", "fwd_port": "5000-5050"}, "different lengths"),
    ({**NEW, "fwd": "8.8.8.8"}, "private LAN address"),
    ({**NEW, "fwd": "not-an-ip"}, "IPv4 address"),
    ({**NEW, "name": "Plex"}, "already called"),
    ({**NEW, "name": " "}, "name is required"),
])
async def test_invalid_input_is_refused(make_session, args, needle):
    net = FakePortForwards(with_real=True)
    async with make_session(net) as c:
        out = await call(c, args)
        res = json.loads((await c.call_tool(TOOL, {**args, "confirm": True, "fingerprint": out["fingerprint"]})).content[0].text)
    assert any(needle in e for e in out["errors"]) and needle in res["error"]
    assert net.writes() == []


async def test_unknown_fields_and_misuse_are_rejected(make_session):
    net = FakePortForwards(with_real=True)
    async with make_session(net) as c:
        bad = await c.call_tool(TOOL, {**NEW, "destination_ip": "1.2.3.4"})
        assert bad.is_error
        no_target = json.loads((await c.call_tool(TOOL, {"action": "delete"})).content[0].text)
        assert "target" in no_target["error"]
        enabled_on_update = await call(c, {"action": "update", "target": "Plex", "enabled": False})
        assert "enable or disable action" in enabled_on_update["error"]
        unknown = json.loads((await c.call_tool(TOOL, {"action": "delete", "target": "nope"})).content[0].text)
        assert "No port forward" in unknown["error"]
    assert net.writes() == []


async def test_ambiguous_name_asks_for_the_id(make_session):
    net = FakePortForwards(with_real=True)
    net.items["dup"] = {**REAL, "_id": "dup"}
    async with make_session(net) as c:
        res = json.loads((await c.call_tool(TOOL, {"action": "delete", "target": "Plex"})).content[0].text)
    assert "2 port forwards are called 'Plex'" in res["error"]


async def test_journal_is_redacted_and_failure_to_journal_blocks_the_write(make_session, settings, tmp_path):
    from unifi_console_mcp.writes import WriteEngine

    net = FakePortForwards()
    # redaction: a secret-looking field never reaches the file
    mcp, api = create_server(dataclasses.replace(settings, enable_writes=True, journal_dir=tmp_path / "j"),
                             transport=httpx.MockTransport(net))
    try:
        WriteEngine(api)._journal({"event": "attempt", "before": {"name": "a", "x_password": "hunter2"}})
    finally:
        await api.client.aclose()
    text = next((tmp_path / "j").glob("*.jsonl")).read_text()
    assert "hunter2" not in text and "[redacted]" in text

    # a journal that cannot be written stops the write before anything is sent
    blocker = tmp_path / "file-not-dir"
    blocker.write_text("x")
    s = dataclasses.replace(settings, enable_writes=True, write_entities=frozenset({"port_forward"}), journal_dir=blocker / "j")
    mcp, api = create_server(s, transport=httpx.MockTransport(net))
    try:
        async with Client(mcp) as raw:
            c = Wrapped(raw)
            fp = (await call(c, NEW))["fingerprint"]
            res = json.loads((await c.call_tool(TOOL, {**NEW, "confirm": True, "fingerprint": fp})).content[0].text)
    finally:
        await api.client.aclose()
    assert "Cannot write the change journal" in res["error"] and net.writes() == []


async def test_tier_c_needs_an_approval_note(settings, tmp_path):
    from unifi_console_mcp.writes import EntitySpec, WriteEngine

    mcp, api = create_server(dataclasses.replace(settings, enable_writes=True, write_entities=frozenset({"firewall_policy"})))
    try:
        eng = WriteEngine(api)
        spec = EntitySpec(key="firewall_policy", label="firewall policy", tier="C", list_op="listPortForwards")
        assert "approval_note" in eng.blocked_reason(spec, None)
        assert "approval_note" in eng.blocked_reason(spec, "  ")
        assert eng.blocked_reason(spec, "plan 2026-10-18 approved in chat") is None
    finally:
        await api.client.aclose()


async def test_generic_tool_still_refuses_and_points_to_the_typed_tool(settings):
    net = FakePortForwards()
    mcp, api = create_server(dataclasses.replace(settings, enable_writes=True, write_entities=frozenset({"port_forward"})),
                             transport=httpx.MockTransport(net))
    try:
        async with Client(mcp) as c:
            res = await c.call_tool("unifi_console_call_operation", {"params": {
                "operation_id": "createPortForward", "body": {"name": "x"}, "confirm": True}})
            text = json.loads(res.content[0].text)["error"]
    finally:
        await api.client.aclose()
    assert "unifi_console_port_forward" in text and net.writes() == []
