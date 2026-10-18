"""Client commands (block, unblock, reconnect, forget) through the shared gates, with read-back."""
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
TOOL = "unifi_console_client_command"
HUB = "02:00:00:00:00:23"
ECHO = "02:00:00:00:00:42"
OLD = "02:00:00:00:00:44"
AP = "02:00:00:00:00:45"


class FakeStamgr:
    def __init__(self) -> None:
        self.known = {m: {"_id": m, "mac": m, "name": n, "blocked": False, "use_fixedip": False}
                      for m, n in ((HUB, "Harmony Hub"), (ECHO, "Amazon Echo"), (OLD, "Old phone"))}
        self.known[ECHO].update(use_fixedip=True, fixed_ip="10.88.1.44")
        self.active = [{"mac": HUB, "name": "Harmony Hub", "is_wired": False}, {"mac": ECHO, "name": "Amazon Echo", "is_wired": True}]
        self.devices = [{"mac": AP, "name": "AP"}]
        self.ignore = False
        self.sent: list[dict] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        if path == "/api/auth/login":
            return httpx.Response(200, json={}, headers={"set-cookie": f"TOKEN={make_jwt()}; Path=/", "x-csrf-token": "c"})
        wrap = lambda x: {"meta": {"rc": "ok"}, "data": x}  # noqa: E731
        if path == BASE + "/rest/user":
            return httpx.Response(200, json=wrap(list(self.known.values())))
        if path == BASE + "/stat/sta":
            return httpx.Response(200, json=wrap(self.active))
        if path == BASE + "/stat/device-basic":
            return httpx.Response(200, json=wrap(self.devices))
        if path == BASE + "/cmd/stamgr" and method == "POST":
            body = json.loads(request.content)
            self.sent.append(body)
            mac, cmd = body["macs"][0], body["cmd"]
            if not self.ignore:
                if cmd == "block-sta":
                    self.known[mac]["blocked"] = True
                elif cmd == "unblock-sta":
                    self.known[mac]["blocked"] = False
                elif cmd == "forget-sta":
                    self.known.pop(mac, None)
            return httpx.Response(200, json=wrap([] if cmd == "kick-sta" else [self.known.get(mac, {})]))
        return httpx.Response(404, json={})


@pytest.fixture
def make_session(settings, tmp_path):
    @contextlib.asynccontextmanager
    async def opener(net: FakeStamgr, *, entities=frozenset({"client"}), writes=True):
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


async def test_block_sends_the_captured_body_verifies_and_rolls_back_with_unblock(make_session):
    net = FakeStamgr()
    async with make_session(net) as c:
        pre, out = await apply(c, {"command": "block", "target": ECHO.upper().replace(":", "-")})
    assert net.sent == [{"macs": [ECHO], "cmd": "block-sta"}]
    assert out["verified"] is True and out["rollback"] == {"command": "unblock", "target": ECHO}
    assert any("fixed IP" in w for w in pre["warnings"])


async def test_unblock_and_already_in_state_sends_nothing(make_session):
    net = FakeStamgr()
    async with make_session(net) as c:
        pre = await call(c, {"command": "unblock", "target": HUB})
        assert pre["note"].startswith("Not blocked")
        out = await call(c, {"command": "unblock", "target": HUB, "confirm": True, "fingerprint": pre["fingerprint"]})
    assert out["applied"] is False and net.sent == []


async def test_reconnect_needs_a_connected_wireless_client(make_session):
    net = FakeStamgr()
    async with make_session(net) as c:
        pre, out = await apply(c, {"command": "reconnect", "target": HUB})
        assert net.sent == [{"macs": [HUB], "cmd": "kick-sta"}] and out["verified"] is None and out["rollback"] is None
        wired = await call(c, {"command": "reconnect", "target": ECHO})
        offline = await call(c, {"command": "reconnect", "target": OLD})
    assert any("wired" in e for e in wired["errors"])
    assert any("not connected" in e for e in offline["errors"])


async def test_forget_needs_offline_and_the_history_acknowledgement(make_session):
    net = FakeStamgr()
    async with make_session(net) as c:
        busy = await call(c, {"command": "forget", "target": HUB})
        assert any("connected right now" in e for e in busy["errors"])
        pre = await call(c, {"command": "forget", "target": OLD})
        refused = await c.call_tool(TOOL, {"command": "forget", "target": OLD, "confirm": True, "fingerprint": pre["fingerprint"]})
        assert "discard_history" in refused.content[0].text and net.sent == []
        out = await call(c, {"command": "forget", "target": OLD, "confirm": True, "fingerprint": pre["fingerprint"], "discard_history": True})
    assert out["verified"] is True and out["rollback"] is None and OLD not in net.known


async def test_unifi_devices_and_unknown_macs_are_refused(make_session):
    net = FakeStamgr()
    async with make_session(net) as c:
        ap = await call(c, {"command": "block", "target": AP})
        unknown = await call(c, {"command": "block", "target": "aa:bb:cc:dd:ee:ff"})
        bad = await c.call_tool(TOOL, {"command": "block", "target": "nonsense"})
    assert any("UniFi device" in e for e in ap["errors"]) and any("no client" in e for e in unknown["errors"])
    assert "MAC address" in bad.content[0].text


async def test_gates_and_stale_fingerprint(make_session):
    net = FakeStamgr()
    async with make_session(net, writes=False) as c:
        pre = await call(c, {"command": "block", "target": HUB})
        assert "Writes are disabled" in pre["apply_blocked_reason"]
    async with make_session(net, entities=frozenset({"wifi"})) as c:
        pre = await call(c, {"command": "block", "target": HUB})
        assert "not enabled" in pre["apply_blocked_reason"]
    async with make_session(net) as c:
        pre = await call(c, {"command": "block", "target": HUB})
        net.known[HUB]["name"] = "Renamed"
        res = await c.call_tool(TOOL, {"command": "block", "target": HUB, "confirm": True, "fingerprint": pre["fingerprint"]})
    assert "differs from the preview" in res.content[0].text and net.sent == []


async def test_a_command_the_console_ignores_is_reported_unverified(make_session):
    net = FakeStamgr()
    net.ignore = True
    async with make_session(net) as c:
        pre, out = await apply(c, {"command": "block", "target": HUB})
    assert out["verified"] is False and "attention" in out
