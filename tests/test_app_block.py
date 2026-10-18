"""Application blocks (Simple App Blocking, v2 `firewall-app-blocks`): the whole set is replaced on every write."""
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
from test_writes import Wrapped
from unifi_console_mcp.entities.app_block import build_blocks, normalise_schedule
from unifi_console_mcp.client import UniFiError
from unifi_console_mcp.server import create_server

BASE = "/proxy/network/v2/api/site/default"
BLOCKS = BASE + "/firewall-app-blocks"
POLICIES = BASE + "/firewall-policies"
NETWORKS = "/proxy/network/api/s/default/rest/networkconf"
DEVICES = "/proxy/network/api/s/default/stat/device-basic"
TOOL = "unifi_console_app_block"
PRIVATE, GUEST = "5a1c0000-0000-4000-8000-000000000001", "5a1c0000-0000-4000-8000-000000000002"
NETS = [{"_id": PRIVATE, "name": "LAN_Private", "purpose": "corporate"}, {"_id": GUEST, "name": "LAN_Guest", "purpose": "guest"}]
MAC = "02:00:00:00:00:31"
AP_MAC = "02:00:00:00:00:32"
DAILY = {"mode": "EVERY_DAY", "time_range_start": "09:00", "time_range_end": "12:00"}


def make_block(ident="b1", name="Existing", *, mac=MAC, apps=(852009,), schedule=None):
    return {"_id": ident, "name": name, "type": "DEVICE", "target_type": "APP_ID", "app_ids": list(apps),
            "app_category_ids": [], "client_macs": [mac], "network_ids": [], "schedule": schedule or dict(DAILY)}


class FakeBlocks:
    def __init__(self, items=()) -> None:
        self.items = [copy.deepcopy(b) for b in items]
        self.log: list[tuple[str, str, object]] = []
        self.bodies: list[object] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        if path == "/api/auth/login":
            return httpx.Response(200, json={}, headers={"set-cookie": f"TOKEN={make_jwt()}; Path=/", "x-csrf-token": "c"})
        body = json.loads(request.content) if request.content else None
        self.log.append((method, path, body))
        if path == NETWORKS:
            return httpx.Response(200, json={"meta": {"rc": "ok"}, "data": NETS})
        if path == DEVICES:
            return httpx.Response(200, json={"meta": {"rc": "ok"}, "data": [{"mac": AP_MAC, "name": "AP"}]})
        if path == POLICIES:
            return httpx.Response(200, json=[{"origin_type": "simple_app_block", "origin_id": b["_id"]} for b in self.items])
        if path == BLOCKS and method == "GET":
            return httpx.Response(200, json=copy.deepcopy(self.items))
        if path == BLOCKS and method == "POST":
            assert isinstance(body, list), "the console wants the whole collection as an array"
            self.bodies.append(body)
            self.items = [{**b, "_id": b.get("_id") or uuid.uuid4().hex} for b in body]
            return httpx.Response(200, json=copy.deepcopy(self.items))
        return httpx.Response(404, json={})

    def writes(self):
        return [e for e in self.log if e[0] in ("POST", "PUT", "DELETE") and "login" not in e[1]]


@pytest.fixture
def make_session(settings, tmp_path):
    @contextlib.asynccontextmanager
    async def opener(net: FakeBlocks, *, entities=frozenset({"app_block"})):
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


async def apply(c, params):
    pre = await call(c, params)
    assert pre.get("ok") and not pre["errors"], pre
    out = await call(c, {**params, "confirm": True, "fingerprint": pre["fingerprint"]})
    assert out.get("ok") is not False and "verified" in out or out.get("applied") is False, out
    return pre, out


def create_op(**kw):
    base = {"op": "create", "name": "new", "clients": [MAC], "apps": [1114144], "schedule": {"mode": "ALWAYS"}}
    return {**base, **kw}


# ------------------------------------------------------------------------------------------ pure helpers
def test_schedule_shapes_match_the_capture():
    assert normalise_schedule({"mode": "ALWAYS"}) == {"mode": "ALWAYS"}
    assert normalise_schedule({"mode": "EVERY_DAY", "time_range_start": "09:00", "time_range_end": "12:00"}) == DAILY
    assert normalise_schedule({"mode": "EVERY_WEEK", "repeat_on_days": ["mon", "wed"], "time_range_start": "09:00", "time_range_end": "12:00"}) == {
        "mode": "EVERY_WEEK", "repeat_on_days": ["mon", "wed"], "time_all_day": False, "time_range_start": "09:00", "time_range_end": "12:00"}
    assert normalise_schedule({"mode": "ONE_TIME_ONLY", "date": "2026-10-27", "time_range_start": "09:00", "time_range_end": "12:00"}) == {
        "mode": "ONE_TIME_ONLY", "date": "2026-10-27", "time_range_start": "09:00", "time_range_end": "12:00"}
    assert normalise_schedule({"mode": "CUSTOM", "date_start": "2026-10-18", "date_end": "2026-10-18", "time_all_day": True, "repeat_on_days": ["sat"]}) == {
        "mode": "CUSTOM", "date_start": "2026-10-18", "date_end": "2026-10-18", "repeat_on_days": ["sat"], "time_all_day": True}


@pytest.mark.parametrize("bad", [
    {"mode": "EVERY_DAY"}, {"mode": "EVERY_WEEK", "time_range_start": "09:00", "time_range_end": "10:00"},
    {"mode": "EVERY_WEEK", "repeat_on_days": ["mon", "mon"], "time_all_day": True}, {"mode": "ONE_TIME_ONLY", "time_range_start": "09:00", "time_range_end": "10:00"},
    {"mode": "CUSTOM", "date_start": "2026-10-18", "repeat_on_days": ["sat"], "time_all_day": True}, {"mode": "SOMETIMES"},
])
def test_incomplete_schedules_are_refused(bad):
    with pytest.raises(UniFiError):
        normalise_schedule(bad)


def test_build_blocks_creates_updates_and_deletes_in_one_pass():
    live = [make_block("a", "A"), make_block("b", "B"), make_block("c", "C")]
    new = build_blocks(live, [create_op(name="D"), {"op": "update", "target": "A", "apps": [5]}, {"op": "delete", "target": "c"}], NETS)
    assert [b["name"] for b in new] == ["A", "B", "D"]
    assert new[0]["_id"] == "a" and new[0]["app_ids"] == [5] and new[2].get("_id") is None
    assert new[2] == {"name": "D", "app_ids": [1114144], "client_macs": [MAC], "network_ids": [], "type": "DEVICE", "target_type": "APP_ID",
                      "app_category_ids": [], "schedule": {"mode": "ALWAYS"}}
    assert live[0]["app_ids"] == [852009], "the live copy is not modified"


def test_switching_to_categories_clears_the_stale_application_list():
    new = build_blocks([make_block("a", "A")], [{"op": "update", "target": "a", "categories": [6]}], NETS)
    assert new[0]["target_type"] == "APP_CATEGORY" and new[0]["app_category_ids"] == [6] and new[0]["app_ids"] == []


def test_switching_to_a_network_clears_client_macs_and_resolves_names():
    new = build_blocks([make_block("a", "A")], [{"op": "update", "target": "a", "networks": ["LAN_Guest"]}], NETS)
    assert new[0]["type"] == "NETWORK" and new[0]["network_ids"] == [GUEST] and new[0]["client_macs"] == []


@pytest.mark.parametrize("op, text", [
    (create_op(clients=None), "exactly one of clients"), (create_op(apps=None), "exactly one of apps"),
    (create_op(schedule=None), "explicit schedule"), (create_op(name=None), "needs a name"),
    ({"op": "delete", "target": "nope"}, "No application block"), ({"op": "update", "target": "A", "clients": ["zz"]}, "not a MAC"),
    ({"op": "update", "target": "A", "networks": ["Nowhere"]}, "match 'Nowhere'"), ({"op": "update", "target": "A", "applies_to": "networks"}, "needs networks"),
])
def test_bad_changes_say_which_one_and_why(op, text):
    with pytest.raises(UniFiError, match=text):
        build_blocks([make_block("a", "A")], [op], NETS)


# ------------------------------------------------------------------------------------------ through the tool
async def test_create_sends_the_complete_array_and_verifies(make_session):
    net = FakeBlocks([make_block("a", "A")])
    async with make_session(net) as c:
        pre, out = await apply(c, {"changes": [create_op(name="B", schedule=DAILY)]})
    assert pre["request"]["method"] == "POST" and pre["request"]["path"] == BLOCKS
    assert len(net.bodies) == 1 and [b["name"] for b in net.bodies[0]] == ["A", "B"]
    assert net.bodies[0][0]["_id"] == "a" and "_id" not in net.bodies[0][1]
    assert out["applied"] and out["verified"] is True and out["summary"] == {"create": ["B"], "update": [], "delete": []}
    assert out["generated_policies"] == {"checked": True, "blocks": 2, "with_generated_policy": 2, "missing": []}
    assert out["rollback"]["replace_all"] == [make_block("a", "A")]


async def test_several_changes_are_one_request(make_session):
    net = FakeBlocks([make_block("a", "A"), make_block("b", "B")])
    async with make_session(net) as c:
        _, out = await apply(c, {"changes": [create_op(name="C"), {"op": "update", "target": "A", "apps": [9]}, {"op": "delete", "target": "B"}]})
    assert len(net.writes()) == 1 and out["verified"] is True
    assert out["summary"] == {"create": ["C"], "update": ["A"], "delete": ["B"]}


async def test_preview_sends_nothing_and_flags_removals(make_session):
    net = FakeBlocks([make_block("a", "A"), make_block("b", "B")])
    async with make_session(net) as c:
        pre = await call(c, {"changes": [{"op": "delete", "target": "A"}]})
    assert net.writes() == [] and pre["preview"] and any("will be deleted" in w and "'A'" in w for w in pre["warnings"])
    assert set(pre["diff"]) == {"A"}


async def test_delete_all_with_replace_all_sends_an_empty_array(make_session):
    net = FakeBlocks([make_block("a", "A")])
    async with make_session(net) as c:
        pre, out = await apply(c, {"replace_all": []})
    assert net.bodies == [[]] and out["verified"] is True and any("NO application blocks" in w for w in pre["warnings"])


async def test_rollback_restores_the_previous_set_and_deleted_blocks_return_without_old_ids(make_session):
    net = FakeBlocks([make_block("a", "A"), make_block("b", "B")])
    async with make_session(net) as c:
        _, out = await apply(c, {"changes": [{"op": "delete", "target": "B"}]})
        assert [b["name"] for b in net.items] == ["A"]
        _, back = await apply(c, out["rollback"])
    assert [b["name"] for b in net.items] == ["A", "B"] and net.items[0]["_id"] == "a" and net.items[1]["_id"] != "b"
    assert back["verified"] is True


async def test_a_stale_preview_is_refused_when_another_block_changed(make_session):
    net = FakeBlocks([make_block("a", "A"), make_block("b", "B")])
    async with make_session(net) as c:
        pre = await call(c, {"changes": [create_op(name="C")]})
        net.items[1]["apps"] = None
        net.items[1]["app_ids"] = [1]
        res = await c.call_tool(TOOL, {"changes": [create_op(name="C")], "confirm": True, "fingerprint": pre["fingerprint"]})
    assert "differs from the preview" in res.content[0].text and net.writes() == []


async def test_no_change_sends_nothing(make_session):
    net = FakeBlocks([make_block("a", "A")])
    async with make_session(net) as c:
        pre, out = await apply(c, {"changes": [{"op": "update", "target": "A", "apps": [852009]}]})
    assert out["applied"] is False and net.writes() == []


@pytest.mark.parametrize("op, text", [
    (create_op(name="A"), "Two blocks are called"),
    (create_op(clients=[AP_MAC]), "UniFi device"),
    (create_op(clients=None, networks=["LAN_Guest"], apps=None, categories=[8]), None),
    (create_op(apps=[0]), "positive whole numbers"),
    (create_op(schedule={"mode": "ONE_TIME_ONLY", "date": "2026-13-40", "time_range_start": "09:00", "time_range_end": "10:00"}), "not a date"),
    (create_op(schedule={"mode": "EVERY_DAY", "time_range_start": "9am", "time_range_end": "10:00"}), "HH:MM"),
])
async def test_validation(make_session, op, text):
    net = FakeBlocks([make_block("a", "A")])
    async with make_session(net) as c:
        pre = await call(c, {"changes": [op]})
    if text is None:
        assert pre["errors"] == [], pre
    else:
        assert any(text in e for e in pre["errors"]), pre
    assert net.writes() == []


async def test_blocking_the_whole_private_network_needs_approval_note(make_session):
    net = FakeBlocks()
    op = create_op(clients=None, networks=["LAN_Private"], apps=None, categories=[8])
    async with make_session(net) as c:
        res = await c.call_tool(TOOL, {"changes": [op]})
        assert "approval_note" in res.content[0].text and net.writes() == []
        pre, out = await apply(c, {"changes": [op], "approval_note": "plan 2026-10-18"})
    assert out["verified"] is True and net.bodies[0][0]["network_ids"] == [PRIVATE]


async def test_gates_still_apply(make_session):
    net = FakeBlocks()
    async with make_session(net, entities=frozenset()) as c:
        pre = await call(c, {"changes": [create_op()]})
        assert "UNIFI_CONSOLE_WRITE_ENTITIES" in pre["apply_blocked_reason"]
        res = await c.call_tool(TOOL, {"changes": [create_op()], "confirm": True, "fingerprint": pre["fingerprint"]})
    assert "not enabled for writes" in res.content[0].text and net.writes() == []


async def test_changes_and_replace_all_are_exclusive(make_session):
    async with make_session(FakeBlocks()) as c:
        a = json.loads((await c.call_tool(TOOL, {})).content[0].text)
        b = json.loads((await c.call_tool(TOOL, {"changes": [create_op()], "replace_all": []})).content[0].text)
    assert a["ok"] is False and b["ok"] is False


async def test_a_console_that_stores_something_else_is_reported(make_session):
    class Lossy(FakeBlocks):
        def __call__(self, request):
            resp = super().__call__(request)
            if request.method == "POST" and request.url.path == BLOCKS:
                self.items = [{**b, "app_ids": []} for b in self.items]
            return resp
    net = Lossy()
    async with make_session(net) as c:
        _, out = await apply(c, {"changes": [create_op()]})
    assert out["verified"] is False and out["mismatches"] and "attention" in out
