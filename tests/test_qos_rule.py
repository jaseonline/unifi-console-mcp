"""QoS rules (dashboard widget, v2 `qos-rules`): create/update with the whole rule, batch delete, narrow scope."""
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
from unifi_console_mcp.server import create_server

BASE = "/proxy/network/v2/api/site/default"
RULES = BASE + "/qos-rules"
NETWORKS = "/proxy/network/api/s/default/rest/networkconf"
TOOL = "unifi_console_qos_rule"
WAN_ID = "85425c54-aa12-44a8-998e-e00820f48ff9"
NETS = [
    {"_id": "98fba899-f53a-4e3d-b257-5b8e2e594189", "name": "LAN_IoT", "purpose": "corporate"},
    {"_id": WAN_ID, "name": "WAN1", "purpose": "wan"},
]
MAC = "02:00:00:00:00:49"
APPS = [393220, 393245]


def make_rule(ident="r1", name="Existing", *, enabled=False, objective="PRIORITIZE", mac=MAC):
    rule = {"_id": ident, "index": 10001, "enabled": enabled, "name": name, "wan_or_vpn_network": WAN_ID,
            "source": {"matching_target": "CLIENT", "client_macs": [mac]},
            "destination": {"matching_target": "APP", "port_matching_type": "ANY", "app_ids": list(APPS)},
            "schedule": {"mode": "ALWAYS"}, "objective": objective, "download_burst": "OFF", "upload_burst": "OFF"}
    if objective == "LIMIT":
        rule.update(download_limit_kbps=10000, upload_limit_kbps=10000)
    return rule


class FakeQos:
    def __init__(self, items=()) -> None:
        self.items = {r["_id"]: copy.deepcopy(r) for r in items}
        self.log: list[tuple[str, str, object]] = []
        self.bodies: list[object] = []
        self.next_index = 10002

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        if path == "/api/auth/login":
            return httpx.Response(200, json={}, headers={"set-cookie": f"TOKEN={make_jwt()}; Path=/", "x-csrf-token": "c"})
        body = json.loads(request.content) if request.content else None
        self.log.append((method, path, body))
        if path == NETWORKS:
            return httpx.Response(200, json={"meta": {"rc": "ok"}, "data": NETS})
        if path == RULES and method == "GET":
            return httpx.Response(200, json=list(self.items.values()))
        if path == RULES and method == "POST":
            self.bodies.append(body)
            new = {**body, "_id": uuid.uuid4().hex, "index": self.next_index}
            self.next_index += 1
            self.items[new["_id"]] = new
            return httpx.Response(201, json=new)
        if path == RULES + "/batch-delete" and method == "POST":
            self.bodies.append(body)
            for i in body:
                self.items.pop(i, None)
            return httpx.Response(204)
        if path.startswith(RULES + "/") and method == "PUT":
            ident = path.rsplit("/", 1)[1]
            if "_id" not in body or "index" not in body:                     # the real console wants the whole rule
                return httpx.Response(400, json={"message": "Validation failed"})
            self.bodies.append(body)
            self.items[ident] = body
            return httpx.Response(200, json=body)
        return httpx.Response(404, json={})

    def writes(self):
        return [e for e in self.log if e[0] in ("POST", "PUT", "DELETE") and "login" not in e[1]]


@pytest.fixture
def make_session(settings, tmp_path):
    @contextlib.asynccontextmanager
    async def opener(net: FakeQos, *, entities=frozenset({"qos_rule"})):
        s = dataclasses.replace(settings, enable_writes=True, write_entities=entities, journal_dir=tmp_path / "journal")
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


async def apply(c, args):
    pre = await call(c, args)
    assert pre.get("ok") and not pre["errors"], pre
    return pre, await call(c, {**args, "confirm": True, "fingerprint": pre["fingerprint"]})


NEW = {"action": "create", "name": "zz-rule", "wan_network": "WAN1", "source_clients": [MAC], "destination_apps": APPS}


async def test_create_prioritize_matches_the_capture_and_starts_off(make_session):
    net = FakeQos()
    async with make_session(net) as c:
        pre, out = await apply(c, {**NEW, "objective": "PRIORITIZE"})
    body = net.bodies[0]
    assert body == {"enabled": False, "name": "zz-rule", "wan_or_vpn_network": WAN_ID,
                    "source": {"matching_target": "CLIENT", "client_macs": [MAC]},
                    "destination": {"matching_target": "APP", "port_matching_type": "ANY", "app_ids": APPS},
                    "schedule": {"mode": "ALWAYS"}, "objective": "PRIORITIZE", "download_burst": "OFF", "upload_burst": "OFF"}
    assert pre["request"]["method"] == "POST" and out["http_status"] == 201 and out["verified"] is True
    assert out["rollback"] == {"action": "delete", "target": out["id"]}


async def test_create_limit_sends_flat_kbps_fields(make_session):
    net = FakeQos()
    async with make_session(net) as c:
        _, out = await apply(c, {**NEW, "download_limit": 20000, "upload_limit": 5000, "download_burst": "LONG"})
    b = net.bodies[0]
    assert b["objective"] == "LIMIT" and b["download_limit_kbps"] == 20000 and b["upload_limit_kbps"] == 5000
    assert b["download_burst"] == "LONG" and b["upload_burst"] == "OFF" and out["verified"]


async def test_update_sends_the_whole_rule_with_id_and_index_and_switches_objective(make_session):
    net = FakeQos([make_rule()])
    async with make_session(net) as c:
        _, out = await apply(c, {"action": "update", "target": "Existing", "objective": "LIMIT", "download_burst": "LONG", "upload_burst": "LONG"})
    b = net.bodies[0]
    assert b["_id"] == "r1" and b["index"] == 10001 and b["objective"] == "LIMIT"
    assert b["download_limit_kbps"] == 10000 and b["upload_limit_kbps"] == 10000 and b["download_burst"] == "LONG"
    assert out["verified"]
    # and back to PRIORITIZE drops the limits (the capture carries none)
    async with make_session(net) as c:
        _, back = await apply(c, {"action": "update", "target": "r1", "objective": "PRIORITIZE"})
    assert "download_limit_kbps" not in net.bodies[-1] and net.bodies[-1]["download_burst"] == "OFF" and back["verified"]


async def test_enable_and_disable(make_session):
    net = FakeQos([make_rule()])
    async with make_session(net) as c:
        pre, out = await apply(c, {"action": "enable", "target": "r1"})
        assert net.items["r1"]["enabled"] is True and any("prioritises" in w for w in pre["warnings"]) and out["verified"]
        await apply(c, {"action": "disable", "target": "r1"})
    assert net.items["r1"]["enabled"] is False


async def test_delete_uses_batch_delete_and_the_rollback_recreates_it(make_session):
    start = make_rule(enabled=True, objective="LIMIT")
    net = FakeQos([start])
    async with make_session(net) as c:
        pre, out = await apply(c, {"action": "delete", "target": "Existing"})
        assert net.writes()[-1][1] == RULES + "/batch-delete" and net.bodies[-1] == ["r1"] and "r1" not in net.items
        assert out["http_status"] == 204 and any("Deleting this rule" in w for w in pre["warnings"])
        rb = out["rollback"]
        assert rb["action"] == "create" and "_id" not in rb["changes"] and "index" not in rb["changes"]
        _, back = await apply(c, {"action": "create", **rb["changes"]})
    assert back["verified"] is True
    created = net.bodies[-1]
    assert {k: v for k, v in created.items()} == {k: v for k, v in start.items() if k not in ("_id", "index")}


@pytest.mark.parametrize("args,needle", [
    ({"source_clients": ["nope"]}, "not a MAC"),
    ({"destination_apps": [-5]}, "positive application ids"),
    ({"objective": "LIMIT"}, None),
    ({"name": "existing"}, "already called"),
    ({"schedule": {"mode": "EVERY_DAY"}}, "ALWAYS"),
    ({"objective": "PRIORITIZE", "download_limit": 100}, "no limits"),
    ({"objective": "LIMIT", "download_limit": 0, "upload_limit": 0}, "needs download_limit"),
    ({"source_clients": None, "source": {"matching_target": "NETWORK"}}, "has not been captured"),
])
async def test_bad_rules_are_refused(make_session, args, needle):
    net = FakeQos([make_rule(name="Existing")])
    async with make_session(net) as c:
        text = await raw(c, {k: v for k, v in {**NEW, **args}.items() if v is not None})
    if needle is None:           # LIMIT with default limits is fine
        assert '"errors":[]' in text
        return
    assert needle in text and net.writes() == []


async def test_non_wan_link_is_refused(make_session):
    net = FakeQos()
    async with make_session(net) as c:
        text = await raw(c, {**NEW, "wan_network": "LAN_IoT"})
    assert "not a WAN or VPN" in text and net.writes() == []


async def test_rule_with_unsupported_source_can_be_renamed_but_not_edited(make_session):
    odd = make_rule()
    odd["source"] = {"matching_target": "NETWORK", "network_ids": ["x"], "port_matching_type": "ANY"}
    net = FakeQos([odd])
    async with make_session(net) as c:
        pre, out = await apply(c, {"action": "update", "target": "r1", "name": "Renamed"})
    assert net.bodies[0]["source"] == odd["source"] and out["verified"] and any("left untouched" in w for w in pre["warnings"])


async def test_stale_preview_and_entity_switch(make_session):
    net = FakeQos([make_rule()])
    async with make_session(net) as c:
        pre = await call(c, {"action": "update", "target": "r1", "name": "Renamed"})
        net.items["r1"]["name"] = "Changed elsewhere"
        res = await raw(c, {"action": "update", "target": "r1", "name": "Renamed", "confirm": True, "fingerprint": pre["fingerprint"]})
    assert "differs from the preview" in res and net.writes() == []
    async with make_session(FakeQos(), entities=frozenset({"port_forward"})) as c:
        pre = await call(c, NEW)
        res = await raw(c, {**NEW, "confirm": True, "fingerprint": pre["fingerprint"]})
    assert "not enabled for writes" in res


@pytest.mark.parametrize("op,args", [
    ("createQosRule", {}),
    ("updateQosRule", {"path_params": {"id": "r1"}}),
    ("batchDeleteQosRules", {}),
])
async def test_the_generic_tool_refuses_and_names_the_typed_one(settings, tmp_path, op, args):
    net = FakeQos([make_rule()])
    mcp, api = create_server(dataclasses.replace(settings, enable_writes=True, write_entities=frozenset({"qos_rule"}),
                                                 journal_dir=tmp_path / "journal"), transport=httpx.MockTransport(net))
    try:
        async with Client(mcp) as c:
            res = await c.call_tool("unifi_console_call_operation", {"params": {"operation_id": op, "confirm": True, **args}})
            text = json.loads(res.content[0].text)["error"]
    finally:
        await api.client.aclose()
    assert "unifi_console_qos_rule" in text and net.writes() == []
