"""Client groups through the write framework: whole-object v2 updates, MAC handling, the reference check."""
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

BASE = "/proxy/network/v2/api/site/default"
GROUPS = BASE + "/network-members-groups"
GROUP = BASE + "/network-members-group"
POLICIES = BASE + "/firewall-policies"
OBJECTS = BASE + "/object-oriented-network-configs"
USER = "/proxy/network/api/s/default/rest/user"
TOOL = "unifi_console_client_group"
M1, M2, M3 = "02:00:00:00:00:46", "02:00:00:00:00:47", "02:00:00:00:00:48"
SONOS = {"id": "eddc3108-ddf4-4fa6-93ce-9b0efcf82f90", "name": "Sonos", "type": "CLIENTS", "members": [M1, M2, M3]}
CAMS = {"id": "cams-id", "name": "Cameras", "type": "CLIENTS", "members": ["aa:aa:aa:aa:aa:10"]}


class FakeGroups:
    def __init__(self, items=(SONOS, CAMS)) -> None:
        self.items = {r["id"]: json.loads(json.dumps(r)) for r in items}
        self.clients = [{"mac": M1, "name": "Sonos Port"}, {"mac": M2, "name": "Sonos Beam"}, {"mac": "aa:aa:aa:aa:aa:20", "name": "Hub"}]
        self.policies: list[dict] = []
        self.objects: list[dict] = []
        self.policy_status = 200
        self.ignore_put = False
        self.log: list[tuple[str, str, dict | None]] = []
        self.bodies: list[dict] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        if path == "/api/auth/login":
            return httpx.Response(200, json={}, headers={"set-cookie": f"TOKEN={make_jwt()}; Path=/", "x-csrf-token": "c"})
        body = json.loads(request.content) if request.content else None
        self.log.append((method, path, body))
        if path == USER:
            return httpx.Response(200, json={"meta": {"rc": "ok"}, "data": self.clients})
        if path == POLICIES:
            return httpx.Response(self.policy_status, json=self.policies)
        if path == OBJECTS:
            return httpx.Response(200, json=self.objects)
        if path == GROUPS and method == "GET":
            return httpx.Response(200, json=list(self.items.values()))
        if path == GROUP and method == "POST":
            self.bodies.append(body)
            new = {**body, "id": uuid.uuid4().hex}
            self.items[new["id"]] = new
            return httpx.Response(201, json=new)
        if path.startswith(GROUP + "/"):
            ident = path.rsplit("/", 1)[1]
            if method == "PUT":
                if not {"id", "name", "members", "type"} <= set(body):          # the real console rejects a partial body
                    return httpx.Response(400, json={"errorCode": 400, "message": "Validation failed"})
                self.bodies.append(body)
                if not self.ignore_put:
                    self.items[ident] = {**self.items[ident], **body}
                return httpx.Response(204)
            if method == "DELETE":
                self.items.pop(ident, None)
                return httpx.Response(204)
        return httpx.Response(404, json={})

    def writes(self):
        return [e for e in self.log if e[0] in ("POST", "PUT", "DELETE") and "login" not in e[1]]


@pytest.fixture
def make_session(settings, tmp_path):
    @contextlib.asynccontextmanager
    async def opener(net: FakeGroups, *, entities=frozenset({"client_group"})):
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


NEW = {"action": "create", "name": "zz-group", "members": ["AA-BB-CC-DD-EE-01", "aabbccddee02"]}


async def test_create_sends_what_the_ui_sends_and_normalises_macs(make_session):
    net = FakeGroups()
    async with make_session(net) as c:
        pre, out = await apply(c, NEW)
    assert pre["request"]["method"] == "POST"
    assert net.bodies == [{"type": "CLIENTS", "name": "zz-group", "members": ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"]}]
    assert out["verified"] and out["http_status"] == 201 and out["rollback"] == {"action": "delete", "target": out["id"]}


async def test_update_sends_the_whole_group_with_its_id(make_session):
    net = FakeGroups()
    async with make_session(net) as c:
        pre, out = await apply(c, {"action": "update", "target": "Sonos", "name": "Sonos speakers"})
    assert pre["request"]["body_style"] == "whole object"
    assert net.bodies == [{**SONOS, "name": "Sonos speakers"}]
    assert out["verified"] and list(out["diff"]) == ["name"] and out["rollback"]["changes"] == {"name": "Sonos"}


async def test_add_and_remove_members_replace_the_array_whole(make_session):
    net = FakeGroups()
    async with make_session(net) as c:
        pre, out = await apply(c, {"action": "update", "target": SONOS["id"], "add_members": ["AA:AA:AA:AA:AA:20", M1.upper()],
                                   "remove_members": [M2]})
    assert net.bodies[0]["members"] == [M1, M3, "aa:aa:aa:aa:aa:20"]
    assert out["verified"] and out["rollback"]["changes"] == {"members": [M1, M2, M3]}
    assert pre["warnings"] == []                                     # the added MAC is a known client


async def test_deleting_the_unused_group_works_and_rollback_recreates(make_session):
    net = FakeGroups()
    async with make_session(net) as c:
        pre, out = await apply(c, {"action": "delete", "target": "cams-id"})
    assert out["verified"] and "cams-id" not in net.items and "Sonos" in [r["name"] for r in net.items.values()]
    assert out["rollback"]["action"] == "create"
    assert out["rollback"]["changes"] == {"name": "Cameras", "type": "CLIENTS", "members": ["aa:aa:aa:aa:aa:10"]}


async def test_the_recorded_rollback_can_be_replayed(make_session):
    net = FakeGroups()
    async with make_session(net) as c:
        _, gone = await apply(c, {"action": "delete", "target": "cams-id"})
        rb = gone["rollback"]
        _, back = await apply(c, {"action": rb["action"], **rb["changes"]})
    assert back["verified"] and [r["name"] for r in net.items.values()].count("Cameras") == 1


async def test_a_group_a_policy_uses_cannot_be_deleted_and_editing_it_warns(make_session):
    net = FakeGroups()
    net.policies = [{"_id": "p1", "name": "Sonos allow", "source": {"client_macs": [], "group_id": SONOS["id"]}}]
    async with make_session(net) as c:
        gone = await call(c, {"action": "delete", "target": "Sonos"})
        edit = await call(c, {"action": "update", "target": "Sonos", "remove_members": [M3]})
        res = await c.call_tool(TOOL, {"action": "delete", "target": "Sonos", "confirm": True, "fingerprint": gone["fingerprint"]})
    assert gone["used_by"] == ["firewall policy: Sonos allow"] and "still used" in " ".join(gone["errors"])
    assert "takes effect for them" in " ".join(edit["warnings"]) and not edit["errors"]
    assert "Refused" in res.content[0].text and net.writes() == []


async def test_a_traffic_object_reference_is_found_too(make_session):
    net = FakeGroups()
    net.objects = [{"_id": "o1", "name": "Kids QoS", "targets": [{"type": "CLIENT_GROUP", "value": "cams-id"}]}]
    async with make_session(net) as c:
        gone = await call(c, {"action": "delete", "target": "cams-id"})
    assert gone["used_by"] == ["traffic object: Kids QoS"]


async def test_a_failed_reference_read_blocks_everything(make_session):
    net = FakeGroups()
    net.policy_status = 500
    async with make_session(net) as c:
        res = await c.call_tool(TOOL, {"action": "delete", "target": "cams-id"})
        res2 = await c.call_tool(TOOL, {"action": "update", "target": "cams-id", "name": "Cams"})
    assert "Nothing was changed" in res.content[0].text and "Nothing was changed" in res2.content[0].text
    assert net.writes() == []


@pytest.mark.parametrize("args,needle", [
    ({"name": "sonos"}, "already called"),
    ({"name": ""}, "create needs name and members"),
    ({"members": ["not-a-mac"]}, "Not a MAC address"),
    ({"members": ["aa:bb:cc:dd:ee:01", "AA-BB-CC-DD-EE-01"]}, "Duplicate members"),
    ({"members": []}, "create needs name and members"),
])
async def test_bad_groups_are_refused(make_session, args, needle):
    net = FakeGroups()
    base = {**NEW, **args}
    async with make_session(net) as c:
        res = await c.call_tool(TOOL, base)
        if res.is_error or "error" in res.content[0].text[:20].lower():          # create validation in the tool itself
            assert needle in res.content[0].text
            assert net.writes() == []
            return
        pre = json.loads(res.content[0].text)
        assert needle in " ".join(pre["errors"]), pre
        res = await c.call_tool(TOOL, {**base, "confirm": True, "fingerprint": pre["fingerprint"]})
    assert "Refused" in res.content[0].text and net.writes() == []


async def test_unknown_macs_are_allowed_with_a_warning(make_session):
    async with make_session(FakeGroups()) as c:
        pre = await call(c, NEW)
    assert not pre["errors"] and "not clients this console has seen" in " ".join(pre["warnings"])


async def test_removing_a_member_that_is_not_there_is_refused(make_session):
    async with make_session(FakeGroups()) as c:
        res = await c.call_tool(TOOL, {"action": "update", "target": "Sonos", "remove_members": ["aa:aa:aa:aa:aa:99"]})
    assert "not in the group" in res.content[0].text


async def test_members_and_helpers_cannot_be_mixed_and_create_rejects_helpers(make_session):
    async with make_session(FakeGroups()) as c:
        mixed = await c.call_tool(TOOL, {"action": "update", "target": "Sonos", "members": [M1], "add_members": [M2]})
        helper = await c.call_tool(TOOL, {**NEW, "add_members": [M2]})
    assert "either members" in mixed.content[0].text and "only apply to an existing group" in helper.content[0].text


async def test_other_group_types_are_refused_and_the_type_cannot_be_set_to_anything_else(make_session):
    other = {"id": "x", "name": "Odd", "type": "NETWORKS", "members": ["n1"]}
    async with make_session(FakeGroups(items=(SONOS, other))) as c:
        pre = await call(c, {"action": "update", "target": "x", "name": "Odd2"})
        res = await c.call_tool(TOOL, {"action": "update", "target": "Sonos", "type": "NETWORKS"})
    assert "Only client groups" in " ".join(pre["errors"]) and "validation error" in res.content[0].text


async def test_no_change_sends_nothing(make_session):
    net = FakeGroups()
    async with make_session(net) as c:
        pre = await call(c, {"action": "update", "target": "Sonos", "name": "Sonos", "members": [M1, M2, M3]})
        out = await call(c, {"action": "update", "target": "Sonos", "name": "Sonos", "members": [M1, M2, M3],
                             "confirm": True, "fingerprint": pre["fingerprint"]})
    assert out["applied"] is False and net.writes() == []


async def test_silent_failure_is_reported(make_session):
    net = FakeGroups()
    net.ignore_put = True
    async with make_session(net) as c:
        _, out = await apply(c, {"action": "update", "target": "cams-id", "name": "Cams"})
    assert out["verified"] is False and out["mismatches"][0]["field"] == "name" and "Nothing was retried" in out["attention"]


async def test_a_partial_put_would_be_rejected_by_the_fake_and_is_never_sent(make_session):
    net = FakeGroups()
    async with make_session(net) as c:
        await apply(c, {"action": "update", "target": "cams-id", "add_members": ["aa:aa:aa:aa:aa:20"]})
    assert all({"id", "name", "members", "type"} <= set(b) for b in net.bodies)


async def test_the_entity_switch_and_previews_when_writes_are_off(make_session):
    net = FakeGroups()
    async with make_session(net, entities=frozenset({"port_forward"})) as c:
        pre = await call(c, {"action": "delete", "target": "cams-id"})
        res = await c.call_tool(TOOL, {"action": "delete", "target": "cams-id", "confirm": True, "fingerprint": pre["fingerprint"]})
    assert "not enabled for writes" in pre["apply_blocked_reason"] and "not enabled for writes" in res.content[0].text
    assert net.writes() == []


async def test_the_generic_tool_refuses_and_names_the_typed_one(settings, tmp_path):
    net = FakeGroups()
    mcp, api = create_server(dataclasses.replace(settings, enable_writes=True, write_entities=frozenset({"client_group"}),
                                                 journal_dir=tmp_path / "journal"), transport=httpx.MockTransport(net))
    try:
        async with Client(mcp) as c:
            res = await c.call_tool("unifi_console_call_operation", {"params": {
                "operation_id": "deleteNetworkMemberGroup", "path_params": {"id": "cams-id"}, "confirm": True}})
            text = json.loads(res.content[0].text)["error"]
    finally:
        await api.client.aclose()
    assert "unifi_console_client_group" in text and net.writes() == []


async def test_removing_every_member_is_refused(make_session):
    net = FakeGroups()
    async with make_session(net) as c:
        pre = await call(c, {"action": "update", "target": "cams-id", "remove_members": ["aa:aa:aa:aa:aa:10"]})
        res = await c.call_tool(TOOL, {"action": "update", "target": "cams-id", "remove_members": ["aa:aa:aa:aa:aa:10"],
                                       "confirm": True, "fingerprint": pre["fingerprint"]})
    assert "at least one member" in " ".join(pre["errors"]) and "Refused" in res.content[0].text and net.writes() == []
