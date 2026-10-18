"""Network lists through the write framework: legacy merge semantics, member helpers, validation and the reference check."""
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

FG = "/proxy/network/api/s/default/rest/firewallgroup"
POLICIES = "/proxy/network/v2/api/site/default/firewall-policies"
OBJECTS = "/proxy/network/v2/api/site/default/object-oriented-network-configs"
TOOL = "unifi_console_network_list"
SONOS = {"_id": "aaaaaaaaaaaaaaaaaaaaaaaa", "site_id": "s", "name": "Sonos ports", "description": "Sonos", "group_type": "port-group",
         "group_members": ["1400", "3400-3405"], "source": "static"}


class FakeLists:
    def __init__(self, with_real: bool = False) -> None:
        self.items = {SONOS["_id"]: dict(SONOS)} if with_real else {}
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
        wrap = lambda x: {"meta": {"rc": "ok"}, "data": x}  # noqa: E731
        if path == POLICIES:
            return httpx.Response(self.policy_status, json=self.policies)
        if path == OBJECTS:
            return httpx.Response(200, json=self.objects)
        if path == FG and method == "GET":
            return httpx.Response(200, json=wrap(list(self.items.values())))
        if path == FG and method == "POST":
            self.bodies.append(body)
            new = {**{k: v for k, v in body.items() if k != "_id"}, "_id": uuid.uuid4().hex[:24], "site_id": "s"}
            self.items[new["_id"]] = new
            return httpx.Response(200, json=wrap([new]))
        if path.startswith(FG + "/"):
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

    def writes(self):
        return [e for e in self.log if e[0] in ("POST", "PUT", "DELETE") and "login" not in e[1]]


@pytest.fixture
def make_session(settings, tmp_path):
    @contextlib.asynccontextmanager
    async def opener(net: FakeLists, *, entities=frozenset({"network_list"})):
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


NEW = {"action": "create", "name": "zz-list", "group_type": "port-group", "group_members": ["58690-58699", "58700"], "description": "zz test"}


async def test_create_sends_what_the_ui_sends_and_verifies(make_session):
    net = FakeLists()
    async with make_session(net) as c:
        pre, out = await apply(c, NEW)
    assert pre["request"]["method"] == "POST" and out["verified"] is True
    assert net.bodies == [{"_id": None, "source": "static", "name": "zz-list", "group_type": "port-group",
                           "group_members": ["58690-58699", "58700"], "description": "zz test"}]
    assert out["rollback"] == {"action": "delete", "target": out["id"]}


async def test_update_description_sends_only_that_field(make_session):
    net = FakeLists(with_real=True)
    async with make_session(net) as c:
        pre, out = await apply(c, {"action": "update", "target": "Sonos ports", "description": "Sonos S2"})
    assert net.bodies == [{"description": "Sonos S2"}]
    assert out["verified"] and list(out["diff"]) == ["description"]
    assert net.items[SONOS["_id"]]["group_members"] == ["1400", "3400-3405"]


async def test_add_and_remove_members_replace_the_array_whole(make_session):
    net = FakeLists(with_real=True)
    async with make_session(net) as c:
        pre, out = await apply(c, {"action": "update", "target": "Sonos ports", "add_members": ["4444", "1400"], "remove_members": ["3400-3405"]})
    assert net.bodies == [{"group_members": ["1400", "4444"]}]
    assert out["verified"] and out["rollback"]["changes"] == {"group_members": ["1400", "3400-3405"]}


async def test_noop_member_change_sends_nothing(make_session):
    net = FakeLists(with_real=True)
    async with make_session(net) as c:
        pre = await call(c, {"action": "update", "target": "Sonos ports", "add_members": ["1400"]})
        assert pre["note"].startswith("Already")
        out = await call(c, {"action": "update", "target": "Sonos ports", "add_members": ["1400"], "confirm": True, "fingerprint": pre["fingerprint"]})
    assert out["applied"] is False and net.writes() == []


@pytest.mark.parametrize("args,needle", [
    ({**NEW, "group_members": ["0"]}, "Not valid for a port-group"),
    ({**NEW, "group_members": ["70000"]}, "Not valid for a port-group"),
    ({**NEW, "group_members": ["1", "1"]}, "Duplicate members"),
    ({**NEW, "group_members": ["1"], "name": "Sonos ports"}, "already called"),
    ({**NEW, "group_type": "address-group", "group_members": ["10.88.1.999"]}, "Not valid for a address-group"),
    ({**NEW, "group_type": "address-group", "group_members": ["10.88.1.20-10.88.1.10"]}, "Not valid for a address-group"),
    ({**NEW, "group_type": "domain-group", "group_members": ["not a domain"]}, "Not valid for a domain-group"),
    ({**NEW, "group_members": ["58690"], "name": " "}, "name is required"),
])
async def test_invalid_input_is_refused(make_session, args, needle):
    net = FakeLists(with_real=True)
    async with make_session(net) as c:
        out = await call(c, args)
        res = json.loads((await c.call_tool(TOOL, {**args, "confirm": True, "fingerprint": out["fingerprint"]})).content[0].text)
    assert any(needle in e for e in out["errors"]) and needle in res["error"]
    assert net.writes() == []


async def test_valid_address_and_domain_lists(make_session):
    net = FakeLists()
    async with make_session(net) as c:
        _, a = await apply(c, {"action": "create", "name": "zz-a", "group_type": "address-group",
                               "group_members": ["10.88.1.15", "10.88.2.0/24", "10.88.3.10-10.88.3.20"]})
        _, d = await apply(c, {"action": "create", "name": "zz-d", "group_type": "domain-group", "group_members": ["example.com", "a.b.example.org"]})
    assert a["verified"] and d["verified"]


async def test_type_cannot_change_and_helpers_cannot_mix(make_session):
    net = FakeLists(with_real=True)
    async with make_session(net) as c:
        t = json.loads((await c.call_tool(TOOL, {"action": "update", "target": "Sonos ports", "group_type": "address-group"})).content[0].text)
        m = json.loads((await c.call_tool(TOOL, {"action": "update", "target": "Sonos ports", "group_members": ["1"], "add_members": ["2"]})).content[0].text)
        r = json.loads((await c.call_tool(TOOL, {"action": "update", "target": "Sonos ports", "remove_members": ["9999"]})).content[0].text)
        cr = json.loads((await c.call_tool(TOOL, {**NEW, "add_members": ["1"]})).content[0].text)
    assert "cannot be changed" in t["error"] and "not both" in m["error"]
    assert "not in the list: 9999" in r["error"] and "only apply to an existing list" in cr["error"]
    assert net.writes() == []


async def test_delete_is_refused_while_a_policy_uses_the_list(make_session):
    net = FakeLists(with_real=True)
    net.policies = [{"_id": "p1", "name": "Allow Sonos", "source": {"port_group_id": SONOS["_id"]}}, {"_id": "p2", "name": "Other"}]
    net.objects = [{"id": "o1", "name": "QoS Sonos", "targets": [SONOS["_id"]]}]
    async with make_session(net) as c:
        pre = await call(c, {"action": "delete", "target": "Sonos ports"})
        assert pre["used_by"] == ["firewall policy: Allow Sonos", "traffic object: QoS Sonos"]
        assert "still used by 2" in pre["errors"][0]
        res = json.loads((await c.call_tool(TOOL, {"action": "delete", "target": "Sonos ports", "confirm": True, "fingerprint": pre["fingerprint"]})).content[0].text)
    assert "still used by" in res["error"] and net.writes() == []


async def test_editing_a_used_list_warns_but_is_allowed(make_session):
    net = FakeLists(with_real=True)
    net.policies = [{"_id": "p1", "name": "Allow Sonos", "source": {"port_group_id": SONOS["_id"]}}]
    async with make_session(net) as c:
        pre, out = await apply(c, {"action": "update", "target": "Sonos ports", "add_members": ["4444"]})
    assert any("used by 1" in w for w in pre["warnings"]) and out["verified"]


async def test_unused_list_can_be_deleted_and_rolled_back(make_session):
    net = FakeLists(with_real=True)
    net.policies = [{"_id": "p2", "name": "Other"}]
    async with make_session(net) as c:
        pre, out = await apply(c, {"action": "delete", "target": "Sonos ports"})
    assert out["verified"] and not net.items
    assert out["rollback"]["action"] == "create" and out["rollback"]["changes"]["group_members"] == ["1400", "3400-3405"]
    assert "_id" not in out["rollback"]["changes"]


async def test_reference_check_failure_blocks_everything(make_session):
    net = FakeLists(with_real=True)
    net.policy_status = 500
    async with make_session(net) as c:
        res = json.loads((await c.call_tool(TOOL, {"action": "delete", "target": "Sonos ports"})).content[0].text)
    assert "Could not check what uses this network list" in res["error"] and net.writes() == []


async def test_system_defined_lists_are_protected(make_session):
    net = FakeLists(with_real=True)
    net.items[SONOS["_id"]]["attr_no_delete"] = True
    net.items[SONOS["_id"]]["attr_no_edit"] = True
    async with make_session(net) as c:
        d = json.loads((await c.call_tool(TOOL, {"action": "delete", "target": "Sonos ports"})).content[0].text)
        u = json.loads((await c.call_tool(TOOL, {"action": "update", "target": "Sonos ports", "description": "x"})).content[0].text)
    assert "no-delete" in d["error"] and "no-edit" in u["error"] and net.writes() == []


async def test_silent_failure_is_reported(make_session):
    net = FakeLists(with_real=True)
    net.ignore_put = True
    async with make_session(net) as c:
        _, out = await apply(c, {"action": "update", "target": "Sonos ports", "description": "new"})
    assert out["verified"] is False and out["mismatches"][0]["field"] == "description"
    assert sum(1 for m, _, _ in net.writes() if m == "PUT") == 1


async def test_generic_tool_points_to_the_typed_tool(settings):
    net = FakeLists()
    mcp, api = create_server(dataclasses.replace(settings, enable_writes=True), transport=httpx.MockTransport(net))
    try:
        async with Client(mcp) as c:
            for op in ("createFirewallGroup", "updateFirewallGroup", "deleteFirewallGroup"):
                res = await c.call_tool("unifi_console_call_operation", {"params": {"operation_id": op, "path_params": {"id": "x"}, "body": {}, "confirm": True}})
                assert "unifi_console_network_list" in json.loads(res.content[0].text)["error"]
    finally:
        await api.client.aclose()
    assert net.writes() == []


async def test_ipv6_list_create_matches_the_captured_body(make_session):
    net = FakeLists()
    args = {"action": "create", "name": "IPv6 List", "group_type": "ipv6-address-group",
            "group_members": ["fe80::f6e2:c6ff:fef2:7881", "2a01:4b00:85c9:6403::1"], "description": ""}
    async with make_session(net) as c:
        pre, out = await apply(c, args)
    assert out["verified"] is True
    assert net.bodies == [{"_id": None, "source": "static", "name": "IPv6 List", "group_type": "ipv6-address-group",
                           "group_members": ["fe80::f6e2:c6ff:fef2:7881", "2a01:4b00:85c9:6403::1"], "description": ""}]


async def test_ipv6_list_refuses_an_ipv4_member(make_session):
    net = FakeLists()
    async with make_session(net) as c:
        pre = await call(c, {"action": "create", "name": "x6", "group_type": "ipv6-address-group", "group_members": ["10.1.1.1"]})
    assert any("Not valid for a ipv6-address-group" in e for e in pre["errors"])
