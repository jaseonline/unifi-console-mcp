"""Traffic (QoS) objects through the write framework: whole-object v2 updates, network resolution, narrow scope."""
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
from unifi_console_mcp.entities.traffic_object import default_qos, default_route, default_secure
from unifi_console_mcp.server import create_server

BASE = "/proxy/network/v2/api/site/default"
OBJECTS = BASE + "/object-oriented-network-configs"
OBJECT = BASE + "/object-oriented-network-config"
NETWORKS = "/proxy/network/api/s/default/rest/networkconf"
TOOL = "unifi_console_traffic_object"
SONOS_NET, IOT_NET, WAN_NET = "e4c2b208-d69f-48fc-b264-564f51e9cc1a", "98fba899-f53a-4e3d-b257-5b8e2e594189", "85425c54-aa12-44a8-998e-e00820f48ff9"
NETS = [
    {"_id": IOT_NET, "name": "LAN_IoT", "purpose": "corporate"},
    {"_id": SONOS_NET, "name": "LAN_Sonos", "purpose": "corporate"},
    {"_id": "03003e5f-5932-42e8-b9f4-e2cdac44aab2", "name": "LAN_Guest", "purpose": "guest"},
    {"_id": WAN_NET, "name": "WAN1", "purpose": "wan"},
]


def make_obj(ident="obj-1", name="Existing", net=IOT_NET, *, enabled=False, qos_on=False, down=None, route_on=False):
    qos = default_qos()
    qos["enabled"] = qos_on
    if down:
        qos["download_limit"] = {"enabled": True, "limit": down, "burst": "DISABLED"}
    route = default_route()
    route["enabled"] = route_on
    return {"id": ident, "enabled": enabled, "name": name, "target_type": "NETWORKS", "targets": [{"type": "NETWORK_ID", "value": net}],
            "secure": default_secure(), "route": route, "qos": qos}


class FakeTraffic:
    def __init__(self, items=()) -> None:
        self.items = {r["id"]: copy.deepcopy(r) for r in items}
        self.ignore_put = False
        self.log: list[tuple[str, str, dict | None]] = []
        self.bodies: list[dict] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        if path == "/api/auth/login":
            return httpx.Response(200, json={}, headers={"set-cookie": f"TOKEN={make_jwt()}; Path=/", "x-csrf-token": "c"})
        body = json.loads(request.content) if request.content else None
        self.log.append((method, path, body))
        if path == NETWORKS:
            return httpx.Response(200, json={"meta": {"rc": "ok"}, "data": NETS})
        if path == OBJECTS:
            return httpx.Response(200, json=list(self.items.values()))
        if path == OBJECT and method == "POST":
            self.bodies.append(body)
            new = {**body, "id": uuid.uuid4().hex}
            self.items[new["id"]] = new
            return httpx.Response(201, json=new)
        if path.startswith(OBJECT + "/"):
            ident = path.rsplit("/", 1)[1]
            if method == "PUT":
                if "id" not in body or "qos" not in body:                         # the real console wants the whole object
                    return httpx.Response(400, json={"message": "Validation failed"})
                self.bodies.append(body)
                if not self.ignore_put:
                    self.items[ident] = {**self.items[ident], **body}
                return httpx.Response(200, json=self.items[ident])
            if method == "DELETE":
                self.items.pop(ident, None)
                return httpx.Response(204)
        return httpx.Response(404, json={})

    def writes(self):
        return [e for e in self.log if e[0] in ("POST", "PUT", "DELETE") and "login" not in e[1]]


@pytest.fixture
def make_session(settings, tmp_path):
    @contextlib.asynccontextmanager
    async def opener(net: FakeTraffic, *, entities=frozenset({"traffic_object"})):
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


NEW = {"action": "create", "name": "zz-qos", "networks": ["LAN_Sonos"]}


async def test_create_sends_the_captured_shape_switched_off_by_default(make_session):
    net = FakeTraffic()
    async with make_session(net) as c:
        pre, out = await apply(c, NEW)
    body = net.bodies[0]
    assert set(body) == {"enabled", "name", "target_type", "targets", "secure", "route", "qos"}
    assert body["enabled"] is False and body["name"] == "zz-qos" and body["target_type"] == "NETWORKS"
    assert body["targets"] == [{"type": "NETWORK_ID", "value": SONOS_NET}]
    assert body["qos"] == default_qos() and body["route"] == default_route() and body["secure"] == default_secure()
    assert pre["request"]["method"] == "POST" and out["http_status"] == 201 and out["verified"] is True
    assert out["rollback"] == {"action": "delete", "target": out["id"]}


async def test_a_limit_on_a_new_object_switches_qos_on_and_states_the_rate(make_session):
    net = FakeTraffic()
    args = {**NEW, "enabled": True, "download_limit": 5000, "upload_limit": 2000}
    async with make_session(net) as c:
        pre, out = await apply(c, args)
    qos = net.bodies[0]["qos"]
    assert qos["enabled"] is True and qos["download_limit"] == {"enabled": True, "limit": 5000, "burst": "DISABLED"}
    assert qos["upload_limit"] == {"enabled": True, "limit": 2000, "burst": "DISABLED"}
    text = " ".join(pre["warnings"])
    assert "LAN_Sonos" in text and "download 5000 kbit/s (5 Mbit/s)" in text and "upload 2000 kbit/s (2 Mbit/s)" in text and out["verified"]


async def test_update_sends_the_whole_object_and_changes_only_qos(make_session):
    start = make_obj()
    net = FakeTraffic([start])
    async with make_session(net) as c:
        pre, out = await apply(c, {"action": "update", "target": "Existing", "download_limit": 8000})
    assert pre["request"]["body_style"] == "whole object"
    sent = net.bodies[0]
    assert set(sent) == set(start) and sent["id"] == "obj-1" and sent["route"] == start["route"] and sent["secure"] == start["secure"]
    assert sent["qos"]["download_limit"] == {"enabled": True, "limit": 8000, "burst": "DISABLED"}
    assert list(out["diff"]) == ["qos"] and out["verified"] is True
    assert any("has no effect" in w for w in pre["warnings"])             # qos is still off


async def test_zero_switches_a_limit_off_and_keeps_its_value(make_session):
    net = FakeTraffic([make_obj(enabled=True, qos_on=True, down=9000)])
    async with make_session(net) as c:
        pre, out = await apply(c, {"action": "update", "target": "Existing", "download_limit": 0})
    assert net.bodies[0]["qos"]["download_limit"] == {"enabled": False, "limit": 9000, "burst": "DISABLED"}
    assert any("limits nothing" in w for w in pre["warnings"]) and out["verified"]


async def test_rename_changes_only_the_name_and_leaves_the_rest_alone(make_session):
    start = make_obj()
    net = FakeTraffic([start])
    async with make_session(net) as c:
        _, out = await apply(c, {"action": "update", "target": "obj-1", "name": "Renamed"})
    assert list(out["diff"]) == ["name"] and net.bodies[0] == {**start, "name": "Renamed"}


async def test_enable_with_a_limit_warns_and_overlap_is_reported(make_session):
    net = FakeTraffic([make_obj("a", "Other", SONOS_NET, enabled=True, qos_on=True, down=1000), make_obj("b", "Mine", SONOS_NET)])
    async with make_session(net) as c:
        pre = await call(c, {"action": "update", "target": "b", "enabled": True, "qos_enabled": True, "download_limit": 3000})
    text = " ".join(pre["warnings"])
    assert "as soon as it is applied" in text and "Other" in text and not pre["errors"]


@pytest.mark.parametrize("args,needle", [
    ({"networks": ["Nope"]}, "No network with id or name 'Nope'"),
    ({"networks": ["WAN1"]}, "WAN network"),
])
async def test_bad_networks_are_refused_before_anything_is_planned(make_session, args, needle):
    net = FakeTraffic()
    async with make_session(net) as c:
        text = await raw(c, {**NEW, **args})
    assert needle in text and net.writes() == []


async def test_networks_may_be_given_by_id_or_case_insensitive_name(make_session):
    net = FakeTraffic()
    async with make_session(net) as c:
        await apply(c, {**NEW, "networks": [IOT_NET, "lan_sonos"]})
    assert [t["value"] for t in net.bodies[0]["targets"]] == [IOT_NET, SONOS_NET]


@pytest.mark.parametrize("args,needle", [
    ({"name": "existing"}, "already called"),
    ({"networks": ["LAN_IoT", "LAN_IoT"]}, "Duplicate targets"),
    ({"route_enabled": True}, "route.network_id must be"),
    ({"block_internet": True, "enabled": True}, "acknowledge_blocking"),
    ({"qos": {"mode": "PRIORITY"}}, "only LIMIT"),
    ({"qos": {"download_limit": {"limit": 0}}}, "whole number"),
    ({"qos": {"download_limit": {"burst": "AUTO"}}}, "burst"),
    ({"qos": {"schedule": {"repeat_on_days": ["funday"]}}}, "repeat_on_days"),
])
async def test_bad_objects_are_refused(make_session, args, needle):
    net = FakeTraffic([make_obj()])
    async with make_session(net) as c:
        pre = await call(c, {**NEW, **args})
        res = await raw(c, {**NEW, **args, "confirm": True, "fingerprint": pre["fingerprint"]})
    assert needle in " ".join(pre["errors"]), pre
    assert "Refused" in res and net.writes() == []


async def test_limits_outside_the_allowed_range_fail_validation(make_session):
    async with make_session(FakeTraffic()) as c:
        text = await raw(c, {**NEW, "download_limit": 50_000_000})
    assert "validation error" in text


async def test_create_needs_a_name_and_networks_and_qos_has_one_form(make_session):
    async with make_session(FakeTraffic()) as c:
        a = await raw(c, {"action": "create", "name": "x"})
        b = await raw(c, {**NEW, "download_limit": 100, "qos": {"enabled": True}})
        d = await raw(c, {"action": "delete", "target": "x", "name": "y"})
    assert "create needs name and networks" in a and "not both" in b and "delete takes no field values" in d


async def test_an_object_with_route_on_is_edited_without_touching_the_route(make_session):
    start = make_obj(route_on=True)
    net = FakeTraffic([start])
    async with make_session(net) as c:
        pre, out = await apply(c, {"action": "update", "target": "obj-1", "name": "Renamed"})
    assert net.bodies[0]["route"] == start["route"] and out["verified"]
    assert any("route settings switched on" in w for w in pre["warnings"])


async def test_another_target_type_can_be_renamed_but_not_retargeted(make_session):
    odd = {**make_obj(), "target_type": "GROUPS", "targets": [{"type": "GROUP_ID", "value": "g1"}]}
    net = FakeTraffic([odd])
    async with make_session(net) as c:
        pre, out = await apply(c, {"action": "update", "target": "obj-1", "name": "Renamed"})
        bad = await raw(c, {"action": "update", "target": "obj-1", "networks": ["LAN_IoT"]})
    assert out["verified"] and net.bodies[0]["targets"] == odd["targets"] and any("left untouched" in w for w in pre["warnings"])
    assert "cannot be changed here" in bad and len(net.bodies) == 1


async def test_delete_warns_that_limits_lift_and_the_rollback_recreates_it(make_session):
    start = make_obj(enabled=True, qos_on=True, down=4000)
    net = FakeTraffic([start])
    async with make_session(net) as c:
        pre, out = await apply(c, {"action": "delete", "target": "Existing"})
        assert "obj-1" not in net.items and any("lifts its limits on LAN_IoT" in w for w in pre["warnings"])
        rb = out["rollback"]
        assert rb["action"] == "create" and "id" not in rb["changes"]
        _, back = await apply(c, {"action": "create", **rb["changes"]})
    assert back["verified"] is True
    restored = net.bodies[-1]
    assert restored == {k: v for k, v in start.items() if k != "id"}


async def test_an_update_rollback_can_be_replayed(make_session):
    net = FakeTraffic([make_obj(enabled=True, qos_on=True, down=4000)])
    async with make_session(net) as c:
        _, out = await apply(c, {"action": "update", "target": "obj-1", "download_limit": 6000})
        rb = out["rollback"]
        _, back = await apply(c, {"action": rb["action"], "target": rb["target"], **rb["changes"]})
    assert back["verified"] and net.items["obj-1"]["qos"]["download_limit"]["limit"] == 4000


async def test_a_change_the_console_silently_drops_is_reported(make_session):
    net = FakeTraffic([make_obj()])
    net.ignore_put = True
    async with make_session(net) as c:
        _, out = await apply(c, {"action": "update", "target": "obj-1", "name": "Renamed"})
    assert out["verified"] is False and out["mismatches"][0]["field"] == "name"


async def test_entity_switch_and_previews_when_writes_are_off(make_session):
    net = FakeTraffic()
    async with make_session(net, entities=frozenset({"port_forward"})) as c:
        pre = await call(c, NEW)
        res = await raw(c, {**NEW, "confirm": True, "fingerprint": pre["fingerprint"]})
    assert "not enabled for writes" in pre["apply_blocked_reason"] and "not enabled for writes" in res and net.writes() == []


async def test_a_stale_preview_is_refused(make_session):
    net = FakeTraffic([make_obj()])
    async with make_session(net) as c:
        pre = await call(c, {"action": "update", "target": "obj-1", "name": "Renamed"})
        net.items["obj-1"]["name"] = "Changed elsewhere"
        res = await raw(c, {"action": "update", "target": "obj-1", "name": "Renamed", "confirm": True, "fingerprint": pre["fingerprint"]})
    assert "differs from the preview" in res and net.writes() == []


@pytest.mark.parametrize("op,args", [
    ("createTrafficPolicyObject", {}),
    ("updateTrafficPolicyObject", {"path_params": {"id": "obj-1"}}),
    ("deleteTrafficPolicyObject", {"path_params": {"id": "obj-1"}}),
])
async def test_the_generic_tool_refuses_and_names_the_typed_one(settings, tmp_path, op, args):
    net = FakeTraffic([make_obj()])
    mcp, api = create_server(dataclasses.replace(settings, enable_writes=True, write_entities=frozenset({"traffic_object"}),
                                                 journal_dir=tmp_path / "journal"), transport=httpx.MockTransport(net))
    try:
        async with Client(mcp) as c:
            res = await c.call_tool("unifi_console_call_operation", {"params": {"operation_id": op, "confirm": True, **args}})
            text = json.loads(res.content[0].text)["error"]
    finally:
        await api.client.aclose()
    assert "unifi_console_traffic_object" in text and net.writes() == []


WAN_ID = WAN_NET


async def test_client_target_with_schedule_burst_and_priority(make_session):
    net = FakeTraffic()
    async with make_session(net) as c:
        pre, out = await apply(c, {"action": "create", "name": "Kid laptop", "clients": ["AA-BB-CC-DD-EE-FF"], "download_limit": 20000,
                                   "download_burst": "SHORT", "qos_schedule": {"mode": "EVERY_DAY", "start": "18:00", "end": "21:00"}})
    body = net.bodies[0]
    assert body["target_type"] == "CLIENTS" and body["targets"] == [{"type": "MAC", "value": "aa:bb:cc:dd:ee:ff"}]
    assert body["enabled"] is False and body["qos"]["enabled"] is True
    assert body["qos"]["download_limit"] == {"enabled": True, "limit": 20000, "burst": "SHORT"}
    assert body["qos"]["schedule"] == {"mode": "EVERY_DAY", "time_range_start": "18:00", "time_range_end": "21:00"}
    assert out["verified"]


async def test_prioritize_and_weekly_schedule(make_session):
    net = FakeTraffic([make_obj()])
    async with make_session(net) as c:
        _, out = await apply(c, {"action": "update", "target": "obj-1", "qos_enabled": True, "qos_mode": "PRIORITIZE",
                                 "qos_schedule": {"mode": "EVERY_WEEK", "days": ["sat", "sun"]}})
    q = net.bodies[0]["qos"]
    assert q["mode"] == "PRIORITIZE" and q["schedule"] == {"mode": "EVERY_WEEK", "repeat_on_days": ["sat", "sun"], "time_all_day": True}
    assert out["verified"]


async def test_block_internet_needs_acknowledgement_only_when_enabled(make_session):
    net = FakeTraffic()
    async with make_session(net) as c:
        _, out = await apply(c, {"action": "create", "name": "Blocker", "networks": ["LAN_IoT"], "block_internet": True,
                                 "block_schedule": {"mode": "EVERY_DAY", "start": "23:00", "end": "06:00"}})
        sec = net.bodies[0]["secure"]
        assert sec["enabled"] is True and sec["internet"]["schedule"]["time_range_start"] == "23:00" and net.bodies[0]["enabled"] is False
        pre = await call(c, {"action": "update", "target": "Blocker", "enabled": True})
        assert not pre["errors"] and any("untouched" in w for w in pre["warnings"])
        again = await call(c, {"action": "create", "name": "Blocker2", "networks": ["LAN_Sonos"], "block_internet": True, "enabled": True})
        assert any("acknowledge_blocking" in e for e in again["errors"])
        ok = await call(c, {"action": "create", "name": "Blocker2", "networks": ["LAN_Sonos"], "block_internet": True, "enabled": True,
                            "acknowledge_blocking": True})
    assert not ok["errors"] and any("blocks all internet" in w for w in ok["warnings"])


async def test_route_through_wan_with_ip_matcher_and_kill_switch(make_session):
    net = FakeTraffic()
    async with make_session(net) as c:
        bad = await raw(c, {"action": "create", "name": "Route", "networks": ["LAN_IoT"], "route_enabled": True, "route_network": "LAN_Sonos",
                            "route_all_traffic": True})
        assert "not a WAN or VPN" in bad
        _, out = await apply(c, {"action": "create", "name": "Route", "networks": ["LAN_IoT"], "route_enabled": True,
                                 "route_network": "WAN1", "route_ip_addresses": ["203.0.113.0/24"], "route_kill_switch": True})
    r = net.bodies[0]["route"]
    assert r["enabled"] and r["network_id"] == WAN_ID and r["kill_switch"] is True and r["all_traffic"] is False
    assert r["ip_addresses"] == {"enabled": True, "values": ["203.0.113.0/24"]} and out["verified"]


async def test_bad_mac_is_refused(make_session):
    async with make_session(FakeTraffic()) as c:
        text = await raw(c, {"action": "create", "name": "x", "clients": ["not-a-mac"]})
    assert "not a MAC" in text


async def test_prioritize_switches_limits_off_and_refuses_limits(make_session):
    net = FakeTraffic([make_obj(enabled=False, qos_on=True, down=4000)])
    async with make_session(net) as c:
        _, out = await apply(c, {"action": "update", "target": "obj-1", "qos_mode": "PRIORITIZE"})
        bad = await call(c, {"action": "update", "target": "obj-1", "download_limit": 5000})
    q = net.bodies[0]["qos"]
    assert q["mode"] == "PRIORITIZE" and q["download_limit"]["enabled"] is False and q["download_limit"]["limit"] == 4000 and out["verified"]
    assert any("Prioritize mode cannot" in e for e in bad["errors"])
