"""Syslog, data retention (super_mgmt) and logging levels through the shared framework."""
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
SYSLOG = {"_id": "89d70a11", "key": "rsyslogd", "site_id": "s", "enabled": True, "this_controller": False, "log_all_contents": False,
          "debug": False, "netconsole_enabled": True, "this_controller_encrypted_only": False, "port": "514",
          "contents": ["admin_activity", "client", "critical"], "netconsole_host": "192.168.1.65", "ip": "192.168.1.65",
          "netconsole_port": "514"}
MAPS_KEY = "AIza" + "SyFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0"   # split so secret scanners do not flag a fake
MGMT = {"_id": "0f8f4e1e", "key": "super_mgmt", "site_id": "s", "data_retention_setting_preference": "manual",
        "data_retention_time_in_hours_for_5minutes_scale": 24, "data_retention_time_in_hours_for_hourly_scale": 168,
        "data_retention_time_in_hours_for_daily_scale": 2160, "data_retention_time_in_hours_for_monthly_scale": 8760,
        "data_retention_time_in_hours_for_others": 8760, "autobackup_enabled": True, "autobackup_cron_expr": "0 4 * * *",
        "google_maps_api_key": MAPS_KEY}


class FakeSettings:
    def __init__(self) -> None:
        self.groups = {"rsyslogd": json.loads(json.dumps(SYSLOG)), "super_mgmt": json.loads(json.dumps(MGMT))}
        self.posts: list[tuple[str, dict]] = []
        self.system: list[dict] = []
        self.fail_system_at: int | None = None

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        if path == "/api/auth/login":
            return httpx.Response(200, json={}, headers={"set-cookie": f"TOKEN={make_jwt()}; Path=/", "x-csrf-token": "c"})
        wrap = lambda x: {"meta": {"rc": "ok"}, "data": x}  # noqa: E731
        if path.startswith(BASE + "/get/setting/"):
            return httpx.Response(200, json=wrap([self.groups[path.rsplit("/", 1)[1]]]))
        if path.startswith(BASE + "/set/setting/") and method == "POST":
            key = path.rsplit("/", 1)[1]
            body = json.loads(request.content)
            self.posts.append((key, body))
            self.groups[key] = {**self.groups[key], **body}
            return httpx.Response(200, json=wrap([self.groups[key]]))
        if path == BASE + "/cmd/system" and method == "POST":
            body = json.loads(request.content)
            self.system.append(body)
            if self.fail_system_at == len(self.system):
                return httpx.Response(500, json={"meta": {"rc": "error", "msg": "api.err.Boom"}, "data": []})
            return httpx.Response(200, json=wrap([]))
        return httpx.Response(404, json={})


@pytest.fixture
def make_session(settings, tmp_path):
    @contextlib.asynccontextmanager
    async def opener(net: FakeSettings, *, entities=frozenset({"syslog", "data_retention", "logging_levels"}), writes=True):
        s = dataclasses.replace(settings, enable_writes=writes, write_entities=entities, journal_dir=tmp_path / "journal")
        mcp, api = create_server(s, transport=httpx.MockTransport(net))
        try:
            async with Client(mcp) as client:
                yield Wrapped(client), tmp_path
        finally:
            await api.client.aclose()
    return opener


async def call(c, tool, args):
    res = await c.call_tool(tool, args)
    assert not res.is_error, res
    return json.loads(res.content[0].text)


async def apply(c, tool, args):
    pre = await call(c, tool, args)
    assert pre.get("ok") and not pre["errors"], pre
    return pre, await call(c, tool, {**args, "confirm": True, "fingerprint": pre["fingerprint"]})


async def test_syslog_destination_change_sends_host_and_ip_and_warns_about_the_feed(make_session):
    net = FakeSettings()
    async with make_session(net) as (c, _):
        pre, out = await apply(c, "unifi_console_syslog", {"netconsole_host": "192.168.1.70", "netconsole_port": 1514, "debug": True})
    assert any("ends the feed" in w for w in pre["warnings"]) and any("Debug" in w for w in pre["warnings"])
    key, body = net.posts[0]
    assert key == "rsyslogd" and body["ip"] == "192.168.1.70" and body["netconsole_host"] == "192.168.1.70"
    assert body["port"] == "1514" and body["netconsole_port"] == "1514" and body["debug"] is True and "_id" not in body and "site_id" not in body
    assert out["verified"] is True


@pytest.mark.parametrize("args,needle", [
    ({"contents": ["client", "nonsense"]}, "Unknown content"),
    ({"netconsole_host": "bad host!"}, "netconsole_host"),
    ({"netconsole_port": 70000}, "netconsole_port"),
])
async def test_syslog_rejects_bad_values(make_session, args, needle):
    net = FakeSettings()
    async with make_session(net) as (c, _):
        pre = await call(c, "unifi_console_syslog", args)
    assert any(needle in e for e in pre["errors"]) and net.posts == []


async def test_retention_preview_hides_the_rest_and_the_write_keeps_it(make_session):
    net = FakeSettings()
    async with make_session(net) as (c, tmp):
        pre, out = await apply(c, "unifi_console_data_retention", {"hours_hourly": 336})
        journal = "".join(p.read_text() for p in (tmp / "journal").glob("*.jsonl"))
    assert MAPS_KEY not in json.dumps(pre) and MAPS_KEY not in json.dumps(out) and MAPS_KEY not in journal
    assert "autobackup_enabled" not in json.dumps(pre["before"])
    _, body = net.posts[0]
    assert body["data_retention_time_in_hours_for_hourly_scale"] == 336 and body["google_maps_api_key"] == MAPS_KEY
    assert body["autobackup_cron_expr"] == "0 4 * * *" and "site_id" not in body and out["verified"] is True
    assert any("storage" in w for w in pre["warnings"])


async def test_retention_shortening_warns_and_auto_refuses_hours(make_session):
    net = FakeSettings()
    async with make_session(net) as (c, _):
        pre = await call(c, "unifi_console_data_retention", {"hours_daily": 720})
        assert any("deletes older" in w for w in pre["warnings"])
        res = await c.call_tool("unifi_console_data_retention", {"data_retention_setting_preference": "auto", "hours_daily": 720})
        assert "only apply when" in res.content[0].text
        auto = await call(c, "unifi_console_data_retention", {"data_retention_setting_preference": "auto"})
    assert any("reset the hours" in w for w in auto["warnings"]) and net.posts == []


async def test_retention_rejects_nonsense_hours(make_session):
    net = FakeSettings()
    async with make_session(net) as (c, _):
        pre = await call(c, "unifi_console_data_retention", {"hours_hourly": 0})
    assert any("hours_hourly" in e or "for_hourly_scale" in e for e in pre["errors"])


async def test_logging_levels_send_the_captured_sequence_and_cannot_verify(make_session):
    net = FakeSettings()
    async with make_session(net) as (c, _):
        pre, out = await apply(c, "unifi_console_logging_levels", {"sdn": "debug"})
    assert net.system == [{"cmd": "set-param", "key": "debug.device", "value": "warn"},
                          {"cmd": "set-param", "key": "debug.mgmt", "value": "warn"},
                          {"cmd": "set-param", "key": "debug.sdn", "value": "debug"},
                          {"cmd": "set-param", "key": "debug.system", "value": "warn"},
                          {"cmd": "set-param", "key": "debug.setting_preference", "value": "manual"}]
    assert out["verified"] is None and out["requests_sent"] == 5 and any("chatty" in w for w in pre["warnings"])


async def test_logging_levels_default_is_auto_warn_and_auto_refuses_debug(make_session):
    net = FakeSettings()
    async with make_session(net) as (c, _):
        pre, out = await apply(c, "unifi_console_logging_levels", {})
        assert net.system[-1] == {"cmd": "set-param", "key": "debug.setting_preference", "value": "auto"}
        bad = await call(c, "unifi_console_logging_levels", {"setting_preference": "auto", "device": "debug"})
    assert bad["errors"] and out["rollback"]["setting_preference"] == "auto"


async def test_logging_levels_partial_failure_is_reported_with_the_rollback(make_session):
    net = FakeSettings()
    net.fail_system_at = 3
    async with make_session(net) as (c, _):
        pre = await call(c, "unifi_console_logging_levels", {"mgmt": "debug"})
        res = await c.call_tool("unifi_console_logging_levels", {"mgmt": "debug", "confirm": True, "fingerprint": pre["fingerprint"]})
    assert "2 of 5 requests had already been sent" in res.content[0].text


async def test_gates_apply_to_all_three(make_session):
    net = FakeSettings()
    async with make_session(net, writes=False) as (c, _):
        for tool, args in (("unifi_console_syslog", {"debug": True}), ("unifi_console_data_retention", {"hours_hourly": 200}),
                           ("unifi_console_logging_levels", {"sdn": "debug"})):
            pre = await call(c, tool, args)
            assert "Writes are disabled" in pre["apply_blocked_reason"]
    async with make_session(net, entities=frozenset({"wifi"})) as (c, _):
        pre = await call(c, "unifi_console_syslog", {"debug": True})
        assert "not enabled" in pre["apply_blocked_reason"]
    assert net.posts == [] and net.system == []
