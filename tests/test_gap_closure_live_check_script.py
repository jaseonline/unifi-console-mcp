"""The gap-closure live check must restore everything it changes on a fake console."""
from __future__ import annotations

import contextlib
import dataclasses
import importlib.util
import json
import uuid
from pathlib import Path

import httpx
from mcp.client import Client

from conftest import make_jwt
from test_network_list import SONOS, FakeLists
from test_site_settings import MAPS_KEY, FakeSettings
from unifi_console_mcp.server import create_server
from unifi_console_mcp.writes import WriteEngine

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "gap_closure_live_check.py"
PF = "/proxy/network/api/s/default/rest/portforward"


def load():
    spec = importlib.util.spec_from_file_location("gap_closure_live_check", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakePortForwards:
    def __init__(self) -> None:
        self.items: dict[str, dict] = {}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        if path == "/api/auth/login":
            return httpx.Response(200, json={}, headers={"set-cookie": f"TOKEN={make_jwt()}; Path=/", "x-csrf-token": "c"})
        wrap = lambda x: {"meta": {"rc": "ok"}, "data": x}  # noqa: E731
        if path == PF and method == "GET":
            return httpx.Response(200, json=wrap(list(self.items.values())))
        if path == PF and method == "POST":
            body = json.loads(request.content)
            new = {**body, "_id": uuid.uuid4().hex[:24], "site_id": "s"}
            self.items[new["_id"]] = new
            return httpx.Response(200, json=wrap([new]))
        if path.startswith(PF + "/") and method == "DELETE":
            self.items.pop(path.rsplit("/", 1)[1], None)
            return httpx.Response(200, json=wrap([]))
        return httpx.Response(404, json={})


@contextlib.asynccontextmanager
async def session(settings, tmp_path, net):
    mod = load()
    s = dataclasses.replace(settings, enable_writes=True, write_entities=mod.ENTITIES, journal_dir=tmp_path / "journal")
    mcp, api = create_server(s, transport=httpx.MockTransport(net))
    try:
        async with Client(mcp) as client:
            yield mod, client, WriteEngine(api)
    finally:
        await api.client.aclose()


async def test_dry_run_touches_nothing(capsys):
    assert await load().main(False) == 0
    assert "Dry run only" in capsys.readouterr().out


async def test_settings_sections_restore_the_original_groups(settings, tmp_path, capsys):
    net = FakeSettings()
    before = json.loads(json.dumps(net.groups))
    async with session(settings, tmp_path, net) as (mod, client, engine):
        fails = await mod.syslog_section(client, engine) + await mod.retention_section(client, engine) + await mod.logging_section(client, engine)
    out = capsys.readouterr().out
    assert fails == 0 and net.groups == before and MAPS_KEY not in out
    assert net.system[-1] == {"cmd": "set-param", "key": "debug.setting_preference", "value": "auto"}


async def test_ipv6_list_section_leaves_real_lists_alone(settings, tmp_path):
    net = FakeLists(with_real=True)
    net.items["old"] = {**SONOS, "_id": "old", "name": "zz-gapcheck-old"}
    async with session(settings, tmp_path, net) as (mod, client, engine):
        assert await mod.lists_section(client, engine) == 0
    assert list(net.items) == [SONOS["_id"]]


async def test_port_forward_section_creates_disabled_and_deletes(settings, tmp_path):
    net = FakePortForwards()
    async with session(settings, tmp_path, net) as (mod, client, engine):
        assert await mod.portfwd_section(client, engine) == 0
    assert net.items == {}
