"""The switch port live check only touches two unused ports and always ends on the original state."""
from __future__ import annotations

import copy

import httpx

from test_doh import load_script
from test_switch_port import FakeSwitchNet


def prepare(monkeypatch, tmp_path):
    from unifi_console_mcp.config import Settings

    monkeypatch.setattr(Settings, "from_env", classmethod(lambda cls: cls(
        host="console.test", username="u", password="p", journal_dir=tmp_path / "journal", dns_probe_window=1.0)))
    monkeypatch.setattr("unifi_console_mcp.entities.switch_port.socket.gethostbyname", lambda host: "127.0.0.1")
    monkeypatch.setattr("socket.gethostbyname", lambda host: "127.0.0.1")
    mod = load_script("switch_port_live_check")
    mod.SWITCH, mod.ADD_PORT, mod.EDIT_PORT = "Switch A", 6, 5
    mod.UPLINK_PORT, mod.AP_PORT, mod.CONSOLE_PORT = 1, 3, 4
    return mod


async def test_dry_run_touches_nothing(capsys):
    assert await load_script("switch_port_live_check").main(False) == 0
    assert "Dry run only" in capsys.readouterr().out


async def test_run_proves_the_tool_and_leaves_nothing_behind(monkeypatch, tmp_path, capsys):
    mod = prepare(monkeypatch, tmp_path)
    net = FakeSwitchNet()
    before = copy.deepcopy(net.ov())
    code = await mod.main(True, httpx.MockTransport(net))
    out = capsys.readouterr().out
    assert code == 0 and "all checks passed" in out, out
    assert sorted(net.ov(), key=lambda e: e["port_idx"]) == sorted(before, key=lambda e: e["port_idx"])
    assert "auto_restored=True" in out
    puts = [b for m, p, b in net.writes() if m == "PUT"]
    assert puts and all(set(b) == {"port_overrides"} for b in puts)


async def test_it_stops_when_a_test_port_has_link(monkeypatch, tmp_path, capsys):
    mod = prepare(monkeypatch, tmp_path)
    net = FakeSwitchNet()
    mod.ADD_PORT = 2          # Sonos port, link up
    assert await mod.main(True, httpx.MockTransport(net)) == 1
    assert "must be unused" in capsys.readouterr().out and net.writes() == []


async def test_a_failure_midway_still_cleans_up(monkeypatch, tmp_path, capsys):
    mod = prepare(monkeypatch, tmp_path)
    net = FakeSwitchNet()
    before = copy.deepcopy(net.ov())
    orig = net.__call__
    state = {"n": 0}

    def flaky(request):
        if request.method == "PUT":
            state["n"] += 1
            if state["n"] == 3:          # the isolation-on write is rejected
                return httpx.Response(500, json={"message": "boom"})
        return orig(request)
    code = await mod.main(True, httpx.MockTransport(flaky))
    assert code == 1 and "FAILED" in capsys.readouterr().out
    assert sorted(net.ov(), key=lambda e: e["port_idx"]) == sorted(before, key=lambda e: e["port_idx"])
