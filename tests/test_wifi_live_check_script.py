"""The Wi-Fi live check only touches its throwaway SSID and always ends on the original state."""
from __future__ import annotations

import copy

import httpx

from test_doh import load_script
from test_wifi import FakeWifi


def prepare(monkeypatch, tmp_path):
    from unifi_console_mcp.config import Settings

    monkeypatch.setattr(Settings, "from_env", classmethod(lambda cls: cls(
        host="console.test", username="u", password="p", journal_dir=tmp_path / "journal")))
    return load_script("wifi_live_check")


async def test_dry_run_touches_nothing(capsys):
    assert await load_script("wifi_live_check").main(False) == 0
    assert "Dry run only" in capsys.readouterr().out


async def test_run_proves_the_tool_and_leaves_nothing_behind(monkeypatch, tmp_path, capsys):
    mod = prepare(monkeypatch, tmp_path)
    count = iter(range(100))
    monkeypatch.setattr(mod.secrets, "token_urlsafe", lambda n: f"SENTINEL-{next(count)}-" + "x" * n)
    net = FakeWifi()
    before = copy.deepcopy(net.rows)
    code = await mod.main(True, httpx.MockTransport(net), pause=0)
    out = capsys.readouterr().out
    assert code == 0 and "all checks passed" in out, out
    assert net.rows == before
    sent = [(m, p) for m, p, _ in net.writes()]
    real = {r["_id"] for r in before}
    assert not any(p.rsplit("/", 1)[1] in real for m, p in sent if m in ("PUT", "DELETE"))
    assert {m for m, _ in sent} == {"POST", "PUT", "DELETE"}
    import os
    assert "UNIFI_WIFI_CHECK_A" not in os.environ and "SENTINEL" not in out


async def test_it_stops_when_the_throwaway_name_exists(monkeypatch, tmp_path, capsys):
    mod = prepare(monkeypatch, tmp_path)
    net = FakeWifi()
    net.rows.append({**net.rows[0], "_id": "w-zz", "name": "zz-wificheck"})
    assert await mod.main(True, httpx.MockTransport(net), pause=0) == 1
    assert "already exists" in capsys.readouterr().out and net.writes() == []


async def test_a_failure_midway_still_deletes_the_throwaway(monkeypatch, tmp_path, capsys):
    mod = prepare(monkeypatch, tmp_path)
    net = FakeWifi()
    before = copy.deepcopy(net.rows)
    orig = net.__call__
    state = {"puts": 0}

    def flaky(request):
        if request.method == "PUT":
            state["puts"] += 1
            if state["puts"] == 2:
                return httpx.Response(500, json={"message": "boom"})
        return orig(request)

    assert await mod.main(True, httpx.MockTransport(flaky), pause=0) == 1
    assert net.rows == before and "cleanup" in capsys.readouterr().out
