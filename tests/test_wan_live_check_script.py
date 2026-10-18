"""The WAN live check only flips report_wan_event and always ends on the original state."""
from __future__ import annotations

import copy

import httpx

from test_doh import FakeDns, load_script
from test_wan import N_WAN, FakeWan, NETS


def prepare(monkeypatch, tmp_path, dns, fake):
    from unifi_console_mcp.config import Settings
    from unifi_console_mcp.entities import wan as wan_mod

    monkeypatch.setattr(Settings, "from_env", classmethod(lambda cls: cls(
        host="console.test", username="u", password="p", journal_dir=tmp_path / "journal", dns_probe_server=f"127.0.0.1:{dns.port}",
        dns_probe_window=1.0)))
    monkeypatch.setattr(wan_mod, "_tcp_ok", lambda host, port, timeout: fake.internet)
    return load_script("wan_live_check")


async def test_dry_run_touches_nothing(capsys):
    assert await load_script("wan_live_check").main(False) == 0
    assert "Dry run only" in capsys.readouterr().out


async def test_run_proves_the_tool_and_leaves_the_wan_as_it_was(monkeypatch, tmp_path, capsys):
    dns = FakeDns()
    try:
        fake = FakeWan(dns)
        mod = prepare(monkeypatch, tmp_path, dns, fake)
        before = copy.deepcopy(fake.rows)
        code = await mod.main(True, httpx.MockTransport(fake))
        out = capsys.readouterr().out
        assert code == 0 and "all checks passed" in out, out
        assert fake.rows == before and "auto_restored=True" in out
        assert len(fake.puts) == 4                                   # flip, flip back, forced flip, its restore
        for body in fake.puts:                                       # only the one harmless field ever differs from the original
            assert {k for k in body if body[k] != before[-1].get(k) and k != "report_wan_event"} == set()
        assert all(p == f"{NETS}/{N_WAN}" for m, p, _ in fake.writes() if m == "PUT")
    finally:
        dns.close()


async def test_it_stops_when_the_internet_is_down(monkeypatch, tmp_path, capsys):
    dns = FakeDns()
    try:
        fake = FakeWan(dns)
        fake.internet = False
        mod = prepare(monkeypatch, tmp_path, dns, fake)
        assert await mod.main(True, httpx.MockTransport(fake)) == 1
        assert "internet probe fails" in capsys.readouterr().out and not fake.puts
    finally:
        dns.close()


async def test_it_stops_when_a_device_is_down(monkeypatch, tmp_path, capsys):
    dns = FakeDns()
    try:
        fake = FakeWan(dns)
        fake.devs[1]["state"] = 0
        mod = prepare(monkeypatch, tmp_path, dns, fake)
        assert await mod.main(True, httpx.MockTransport(fake)) == 1
        assert "devices not connected" in capsys.readouterr().out and not fake.puts
    finally:
        dns.close()


async def test_a_failure_midway_still_puts_the_setting_back(monkeypatch, tmp_path, capsys):
    dns = FakeDns()
    try:
        fake = FakeWan(dns)
        mod = prepare(monkeypatch, tmp_path, dns, fake)
        before = copy.deepcopy(fake.rows)
        orig = fake.__call__
        n = {"put": 0}

        def flaky(request):
            if request.method == "PUT" and request.url.path.endswith(N_WAN):
                n["put"] += 1
                if n["put"] == 2:                                    # the flip back fails
                    return httpx.Response(500, json={"message": "boom"})
            return orig(request)

        code = await mod.main(True, httpx.MockTransport(flaky))
        assert code == 1 and fake.rows == before and "cleanup" in capsys.readouterr().out
    finally:
        dns.close()
