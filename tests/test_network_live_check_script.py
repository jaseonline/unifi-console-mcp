"""The network live check only touches its throwaway VLAN and always ends on the original state."""
from __future__ import annotations

import copy

import httpx

from test_doh import load_script
from test_network import FakeNet, N_PRIV
from test_doh import FakeDns


def prepare(monkeypatch, tmp_path, dns):
    from unifi_console_mcp.config import Settings

    monkeypatch.setattr(Settings, "from_env", classmethod(lambda cls: cls(
        host="console.test", username="u", password="p", journal_dir=tmp_path / "journal", dns_probe_server=f"127.0.0.1:{dns.port}",
        dns_probe_window=1.0)))
    monkeypatch.setattr("unifi_console_mcp.entities.network.socket.gethostbyname", lambda host: "192.168.1.2")
    return load_script("network_live_check")


async def test_dry_run_touches_nothing(capsys):
    assert await load_script("network_live_check").main(False) == 0
    assert "Dry run only" in capsys.readouterr().out


async def test_run_proves_the_tool_and_leaves_nothing_behind(monkeypatch, tmp_path, capsys):
    dns = FakeDns()
    try:
        mod = prepare(monkeypatch, tmp_path, dns)
        fake = FakeNet(dns)
        before = copy.deepcopy(fake.rows)
        code = await mod.main(True, httpx.MockTransport(fake))
        out = capsys.readouterr().out
        assert code == 0 and "all checks passed" in out, out
        assert fake.rows == before and "auto_restored=True" in out
        real = {r["_id"] for r in before}
        for m, p, b in fake.writes():
            if m in ("PUT", "DELETE") and p.rsplit("/", 1)[-1] != "networkconf":
                assert p.rsplit("/", 1)[1] not in real
            if p.endswith("/group/networkconf"):
                assert not set(b["id"]) & real
    finally:
        dns.close()


async def test_it_stops_when_the_zone_is_not_empty(monkeypatch, tmp_path, capsys):
    dns = FakeDns()
    try:
        mod = prepare(monkeypatch, tmp_path, dns)
        fake = FakeNet(dns)
        fake.rows[1]["firewall_zone_id"] = "z-dmz"
        assert await mod.main(True, httpx.MockTransport(fake)) == 1
        assert "not empty" in capsys.readouterr().out and fake.writes() == []
    finally:
        dns.close()


async def test_a_failure_midway_still_deletes_the_throwaway(monkeypatch, tmp_path, capsys):
    dns = FakeDns()
    try:
        mod = prepare(monkeypatch, tmp_path, dns)
        fake = FakeNet(dns)
        before = copy.deepcopy(fake.rows)
        orig = fake.__call__
        state = {"puts": 0}

        def flaky(request):
            if request.method == "PUT" and not request.url.path.endswith("/group/networkconf"):
                state["puts"] += 1
                return httpx.Response(500, json={"message": "boom"})
            return orig(request)

        assert await mod.main(True, httpx.MockTransport(flaky)) == 1
        assert fake.rows == before and "cleanup" in capsys.readouterr().out
    finally:
        dns.close()
