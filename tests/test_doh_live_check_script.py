"""The DoH live check changes only the DoH group, only by adding Google's resolvers, and always ends on the original."""
from __future__ import annotations

import httpx

from test_doh import FakeDoh, ORIGINAL, dns, load_script  # noqa: F401  (dns is a fixture)


def patch_settings(monkeypatch, tmp_path, port):
    from unifi_console_mcp.config import Settings

    monkeypatch.setattr(Settings, "from_env", classmethod(lambda cls: cls(
        host="console.test", username="u", password="p", journal_dir=tmp_path / "journal",
        dns_probe_server=f"127.0.0.1:{port}", dns_probe_window=1.0)))


async def test_dry_run_touches_nothing(capsys):
    assert await load_script("doh_live_check").main(False) == 0
    assert "Dry run only" in capsys.readouterr().out


async def test_run_adds_reverts_proves_the_auto_restore_and_ends_on_the_original(monkeypatch, tmp_path, dns, capsys):
    patch_settings(monkeypatch, tmp_path, dns.port)
    net = FakeDoh(dns)
    code = await load_script("doh_live_check").main(True, httpx.MockTransport(net))
    out = capsys.readouterr().out
    assert code == 0 and "all checks passed" in out, out
    assert {k: net.group[k] for k in ORIGINAL} == ORIGINAL
    assert all(set(b) == {"key", "state", "server_names", "custom_servers"} for b in net.bodies)
    assert len(net.bodies) == 4          # add, revert, add (forced fail), automatic restore
    assert "auto_restored=True" in out


async def test_it_stops_unless_doh_is_in_manual_mode(monkeypatch, tmp_path, dns, capsys):
    patch_settings(monkeypatch, tmp_path, dns.port)
    net = FakeDoh(dns, {**ORIGINAL, "state": "off", "server_names": []})
    assert await load_script("doh_live_check").main(True, httpx.MockTransport(net)) == 1
    assert "not in manual mode" in capsys.readouterr().out and net.writes() == []


async def test_a_failure_midway_still_ends_on_the_original(monkeypatch, tmp_path, dns, capsys):
    patch_settings(monkeypatch, tmp_path, dns.port)
    net = FakeDoh(dns)
    net.ignore_post = True                        # the console silently ignores writes: the check must fail but touch nothing else
    code = await load_script("doh_live_check").main(True, httpx.MockTransport(net))
    assert code == 1 and "FAILED" in capsys.readouterr().out
    assert {k: net.group[k] for k in ORIGINAL} == ORIGINAL
