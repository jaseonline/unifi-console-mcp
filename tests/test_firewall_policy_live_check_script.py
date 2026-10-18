"""The firewall live check only touches zz-fwcheck-* policies in Dmz -> Vpn and always ends on the original state."""
from __future__ import annotations

import httpx

from test_doh import load_script
from test_firewall_policy import FakeFw, Z, dns, policy, ep  # noqa: F401  (dns is a fixture)


def patch_settings(monkeypatch, tmp_path, port):
    from unifi_console_mcp.config import Settings

    monkeypatch.setattr(Settings, "from_env", classmethod(lambda cls: cls(
        host="console.test", username="u", password="p", journal_dir=tmp_path / "journal",
        dns_probe_server=f"127.0.0.1:{port}", dns_probe_window=1.0)))
    monkeypatch.setattr("unifi_console_mcp.entities.firewall_policy.socket.gethostbyname", lambda host: "127.0.0.1")


async def test_dry_run_touches_nothing(capsys):
    assert await load_script("firewall_policy_live_check").main(False) == 0
    assert "Dry run only" in capsys.readouterr().out


async def test_run_proves_every_action_and_leaves_nothing_behind(monkeypatch, tmp_path, dns, capsys):
    patch_settings(monkeypatch, tmp_path, dns.port)
    net = FakeFw(dns)
    before = [dict(r) for r in net.rows]
    code = await load_script("firewall_policy_live_check").main(True, httpx.MockTransport(net))
    out = capsys.readouterr().out
    assert code == 0 and "all checks passed" in out, out
    assert [r["_id"] for r in net.rows] == [r["_id"] for r in before]
    assert all(r["name"].startswith("zz-fwcheck") is False for r in net.rows)
    kinds = [(m, p.rsplit("/", 1)[-1]) for m, p, _ in net.writes()]
    assert ("PUT", "batch-reorder") in kinds and ("POST", "batch-delete") in kinds and ("POST", "firewall-policies") in kinds
    assert "auto_restored=True" in out
    for _, p, body in net.writes():            # nothing outside the throwaway pair is ever written
        if isinstance(body, dict) and "source" in body:
            assert body["source"]["zone_id"] == Z["Dmz"] and body["destination"]["zone_id"] == Z["Vpn"]


async def test_it_stops_when_a_zone_has_networks(monkeypatch, tmp_path, dns, capsys):
    patch_settings(monkeypatch, tmp_path, dns.port)
    net = FakeFw(dns)
    orig = net.__call__
    def zones_with_net(request):
        resp = orig(request)
        if request.url.path.endswith("/firewall/zone"):
            import json
            data = json.loads(resp.content)
            for z in data:
                if z["name"] == "Dmz":
                    z["network_ids"] = ["n-iot"]
            return httpx.Response(200, json=data)
        return resp
    assert await load_script("firewall_policy_live_check").main(True, httpx.MockTransport(zones_with_net)) == 1
    assert "no networks" in capsys.readouterr().out and net.writes() == []


async def test_a_failure_midway_still_cleans_up(monkeypatch, tmp_path, dns, capsys):
    patch_settings(monkeypatch, tmp_path, dns.port)
    net = FakeFw(dns)
    net.break_dns = lambda m, p, b: False
    orig = net._write
    def flaky(method, path, body):
        if method == "PUT" and path.endswith("/batch-reorder"):
            return httpx.Response(200, json=[])          # accepted but ignored: the move check must fail
        return orig(method, path, body)
    net._write = flaky
    code = await load_script("firewall_policy_live_check").main(True, httpx.MockTransport(net))
    assert code == 1 and "FAILED" in capsys.readouterr().out
    assert all(not r["name"].startswith("zz-fwcheck") for r in net.rows)
