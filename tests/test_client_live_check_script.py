"""The client live check must only touch the Harmony Hub and put it back exactly, also when a step fails."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import httpx

from test_client import HUB, FakeClients
from test_network_list_live_check_script import patch_settings

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "client_live_check.py"


def load():
    spec = importlib.util.spec_from_file_location("client_live_check", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def hub(net):
    return net.items[HUB["_id"]]


async def test_dry_run_touches_nothing(capsys):
    assert await load().main(False) == 0
    assert "Dry run only" in capsys.readouterr().out


async def test_run_changes_and_restores_the_hub_and_leaves_others_alone(monkeypatch, tmp_path, capsys):
    patch_settings(monkeypatch, tmp_path)
    net = FakeClients()
    others = {k: dict(v) for k, v in net.items.items() if k != HUB["_id"]}
    code = await load().main(True, transport=httpx.MockTransport(net))
    out = capsys.readouterr().out
    assert code == 0 and "all checks passed" in out, out
    assert {k: hub(net)[k] for k in ("name", "note", "noted", "use_fixedip", "fixed_ip", "local_dns_record", "local_dns_record_enabled")} == {
        k: HUB[k] for k in ("name", "note", "noted", "use_fixedip", "fixed_ip", "local_dns_record", "local_dns_record_enabled")}
    assert {k: v for k, v in net.items.items() if k != HUB["_id"]} == others
    assert all(p.endswith(HUB["_id"]) for m, p, _ in net.writes())
    assert "fixed IP: skipped" in out and len(net.writes()) == 4          # note, name, dns, one restore


async def test_fixed_ip_step_uses_a_spare_address_and_restores(monkeypatch, tmp_path, capsys):
    patch_settings(monkeypatch, tmp_path)
    net = FakeClients()
    code = await load().main(True, with_fixed_ip=True, transport=httpx.MockTransport(net))
    out = capsys.readouterr().out
    assert code == 0, out
    assert any(b.get("fixed_ip") == "10.88.1.99" for b in net.bodies) and hub(net)["fixed_ip"] == "10.88.1.23"


async def test_a_step_failing_midway_still_restores_the_hub(monkeypatch, tmp_path, capsys):
    patch_settings(monkeypatch, tmp_path)
    net = FakeClients()
    net.fail_put_at = 3                                                     # the Local DNS step is refused by the console
    code = await load().main(True, transport=httpx.MockTransport(net))
    out = capsys.readouterr().out
    assert code == 1 and "FAILED" in out
    assert hub(net)["name"] == "Harmony Hub" and hub(net)["note"] == "" and hub(net)["local_dns_record"] == ""


async def test_refuses_to_run_if_the_hub_is_not_what_it_expects(monkeypatch, tmp_path, capsys):
    patch_settings(monkeypatch, tmp_path)
    net = FakeClients()
    hub(net)["name"] = "Something else"
    code = await load().main(True, transport=httpx.MockTransport(net))
    assert code == 1 and "STOP" in capsys.readouterr().out and net.writes() == []
