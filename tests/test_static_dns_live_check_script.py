"""The static DNS live check must only touch zz-dnscheck records and leave the fake console as it found it."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import httpx

from test_network_list_live_check_script import patch_settings
from test_static_dns import ALIAS, NAS, OFF, V6, FakeDns, rec

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "static_dns_live_check.py"


def load():
    spec = importlib.util.spec_from_file_location("static_dns_live_check", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


async def test_dry_run_touches_nothing(capsys):
    assert await load().main(False) == 0
    assert "Dry run only" in capsys.readouterr().out


async def test_run_creates_edits_deletes_and_leaves_real_records_alone(monkeypatch, tmp_path, capsys):
    patch_settings(monkeypatch, tmp_path)
    net = FakeDns()
    net.items["old"] = rec("old", "zz-dnscheck.example.home", "A", "192.0.2.1")        # earlier aborted run
    real = {r["_id"]: dict(r) for r in (NAS, ALIAS, V6, OFF)}
    code = await load().main(True, httpx.MockTransport(net))
    out = capsys.readouterr().out
    assert code == 0 and "all checks passed" in out, out
    assert net.items == real
    assert not any(m in ("PUT", "DELETE") and p.rsplit("/", 1)[1] in real for m, p, _ in net.writes())
    assert "applied=False" in out


async def test_failure_midway_still_cleans_up(monkeypatch, tmp_path, capsys):
    patch_settings(monkeypatch, tmp_path)
    net = FakeDns()
    net.ignore_put = True
    code = await load().main(True, httpx.MockTransport(net))
    assert code == 1 and "FAILED" in capsys.readouterr().out
    assert set(net.items) == {NAS["_id"], ALIAS["_id"], V6["_id"], OFF["_id"]}
