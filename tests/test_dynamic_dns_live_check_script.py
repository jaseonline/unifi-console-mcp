"""The Dynamic DNS live check must only touch zz-ddnscheck entries, keep the token out of every output and clean up."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import httpx

from test_dynamic_dns import REAL, FakeDdns

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "dynamic_dns_live_check.py"


def load():
    spec = importlib.util.spec_from_file_location("dynamic_dns_live_check", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def patch_settings(monkeypatch, tmp_path):
    from unifi_console_mcp.config import Settings

    monkeypatch.setattr(Settings, "from_env", classmethod(lambda cls: cls(
        host="console.test", username="u", password="p", journal_dir=tmp_path / "journal")))


async def test_dry_run_touches_nothing(capsys):
    assert await load().main(False) == 0
    assert "Dry run only" in capsys.readouterr().out


async def test_run_creates_deletes_and_leaves_the_real_entry_alone(monkeypatch, tmp_path, capsys):
    patch_settings(monkeypatch, tmp_path)
    net = FakeDdns()
    net.items["old"] = {**REAL, "_id": "old", "host_name": "zz-ddnscheck.invalid", "interface": "wan2"}     # earlier aborted run
    code = await load().main(True, httpx.MockTransport(net))
    out = capsys.readouterr().out
    assert code == 0 and "all checks passed" in out
    assert list(net.items) == [REAL["_id"]] and net.items[REAL["_id"]] == REAL
    assert not any(m == "DELETE" and p.endswith(REAL["_id"]) for m, p, _ in net.log)
    assert "found in any tool output or journal file: False" in out and "refused without discard_token: True" in out


async def test_failure_midway_still_cleans_up(monkeypatch, tmp_path, capsys):
    patch_settings(monkeypatch, tmp_path)
    net = FakeDdns()
    net.ignore_post = True
    code = await load().main(True, httpx.MockTransport(net))
    assert code == 1 and "FAILED" in capsys.readouterr().out
    assert list(net.items) == [REAL["_id"]]
