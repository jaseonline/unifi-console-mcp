"""The live-check script must only touch zz-pfcheck rules, never enable one, and leave the fake console as it found it."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import httpx

from test_writes import REAL, FakePortForwards

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "port_forward_live_check.py"


def load():
    spec = importlib.util.spec_from_file_location("port_forward_live_check", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def patch_settings(monkeypatch, tmp_path):
    from unifi_console_mcp.config import Settings

    monkeypatch.setattr(Settings, "from_env", classmethod(lambda cls: cls(
        host="console.test", username="u", password="p", journal_dir=tmp_path / "journal")))


async def test_dry_run_touches_nothing(capsys):
    mod = load()
    assert await mod.main(False) == 0
    assert "Dry run only" in capsys.readouterr().out


async def test_run_creates_renames_deletes_and_never_enables(monkeypatch, tmp_path, capsys):
    patch_settings(monkeypatch, tmp_path)
    net = FakePortForwards(with_real=True)
    net.items["old"] = {**REAL, "_id": "old", "name": "zz-pfcheck-old", "enabled": False, "dst_port": "58690"}   # earlier aborted run
    mod = load()
    code = await mod.main(True, httpx.MockTransport(net))
    out = capsys.readouterr().out
    assert code == 0 and "all checks passed" in out
    assert list(net.items) == ["real1"] and net.items["real1"] == REAL            # only the real rule remains, untouched
    assert not any(b.get("enabled") is True for b in net.bodies)                   # nothing was ever enabled
    assert not any(m in ("PUT", "DELETE") and p.endswith("/real1") for m, p, _ in net.log)
    assert "exposes" in out and "applied=False" in out


async def test_failure_midway_still_cleans_up(monkeypatch, tmp_path, capsys):
    patch_settings(monkeypatch, tmp_path)
    net = FakePortForwards(with_real=True)
    net.ignore_put = True                                   # the rename will not stick, so the check must report failure
    mod = load()
    code = await mod.main(True, httpx.MockTransport(net))
    out = capsys.readouterr().out
    assert code == 1 and "FAILED" in out
    assert list(net.items) == ["real1"]
