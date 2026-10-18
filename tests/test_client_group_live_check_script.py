"""The client-group live check must only touch zz-groupcheck groups and leave the fake console as it found it."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import httpx

from test_client_group import CAMS, SONOS, FakeGroups

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "client_group_live_check.py"
HUB = "02:00:00:00:00:23"


def load():
    spec = importlib.util.spec_from_file_location("client_group_live_check", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def patch_settings(monkeypatch, tmp_path):
    from unifi_console_mcp.config import Settings

    monkeypatch.setattr(Settings, "from_env", classmethod(lambda cls: cls(
        host="console.test", username="u", password="p", journal_dir=tmp_path / "journal")))


def fake() -> FakeGroups:
    net = FakeGroups()
    net.clients.append({"mac": HUB, "name": "Harmony Hub"})
    return net


async def test_dry_run_touches_nothing(capsys):
    assert await load().main(False) == 0
    assert "Dry run only" in capsys.readouterr().out


async def test_run_creates_edits_deletes_and_leaves_real_groups_alone(monkeypatch, tmp_path, capsys):
    patch_settings(monkeypatch, tmp_path)
    net = fake()
    net.items["old"] = {"id": "old", "name": "zz-groupcheck-old", "type": "CLIENTS", "members": ["02:00:00:00:00:01"]}   # earlier aborted run
    code = await load().main(True, httpx.MockTransport(net))
    out = capsys.readouterr().out
    assert code == 0 and "all checks passed" in out
    assert sorted(net.items) == sorted([SONOS["id"], CAMS["id"]]) and net.items[SONOS["id"]] == SONOS
    assert not any(m in ("PUT", "DELETE") and p.endswith((SONOS["id"], CAMS["id"])) for m, p, _ in net.log)
    assert "used_by=[]" in out and "warnings about the Hub: none" in out


async def test_failure_midway_still_cleans_up(monkeypatch, tmp_path, capsys):
    patch_settings(monkeypatch, tmp_path)
    net = fake()
    net.ignore_put = True
    code = await load().main(True, httpx.MockTransport(net))
    assert code == 1 and "FAILED" in capsys.readouterr().out
    assert sorted(net.items) == sorted([SONOS["id"], CAMS["id"]])
