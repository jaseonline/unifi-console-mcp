"""The traffic-object live check must only touch zz-qoscheck objects, never switch one on, and leave the fake console as it found it."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import httpx

from test_traffic_object import FakeTraffic, make_obj

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "traffic_object_live_check.py"
GUEST = "03003e5f-5932-42e8-b9f4-e2cdac44aab2"


def load():
    spec = importlib.util.spec_from_file_location("traffic_object_live_check", SCRIPT)
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


async def test_run_creates_edits_deletes_and_never_switches_the_object_on(monkeypatch, tmp_path, capsys):
    patch_settings(monkeypatch, tmp_path)
    real = make_obj("real", "Real limit", enabled=True, qos_on=True, down=1000)
    net = FakeTraffic([real, make_obj("old", "zz-qoscheck-old", GUEST)])               # an earlier aborted run is cleaned up first
    code = await load().main(True, httpx.MockTransport(net))
    out = capsys.readouterr().out
    assert code == 0 and "all checks passed" in out
    assert list(net.items) == ["real"] and net.items["real"] == real
    assert all(body.get("enabled") is False for body in net.bodies)
    assert not any(m in ("PUT", "DELETE") and p.endswith("/real") for m, p, _ in net.log)


async def test_failure_midway_still_cleans_up(monkeypatch, tmp_path, capsys):
    patch_settings(monkeypatch, tmp_path)
    net = FakeTraffic()
    net.ignore_put = True
    code = await load().main(True, httpx.MockTransport(net))
    assert code == 1 and "FAILED" in capsys.readouterr().out
    assert net.items == {}
