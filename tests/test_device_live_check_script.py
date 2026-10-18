"""The device live check only ever touches the chosen access point (and an explicit spare) and always puts it back."""
from __future__ import annotations

import copy

import httpx
import pytest

from test_device import AP, GW, NEW, SW, FakeDevices, no_sleep  # noqa: F401  (no_sleep: autouse fixture)
from test_doh import load_script


def prepare(monkeypatch, tmp_path):
    from unifi_console_mcp.config import Settings

    monkeypatch.setattr(Settings, "from_env", classmethod(lambda cls: cls(
        host="console.test", username="u", password="p", journal_dir=tmp_path / "journal")))
    mod = load_script("device_live_check")

    async def fast(_seconds: float) -> None:
        return None
    monkeypatch.setattr(mod, "_pause", fast)
    return mod


async def test_dry_run_touches_nothing(capsys):
    assert await load_script("device_live_check").main(False) == 0
    assert "Dry run only" in capsys.readouterr().out


async def test_run_needs_an_ap(monkeypatch, tmp_path, capsys):
    mod = prepare(monkeypatch, tmp_path)
    net = FakeDevices()
    assert await mod.main(True, httpx.MockTransport(net)) == 2 and net.writes() == []


async def test_unknown_stage_is_refused(monkeypatch, tmp_path):
    mod = prepare(monkeypatch, tmp_path)
    net = FakeDevices()
    assert await mod.main(True, httpx.MockTransport(net), ap=AP, stages=("wipe",)) == 2 and net.writes() == []


async def test_a_leaf_switch_is_accepted_and_put_back(monkeypatch, tmp_path, capsys):
    mod = prepare(monkeypatch, tmp_path)
    net = FakeDevices()
    net.rows = [r for r in net.rows if r["type"] != "uap"]        # nothing behind the switch now
    assert await mod.main(True, httpx.MockTransport(net), ap=SW,
                          stages=("locate", "rename", "led", "disable", "restart")) == 0, capsys.readouterr().out
    sw = next(r for r in net.rows if r["mac"] == SW)
    assert sw["name"] == "Switch-Core" and not sw.get("disabled") and not sw.get("locating")
    assert {b.get("mac") for _m, p, b in net.writes() if p.endswith("devmgr")} == {SW}


@pytest.mark.parametrize("ap", [SW, GW])
async def test_only_a_leaf_access_point_or_switch_is_accepted(monkeypatch, tmp_path, ap):
    mod = prepare(monkeypatch, tmp_path)
    net = FakeDevices()
    assert await mod.main(True, httpx.MockTransport(net), ap=ap) == 2 and net.writes() == []


async def test_default_stages_leave_the_ap_as_it_was(monkeypatch, tmp_path, capsys):
    mod = prepare(monkeypatch, tmp_path)
    net = FakeDevices()
    before = copy.deepcopy(net.rows)
    assert await mod.main(True, httpx.MockTransport(net), ap="AP-Lounge") == 0, capsys.readouterr().out
    ap = net.rows[0]
    assert ap["name"] == before[0]["name"] and not ap.get("locating") and ap.get("led_override") == "default"
    assert net.rows[1:] == before[1:]
    methods = {(m, p.rsplit("/", 1)[-1]) for m, p, _b in net.writes()}
    assert ("PUT", "id-ap") in methods
    assert not any(p.endswith("sitemgr") for _m, p, _b in net.writes())
    assert {b.get("name") for _m, _p, b in net.writes() if isinstance(b, dict) and "name" in b} <= {"AP-Lounge", "AP-Lounge-check"}


async def test_full_stages_disable_and_restart_the_ap_only(monkeypatch, tmp_path, capsys):
    mod = prepare(monkeypatch, tmp_path)
    net = FakeDevices()
    assert await mod.main(True, httpx.MockTransport(net), ap=AP,
                          stages=("locate", "rename", "led", "disable", "restart")) == 0, capsys.readouterr().out
    assert not net.rows[0].get("disabled")
    touched = {b.get("mac") for _m, p, b in net.writes() if p.endswith("devmgr")}
    assert touched == {AP}
    assert all(p.endswith("id-ap") or p.endswith("devmgr") for _m, p, _b in net.writes())


async def test_remove_adopt_needs_a_device_and_never_the_ap(monkeypatch, tmp_path, capsys):
    mod = prepare(monkeypatch, tmp_path)
    net = FakeDevices()
    assert await mod.main(True, httpx.MockTransport(net), ap=AP, stages=("remove-adopt",)) == 2
    assert await mod.main(True, httpx.MockTransport(net), ap=AP, stages=("remove-adopt",), spare=AP) == 2
    assert await mod.main(True, httpx.MockTransport(net), stages=("remove", "remove-adopt"), spare=AP) == 2
    assert net.writes() == []


def leaf_switch_net():
    net = FakeDevices()
    net.pending = []
    net.rows = [r for r in net.rows if r["type"] != "uap"]         # nothing behind the switch
    net.rows[0]["name"] = "Switch-Leaf"
    net.rows[0]["stp_priority"] = "8192"
    return net


async def test_remove_then_adopt_as_two_separate_runs_restores_what_it_can(monkeypatch, tmp_path, capsys):
    mod = prepare(monkeypatch, tmp_path)
    net = leaf_switch_net()
    net.rows[0]["port_overrides"] = [{"port_idx": 3, "name": "TV", "native_networkconf_id": "net-a"}]
    # run 1: remove only
    assert await mod.main(True, httpx.MockTransport(net), stages=("remove",), spare=SW) == 0, capsys.readouterr().out
    out1 = capsys.readouterr().out
    assert not any(r["mac"] == SW for r in net.rows) and [p for p in net.pending if p["mac"] == SW]
    snaps = list((tmp_path / "journal" / "device-snapshots").glob("*.json"))
    assert len(snaps) == 1 and "TV" in snaps[0].read_text() and "Switch-Leaf" in snaps[0].read_text()
    # run 2: adopt only, no --ap needed
    assert await mod.main(True, httpx.MockTransport(net), stages=("adopt",), spare=SW) == 0
    out2 = capsys.readouterr().out
    sw = next(r for r in net.rows if r["mac"] == SW)
    assert sw["name"] == "Switch-Leaf" and sw["stp_priority"] == "8192"
    assert "port settings for port(s) 3" in out2 and "NOT restored automatically" in out2
    assert net.writes()[-1][0] == "PUT"


async def test_remove_adopt_in_one_run(monkeypatch, tmp_path, capsys):
    mod = prepare(monkeypatch, tmp_path)
    net = leaf_switch_net()
    assert await mod.main(True, httpx.MockTransport(net), stages=("remove-adopt",), spare=SW) == 0, capsys.readouterr().out
    assert next(r for r in net.rows if r["mac"] == SW)["name"] == "Switch-Leaf"


async def test_remove_refuses_a_device_with_something_behind_it(monkeypatch, tmp_path, capsys):
    mod = prepare(monkeypatch, tmp_path)
    net = FakeDevices()                                            # the AP hangs off the switch
    assert await mod.main(True, httpx.MockTransport(net), stages=("remove",), spare=SW) == 1
    assert net.writes() == [] and not list((tmp_path / "journal").rglob("*.json"))


async def test_adopt_without_a_snapshot_still_adopts(monkeypatch, tmp_path, capsys):
    mod = prepare(monkeypatch, tmp_path)
    net = leaf_switch_net()
    net.rows = [r for r in net.rows if r["mac"] != SW]
    net.pending = [{"_id": "p", "mac": SW, "name": "USW8", "type": "usw", "adopted": False, "state": 2}]
    assert await mod.main(True, httpx.MockTransport(net), stages=("adopt",), spare=SW) == 0
    assert "no snapshot found" in capsys.readouterr().out


async def test_a_failure_midway_still_restores(monkeypatch, tmp_path, capsys):
    mod = prepare(monkeypatch, tmp_path)
    net = FakeDevices()
    orig = net.__call__
    state = {"puts": 0}

    def flaky(request):
        if request.method == "PUT":
            state["puts"] += 1
            if state["puts"] == 1:
                return httpx.Response(500, json={"message": "boom"})
        return orig(request)

    assert await mod.main(True, httpx.MockTransport(flaky), ap=AP) == 1
    assert net.rows[0]["name"] == "AP-Lounge" and not net.rows[0].get("locating")
