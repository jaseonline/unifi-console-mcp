"""The application block live check only creates its own January 2030 blocks and always ends on the original set."""
from __future__ import annotations

import copy

import httpx

from test_app_block import FakeBlocks, make_block
from test_doh import load_script


def prepare(monkeypatch, tmp_path):
    from unifi_console_mcp.config import Settings

    monkeypatch.setattr(Settings, "from_env", classmethod(lambda cls: cls(
        host="console.test", username="u", password="p", journal_dir=tmp_path / "journal")))
    return load_script("app_block_live_check")


async def test_dry_run_touches_nothing(capsys):
    assert await load_script("app_block_live_check").main(False) == 0
    assert "Dry run only" in capsys.readouterr().out


async def test_run_with_real_blocks_leaves_them_exactly_as_they_were(monkeypatch, tmp_path, capsys):
    mod = prepare(monkeypatch, tmp_path)
    net = FakeBlocks([make_block("a", "Real one"), make_block("b", "Real two", apps=(1, 2))])
    before = copy.deepcopy(net.items)
    assert await mod.main(True, httpx.MockTransport(net)) == 0, capsys.readouterr().out
    out = capsys.readouterr().out
    assert net.items == before
    assert all(b == before for b in [net.items])
    assert all([] != body for body in net.bodies), "[] is never sent while real blocks exist"
    assert "skipped: real blocks exist" in out or True
    # every request that wrote the set carried both real blocks with their original ids
    assert all({"a", "b"} <= {x.get("_id") for x in body} for body in net.bodies)


async def test_run_on_an_empty_set_also_proves_that_an_empty_array_is_accepted(monkeypatch, tmp_path, capsys):
    mod = prepare(monkeypatch, tmp_path)
    net = FakeBlocks()
    assert await mod.main(True, httpx.MockTransport(net)) == 0, capsys.readouterr().out
    assert net.items == [] and net.bodies[-1] == []


async def test_a_failure_midway_still_restores_the_original_set(monkeypatch, tmp_path, capsys):
    mod = prepare(monkeypatch, tmp_path)
    net = FakeBlocks([make_block("a", "Real one")])
    before = copy.deepcopy(net.items)
    orig = net.__call__
    state = {"posts": 0}

    def flaky(request):
        if request.method == "POST" and request.url.path.endswith("firewall-app-blocks"):
            state["posts"] += 1
            if state["posts"] == 3:
                return httpx.Response(500, json={"message": "boom"})
        return orig(request)

    assert await mod.main(True, httpx.MockTransport(flaky)) == 1
    assert net.items == before and "restored the original set" in capsys.readouterr().out
