"""The one-record removal script deletes only the record whose id and key both match."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import httpx

from test_network_list_live_check_script import patch_settings
from test_static_dns import NAS, OFF, FakeDns

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "remove_static_dns_record.py"


def load():
    spec = importlib.util.spec_from_file_location("remove_static_dns_record", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


async def test_dry_run_deletes_nothing(monkeypatch, tmp_path, capsys):
    patch_settings(monkeypatch, tmp_path)
    net = FakeDns()
    assert await load().main(OFF["_id"], OFF["key"], False, httpx.MockTransport(net)) == 0
    assert OFF["_id"] in net.items and net.writes() == [] and "Dry run only" in capsys.readouterr().out


async def test_run_deletes_the_matching_record_only(monkeypatch, tmp_path, capsys):
    patch_settings(monkeypatch, tmp_path)
    net = FakeDns()
    assert await load().main(OFF["_id"], OFF["key"], True, httpx.MockTransport(net)) == 0
    assert OFF["_id"] not in net.items and NAS["_id"] in net.items and len(net.writes()) == 1


async def test_refuses_when_the_key_does_not_match(monkeypatch, tmp_path, capsys):
    patch_settings(monkeypatch, tmp_path)
    net = FakeDns()
    assert await load().main(OFF["_id"], "something.else", True, httpx.MockTransport(net)) == 1
    assert OFF["_id"] in net.items and net.writes() == [] and "STOP" in capsys.readouterr().out
