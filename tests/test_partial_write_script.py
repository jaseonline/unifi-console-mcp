"""The partial-write test script must create only zz-partial- objects, report differences, and leave nothing behind."""
from __future__ import annotations

import importlib.util
import json
import uuid
from pathlib import Path

import httpx
import pytest

from conftest import make_jwt

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "partial_write_test.py"
L = "/proxy/network/api/s/default"
V2 = "/proxy/network/v2/api/site/default"


class FakeNetwork:
    """In-memory collections. merge=True collections keep omitted fields; others replace the object."""

    def __init__(self) -> None:
        self.store = {
            f"{V2}/static-dns": ({}, True, "_id", False),
            f"{L}/rest/portforward": ({}, True, "_id", True),
            f"{V2}/network-members-group": ({}, False, "id", False),
            f"{L}/rest/firewallgroup": ({}, True, "_id", True),
        }
        # pre-existing real objects that must never be touched
        self.store[f"{V2}/static-dns"][0]["real"] = {"_id": "real", "key": "nuc.example.home", "value": "192.168.1.60"}
        self.log: list[tuple[str, str]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        if path == "/api/auth/login":
            return httpx.Response(200, json={}, headers={"set-cookie": f"TOKEN={make_jwt()}; Path=/", "x-csrf-token": "c"})
        self.log.append((method, path))
        for base, (items, merge, idkey, legacy) in self.store.items():
            if path == base or path.startswith(base + "/"):
                ident = path[len(base) + 1:] or None
                body = json.loads(request.content) if request.content else None
                wrap = (lambda x: {"meta": {"rc": "ok"}, "data": x}) if legacy else (lambda x: x)
                if method == "GET" and ident is None:
                    return httpx.Response(200, json=wrap(list(items.values())))
                if method == "GET":
                    return httpx.Response(200, json=wrap(items[ident]) if ident in items else {})
                if method == "POST":
                    new = {**body, idkey: str(uuid.uuid4())}
                    items[new[idkey]] = new
                    return httpx.Response(200 if legacy else 201, json=wrap([new] if legacy else new))
                if method == "PUT":
                    items[ident] = {**items[ident], **body} if merge else {idkey: ident, **body}
                    return httpx.Response(200, json=wrap([items[ident]] if legacy else items[ident]))
                if method == "DELETE":
                    items.pop(ident, None)
                    return httpx.Response(200, json={})
        return httpx.Response(404, json={})


@pytest.mark.asyncio
async def test_partial_write_script_cleans_up_and_reports(monkeypatch, capsys):
    from unifi_console_mcp.config import Settings

    monkeypatch.setattr(Settings, "from_env", classmethod(lambda cls: cls(host="console.test", username="u", password="p")))
    spec = importlib.util.spec_from_file_location("partial_write_test", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    net = FakeNetwork()
    await mod.main(True, httpx.MockTransport(net))
    out = capsys.readouterr().out

    # nothing created by the script remains, and the real record is untouched
    assert list(net.store[f"{V2}/static-dns"][0]) == ["real"]
    assert not net.store[f"{L}/rest/portforward"][0]
    assert not net.store[f"{V2}/network-members-group"][0]
    assert not net.store[f"{L}/rest/firewallgroup"][0]
    # it only ever wrote to zz-partial- objects or to ids the fake generated
    assert not any(m in ("PUT", "DELETE") and p.endswith("/real") for m, p in net.log)
    # the replace-style collection shows members disappearing
    assert '"disappeared": ["members", "type"]' in out
    assert out.count("partial:") >= 5


@pytest.mark.asyncio
async def test_dry_run_touches_nothing(capsys):
    spec = importlib.util.spec_from_file_location("partial_write_test", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    await mod.main(False)
    assert "Dry run only" in capsys.readouterr().out
