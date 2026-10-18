"""DNS over HTTPS through the write framework: a settings group, tier C, with a DNS safety probe and one automatic restore."""
from __future__ import annotations

import contextlib
import dataclasses
import json
import socket
import struct
import threading

import httpx
import pytest
from mcp.client import Client

from conftest import make_jwt
from test_writes import Wrapped
from unifi_console_mcp.server import create_server

GET = "/proxy/network/api/s/default/get/setting/doh"
POST = "/proxy/network/api/s/default/set/setting/doh"
NAMES = "/proxy/network/v2/api/site/default/settings/doh/available-server-names"
NETS = "/proxy/network/api/s/default/rest/networkconf"
TOOL = "unifi_console_doh"
NOTE = "plan claude/unifi-console-doh-plan-2026-10-18.md, approved in chat"
ORIGINAL = {"_id": "f6ba6f7f-818f-4819-a1e3-e9316aa2e8a7", "key": "doh", "state": "manual",
            "server_names": ["cloudflare", "cloudflare-ipv6"], "custom_servers": []}
AVAILABLE = ["cloudflare", "cloudflare-ipv6", "google", "google-ipv6", "quad9-dnscrypt-ip4-filter-pri"]
GOOD_STAMP = "sdns://AgcAAAAAAAAACTEuMS4xLjEAABEvZG5zLXF1ZXJ5aHR0cHM6Ly8"          # contains the text https://


class FakeDns:
    """A UDP DNS server on 127.0.0.1. mode: ok (NXDOMAIN), servfail, silent."""

    def __init__(self) -> None:
        self.mode = "ok"
        self.refuse_first = 0          # answer REFUSED to this many queries before behaving normally
        self.queries = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()

    def _run(self) -> None:
        while not self._stop:
            try:
                data, addr = self.sock.recvfrom(2048)
            except (socket.timeout, OSError):
                continue
            self.queries += 1
            if self.mode == "silent":
                continue
            rcode = 3 if self.mode == "ok" else 2
            if self.refuse_first > 0:
                self.refuse_first -= 1
                rcode = 5
            flags = 0x8000 | 0x0100 | 0x0080 | rcode
            self.sock.sendto(data[:2] + struct.pack(">H", flags) + data[4:], addr)

    def close(self) -> None:
        self._stop = True
        self._t.join(timeout=2)
        self.sock.close()


@pytest.fixture
def dns():
    server = FakeDns()
    yield server
    server.close()


class FakeDoh:
    def __init__(self, dns: FakeDns, state=ORIGINAL) -> None:
        self.dns = dns
        self.group = json.loads(json.dumps(state))
        self.log: list[tuple[str, str, dict | None]] = []
        self.bodies: list[dict] = []
        self.reject = False
        self.ignore_post = False
        self.break_dns_when = lambda body: False     # called with each POST body: should DNS stop working after it?
        self.fail_posts_after = None                 # let N posts succeed, then answer 500 (to make a restore fail)
        self.posts = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        if path == "/api/auth/login":
            return httpx.Response(200, json={}, headers={"set-cookie": f"TOKEN={make_jwt()}; Path=/", "x-csrf-token": "c"})
        body = json.loads(request.content) if request.content else None
        self.log.append((method, path, body))
        wrap = lambda x: {"meta": {"rc": "ok"}, "data": x}  # noqa: E731
        if path == GET:
            return httpx.Response(200, json=wrap([self.group]))
        if path == NAMES:
            return httpx.Response(200, json={"server_names": AVAILABLE})
        if path == NETS:
            return httpx.Response(200, json=wrap([{"_id": "n1", "name": "Default", "purpose": "corporate", "ip_subnet": "127.0.0.1/8"}]))
        if path == POST and method == "POST":
            self.posts += 1
            if self.fail_posts_after is not None and self.posts > self.fail_posts_after:
                return httpx.Response(500, json={"meta": {"rc": "error", "msg": "api.err.Boom"}, "data": []})
            if self.reject:
                return httpx.Response(400, json={"meta": {"rc": "error", "msg": "api.err.Invalid"}, "data": []})
            self.bodies.append(body)
            if not self.ignore_post:
                self.group = {**self.group, **{k: v for k, v in body.items()}}
            if self.break_dns_when(body):
                self.dns.mode = "servfail"
            return httpx.Response(200, json=wrap([self.group]))
        return httpx.Response(404, json={})

    def writes(self):
        return [e for e in self.log if e[0] in ("POST", "PUT", "DELETE") and "login" not in e[1]]


@pytest.fixture
def make_session(settings, tmp_path):
    @contextlib.asynccontextmanager
    async def opener(net: FakeDoh, *, entities=frozenset({"doh"}), writes=True, **extra):
        s = dataclasses.replace(settings, enable_writes=writes, write_entities=entities, journal_dir=tmp_path / "journal",
                                dns_probe_server=f"127.0.0.1:{net.dns.port}", dns_probe_window=1.0, **extra)
        mcp, api = create_server(s, transport=httpx.MockTransport(net))
        try:
            async with Client(mcp) as client:
                yield Wrapped(client)
        finally:
            await api.client.aclose()
    return opener


async def raw(c, args):
    return (await c.call_tool(TOOL, args)).content[0].text


async def call(c, args):
    res = await c.call_tool(TOOL, args)
    assert not res.is_error, res
    return json.loads(res.content[0].text)


async def apply(c, args, note=NOTE):
    pre = await call(c, args)
    assert pre.get("ok") and not pre["errors"], pre
    return pre, await call(c, {**args, "confirm": True, "fingerprint": pre["fingerprint"], "approval_note": note})


ADD_GOOGLE = {"state": "manual", "server_names": ["cloudflare", "cloudflare-ipv6", "google", "google-ipv6"]}


# ---------------------------------------------------------------------------------------------- the happy path
async def test_manual_change_sends_exactly_the_four_captured_keys_and_verifies(make_session, dns):
    net = FakeDoh(dns)
    async with make_session(net) as c:
        pre, out = await apply(c, ADD_GOOGLE)
    assert net.bodies == [{"key": "doh", "state": "manual", "server_names": ["cloudflare", "cloudflare-ipv6", "google", "google-ipv6"],
                           "custom_servers": []}]
    assert out["applied"] is True and out["verified"] is True and out["guard"] == {"probe_after": "ok"}
    assert list(out["diff"]) == ["server_names"]
    assert out["rollback"]["changes"]["server_names"] == ["cloudflare", "cloudflare-ipv6"]
    assert pre["guard"]["check_before"] == "ok" and any("Safety net" in w for w in pre["warnings"])
    assert dns.queries >= 2         # before and after


async def test_previews_work_with_writes_disabled_and_change_nothing(make_session, dns):
    net = FakeDoh(dns)
    async with make_session(net, writes=False) as c:
        pre = await call(c, ADD_GOOGLE)
    assert pre["apply_blocked_reason"] and net.writes() == []


async def test_tier_c_needs_an_approval_note(make_session, dns):
    net = FakeDoh(dns)
    async with make_session(net) as c:
        pre = await call(c, ADD_GOOGLE)
        text = await raw(c, {**ADD_GOOGLE, "confirm": True, "fingerprint": pre["fingerprint"]})
    assert "approval_note" in text and net.writes() == []


async def test_entity_must_be_enabled(make_session, dns):
    net = FakeDoh(dns)
    async with make_session(net, entities=frozenset({"port_forward"})) as c:
        pre = await call(c, ADD_GOOGLE)
        text = await raw(c, {**ADD_GOOGLE, "confirm": True, "fingerprint": pre["fingerprint"], "approval_note": NOTE})
    assert "not enabled for writes" in text and net.writes() == []


async def test_stale_preview_is_refused(make_session, dns):
    net = FakeDoh(dns)
    async with make_session(net) as c:
        pre = await call(c, ADD_GOOGLE)
        net.group["server_names"] = ["cloudflare"]
        text = await raw(c, {**ADD_GOOGLE, "confirm": True, "fingerprint": pre["fingerprint"], "approval_note": NOTE})
    assert "differs from the preview" in text and net.writes() == []


async def test_no_change_sends_nothing(make_session, dns):
    net = FakeDoh(dns)
    async with make_session(net) as c:
        pre = await call(c, {"state": "manual", "server_names": ["cloudflare", "cloudflare-ipv6"]})
        out = await call(c, {"state": "manual", "server_names": ["cloudflare", "cloudflare-ipv6"], "confirm": True,
                             "fingerprint": pre["fingerprint"], "approval_note": NOTE})
    assert "Already in the requested state" in pre["note"] and out["applied"] is False and net.writes() == []


# ---------------------------------------------------------------------------------------------- state handling
async def test_switching_to_off_clears_both_lists(make_session, dns):
    net = FakeDoh(dns)
    async with make_session(net) as c:
        _, out = await apply(c, {"state": "off"})
    assert net.bodies == [{"key": "doh", "state": "off", "server_names": [], "custom_servers": []}]
    assert out["verified"] is True and out["rollback"]["changes"]["state"] == "manual"


async def test_switching_to_custom_clears_the_names(make_session, dns):
    net = FakeDoh(dns)
    entry = {"server_name": "my-gateway", "sdns_stamp": GOOD_STAMP, "enabled": True}
    async with make_session(net) as c:
        pre, out = await apply(c, {"state": "custom", "custom_servers": [entry]})
    assert net.bodies[0]["server_names"] == [] and net.bodies[0]["custom_servers"] == [entry]
    assert out["verified"] is True and any("shape-checked" in w for w in pre["warnings"])


async def test_names_given_without_the_mode_are_refused(make_session, dns):
    net = FakeDoh(dns, {**ORIGINAL, "state": "off", "server_names": []})
    async with make_session(net) as c:
        text = await raw(c, {"server_names": ["google"]})
    assert "only applies when state is manual" in text and net.writes() == []


@pytest.mark.parametrize("args,needle", [
    ({"state": "manual", "server_names": []}, "at least one resolver"),
    ({"state": "manual", "server_names": ["nosuch"]}, "not a resolver this console offers"),
    ({"state": "custom", "custom_servers": []}, "at least one enabled entry"),
    ({"state": "custom", "custom_servers": [{"server_name": "a", "sdns_stamp": "https://x", "enabled": True}]}, "must start with sdns://"),
    ({"state": "custom", "custom_servers": [{"server_name": "a", "sdns_stamp": "sdns://!!!", "enabled": True}]}, "base64"),
    ({"state": "custom", "custom_servers": [{"server_name": "a", "sdns_stamp": "sdns://AAAA", "enabled": True}]}, "not a DoH stamp"),
    ({"state": "custom", "custom_servers": [{"server_name": "a", "sdns_stamp": GOOD_STAMP}, {"server_name": "a", "sdns_stamp": GOOD_STAMP}]}, "used twice"),
])
async def test_invalid_requests_are_refused_in_the_preview(make_session, dns, args, needle):
    net = FakeDoh(dns)
    async with make_session(net) as c:
        res = await raw(c, args)
        pre = json.loads(res) if res.startswith("{") else {}
        refused = pre.get("errors") or [res]
        text = " ".join(refused)
        if pre.get("fingerprint"):
            text += await raw(c, {**args, "confirm": True, "fingerprint": pre["fingerprint"], "approval_note": NOTE})
    assert needle in text and net.writes() == []


async def test_warnings_for_off_single_resolver_and_missing_partner(make_session, dns):
    net = FakeDoh(dns)
    async with make_session(net) as c:
        off = await call(c, {"state": "off"})
        one = await call(c, {"state": "manual", "server_names": ["google"]})
    assert any("unencrypted" in w for w in off["warnings"])
    assert any("Only one resolver" in w for w in one["warnings"]) and any("partner" in w for w in one["warnings"])


async def test_nothing_to_change_is_an_error_and_unknown_fields_are_rejected(make_session, dns):
    net = FakeDoh(dns)
    async with make_session(net) as c:
        assert "Nothing to change" in await raw(c, {})
        assert "key" in (await raw(c, {"state": "off", "key": "x"})).lower()
    assert net.writes() == []


# ---------------------------------------------------------------------------------------------- safety net
async def test_a_refused_zone_does_not_fail_the_probe_but_every_zone_failing_does(make_session, dns):
    net = FakeDoh(dns)
    dns.refuse_first = 2                       # the first two zones answer REFUSED (as cloudflare.com does on the real gateway)
    async with make_session(net) as c:
        pre = await call(c, ADD_GOOGLE)
    assert pre["guard"]["check_before"] == "ok" and pre["errors"] == []
    dns.refuse_first = 99
    async with make_session(net) as c:
        pre = await call(c, ADD_GOOGLE)
    assert any("DNS is not working before the change" in e for e in pre["errors"])


async def test_probe_failing_before_refuses_the_change(make_session, dns):
    net = FakeDoh(dns)
    dns.mode = "servfail"
    async with make_session(net) as c:
        pre = await call(c, ADD_GOOGLE)
        text = await raw(c, {**ADD_GOOGLE, "confirm": True, "fingerprint": pre["fingerprint"], "approval_note": NOTE})
    assert any("DNS is not working before the change" in e for e in pre["errors"])
    assert "Refused" in text and net.writes() == []


async def test_probe_failing_after_the_change_restores_once_and_says_so(make_session, dns, tmp_path):
    net = FakeDoh(dns)
    net.break_dns_when = lambda body: "google" in body["server_names"]
    async with make_session(net) as c:
        pre = await call(c, ADD_GOOGLE)
        out = await call(c, {**ADD_GOOGLE, "confirm": True, "fingerprint": pre["fingerprint"], "approval_note": NOTE})
    assert out["applied"] is False and out["guard"]["auto_restored"] is True and out["guard"]["restore_verified"] is True
    assert "failed" in out["guard"]["probe_after"] and "attention" in out
    assert len(net.bodies) == 2 and net.bodies[1] == {"key": "doh", "state": "manual", "server_names": ["cloudflare", "cloudflare-ipv6"],
                                                      "custom_servers": []}
    assert net.group["server_names"] == ["cloudflare", "cloudflare-ipv6"] and out["diff"] == {}
    events = [json.loads(line)["event"] for p in (tmp_path / "journal").glob("*.jsonl") for line in p.read_text().splitlines()]
    assert events == ["attempt", "guard_failed", "auto_restore", "result"]
    # the fake resolver is still broken (that is the fake's doing), so the post-restore probe is reported honestly
    assert out["guard"]["probe_after_restore"].startswith("failed")


async def test_force_fail_switch_proves_the_restore_with_a_healthy_resolver(make_session, dns):
    net = FakeDoh(dns)
    async with make_session(net, dns_probe_force_fail=True) as c:
        pre, out = await apply(c, ADD_GOOGLE)
    assert out["applied"] is False and out["guard"]["auto_restored"] is True
    assert out["guard"]["probe_after_restore"] == "ok"            # the switch only fails the "change" phase
    assert net.group["server_names"] == ["cloudflare", "cloudflare-ipv6"] and len(net.bodies) == 2


async def test_a_failed_restore_is_reported_loudly(make_session, dns):
    net = FakeDoh(dns)
    net.fail_posts_after = 1
    async with make_session(net, dns_probe_force_fail=True) as c:
        _, out = await apply(c, ADD_GOOGLE)
    assert out["guard"]["auto_restored"] is False and "restore_error" in out["guard"]
    assert "AND the automatic restore failed" in out["attention"] and "doh_restore.py" in out["attention"]
    assert len(net.bodies) == 1          # tried once, not in a loop


async def test_the_console_rejecting_the_change_does_not_probe_or_restore(make_session, dns):
    net = FakeDoh(dns)
    net.reject = True
    async with make_session(net) as c:
        pre = await call(c, ADD_GOOGLE)
        text = await raw(c, {**ADD_GOOGLE, "confirm": True, "fingerprint": pre["fingerprint"], "approval_note": NOTE})
    assert "console rejected" in text and net.bodies == []


async def test_an_unreachable_probe_server_blocks_the_change(make_session, dns):
    net = FakeDoh(dns)
    dns.mode = "silent"
    async with make_session(net) as c:
        pre = await call(c, ADD_GOOGLE)
    assert any("before the change" in e for e in pre["errors"])


# ---------------------------------------------------------------------------------------------- gates elsewhere
async def test_the_generic_tool_refuses_the_raw_operation_and_names_the_typed_tool(make_session, dns):
    net = FakeDoh(dns)
    async with make_session(net) as c:
        text = await raw_generic(c, "updateDohSetting", {"body": {"key": "doh", "state": "off", "server_names": [], "custom_servers": []}})
    assert "unifi_console_doh" in text and net.writes() == []


async def raw_generic(c, op, args):
    res = await c.call_tool("unifi_console_call_operation", {"operation_id": op, **args})
    return res.content[0].text


def test_probe_query_and_reply_helpers():
    from unifi_console_mcp.dnsprobe import build_query, reply_ok
    q = build_query("abc.example.com", 0x1234)
    assert q[:2] == b"\x12\x34" and q.endswith(b"\x00\x00\x01\x00\x01")
    ok = q[:2] + struct.pack(">H", 0x8183) + q[4:]
    servfail = q[:2] + struct.pack(">H", 0x8182) + q[4:]
    assert reply_ok(ok, 0x1234) and not reply_ok(servfail, 0x1234) and not reply_ok(ok, 0x9999) and not reply_ok(b"", 1)


# ---------------------------------------------------------------------------------------------- restore script
def load_script(name):
    import importlib.util
    from pathlib import Path
    path = Path(__file__).resolve().parents[1] / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def patch_settings(monkeypatch, tmp_path):
    from unifi_console_mcp.config import Settings
    monkeypatch.setattr(Settings, "from_env", classmethod(lambda cls: cls(
        host="console.test", username="u", password="p", journal_dir=tmp_path / "journal")))


async def test_restore_script_refuses_with_an_empty_journal(monkeypatch, tmp_path, dns, capsys):
    patch_settings(monkeypatch, tmp_path)
    net = FakeDoh(dns)
    code = await load_script("doh_restore").main(True, httpx.MockTransport(net))
    assert code == 1 and "no DoH change found" in capsys.readouterr().out and net.writes() == []


async def test_restore_script_dry_run_then_run_puts_the_journalled_values_back(make_session, monkeypatch, tmp_path, dns, capsys):
    net = FakeDoh(dns)
    async with make_session(net) as c:
        await apply(c, ADD_GOOGLE)                       # a real, journalled change
    assert net.group["server_names"] == ["cloudflare", "cloudflare-ipv6", "google", "google-ipv6"]
    patch_settings(monkeypatch, tmp_path)
    script = load_script("doh_restore")
    posts = len(net.writes())
    assert await script.main(False, httpx.MockTransport(net)) == 0
    assert "Dry run only" in capsys.readouterr().out and len(net.writes()) == posts
    assert await script.main(True, httpx.MockTransport(net)) == 0
    assert "restored and verified" in capsys.readouterr().out
    assert net.group["server_names"] == ["cloudflare", "cloudflare-ipv6"] and net.group["state"] == "manual"
    assert net.bodies[-1] == {"key": "doh", "state": "manual", "server_names": ["cloudflare", "cloudflare-ipv6"], "custom_servers": []}
    assert await script.main(True, httpx.MockTransport(net)) == 0           # second run: already the same, sends nothing
    assert "Already the same" in capsys.readouterr().out
