"""The write gate: writes are on by default; UNIFI_CONSOLE_READ_ONLY and UNIFI_CONSOLE_DISABLE_ENTITIES narrow it.

The old UNIFI_CONSOLE_ENABLE_WRITES and UNIFI_CONSOLE_WRITE_ENTITIES variables still work for one release,
with a deprecation note, so existing configurations keep the same safety they had.
"""

from __future__ import annotations

import pytest

from unifi_console_mcp.config import Settings

GATE_VARS = (
    "UNIFI_CONSOLE_READ_ONLY",
    "UNIFI_CONSOLE_DISABLE_ENTITIES",
    "UNIFI_CONSOLE_ENABLE_WRITES",
    "UNIFI_CONSOLE_WRITE_ENTITIES",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.setenv("UNIFI_LOCAL_HOST", "192.168.1.1")
    for name in GATE_VARS:
        monkeypatch.delenv(name, raising=False)


def test_defaults_are_writes_on_with_nothing_switched_off():
    s = Settings.from_env()
    assert s.enable_writes is True
    assert s.write_entities == frozenset() and s.disabled_entities == frozenset()
    assert s.deprecations == ()


@pytest.mark.parametrize("value", ["true", "1", "yes"])
def test_read_only_flag_turns_writes_off(monkeypatch, value):
    monkeypatch.setenv("UNIFI_CONSOLE_READ_ONLY", value)
    s = Settings.from_env()
    assert s.enable_writes is False
    assert s.deprecations == ()


def test_disable_entities_is_a_denylist(monkeypatch):
    monkeypatch.setenv("UNIFI_CONSOLE_DISABLE_ENTITIES", "WAN, doh")
    s = Settings.from_env()
    assert s.enable_writes is True
    assert s.disabled_entities == frozenset({"wan", "doh"})
    assert s.write_entities == frozenset()


def test_the_old_enable_writes_false_still_means_read_only_and_says_so(monkeypatch):
    monkeypatch.setenv("UNIFI_CONSOLE_ENABLE_WRITES", "false")
    s = Settings.from_env()
    assert s.enable_writes is False
    assert any("UNIFI_CONSOLE_READ_ONLY" in note for note in s.deprecations)


def test_the_old_enable_writes_true_is_ignored_with_a_note(monkeypatch):
    monkeypatch.setenv("UNIFI_CONSOLE_ENABLE_WRITES", "true")
    s = Settings.from_env()
    assert s.enable_writes is True
    assert any("ENABLE_WRITES" in note for note in s.deprecations)


def test_an_unparsable_enable_writes_fails_safe_to_read_only(monkeypatch):
    monkeypatch.setenv("UNIFI_CONSOLE_ENABLE_WRITES", "maybe")
    s = Settings.from_env()
    assert s.enable_writes is False
    assert s.deprecations


def test_the_old_write_entities_allowlist_still_restricts_and_says_so(monkeypatch):
    monkeypatch.setenv("UNIFI_CONSOLE_WRITE_ENTITIES", "Wifi, network")
    s = Settings.from_env()
    assert s.write_entities == frozenset({"wifi", "network"})
    assert any("UNIFI_CONSOLE_DISABLE_ENTITIES" in note for note in s.deprecations)


def test_read_only_wins_over_everything(monkeypatch):
    monkeypatch.setenv("UNIFI_CONSOLE_READ_ONLY", "true")
    monkeypatch.setenv("UNIFI_CONSOLE_ENABLE_WRITES", "true")
    s = Settings.from_env()
    assert s.enable_writes is False


async def test_a_disabled_entity_is_refused_but_others_are_not(settings, tmp_path):
    import dataclasses

    from unifi_console_mcp.server import create_server
    from unifi_console_mcp.writes import EntitySpec, WriteEngine

    s = dataclasses.replace(settings, enable_writes=True, disabled_entities=frozenset({"wan"}))
    _mcp, api = create_server(s)
    try:
        eng = WriteEngine(api)
        wan = EntitySpec(key="wan", label="WAN", tier="B", list_op="listPortForwards")
        other = EntitySpec(key="wifi", label="Wi-Fi", tier="B", list_op="listPortForwards")
        assert "UNIFI_CONSOLE_DISABLE_ENTITIES" in eng.blocked_reason(wan, None)
        assert eng.blocked_reason(other, None) is None
    finally:
        await api.client.aclose()


async def _apply_through_the_server(settings, tmp_path, **overrides):
    """Preview then apply one port-forward create through a real in-process server; return (reply text, requests sent)."""
    import dataclasses

    import httpx
    from mcp.client import Client
    from test_writes import NEW, TOOL, FakePortForwards, Wrapped, call

    from unifi_console_mcp.server import create_server

    net = FakePortForwards()
    s = dataclasses.replace(settings, journal_dir=tmp_path / "journal", **overrides)
    mcp, api = create_server(s, transport=httpx.MockTransport(net))
    try:
        async with Client(mcp) as client:
            wrapped = Wrapped(client)
            pre = await call(wrapped, NEW)
            assert pre["ok"] and pre["preview"], pre  # a preview is always allowed, whatever the gate says
            res = await wrapped.call_tool(TOOL, {**NEW, "confirm": True, "fingerprint": pre["fingerprint"]})
            text = res.content[0].text
    finally:
        await api.client.aclose()
    return text, net.writes()


async def test_default_server_applies_a_confirmed_change(settings, tmp_path):
    text, writes = await _apply_through_the_server(settings, tmp_path, enable_writes=True)
    assert writes, text


async def test_read_only_server_refuses_the_apply_and_sends_nothing(settings, tmp_path):
    text, writes = await _apply_through_the_server(settings, tmp_path, enable_writes=False)
    assert "UNIFI_CONSOLE_READ_ONLY" in text and writes == []


async def test_a_disabled_entity_refuses_the_apply_and_sends_nothing(settings, tmp_path):
    text, writes = await _apply_through_the_server(
        settings, tmp_path, enable_writes=True, disabled_entities=frozenset({"port_forward"})
    )
    assert "UNIFI_CONSOLE_DISABLE_ENTITIES" in text and writes == []


async def test_disabling_one_entity_leaves_the_others_working(settings, tmp_path):
    text, writes = await _apply_through_the_server(
        settings, tmp_path, enable_writes=True, disabled_entities=frozenset({"wan", "doh"})
    )
    assert writes, text


async def test_every_typed_write_tool_is_annotated_as_able_to_change_things(settings):
    """Writes are on by default now, so clients rely on these hints to decide when to ask before calling a tool."""
    import dataclasses

    from mcp.client import Client

    from unifi_console_mcp.server import create_server

    typed_writers = {
        "app_block",
        "client",
        "client_command",
        "client_group",
        "data_retention",
        "device",
        "doh",
        "dynamic_dns",
        "firewall_policy",
        "network",
        "network_list",
        "port_forward",
        "qos_rule",
        "static_dns",
        "switch_port",
        "syslog",
        "traffic_object",
        "wan",
        "wifi",
    }
    mcp, api = create_server(dataclasses.replace(settings, enable_writes=True))
    try:
        async with Client(mcp) as client:
            tools = {t.name: t for t in (await client.list_tools()).tools}
    finally:
        await api.client.aclose()
    for key in typed_writers:
        a = tools[f"unifi_console_{key}"].annotations
        assert a.read_only_hint is False and a.destructive_hint is True, key
    # The raw-operation tool may create backups and support files but never applies configuration.
    assert tools["unifi_console_call_operation"].annotations.read_only_hint is False
    assert tools["unifi_console_call_operation"].annotations.destructive_hint is False
