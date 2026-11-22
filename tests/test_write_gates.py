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
