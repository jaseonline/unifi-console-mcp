"""Credentials: install-form field, then the password-manager credential cache, then the system variables."""

from __future__ import annotations

import sys
import types

import pytest

from unifi_console_mcp import config

_REAL_CREDENTIAL_CACHED = config._credential_cached  # captured at import, before conftest swaps it out
FORM = (
    "UNIFI_BUNDLE_USERNAME",
    "UNIFI_BUNDLE_PASSWORD",
    "UNIFI_BUNDLE_API_KEY",
    "UNIFI_BUNDLE_SITE_MANAGER_API_KEY",
)
SYSTEM = (
    "UNIFI_MCP_USERNAME",
    "UNIFI_MCP_PASSWORD",
    "UNIFI_MCP_API_KEY",
    "UNIFI_SITE_MANAGER_API_KEY",
)


@pytest.fixture
def cache(monkeypatch):
    """A fake credential store standing in for the OS keyring, with the cache switched on."""
    store: dict[tuple[str, str], str] = {}
    fake = types.ModuleType("keyring")
    fake.get_password = lambda service, name: store.get((service, name))
    monkeypatch.setattr(config, "_credential_cached", _REAL_CREDENTIAL_CACHED)
    monkeypatch.setitem(sys.modules, "keyring", fake)
    monkeypatch.delenv("UNIFI_CONSOLE_KEYRING", raising=False)
    monkeypatch.setattr(config, "_registry_lookup", lambda name: None)
    monkeypatch.setenv("UNIFI_BUNDLE_HOST", "console.example")
    for name in FORM + SYSTEM:
        monkeypatch.delenv(name, raising=False)

    def put(field: str, value: str) -> None:
        store[(config.CACHE_SERVICE, f"{config.CACHE_ENTRY}/{field}")] = value

    return put


def test_cache_supplies_blank_credentials(cache):
    cache("username", "cached-user")
    cache("password", "cached-pass")
    cache("api_key", "cached-key")
    s = config.Settings.from_env()
    assert (s.username, s.password, s.api_key) == ("cached-user", "cached-pass", "cached-key")
    assert s.has_session_credentials


def test_form_field_beats_cache(cache, monkeypatch):
    cache("password", "cached-pass")
    monkeypatch.setenv("UNIFI_BUNDLE_PASSWORD", "form-pass")
    assert config.Settings.from_env().password == "form-pass"


def test_cache_beats_stale_system_variable(cache, monkeypatch):
    cache("password", "fresh-pass")
    monkeypatch.setenv("UNIFI_MCP_PASSWORD", "stale-pass")
    assert config.Settings.from_env().password == "fresh-pass"


def test_system_variable_used_when_cache_empty(cache, monkeypatch):
    monkeypatch.setenv("UNIFI_MCP_PASSWORD", "env-pass")
    assert config.Settings.from_env().password == "env-pass"


def test_unfilled_form_placeholder_falls_through_to_cache(cache, monkeypatch):
    cache("api_key", "cached-key")
    monkeypatch.setenv("UNIFI_BUNDLE_API_KEY", "${user_config.api_key}")
    assert config.Settings.from_env().api_key == "cached-key"


def test_cache_can_be_switched_off(cache, monkeypatch):
    cache("password", "cached-pass")
    monkeypatch.setenv("UNIFI_CONSOLE_KEYRING", "off")
    monkeypatch.setenv("UNIFI_MCP_PASSWORD", "env-pass")
    assert config.Settings.from_env().password == "env-pass"


def test_blank_cache_value_is_ignored(cache, monkeypatch):
    cache("password", "   ")
    monkeypatch.setenv("UNIFI_MCP_PASSWORD", "env-pass")
    assert config.Settings.from_env().password == "env-pass"


def test_unreadable_store_falls_through(cache, monkeypatch):
    def boom(service, name):
        raise RuntimeError("store locked")

    monkeypatch.setattr(sys.modules["keyring"], "get_password", boom)
    monkeypatch.setenv("UNIFI_MCP_PASSWORD", "env-pass")
    assert config.Settings.from_env().password == "env-pass"


def test_missing_keyring_package_falls_through(cache, monkeypatch):
    monkeypatch.setitem(sys.modules, "keyring", None)  # makes "import keyring" raise ImportError
    monkeypatch.setenv("UNIFI_MCP_PASSWORD", "env-pass")
    assert config.Settings.from_env().password == "env-pass"


def test_site_manager_key_comes_from_cache(cache):
    cache("site_manager_api_key", "cached-sm-key")
    assert config.Settings.from_env().site_manager_api_key == "cached-sm-key"


def test_site_manager_key_form_field_beats_cache(cache, monkeypatch):
    cache("site_manager_api_key", "cached-sm-key")
    monkeypatch.setenv("UNIFI_BUNDLE_SITE_MANAGER_API_KEY", "form-sm-key")
    assert config.Settings.from_env().site_manager_api_key == "form-sm-key"


def test_site_manager_key_cache_beats_stale_system_variable(cache, monkeypatch):
    cache("site_manager_api_key", "fresh-sm-key")
    monkeypatch.setenv("UNIFI_SITE_MANAGER_API_KEY", "stale-sm-key")
    assert config.Settings.from_env().site_manager_api_key == "fresh-sm-key"
