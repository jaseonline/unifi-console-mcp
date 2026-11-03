"""The MCPB manifest must stay in step with the server, and the config must survive host quirks."""

from __future__ import annotations

import dataclasses
import importlib.util
import json
import sys
from pathlib import Path

import httpx
import pytest
from mcp.client import Client

from unifi_console_mcp import __version__
from unifi_console_mcp import config as config_module
from unifi_console_mcp.config import Settings, _get
from unifi_console_mcp.server import create_server

MCPB = Path(__file__).resolve().parent.parent / "mcpb"


def _load_generator():
    spec = importlib.util.spec_from_file_location("gen_manifest", MCPB / "gen_manifest.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["gen_manifest"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def manifest() -> dict:
    return json.loads((MCPB / "manifest.json").read_text(encoding="utf-8"))


async def _live_tools(settings, console) -> list[dict[str, str]]:
    gen = _load_generator()
    mcp, _ = create_server(dataclasses.replace(settings, enable_writes=True), transport=httpx.MockTransport(console))
    async with Client(mcp) as client:
        listed = await client.list_tools()
    return [
        {"name": t.name, "description": gen.first_sentence(t.description or "")}
        for t in sorted(listed.tools, key=lambda t: t.name)
    ]


async def test_manifest_is_exactly_what_the_generator_produces(manifest, settings, console):
    """Fails when a tool, its description or the version changed without `uv run mcpb/gen_manifest.py`."""
    gen = _load_generator()
    expected = gen.build(__version__, await _live_tools(settings, console))
    assert manifest == expected, "mcpb/manifest.json is stale: run `uv run mcpb/gen_manifest.py`"


async def test_manifest_tool_names_match_the_server(manifest, settings, console):
    live = {t["name"] for t in await _live_tools(settings, console)}
    assert {t["name"] for t in manifest["tools"]} == live


def test_manifest_basics(manifest):
    assert manifest["manifest_version"] == "0.4"
    assert manifest["version"] == __version__
    assert manifest["server"]["type"] == "uv"
    assert (MCPB.parent / manifest["server"]["entry_point"]).is_file()
    for icon in manifest["icons"]:
        assert (MCPB / icon["src"]).is_file()
        assert icon["size"] == "512x512"
    assert {i["theme"] for i in manifest["icons"]} == {"light", "dark"}


def test_every_user_config_field_reaches_the_server_and_secrets_are_marked(manifest):
    env = manifest["server"]["mcp_config"]["env"]
    referenced = {v[len("${user_config.") : -1] for v in env.values()}
    assert referenced == set(manifest["user_config"]), "user_config fields and env mapping disagree"
    assert manifest["user_config"]["password"]["sensitive"] is True
    assert manifest["user_config"]["api_key"]["sensitive"] is True
    # Blank form fields must fall through to system variables, so no field may carry a default that would beat them.
    for key in (
        "console_host",
        "api_key",
        "username",
        "password",
        "site",
        "port",
        "verify_ssl",
        "enable_writes",
        "write_entities",
    ):
        assert "default" not in manifest["user_config"][key], key
        assert not manifest["user_config"][key].get("required"), key
    assert all(v.startswith("UNIFI_BUNDLE_") for v in env), "form fields must use UNIFI_BUNDLE_* names"


# --- config behaviour the bundle relies on ---------------------------------------------------------------


def test_unfilled_placeholders_are_treated_as_unset(monkeypatch):
    monkeypatch.setenv("UNIFI_LOCAL_HOST", "192.168.1.1")
    for name in (
        "USERNAME",
        "PASSWORD",
        "API_KEY",
        "SITE",
        "PORT",
        "WRITE_ENTITIES",
        "DOWNLOAD_DIR",
        "JOURNAL_DIR",
        "CERT_SHA256",
        "LOG_LEVEL",
        "ENABLE_WRITES",
        "VERIFY_SSL",
    ):
        monkeypatch.setenv("UNIFI_BUNDLE_" + name, "${user_config.whatever}")
    s = Settings.from_env()
    assert (s.username, s.password, s.api_key) == ("", "", "")
    assert s.site == "default" and s.port == 443 and s.verify_ssl is True
    assert s.enable_writes is False and s.write_entities == frozenset()
    assert s.log_level == "INFO" and s.pinned_sha256 == ""
    assert s.download_dir == Path.home() / ".unifi-console-mcp" / "downloads"


def test_unfilled_host_placeholder_is_a_clear_error(monkeypatch):
    monkeypatch.delenv("UNIFI_LOCAL_HOST", raising=False)
    monkeypatch.setenv("UNIFI_BUNDLE_HOST", "${user_config.console_host}")
    with pytest.raises(RuntimeError, match="UNIFI_LOCAL_HOST is not set"):
        Settings.from_env()


def test_blank_form_fields_fall_back_to_the_system_variables(monkeypatch):
    for name in (
        "HOST",
        "API_KEY",
        "USERNAME",
        "PASSWORD",
        "SITE",
        "PORT",
        "VERIFY_SSL",
        "ENABLE_WRITES",
        "WRITE_ENTITIES",
    ):
        monkeypatch.setenv("UNIFI_BUNDLE_" + name, "")
    monkeypatch.setenv("UNIFI_LOCAL_HOST", "https://10.0.0.1/")
    monkeypatch.setenv("UNIFI_MCP_API_KEY", "sys-key")
    monkeypatch.setenv("UNIFI_MCP_USERNAME", "sys-user")
    monkeypatch.setenv("UNIFI_MCP_PASSWORD", "sys-pass")
    monkeypatch.setenv("UNIFI_LOCAL_PORT", "8443")
    monkeypatch.setenv("UNIFI_LOCAL_VERIFY_SSL", "false")
    monkeypatch.setenv("UNIFI_DEFAULT_SITE", "home")
    monkeypatch.setenv("UNIFI_CONSOLE_ENABLE_WRITES", "true")
    monkeypatch.setenv("UNIFI_CONSOLE_WRITE_ENTITIES", "Wifi, network")
    s = Settings.from_env()
    assert (s.host, s.port, s.site, s.verify_ssl) == ("10.0.0.1", 8443, "home", False)
    assert (s.api_key, s.username, s.password) == ("sys-key", "sys-user", "sys-pass")
    assert s.enable_writes is True and s.write_entities == frozenset({"wifi", "network"})


def test_filled_form_fields_win_over_the_system_variables(monkeypatch):
    monkeypatch.setenv("UNIFI_LOCAL_HOST", "10.0.0.1")
    monkeypatch.setenv("UNIFI_BUNDLE_HOST", "192.168.1.1")
    monkeypatch.setenv("UNIFI_MCP_API_KEY", "sys-key")
    monkeypatch.setenv("UNIFI_BUNDLE_API_KEY", "form-key")
    monkeypatch.setenv("UNIFI_CONSOLE_ENABLE_WRITES", "true")
    monkeypatch.setenv("UNIFI_BUNDLE_ENABLE_WRITES", "false")
    monkeypatch.setenv("UNIFI_LOCAL_PORT", "8443")
    monkeypatch.setenv("UNIFI_BUNDLE_PORT", "1443")
    s = Settings.from_env()
    assert (s.host, s.api_key, s.enable_writes, s.port) == ("192.168.1.1", "form-key", False, 1443)


def test_the_older_variable_names_still_work(monkeypatch):
    monkeypatch.setenv("UNIFI_LOCAL_HOST", "192.168.1.1")
    monkeypatch.setenv("UNIFI_NETWORK_PORT", "9443")
    monkeypatch.setenv("UNIFI_NETWORK_SITE", "lab")
    monkeypatch.setenv("UNIFI_EXT_ENABLE_WRITES", "1")
    s = Settings.from_env()
    assert (s.port, s.site, s.enable_writes) == (9443, "lab", True)


@pytest.mark.parametrize(
    "raw, expected", [("debug", "DEBUG"), (" Warning ", "WARNING"), ("", "INFO"), ("loud", "INFO")]
)
def test_log_level_is_validated(monkeypatch, raw, expected):
    monkeypatch.setenv("UNIFI_LOCAL_HOST", "192.168.1.1")
    monkeypatch.setenv("UNIFI_CONSOLE_LOG_LEVEL", raw)
    assert Settings.from_env().log_level == expected


def test_real_values_are_not_mistaken_for_placeholders(monkeypatch):
    monkeypatch.setenv("UNIFI_MCP_PASSWORD", "pa${ss}word")
    assert _get("UNIFI_MCP_PASSWORD") == "pa${ss}word"


# --- Windows persistent environment (hosts only pass a short whitelist of variables) ----------------------


@pytest.fixture
def registry(monkeypatch):
    """Pretend these persistent variables are stored in the Windows registry; the process env has none of them."""
    store: dict[str, str] = {}
    monkeypatch.setattr(config_module, "_registry_lookup", lambda name: store.get(name))
    for name in list(__import__("os").environ):
        if name.startswith(("UNIFI_",)):
            monkeypatch.delenv(name)
    return store


def test_variables_are_read_from_the_persistent_environment_when_the_host_does_not_pass_them(registry):
    registry.update(
        {
            "UNIFI_LOCAL_HOST": "192.168.1.2",
            "UNIFI_MCP_API_KEY": "reg-key",
            "UNIFI_MCP_USERNAME": "reg-user",
            "UNIFI_MCP_PASSWORD": "reg-pass",
            "UNIFI_CONSOLE_ENABLE_WRITES": "true",
            "UNIFI_LOCAL_PORT": "8443",
        }
    )
    s = Settings.from_env()
    assert (s.host, s.api_key, s.username, s.password) == ("192.168.1.2", "reg-key", "reg-user", "reg-pass")
    assert s.enable_writes is True and s.port == 8443


def test_a_process_value_beats_the_persistent_environment(registry, monkeypatch):
    registry["UNIFI_LOCAL_HOST"] = "10.0.0.1"
    monkeypatch.setenv("UNIFI_LOCAL_HOST", "192.168.1.1")
    assert Settings.from_env().host == "192.168.1.1"


def test_a_blank_form_field_still_falls_through_to_the_persistent_environment(registry, monkeypatch):
    registry["UNIFI_LOCAL_HOST"] = "192.168.1.2"
    monkeypatch.setenv("UNIFI_BUNDLE_HOST", "")
    assert Settings.from_env().host == "192.168.1.2"


def test_an_unfilled_placeholder_in_the_registry_is_ignored(registry):
    registry["UNIFI_LOCAL_HOST"] = "${user_config.console_host}"
    with pytest.raises(RuntimeError, match="UNIFI_LOCAL_HOST is not set"):
        Settings.from_env()


@pytest.mark.skipif(__import__("sys").platform != "win32", reason="Windows registry")
def test_the_real_registry_lookup_returns_none_for_a_missing_name():
    assert config_module._registry_lookup("UNIFI_SURELY_NOT_SET_ANYWHERE") is None
