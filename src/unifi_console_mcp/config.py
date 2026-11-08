"""Runtime configuration, read from environment variables.

The first group of variables already exists on the host (shared with the other UniFi tooling).
The UNIFI_CONSOLE_* group is specific to this server.

The MCPB install form supplies UNIFI_BUNDLE_* variables. A filled-in form field wins; a blank one falls
through to the system variable, so values set in the user's Windows environment keep working.

Credentials (username, password, API key, Site Manager API key) have one more source. After a filled-in form field and
before the system variables, the server reads a credential cache in the OS credential store (Windows Credential
Manager, service CACHE_SERVICE, entry "unifi-mcp/<field>"). A password manager stays the source of truth; a separate
sync step refreshes the cache, so a rotation reaches the server without editing the form or the Windows environment.
A stale system variable left over from before a rotation can no longer override it. Set UNIFI_CONSOLE_KEYRING=off to
skip the cache.
"""

from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


def _registry_lookup(name: str) -> str | None:
    """Windows only: the persistent user, then system, environment variable straight from the registry.

    MCP hosts start servers with a short whitelist of inherited variables (PATH, APPDATA, ...), so a variable the
    user set with setx or System Properties does not reach the process. Reading the registry needs no restart of
    the host and no change to how it launches the server.
    """
    if sys.platform != "win32":
        return None
    import winreg

    for hive, subkey in (
        (winreg.HKEY_CURRENT_USER, "Environment"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"),
    ):
        try:
            with winreg.OpenKey(hive, subkey) as key:
                value, kind = winreg.QueryValueEx(key, name)
        except OSError:
            continue
        if isinstance(value, str) and value.strip():
            return winreg.ExpandEnvironmentStrings(value) if kind == winreg.REG_EXPAND_SZ else value
    return None


def _unfilled(value: str) -> bool:
    stripped = value.strip()
    return stripped.startswith("${") and stripped.endswith("}")


def _get(name: str) -> str | None:
    """Read a variable: the process environment, then (Windows) the persistent environment in the registry.

    An unfilled ${placeholder} counts as unset. An MCPB host substitutes ${user_config.KEY} into the server's env
    block; if the user left an optional field blank the literal placeholder can reach the process, and it must
    never be used as a value. A blank process value is returned as is so callers can fall through to the next name.
    """
    value = os.environ.get(name)
    if value is not None and _unfilled(value):
        value = None
    if value is None or not value.strip():
        stored = _registry_lookup(name)
        if stored is not None and not _unfilled(stored):
            return stored
    return value


BUNDLE = "UNIFI_BUNDLE_"  # fields from the MCPB install form; blank means "use the system variable"


def _pick(*names: str) -> str:
    """First non-blank value among the named variables, or ''."""
    for name in names:
        value = _get(name)
        if value is not None and value.strip():
            return value.strip()
    return ""


CACHE_SERVICE = "unifi-mcp-cache"  # credential-store service written by the password-manager sync step
CACHE_ENTRY = "unifi-mcp"  # entries are named "unifi-mcp/<field>"
_log = logging.getLogger(__name__)


def _credential_cached(field: str) -> str:
    """A secret from the password-manager credential cache, or '' when there is none.

    The `keyring` package is optional: if it is missing, the store has no usable backend or it cannot be read, this
    quietly returns '' and the caller falls through to the next source. UNIFI_CONSOLE_KEYRING=off skips the cache.
    """
    if os.environ.get("UNIFI_CONSOLE_KEYRING", "").strip().lower() in _FALSE:
        return ""
    try:
        import keyring

        value = keyring.get_password(CACHE_SERVICE, f"{CACHE_ENTRY}/{field}")
    except Exception:  # noqa: BLE001 - no backend, locked store or no package: use the next source
        return ""
    return value.strip() if value and value.strip() else ""


def _secret(field: str, *names: str) -> str:
    """Credential lookup order: the install-form field, the credential cache, then the system variables.

    names[0] is the UNIFI_BUNDLE_* form field and wins when filled in; the rest are the system variables.
    """
    value = _pick(names[0])
    if value:
        return value
    value = _credential_cached(field)
    if value:
        _log.debug("UniFi %s taken from the credential cache", field)
        return value
    return _pick(*names[1:])


def _env(name: str, default: str = "") -> str:
    """Read a variable. UNIFI_CONSOLE_X is looked up as UNIFI_BUNDLE_X (install form), UNIFI_CONSOLE_X, then UNIFI_EXT_X."""
    if name.startswith("UNIFI_CONSOLE_"):
        key = name[len("UNIFI_CONSOLE_") :]
        return _pick(BUNDLE + key, name, "UNIFI_EXT_" + key) or default
    return _pick(name) or default


def _int(names: tuple[str, ...], default: int) -> int:
    raw = _pick(*names)
    return int(raw) if raw else default


LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


def _flag(names: str | tuple[str, ...], default: bool) -> bool:
    raw = _env(names) if isinstance(names, str) else _pick(*names)
    value = raw.strip().lower()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    return default


def _clean_host(raw: str) -> str:
    host = raw.strip()
    for prefix in ("https://", "http://"):
        if host.lower().startswith(prefix):
            host = host[len(prefix) :]
    return host.rstrip("/").split("/")[0]


@dataclass(frozen=True)
class Settings:
    host: str
    port: int = 443
    site: str = "default"
    username: str = field(default="", repr=False)
    password: str = field(default="", repr=False)
    api_key: str = field(default="", repr=False)
    # Site Manager (api.ui.com) key: a cloud key from unifi.ui.com, separate from the console's Integration API key.
    site_manager_api_key: str = field(default="", repr=False)
    verify_ssl: bool = True
    pinned_sha256: str = ""
    enable_writes: bool = False
    write_entities: frozenset[str] = frozenset()
    journal_dir: Path = Path.home() / ".unifi-console-mcp" / "journal"
    download_dir: Path = Path.home() / ".unifi-console-mcp" / "downloads"
    spec_path: Path | None = None
    max_chars: int = 40_000
    # DNS safety probe used by settings whose change can stop DNS (see dnsprobe.py). Empty server = the gateway on the console's LAN.
    dns_probe_server: str = ""
    dns_probe_window: float = 30.0
    dns_probe_force_fail: bool = (
        False  # test switch: makes the probe after a change report failure, to prove the automatic restore
    )
    log_level: str = "INFO"  # server log level; logs go to stderr, never stdout (stdout is the MCP stream)

    @property
    def base_url(self) -> str:
        port = "" if self.port == 443 else f":{self.port}"
        return f"https://{self.host}{port}"

    @property
    def has_session_credentials(self) -> bool:
        return bool(self.username and self.password)

    @classmethod
    def from_env(cls) -> Settings:
        host = _clean_host(_pick("UNIFI_BUNDLE_HOST", "UNIFI_LOCAL_HOST"))
        if not host:
            raise RuntimeError(
                "UNIFI_LOCAL_HOST is not set. Fill in the console address in the extension settings, or set the UNIFI_LOCAL_HOST "
                "environment variable (checked: process environment and, on Windows, the user and system environment)."
            )
        spec = _env("UNIFI_CONSOLE_SPEC_PATH").strip()
        download = _env("UNIFI_CONSOLE_DOWNLOAD_DIR").strip()
        journal = _env("UNIFI_CONSOLE_JOURNAL_DIR").strip()
        entities = frozenset(e.strip().lower() for e in _env("UNIFI_CONSOLE_WRITE_ENTITIES").split(",") if e.strip())
        return cls(
            host=host,
            port=_int(("UNIFI_BUNDLE_PORT", "UNIFI_LOCAL_PORT", "UNIFI_NETWORK_PORT"), 443),
            site=_pick("UNIFI_BUNDLE_SITE", "UNIFI_DEFAULT_SITE", "UNIFI_NETWORK_SITE") or "default",
            username=_secret("username", "UNIFI_BUNDLE_USERNAME", "UNIFI_MCP_USERNAME"),
            password=_secret("password", "UNIFI_BUNDLE_PASSWORD", "UNIFI_MCP_PASSWORD"),
            api_key=_secret("api_key", "UNIFI_BUNDLE_API_KEY", "UNIFI_MCP_API_KEY"),
            site_manager_api_key=_secret(
                "site_manager_api_key", "UNIFI_BUNDLE_SITE_MANAGER_API_KEY", "UNIFI_SITE_MANAGER_API_KEY"
            ),
            verify_ssl=_flag(("UNIFI_BUNDLE_VERIFY_SSL", "UNIFI_LOCAL_VERIFY_SSL"), True),
            pinned_sha256=_env("UNIFI_CONSOLE_CERT_SHA256").replace(":", "").strip().lower(),
            enable_writes=_flag("UNIFI_CONSOLE_ENABLE_WRITES", False),
            write_entities=entities,
            journal_dir=Path(journal) if journal else Path.home() / ".unifi-console-mcp" / "journal",
            download_dir=Path(download) if download else Path.home() / ".unifi-console-mcp" / "downloads",
            spec_path=Path(spec) if spec else None,
            max_chars=int(_env("UNIFI_CONSOLE_MAX_CHARS", "40000") or 40000),
            dns_probe_server=_env("UNIFI_CONSOLE_DNS_PROBE_SERVER").strip(),
            dns_probe_window=float(_env("UNIFI_CONSOLE_DNS_PROBE_WINDOW", "30") or 30),
            dns_probe_force_fail=_flag("UNIFI_CONSOLE_DNS_PROBE_FORCE_FAIL", False),
            log_level=_log_level(_env("UNIFI_CONSOLE_LOG_LEVEL")),
        )


def _log_level(raw: str) -> str:
    level = raw.strip().upper()
    return level if level in LOG_LEVELS else "INFO"
