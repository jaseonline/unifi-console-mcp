"""Runtime configuration, read from environment variables.

The first group of variables already exists on the host (shared with the other UniFi tooling).
The UNIFI_CONSOLE_* group is specific to this server.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


def _env(name: str, default: str = "") -> str:
    """Read a UNIFI_CONSOLE_* variable, falling back to its pre-rename UNIFI_EXT_* name."""
    value = os.environ.get(name)
    if value is None and name.startswith("UNIFI_CONSOLE_"):
        value = os.environ.get("UNIFI_EXT_" + name[len("UNIFI_CONSOLE_"):])
    return default if value is None else value


def _flag(name: str, default: bool) -> bool:
    raw = _env(name)
    if not raw.strip():
        return default
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
    dns_probe_force_fail: bool = False      # test switch: makes the probe after a change report failure, to prove the automatic restore

    @property
    def base_url(self) -> str:
        port = "" if self.port == 443 else f":{self.port}"
        return f"https://{self.host}{port}"

    @property
    def has_session_credentials(self) -> bool:
        return bool(self.username and self.password)

    @classmethod
    def from_env(cls) -> "Settings":
        host = _clean_host(os.environ.get("UNIFI_LOCAL_HOST", ""))
        if not host:
            raise RuntimeError(
                "UNIFI_LOCAL_HOST is not set. Set it to the console address, e.g. 192.168.1.2."
            )
        spec = _env("UNIFI_CONSOLE_SPEC_PATH").strip()
        download = _env("UNIFI_CONSOLE_DOWNLOAD_DIR").strip()
        journal = _env("UNIFI_CONSOLE_JOURNAL_DIR").strip()
        entities = frozenset(e.strip().lower() for e in _env("UNIFI_CONSOLE_WRITE_ENTITIES").split(",") if e.strip())
        return cls(
            host=host,
            port=int(os.environ.get("UNIFI_NETWORK_PORT", "443") or 443),
            site=os.environ.get("UNIFI_NETWORK_SITE", "default") or "default",
            username=os.environ.get("UNIFI_MCP_USERNAME", ""),
            password=os.environ.get("UNIFI_MCP_PASSWORD", ""),
            api_key=os.environ.get("UNIFI_MCP_API_KEY", ""),
            verify_ssl=_flag("UNIFI_LOCAL_VERIFY_SSL", True),
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
        )
