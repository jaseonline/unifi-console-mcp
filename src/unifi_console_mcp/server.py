"""Server entry point: builds the Api, registers tools and runs over stdio."""

from __future__ import annotations

import base64
import sys
from importlib import resources

import httpx
from mcp.server.mcpserver import MCPServer
from mcp.types import Icon

from . import __version__, tools_curated, tools_generic, tools_writes
from .api import Api
from .client import UniFiClient
from .config import Settings
from .registry import Registry

TITLE = "UniFi Console"
DESCRIPTION = (
    "Read, diagnose and (when enabled) change a UniFi Network console: the official Integration API, the undocumented "
    "controller and UniFi OS APIs, curated diagnostics, and typed configuration tools that preview before they apply."
)
WEBSITE_URL = "https://github.com/jaseonline/unifi-console-mcp"

INSTRUCTIONS = """\
UniFi Network console server. Reads are always available; configuration changes are off unless the server is started
with UNIFI_CONSOLE_ENABLE_WRITES=true and the entity is listed in UNIFI_CONSOLE_WRITE_ENTITIES.

Reading
- Use a curated tool when one fits (system log, firewall policy hits, PoE overview, switch port detail, access review,
  session status): the results are shaped and compact.
- Otherwise find the operation with unifi_console_list_operations, check it with unifi_console_describe_operation, then
  run it with unifi_console_read_operation. It only runs reads and never changes anything.
- unifi_console_call_operation is for file downloads (backups, support files) and safe writes (generate a backup or
  support file). Those need confirm=true. It never applies configuration changes.
- Site Manager operations (api 'site_manager') read every console on the UI account from api.ui.com. They are
  read-only, need UNIFI_SITE_MANAGER_API_KEY, and page with next_token instead of offset.
- Secrets are redacted from every result. Large results are cut; narrow them with fields, search, limit and offset.

Changing configuration (preview, then confirm)
- Configuration changes go only through the typed tools (unifi_console_wifi, _network, _firewall_policy, _switch_port,
  _port_forward, _static_dns and so on). Each works in two steps, always.
- Step 1: call with confirm=false. Nothing is changed. The result is a preview: the object before and after, the diff,
  warnings and errors, anything affected (for example the clients on an SSID), and a fingerprint of that preview.
- Show the user the preview and wait for their approval. Never confirm on your own.
- Step 2: call again with the same fields plus confirm=true, the fingerprint from the preview and an approval_note
  recording the user's approval. The server re-reads the object, refuses a stale preview, journals the attempt, sends
  the change, reads it back to verify it, and returns the diff with the exact call that rolls it back.
- If a write is refused because writes are disabled or the entity is not allowed, say so; do not look for another route.
""".strip()


def _icons() -> list[Icon]:
    """The light and dark logos shipped with the package, as data URIs so no hosting is needed."""
    assets = resources.files("unifi_console_mcp").joinpath("assets")
    out: list[Icon] = []
    for theme in ("light", "dark"):
        data = assets.joinpath(f"unifi-{theme}.svg").read_bytes()
        out.append(
            Icon(
                src="data:image/svg+xml;base64," + base64.b64encode(data).decode("ascii"),
                mime_type="image/svg+xml",
                sizes=["any"],
                theme=theme,
            )
        )
    return out


def create_server(settings: Settings, transport: httpx.AsyncBaseTransport | None = None) -> tuple[MCPServer, Api]:
    registry = Registry(settings.spec_path)
    client = UniFiClient(settings, transport=transport)
    api = Api(settings, registry, client)
    mcp = MCPServer(
        "unifi_console_mcp",
        title=TITLE,
        description=DESCRIPTION,
        instructions=INSTRUCTIONS,
        website_url=WEBSITE_URL,
        icons=_icons(),
        version=__version__,
        log_level=settings.log_level,  # type: ignore[arg-type]
    )
    tools_generic.register(mcp, api)
    tools_curated.register(mcp, api)
    tools_writes.register(mcp, api)
    return mcp, api


def main() -> None:
    try:
        settings = Settings.from_env()
    except RuntimeError as exc:
        print(f"unifi_console_mcp: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    mcp, _ = create_server(settings)
    # stdout carries the protocol; anything human-readable goes to stderr.
    entities = ", ".join(sorted(settings.write_entities)) or "none"
    print(
        f"unifi_console_mcp ready on stdio (console {settings.host}, writes "
        f"{'enabled' if settings.enable_writes else 'disabled'}, writable entities: {entities})",
        file=sys.stderr,
    )
    mcp.run()


if __name__ == "__main__":
    main()
