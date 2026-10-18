"""Server entry point: builds the Api, registers tools and runs over stdio."""

from __future__ import annotations

import sys

import httpx
from mcp.server.mcpserver import MCPServer

from . import __version__, tools_curated, tools_generic, tools_writes
from .api import Api
from .client import UniFiClient
from .config import Settings
from .registry import Registry


def create_server(settings: Settings, transport: httpx.AsyncBaseTransport | None = None) -> tuple[MCPServer, Api]:
    registry = Registry(settings.spec_path)
    client = UniFiClient(settings, transport=transport)
    api = Api(settings, registry, client)
    mcp = MCPServer("unifi_console_mcp", version=__version__)
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
    print(f"unifi_console_mcp ready on stdio (console {settings.host}, writes "
          f"{'enabled' if settings.enable_writes else 'disabled'}, writable entities: {entities})", file=sys.stderr)
    mcp.run()


if __name__ == "__main__":
    main()
