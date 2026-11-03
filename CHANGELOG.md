# Changelog

All notable changes to this project. Versions follow `__version__` in `src/unifi_console_mcp/__init__.py`.

## Unreleased

- Claude Desktop extension (MCP Bundle, `uv` server type) with a settings form; blank fields fall back to environment
  variables, including persistent Windows user and system variables read from the registry.
- `unifi_console_read_operation`: a read-only generic tool, annotated so a client can allow it without prompting.
- `UNIFI_CONSOLE_LOG_LEVEL` sets the server log level (stderr only).

## 0.1.0

- First release: generic tools over the console's OpenAPI spec, curated read tools, and typed write tools with
  preview, confirm, verify and rollback, all off by default.
