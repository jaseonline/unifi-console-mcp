"""Generic, spec-driven tools: search, describe and call any operation in the registry.

Three tools give access to every operation in the spec without registering ~180 tools, which would
swamp an MCP client. Access policy (read-only by default) is enforced in Api.authorize.
"""

from __future__ import annotations

import json
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel, ConfigDict, Field

from .api import Api, error_text


class ListOperationsInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    search: str | None = Field(default=None, description="Words to match against operationId, summary, path and description, e.g. 'system log' or 'stp'.")
    tag: str | None = Field(default=None, description="Substring of the spec tag, e.g. 'Controller', 'Devices', 'UniFi OS', 'Integration'.")
    access: Literal["read", "sensitive_read", "safe_write", "blocked", "all"] = Field(
        default="read",
        description="read = callable now; sensitive_read = file downloads needing confirm; safe_write = creates files/backups (needs UNIFI_CONSOLE_ENABLE_WRITES + confirm); blocked = configuration writes, not exposed; all = everything.",
    )
    limit: int = Field(default=25, ge=1, le=100, description="Maximum operations to return.")
    offset: int = Field(default=0, ge=0, description="Operations to skip, for paging.")


class DescribeOperationInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    operation_id: str = Field(..., min_length=1, description="operationId from unifi_console_list_operations, e.g. 'listFirewallPoliciesWithHits'.")


class CallOperationInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    operation_id: str = Field(..., min_length=1, description="operationId from unifi_console_list_operations.")
    path_params: dict[str, Any] = Field(default_factory=dict, description="Values for {placeholders} in the path, e.g. {'mac': 'aa:bb:cc:dd:ee:ff'}. {site} defaults to the configured site.")
    query: dict[str, Any] = Field(default_factory=dict, description="Query-string parameters.")
    body: dict[str, Any] | list[Any] | None = Field(default=None, description="JSON request body, for the POST query operations that need one.")
    confirm: bool = Field(default=False, description="Required for file downloads and safe writes. Never needed for plain reads.")
    fields: list[str] | None = Field(default=None, description="For list/dict results, keep only these keys of each item.")
    search: str | None = Field(default=None, description="For list results, keep only items whose JSON contains this text (case-insensitive).")
    offset: int = Field(default=0, ge=0, description="For list results, items to skip.")
    limit: int | None = Field(default=None, ge=1, le=1000, description="For list results, maximum items to return.")


def register(mcp: MCPServer, api: Api) -> None:
    @mcp.tool(
        name="unifi_console_list_operations",
        annotations={"title": "List UniFi API operations", "readOnlyHint": True, "destructiveHint": False,
                     "idempotentHint": True, "openWorldHint": False},
    )
    async def unifi_console_list_operations(params: ListOperationsInput) -> str:
        """Search the UniFi OpenAPI spec for operations (undocumented controller / UniFi OS APIs plus the Integration API).

        Use this first to find an operationId, then unifi_console_describe_operation, then unifi_console_call_operation.
        Does not call the console.

        Returns JSON: {"ok": true, "total": int, "operations": [{"operation_id", "method", "path", "tag",
        "summary", "access"}], "next_offset": int|null}. By default only operations callable right now are shown.
        """
        ops = api.registry.search(params.search, params.tag, params.access)
        sliced = ops[params.offset : params.offset + params.limit]
        end = params.offset + len(sliced)
        return json.dumps({
            "ok": True, "total": len(ops), "spec_version": api.registry.spec_version,
            "operations": [{"operation_id": o.operation_id, "method": o.method, "path": o.path, "tag": o.tag,
                            "summary": o.summary, "access": o.access} for o in sliced],
            "next_offset": end if end < len(ops) else None,
        }, separators=(",", ":"))

    @mcp.tool(
        name="unifi_console_describe_operation",
        annotations={"title": "Describe a UniFi API operation", "readOnlyHint": True, "destructiveHint": False,
                     "idempotentHint": True, "openWorldHint": False},
    )
    async def unifi_console_describe_operation(params: DescribeOperationInput) -> str:
        """Show an operation's parameters, request-body schema, access level and description from the spec.

        Does not call the console. Returns JSON with "parameters" (name, in, required, description),
        "body_schema" (resolved JSON schema or null), "access" and "description". Descriptions often record
        quirks such as 'Read-only despite POST' or which fields hold secrets, so read them before calling.
        """
        try:
            op = api.registry.get(params.operation_id)
        except KeyError as exc:
            return json.dumps({"ok": False, "error": str(exc.args[0])})
        return json.dumps({
            "ok": True, "operation_id": op.operation_id, "method": op.method, "path": op.path, "tag": op.tag,
            "summary": op.summary, "access": op.access, "x_destructive": op.destructive,
            "auth": "login session (cookie + CSRF)" if op.needs_session else "API key",
            "parameters": [{"name": p.name, "in": p.location, "required": p.required, "description": p.description,
                            "schema": p.schema} for p in op.params],
            "body_required": op.body_required, "body_schema": op.body_schema, "description": op.description,
        }, separators=(",", ":"), default=str)

    @mcp.tool(
        name="unifi_console_call_operation",
        annotations={"title": "Call a UniFi API operation", "readOnlyHint": False, "destructiveHint": False,
                     "idempotentHint": False, "openWorldHint": False},
    )
    async def unifi_console_call_operation(params: CallOperationInput) -> str:
        """Call one spec operation on the console. Reads run immediately; configuration writes are refused.

        Read-only POST queries (system log, traffic flows) are treated as reads. File downloads (backups,
        support files) are saved to disk, never returned, and need confirm=true. Safe writes (generate a
        support file or backup) also need UNIFI_CONSOLE_ENABLE_WRITES=true on the server.
        Secrets (x_* fields, passwords, keys) are always redacted. Large results are cut to fit; use
        fields/search/limit/offset to narrow them.

        Returns JSON: {"ok": true, "operation", "http_status", "meta"?, "data"} or {"ok": false, "error"}.
        """
        try:
            result = await api.run(
                params.operation_id, path_params=params.path_params, query=params.query,
                body=params.body, confirm=params.confirm,
            )
            return api.render(result, fields=params.fields, search=params.search,
                              offset=params.offset, limit=params.limit)
        except Exception as exc:  # noqa: BLE001 - converted to an actionable message
            return error_text(exc)
