"""Glue between the registry, the HTTP client and the response shaping.

Every tool, generic or curated, goes through `Api.run`, so access policy, redaction and error
messages are enforced in exactly one place.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .client import DownloadResult, UniFiClient, UniFiError, explain_status
from .config import Settings
from .redact import fit, filter_text, page, project_fields, redact, unwrap
from .registry import EMPTY_BODY_POSTS, NULL_BODY_POSTS, TYPED_WRITE_TOOLS, Operation, Registry


@dataclass
class RunResult:
    operation_id: str
    status: int
    data: Any
    download: DownloadResult | None = None


class Api:
    def __init__(self, settings: Settings, registry: Registry, client: UniFiClient) -> None:
        self.settings = settings
        self.registry = registry
        self.client = client

    # ----------------------------------------------------------------- policy
    def authorize(self, op: Operation, confirm: bool) -> None:
        access = op.access
        if access == "read":
            return
        if access == "sensitive_read":
            if not confirm:
                raise UniFiError(
                    f"{op.operation_id} downloads a file that contains credentials and configuration in plain text. "
                    "Call again with confirm=true to save it to the local download folder (the content is never "
                    "returned to the conversation)."
                )
            return
        if access == "safe_write":
            if not self.settings.enable_writes:
                raise UniFiError(
                    f"{op.operation_id} creates state on the console (a file or backup). Writes are disabled: "
                    "set UNIFI_CONSOLE_ENABLE_WRITES=true in the server environment to allow this class of action."
                )
            if not confirm:
                raise UniFiError(
                    f"{op.operation_id}: {op.summary}. This creates state on the console but changes no "
                    "configuration. Call again with confirm=true to proceed."
                )
            return
        typed = TYPED_WRITE_TOOLS.get(op.operation_id)
        if typed:
            raise UniFiError(
                f"{op.operation_id} changes configuration, so it is not available through the generic tool. "
                f"Use {typed}: it previews the change, needs confirm=true with the preview's fingerprint, journals "
                "the write and reads it back. It also needs UNIFI_CONSOLE_ENABLE_WRITES=true and the entity listed "
                "in UNIFI_CONSOLE_WRITE_ENTITIES."
            )
        raise UniFiError(
            f"{op.operation_id} ({op.method} {op.path}) changes configuration"
            f"{' and is marked x-destructive in the spec' if op.destructive else ''}. "
            "This proof of concept does not expose configuration writes; use the existing unifi-network-mcp "
            "server for that, or extend SAFE_WRITES in registry.py after reviewing the operation."
        )

    # -------------------------------------------------------------------- run
    async def run(
        self,
        operation_id: str,
        *,
        path_params: dict[str, Any] | None = None,
        query: dict[str, Any] | None = None,
        body: Any = None,
        confirm: bool = False,
    ) -> RunResult:
        try:
            op = self.registry.get(operation_id)
        except KeyError as exc:
            raise UniFiError(str(exc.args[0])) from None
        self.authorize(op, confirm)

        try:
            path = op.build_path(path_params or {}, self.settings.site)
        except ValueError as exc:
            raise UniFiError(str(exc)) from None

        for p in op.params:
            if p.location == "query" and p.required and (query or {}).get(p.name) is None:
                raise UniFiError(f"Missing required query parameter '{p.name}'. See unifi_console_describe_operation.")
        if op.method != "GET" and op.body_required and body is None and op.operation_id not in (
            EMPTY_BODY_POSTS | NULL_BODY_POSTS
        ):
            raise UniFiError(f"{op.operation_id} requires a JSON body. See unifi_console_describe_operation.")

        if op.is_download:
            result = await self.client.download(
                path, query, self.settings.download_dir, fallback_name=f"{op.operation_id}.bin",
                needs_session=op.needs_session,
            )
            return RunResult(op.operation_id, 200, None, result)

        send_body = op.operation_id not in EMPTY_BODY_POSTS and (
            body is not None or op.operation_id in NULL_BODY_POSTS or (op.method != "GET" and op.body_schema is not None)
        )
        resp = await self.client.request(
            op.method, path, params=query, json_body=body, needs_session=op.needs_session, send_body=send_body
        )
        if resp.status_code >= 400:
            raise UniFiError(explain_status(resp.status_code, path, resp.text))
        ctype = resp.headers.get("content-type", "")
        if resp.status_code == 204 or not resp.content:
            data: Any = None
        elif "json" in ctype:
            data = resp.json()
            # The UniFi OS users API reports failures inside an HTTP 200 envelope.
            if isinstance(data, dict) and "codeS" in data and str(data["codeS"]).upper() != "SUCCESS":
                raise UniFiError(
                    f"{operation_id}: the console answered HTTP {resp.status_code} but reported an error "
                    f"(code {data.get('code')}, {data.get('codeS')}: {data.get('msg') or 'no message'}). "
                    "For UniFi OS user and API-key calls this usually means the MCP account lacks permission; "
                    "raise its Control Plane permission from View to Admin."
                )
        else:
            data = resp.text[:2_000]
        return RunResult(operation_id, resp.status_code, redact(unwrap(data)))

    # ---------------------------------------------------------------- present
    def render(
        self,
        result: RunResult,
        *,
        fields: list[str] | None = None,
        field_pattern: str | None = None,
        search: str | None = None,
        offset: int = 0,
        limit: int | None = None,
        extra: dict[str, Any] | None = None,
    ) -> str:
        """Shape a result into a compact JSON envelope that fits the character budget."""
        envelope: dict[str, Any] = {"ok": True, "operation": result.operation_id, "http_status": result.status}
        if result.download is not None:
            d = result.download
            envelope["saved_file"] = {
                "path": str(d.path), "bytes": d.size, "sha256": d.sha256, "content_type": d.content_type,
                "warning": "Contains secrets in plain text. Store in a password manager or encrypted storage; do not share.",
            }
            envelope.update(extra or {})
            return json.dumps(envelope, separators=(",", ":"))

        data = filter_text(result.data, search)
        data = project_fields(data, fields, field_pattern)
        data, page_meta = page(data, offset, limit)
        envelope.update(extra or {})
        body, fit_meta = fit(data, max(1_000, self.settings.max_chars - 600))
        meta = {**page_meta, **fit_meta}
        if meta:
            envelope["meta"] = meta
        envelope["data"] = json.loads(body) if not fit_meta.get("hint", "").startswith("Response cut") else body
        return json.dumps(envelope, separators=(",", ":"), default=str)


def error_text(exc: Exception) -> str:
    """Format any exception for the model. UniFiError messages are already actionable."""
    import httpx

    if isinstance(exc, UniFiError):
        return json.dumps({"ok": False, "error": str(exc)})
    if isinstance(exc, httpx.ConnectError):
        return json.dumps({"ok": False, "error": "Could not connect to the console. Check UNIFI_LOCAL_HOST / "
                           "UNIFI_NETWORK_PORT and that the console is reachable from this machine "
                           "(or, if the certificate is self-signed, set UNIFI_LOCAL_VERIFY_SSL=false or pin it "
                           "with UNIFI_CONSOLE_CERT_SHA256)."})
    if isinstance(exc, httpx.TimeoutException):
        return json.dumps({"ok": False, "error": "The console timed out. Retry once; large queries may need a "
                           "narrower time window."})
    return json.dumps({"ok": False, "error": f"Unexpected {type(exc).__name__}: {exc}"})
