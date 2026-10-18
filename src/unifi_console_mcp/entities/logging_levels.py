"""Logging levels (`cmd/system` set-param): how much detail the Network application's own services log. Tier A.

Captured 2026-10-18 (`logging-levels.har`): one `POST cmd/system {"cmd": "set-param", "key": "debug.device" | "debug.mgmt" |
"debug.sdn" | "debug.system", "value": "warn" | "debug"}` per service, then `{"key": "debug.setting_preference", "value":
"auto" | "manual"}`. The reply is an empty list. The console's defaults are `GET v2/api/log-levels/defaults` =
`{device: warn, mgmt: warn, sdn: warn, system: warn, setting_preference: auto}`.

Not a stored object, and no read of the current levels was captured, so this tool cannot show a "before" or read the change
back: the result says verified null, and the rollback is the console's defaults. With preference auto the UI sends warn for
every service first, so auto requires warn everywhere. Debug logging is for diagnosis: it is chatty and fills storage.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel, ConfigDict, Field

from ..api import error_text
from ..client import UniFiError
from ..writes import EntitySpec, WriteEngine, _canon

KEY = "logging_levels"
TOOL = "unifi_console_logging_levels"
SERVICES = ("device", "mgmt", "sdn", "system")
DEFAULTS = {"device": "warn", "mgmt": "warn", "sdn": "warn", "system": "warn", "setting_preference": "auto"}
SPEC = EntitySpec(key=KEY, label="logging levels", tier="A", list_op="getSiteSetting")


def calls_for(levels: dict[str, str], preference: str) -> list[dict[str, str]]:
    """The requests the UI sends, in its order: each service, then the preference."""
    out = [{"cmd": "set-param", "key": f"debug.{s}", "value": levels[s]} for s in SERVICES]
    out.append({"cmd": "set-param", "key": "debug.setting_preference", "value": preference})
    return out


def settle(params: "LoggingInput") -> tuple[dict[str, str], str, list[str], list[str]]:
    levels = {s: (getattr(params, s) or DEFAULTS[s]) for s in SERVICES}
    given = [s for s in SERVICES if getattr(params, s) is not None]
    pref = params.setting_preference or ("manual" if given else "auto")
    errors: list[str] = []
    warnings: list[str] = []
    if pref == "auto" and any(v != "warn" for v in levels.values()):
        errors.append("With setting_preference=auto the console uses warn everywhere. Use manual to choose debug for a service.")
    if pref == "manual" and any(v == "debug" for v in levels.values()):
        on = ", ".join(s for s in SERVICES if levels[s] == "debug")
        warnings.append(f"Debug logging on {on} is very chatty and can fill the console's storage; set it back to warn when the diagnosis is done.")
    warnings.append("The current levels cannot be read back, so this sets all four services and the preference as given. "
                    "Services you leave out are set to warn.")
    return levels, pref, errors, warnings


async def run(engine: WriteEngine, params: "LoggingInput") -> dict[str, Any]:
    levels, pref, errors, warnings = settle(params)
    op = engine.api.registry.get("systemCommand")
    path = op.build_path({}, engine.api.settings.site)
    calls = calls_for(levels, pref)
    fp = hashlib.sha256(_canon({"entity": KEY, "path": path, "calls": calls}).encode()).hexdigest()[:16]
    blocked = engine.blocked_reason(SPEC, None)
    if not params.confirm:
        return {"ok": True, "applied": False, "preview": True, "entity": KEY, "tier": "A", "action": "update",
                "request": {"method": op.method, "path": path, "calls": calls},
                "levels": {**levels, "setting_preference": pref}, "defaults": DEFAULTS, "warnings": warnings, "errors": errors,
                "fingerprint": fp, "apply_blocked_reason": blocked or ("; ".join(errors) or None),
                "next_step": f"To apply, call again with the same fields, confirm=true and fingerprint='{fp}'."}
    if blocked:
        raise UniFiError(blocked)
    if errors:
        raise UniFiError("Refused: " + " ".join(errors))
    if not params.fingerprint:
        raise UniFiError("confirm=true needs the fingerprint from a preview of exactly this change. Preview first.")
    if params.fingerprint != fp:
        raise UniFiError("The requested change differs from the preview you confirmed. Run the preview again and review it.")
    async with engine._lock:
        journal_id = uuid.uuid4().hex[:12]
        engine._journal({"event": "attempt", "journal_id": journal_id, "entity": KEY, "tier": "A", "action": "update",
                         "method": op.method, "path": path, "body": calls})
        sent = 0
        for body in calls:
            status, _data, problem = await engine._send_json(op.method, path, body, op.needs_session)
            if problem:
                engine._journal({"event": "failed", "journal_id": journal_id, "http_status": status, "error": problem, "sent": sent})
                raise UniFiError(f"The console rejected {body['key']}: {problem} {sent} of {len(calls)} requests had already been sent; "
                                 "run the rollback (all warn, auto) to return to a known state.")
            sent += 1
        engine._journal({"event": "result", "journal_id": journal_id, "http_status": 200, "verified": None, "sent": sent})
    return {"ok": True, "applied": True, "entity": KEY, "tier": "A", "action": "update", "requests_sent": sent, "verified": None,
            "note": "The console does not report these levels back, so nothing was read to verify them.",
            "rollback": {"action": "update", "setting_preference": "auto"}, "journal_id": journal_id}


class LoggingInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    action: Literal["update"] = Field(default="update", description="Only update exists.")
    target: str | None = Field(default=None, description="Leave empty. Accepted only so a rollback call can be replayed.")
    device: Literal["warn", "debug"] | None = Field(default=None, description="Level for device management (default warn).")
    mgmt: Literal["warn", "debug"] | None = Field(default=None, description="Level for the management service (default warn).")
    sdn: Literal["warn", "debug"] | None = Field(default=None, description="Level for the SDN service (default warn).")
    system: Literal["warn", "debug"] | None = Field(default=None, description="Level for the system service (default warn).")
    setting_preference: Literal["auto", "manual"] | None = Field(
        default=None, description="auto = the console's defaults (warn everywhere); manual = the levels above. Defaults to manual when any level is given, else auto.")
    confirm: bool = Field(default=False, description="false (default) returns a read-only preview. true applies the change and needs fingerprint.")
    fingerprint: str | None = Field(default=None, description="From the preview of exactly this change; required with confirm=true.")


def register(mcp: MCPServer, engine: WriteEngine) -> None:
    @mcp.tool(
        name=TOOL,
        annotations={"title": "Change the console's logging levels", "readOnlyHint": False, "destructiveHint": False,
                     "idempotentHint": True, "openWorldHint": False},
    )
    async def unifi_console_logging_levels(params: LoggingInput) -> str:
        """Preview, then apply, the logging level (warn or debug) of the Network application's services: device, mgmt, sdn, system.

        Two steps, always: call with confirm=false to get a read-only preview (the exact requests, warnings, a fingerprint); call
        again with the same fields plus confirm=true and that fingerprint to apply. With no fields, or setting_preference=auto,
        everything returns to the console's defaults (warn). The console does not report the current levels, so the preview
        has no before and the result cannot be read back (verified is null). Debug is chatty and fills storage: use it for
        diagnosis and put it back. Applying also needs UNIFI_CONSOLE_ENABLE_WRITES=true and 'logging_levels' in
        UNIFI_CONSOLE_WRITE_ENTITIES. Every write is journalled.
        """
        try:
            return json.dumps(await run(engine, params), separators=(",", ":"), default=str)
        except Exception as exc:  # noqa: BLE001 - converted to an actionable message
            return error_text(exc)
