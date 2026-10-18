"""Client commands (legacy `cmd/stamgr`): block, unblock, reconnect (kick) and forget one client. Tier B.

Captured 2026-10-18 (`client-block-reconnect.har`, `client-reconnect.har`): every command is
`POST cmd/stamgr {"macs": [mac], "cmd": "block-sta" | "unblock-sta" | "kick-sta" | "forget-sta"}`. block, unblock and forget
reply with the client record; kick replies with an empty list. (The bundled spec says `mac` for some; the UI sends `macs`.)

These are commands, not edits of a stored object, so they do not go through the entity engine's update path. They use the
same gates, lock, journal and two-step fingerprint, under the existing `client` write switch:
  * block / unblock: read back `blocked` on the known client. Each is the other's rollback.
  * reconnect: disconnects a wireless client once; it normally rejoins on its own. Only a connected, wireless client is
    accepted. There is nothing stored to verify.
  * forget: deletes the client's history, name, note, fixed IP and Local DNS record for good. Needs `discard_history=true`
    and there is no rollback. Only an offline client is accepted, so a device in use is not dropped by mistake.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel, ConfigDict, Field

from ..api import error_text
from ..client import UniFiError
from ..redact import redact
from ..writes import EntitySpec, WriteEngine, _canon

KEY = "client"          # same write switch as the client record tool
TOOL = "unifi_console_client_command"
COMMANDS = {"block": "block-sta", "unblock": "unblock-sta", "reconnect": "kick-sta", "forget": "forget-sta"}
_MAC = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
SPEC = EntitySpec(key=KEY, label="client command", tier="B", list_op="listKnownClients")


def norm_mac(value: str) -> str:
    mac = value.strip().lower().replace("-", ":")
    if not _MAC.match(mac):
        raise UniFiError("target must be a client MAC address such as aa:bb:cc:dd:ee:ff.")
    return mac


def _label(row: dict[str, Any] | None, mac: str) -> str:
    row = row or {}
    return str(row.get("name") or row.get("hostname") or mac)


def assess(command: str, mac: str, known: dict[str, Any] | None, active: dict[str, Any] | None,
           devices: list[dict[str, Any]]) -> tuple[list[str], list[str], bool, str | None]:
    """Returns (errors, warnings, no_change, note)."""
    errors: list[str] = []
    warnings: list[str] = []
    no_change, note = False, None
    if any(str(d.get("mac") or "").lower() == mac for d in devices):
        errors.append("That MAC belongs to a UniFi device, not a client. Manage devices in the UniFi UI.")
        return errors, warnings, no_change, note
    if known is None and active is None:
        errors.append(f"The console has no client with MAC {mac}.")
        return errors, warnings, no_change, note
    name = _label(known or active, mac)
    if command == "block":
        if (known or {}).get("blocked"):
            no_change, note = True, "Already blocked; nothing would be sent."
        warnings.append(f"Blocking {name} stops it using the network until it is unblocked. If it is the machine running this "
                        "session or an access point you depend on, access may be lost.")
        if (known or {}).get("use_fixedip"):
            warnings.append(f"{name} has a fixed IP ({(known or {}).get('fixed_ip')}); the reservation is kept while it is blocked.")
    elif command == "unblock":
        if not (known or {}).get("blocked"):
            no_change, note = True, "Not blocked; nothing would be sent."
    elif command == "reconnect":
        if not active:
            errors.append(f"{name} is not connected right now, so there is nothing to disconnect.")
        elif active.get("is_wired"):
            errors.append(f"{name} is wired. Reconnect only works for wireless clients; use the switch port tool to cycle a port.")
        else:
            warnings.append(f"{name} is disconnected once and normally rejoins within seconds; anything in use on it is interrupted.")
    elif command == "forget":
        if active:
            errors.append(f"{name} is connected right now. Forget only works on a client that is offline, so a device in use is not dropped.")
        warnings.append(f"Forgetting {name} deletes its history, name, note, fixed IP and Local DNS record for good. "
                        "It cannot be undone; the device appears as a new client if it connects again.")
        if (known or {}).get("use_fixedip") or (known or {}).get("local_dns_record_enabled"):
            warnings.append(f"{name} has a fixed IP or Local DNS record that will be lost.")
    return errors, warnings, no_change, note


def rollback_for(command: str, mac: str) -> dict[str, Any] | None:
    inverse = {"block": "unblock", "unblock": "block"}.get(command)
    return {"command": inverse, "target": mac} if inverse else None


async def run(engine: WriteEngine, *, command: str, target: str, confirm: bool, fingerprint: str | None,
              discard_history: bool) -> dict[str, Any]:
    if command not in COMMANDS:
        raise UniFiError(f"command must be one of: {', '.join(COMMANDS)}.")
    mac = norm_mac(target)
    async with engine._lock:
        known_rows = await engine._read_list("listKnownClients")
        active_rows = await engine._read_list("listActiveClientsLegacy")
        devices = await engine._read_list("listDevicesBasic")
        known = next((r for r in known_rows if str(r.get("mac") or "").lower() == mac), None)
        active = next((r for r in active_rows if str(r.get("mac") or "").lower() == mac), None)
        errors, warnings, no_change, note = assess(command, mac, known, active, devices)
        op = engine.api.registry.get("clientManagerCommand")
        path = op.build_path({}, engine.api.settings.site)
        body = {"macs": [mac], "cmd": COMMANDS[command]}
        stable = {k: (known or {}).get(k) for k in ("blocked", "name", "use_fixedip", "fixed_ip", "local_dns_record")}
        fp = hashlib.sha256(_canon({"entity": TOOL, "command": command, "mac": mac, "path": path, "body": body,
                                    "before": stable, "connected": bool(active)}).encode()).hexdigest()[:16]
        blocked = engine.blocked_reason(SPEC, None)
        view = {"mac": mac, "name": _label(known or active, mac), "blocked": (known or {}).get("blocked", False),
                "connected": bool(active), "wired": bool((active or {}).get("is_wired", False))}
        if not confirm:
            out: dict[str, Any] = {
                "ok": True, "applied": False, "preview": True, "entity": TOOL, "tier": "B", "command": command,
                "client": view, "request": {"method": op.method, "path": path, "body": body},
                "warnings": warnings, "errors": errors, "fingerprint": fp,
                "apply_blocked_reason": blocked or ("; ".join(errors) or None),
            }
            if note:
                out["note"] = note
            else:
                out["next_step"] = f"To apply, call again with the same fields, confirm=true and fingerprint='{fp}'" + (
                    " and discard_history=true." if command == "forget" else ".")
            return out
        if blocked:
            raise UniFiError(blocked)
        if errors:
            raise UniFiError("Refused: " + " ".join(errors))
        if not fingerprint:
            raise UniFiError("confirm=true needs the fingerprint from a preview of exactly this change. Preview first.")
        if fingerprint != fp:
            raise UniFiError("The client, or the request, differs from the preview you confirmed. Run the preview again and review it.")
        if command == "forget" and not discard_history:
            raise UniFiError("Forgetting deletes the client's history for good. Repeat with discard_history=true to confirm. Nothing was changed.")
        if no_change:
            return {"ok": True, "applied": False, "entity": TOOL, "command": command, "note": note}

        journal_id = uuid.uuid4().hex[:12]
        base = {"journal_id": journal_id, "entity": TOOL, "tier": "B", "action": command, "id": mac, "method": op.method,
                "path": path, "before": known, "body": body}
        engine._journal({"event": "attempt", **base})
        status, data, problem = await engine._send_json(op.method, path, body, op.needs_session)
        if problem:
            engine._journal({"event": "failed", "journal_id": journal_id, "http_status": status, "error": problem})
            raise UniFiError(f"The console rejected the {command}: {problem} Re-run the preview to see the current state.")
        verified: bool | None = None
        mismatch: dict[str, Any] | None = None
        if command in ("block", "unblock", "forget"):
            rows = await engine._read_list("listKnownClients")
            stored = next((r for r in rows if str(r.get("mac") or "").lower() == mac), None)
            if command == "forget":
                verified = stored is None
                mismatch = None if verified else {"field": "(client)", "requested": "forgotten", "stored": "still present"}
            else:
                want = command == "block"
                verified = stored is not None and bool(stored.get("blocked")) == want
                mismatch = None if verified else {"field": "blocked", "requested": want, "stored": (stored or {}).get("blocked")}
        result: dict[str, Any] = {"ok": True, "applied": True, "entity": TOOL, "tier": "B", "command": command, "id": mac,
                                  "http_status": status, "verified": verified, "rollback": rollback_for(command, mac),
                                  "journal_id": journal_id}
        if verified is None:
            result["note"] = "A reconnect has nothing stored to read back; check the client's connection in the console."
        if mismatch:
            result["mismatches"] = redact([mismatch])
            result["attention"] = "The console accepted the command but the stored client does not match it. Nothing was retried."
        engine._journal({"event": "result", "journal_id": journal_id, "http_status": status, "verified": verified,
                         "mismatches": [mismatch] if mismatch else []})
        return result


class ClientCommandInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    command: Literal["block", "unblock", "reconnect", "forget"] = Field(
        ..., description="block or unblock network access; reconnect (disconnect a wireless client once); forget (delete an offline client's history).")
    target: str = Field(..., description="The client's MAC address (any case, ':' or '-').")
    discard_history: bool = Field(default=False, description="forget only, with confirm=true: acknowledges the history is lost for good.")
    confirm: bool = Field(default=False, description="false (default) returns a read-only preview. true applies the command and needs fingerprint.")
    fingerprint: str | None = Field(default=None, description="From the preview of exactly this command; required with confirm=true.")


def register(mcp: MCPServer, engine: WriteEngine) -> None:
    @mcp.tool(
        name=TOOL,
        annotations={"title": "Block, unblock, reconnect or forget a client", "readOnlyHint": False, "destructiveHint": True,
                     "idempotentHint": False, "openWorldHint": False},
    )
    async def unifi_console_client_command(params: ClientCommandInput) -> str:
        """Preview, then apply, a command for one client: block, unblock, reconnect or forget.

        Two steps, always: call with confirm=false to get a read-only preview (the client, the request, warnings, a
        fingerprint); call again with the same fields plus confirm=true and that fingerprint to apply. block and unblock
        are read back and are each other's rollback. reconnect disconnects a connected wireless client once. forget
        deletes an offline client's history, name, note, fixed IP and Local DNS record for good, so it also needs
        discard_history=true and has no rollback. UniFi devices are refused. Applying needs UNIFI_CONSOLE_ENABLE_WRITES=true
        and 'client' in UNIFI_CONSOLE_WRITE_ENTITIES (the same switch as the client record tool). Every command is journalled.
        """
        try:
            result = await run(engine, command=params.command, target=params.target, confirm=params.confirm,
                               fingerprint=params.fingerprint, discard_history=params.discard_history)
            return json.dumps(result, separators=(",", ":"), default=str)
        except Exception as exc:  # noqa: BLE001 - converted to an actionable message
            return error_text(exc)
