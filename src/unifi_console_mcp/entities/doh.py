"""DNS over HTTPS (the `doh` setting group): which encrypted resolver the gateway uses for its DNS queries. Tier C.

Captured 2026-10-17 (DoH HAR): the group is read with `getSiteSetting` key `doh` and written with POST
`set/setting/doh`, body `{key: "doh", state, server_names[], custom_servers[]}`; the reply is the legacy envelope with the
whole group. `state` is `off`, `auto` (captured 2026-10-18: the UI's Auto sends `server_names: ["cloudflare", "google"]`),
`manual` (named resolvers from `getDohAvailableServerNames`) or `custom` (entries `{server_name, sdns_stamp, enabled}`). The UI clears the list that does not apply when it switches mode, and so does this tool.

Why tier C: a wrong resolver, or one that cannot be reached, stops DNS for every client, and that may also cut the very
connection this tool runs over. So the change is wrapped in a safety net (see `dnsprobe.py`): DNS is tested through the
gateway before the change (a broken start refuses it) and again after it; if the test fails, the previous values are put
back once, automatically, and the result says so.

SSL inspection is a separate group and stays read-only. Custom stamps are only shape-checked (the captured one is not a
standard DoH stamp), so a custom change relies on the safety net rather than on validation.
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel, ConfigDict, Field

from ..api import error_text
from ..client import UniFiError
from ..dnsprobe import make_guard
from ..writes import EntitySpec, Findings, WriteEngine

KEY = "doh"
TOOL = "unifi_console_doh"
STATES = ("off", "auto", "manual", "custom")
AUTO_NAMES = ["cloudflare", "google"]  # what the UI sends for Auto (captured 2026-10-18)
BODY_KEYS = ("key", "state", "server_names", "custom_servers")
_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
GUARD_TEXT = ("Safety net: DNS is tested through the gateway before and after this change. If it fails afterwards, the previous "
              "values are put back automatically, once, and the result says so.")


def _norm_names(value: Any) -> list[str]:
    if not isinstance(value, (list, tuple)):
        raise UniFiError("server_names must be a list of resolver names, for example [\"cloudflare\", \"cloudflare-ipv6\"].")
    out: list[str] = []
    for v in value:
        name = str(v).strip().lower()
        if name and name not in out:
            out.append(name)
    return out


def _norm_custom(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, (list, tuple)):
        raise UniFiError("custom_servers must be a list of {server_name, sdns_stamp, enabled}.")
    out = []
    for v in value:
        if not isinstance(v, dict):
            raise UniFiError("Each custom server must be an object with server_name and sdns_stamp.")
        out.append({"server_name": str(v.get("server_name") or "").strip(),
                    "sdns_stamp": str(v.get("sdns_stamp") or "").strip(),
                    "enabled": bool(v.get("enabled", True))})
    return out


def prepare(action: str, before: dict[str, Any] | None, changes: dict[str, Any]) -> dict[str, Any]:
    """Settle the final state and clear the list that does not apply, as the UI does."""
    unknown = set(changes) - {"state", "server_names", "custom_servers"}
    if unknown:
        raise UniFiError(f"Unknown field(s): {', '.join(sorted(unknown))}. Use state, server_names and custom_servers.")
    b = before or {}
    state = str(changes.get("state") or b.get("state") or "off").strip().lower()
    names = _norm_names(changes["server_names"]) if "server_names" in changes else _norm_names(b.get("server_names") or [])
    custom = _norm_custom(changes["custom_servers"]) if "custom_servers" in changes else _norm_custom(b.get("custom_servers") or [])
    if state not in STATES:
        raise UniFiError(f"state must be one of: {', '.join(STATES)}.")
    if state == "auto" and "server_names" in changes and names != AUTO_NAMES:
        raise UniFiError("auto uses the console's own resolvers (cloudflare, google); use state=manual to choose names.")
    if state not in ("manual", "auto") and "server_names" in changes and names:
        raise UniFiError(f"server_names only applies when state is manual (state would be '{state}'). "
                         "Pass state=manual with the names, or leave server_names out.")
    if state != "custom" and "custom_servers" in changes and custom:
        raise UniFiError(f"custom_servers only applies when state is custom (state would be '{state}'). "
                         "Pass state=custom with the entries, or leave custom_servers out.")
    if state == "auto":
        names, custom = list(AUTO_NAMES), []
    elif state == "manual":
        custom = []
    elif state == "custom":
        names = []
    else:
        names, custom = [], []
    return {"state": state, "server_names": names, "custom_servers": custom}


def _stamp_problem(stamp: str) -> str | None:
    if not stamp.startswith("sdns://"):
        return "must start with sdns://"
    raw = stamp[len("sdns://"):]
    if not raw or not re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", raw):
        return "is not valid URL-safe base64 after sdns://"
    try:
        data = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    except (ValueError, TypeError):
        return "is not valid URL-safe base64 after sdns://"
    if b"https://" not in data:
        return "does not contain an https:// address, so it is not a DoH stamp"
    return None


def validate(action: str, before: dict[str, Any] | None, after: dict[str, Any], others: list[dict[str, Any]],
             ctx: dict[str, list[dict[str, Any]]]) -> Findings:
    f = Findings()
    state = str(after.get("state") or "")
    names = list(after.get("server_names") or [])
    custom = list(after.get("custom_servers") or [])
    b = before or {}
    available = sorted({n for row in ctx.get("names", []) for n in (row.get("server_names") or [])})
    if state not in STATES:
        f.errors.append(f"state must be one of: {', '.join(STATES)}.")
        return f
    if state == "off":
        f.warnings.append("DoH off: the gateway sends its DNS queries to the upstream resolver unencrypted.")
    elif state == "auto":
        f.warnings.append("Auto lets the console choose between its own resolvers (Cloudflare and Google); you do not pick them.")
    elif state == "manual":
        if not names:
            f.errors.append("manual needs at least one resolver name in server_names.")
        for n in names:
            if not _NAME.match(n):
                f.errors.append(f"'{n}' is not a valid resolver name.")
            elif available and n not in available:
                f.errors.append(f"'{n}' is not a resolver this console offers. List them with getDohAvailableServerNames.")
        if names and len(names) == 1:
            f.warnings.append("Only one resolver is selected, so DNS depends on it alone.")
        for n in names:
            partner = n[:-5] if n.endswith("-ipv6") else n + "-ipv6"
            if partner not in names and (not available or partner in available):
                f.warnings.append(f"'{n}' is selected without its {'IPv4' if n.endswith('-ipv6') else 'IPv6'} partner '{partner}'.")
    else:
        enabled = [c for c in custom if c.get("enabled")]
        if not enabled:
            f.errors.append("custom needs at least one enabled entry in custom_servers.")
        seen: set[str] = set()
        for c in custom:
            label = c.get("server_name") or "(unnamed)"
            if not c.get("server_name"):
                f.errors.append("Every custom server needs a server_name.")
            elif c["server_name"] in seen:
                f.errors.append(f"The custom server name '{c['server_name']}' is used twice.")
            seen.add(c.get("server_name") or "")
            problem = _stamp_problem(str(c.get("sdns_stamp") or ""))
            if problem:
                f.errors.append(f"The stamp for '{label}' {problem}.")
        f.warnings.append("Custom stamps are only shape-checked here (the console's own format is not fully known); "
                          "the safety net is what catches a stamp that does not work.")
    prev_state = str(b.get("state") or "")
    if prev_state and prev_state != "off" and state != prev_state and not f.errors:
        f.warnings.append(f"Moving from {prev_state} to {state}: DNS may pause briefly while the gateway switches resolver.")
    if not f.errors:
        f.warnings.append("Clients with a hard-coded DNS server bypass the gateway, so this setting does not affect them.")
    return f


SPEC = EntitySpec(
    key=KEY, label="DNS over HTTPS setting", tier="C", list_op="getSiteSetting", create_op=None,
    update_op="updateDohSetting", delete_op=None, whole_object=True, id_field="_id", name_field="key",
    prepare=prepare, validate_ctx=validate,
    context_ops=(("names", "getDohAvailableServerNames"),),
    singleton=True, list_path_params={"key": KEY}, body_keys=BODY_KEYS,
    guard=make_guard(GUARD_TEXT),
)


class CustomServer(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    server_name: str = Field(..., description="A label for this resolver, unique in the list.")
    sdns_stamp: str = Field(..., description="The resolver's DNS stamp, starting sdns://")
    enabled: bool = Field(default=True)


class DohInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    action: Literal["update"] = Field(default="update", description="Only update exists: DoH is a single settings group.")
    target: str | None = Field(default=None, description="Leave empty. Accepted only so a rollback call can be replayed.")
    state: Literal["off", "auto", "manual", "custom"] | None = Field(
        default=None, description="off, auto (console picks Cloudflare/Google), manual (named resolvers) or custom (your own stamps). Defaults to the current state.")
    server_names: list[str] | None = Field(
        default=None, description="Resolver names for manual, for example [\"cloudflare\", \"cloudflare-ipv6\"]. Replaces the list.")
    custom_servers: list[CustomServer] | None = Field(
        default=None, description="Entries for custom: server_name, sdns_stamp, enabled. Replaces the list.")
    approval_note: str | None = Field(
        default=None, description="Required with confirm=true: where the approval for this tier C change was given.")
    confirm: bool = Field(default=False, description="false (default) returns a read-only preview. true applies the change and needs fingerprint.")
    fingerprint: str | None = Field(default=None, description="From the preview of exactly this change; required with confirm=true.")

    def changes(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.state is not None:
            out["state"] = self.state
        if self.server_names is not None:
            out["server_names"] = list(self.server_names)
        if self.custom_servers is not None:
            out["custom_servers"] = [c.model_dump() for c in self.custom_servers]
        return out


def register(mcp: MCPServer, engine: WriteEngine) -> None:
    @mcp.tool(
        name=TOOL,
        annotations={"title": "Change the DNS over HTTPS setting", "readOnlyHint": False, "destructiveHint": True,
                     "idempotentHint": True, "openWorldHint": False},
    )
    async def unifi_console_doh(params: DohInput) -> str:
        """Preview, then apply, a change to the gateway's DNS over HTTPS (DoH) setting. Tier C: it can stop DNS for the whole network.

        Two steps, always: call with confirm=false to get a read-only preview (before, after, diff, warnings, the safety
        probe result, a fingerprint); call again with the same fields plus confirm=true, that fingerprint and an
        approval_note to apply. Fields: state (off, auto, manual or custom), server_names (manual) and custom_servers (custom);
        the list that does not apply is cleared, as the UI does. Before applying, DNS is tested through the gateway; if it is
        already failing, the change is refused. After applying, DNS is tested again and, if it fails, the previous values are
        put back automatically (once) and the result says applied=false with auto_restored=true. Applying also needs
        UNIFI_CONSOLE_ENABLE_WRITES=true and 'doh' in UNIFI_CONSOLE_WRITE_ENTITIES. SSL inspection is a separate setting and
        is not changed here. Every write is journalled; scripts/doh_restore.py can put the last values back from the journal.
        """
        try:
            changes = params.changes()
            if not changes:
                return json.dumps({"ok": False, "error": "Nothing to change: pass state, server_names or custom_servers."})
            result = await engine.execute(
                SPEC, action="update", target=params.target, changes=changes,
                confirm=params.confirm, fingerprint=params.fingerprint, approval_note=params.approval_note,
            )
            return json.dumps(result, separators=(",", ":"), default=str)
        except Exception as exc:  # noqa: BLE001 - converted to an actionable message
            return error_text(exc)
