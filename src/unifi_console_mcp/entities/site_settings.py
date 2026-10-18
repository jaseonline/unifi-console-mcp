"""Two site setting groups: remote syslog (`rsyslogd`) and data retention (`super_mgmt`). Tier B.

Both are written with POST `set/setting/{key}` (`updateSiteSetting`) and read with `getSiteSetting`.

rsyslogd, captured 2026-10-18 (`rsyslogd.har`): the UI writes `enabled`, `this_controller`, `this_controller_encrypted_only`,
`debug`, `log_all_contents`, `contents[]` (admin_activity, client, critical, device, security_detections, triggers, updates,
vpn), `netconsole_enabled`, `netconsole_host`, `netconsole_port` and the same host and port again as `ip` and `port`
(strings). The reply is the whole group. The UI leaves `contents` out when `log_all_contents` is true; this tool sends what is
stored, which has not been tested against the console for that combination.

super_mgmt, captured 2026-10-18 (`data-retention.har`): one whole-object write that also carries auto-backup, analytics and a
Google Maps key. Only the retention fields are offered here; everything else is sent back exactly as read, and the key is
never shown (it is redacted in previews and the journal). With `data_retention_setting_preference` set to auto the console
recalculates the hours itself, so they are not accepted together with it and are not read back.
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel, ConfigDict, Field

from ..api import error_text
from ..client import UniFiError
from ..writes import EntitySpec, Findings, WriteEngine

SYSLOG_KEY, SYSLOG_TOOL = "syslog", "unifi_console_syslog"
RETENTION_KEY, RETENTION_TOOL = "data_retention", "unifi_console_data_retention"

CONTENTS = ("admin_activity", "client", "critical", "device", "security_detections", "triggers", "updates", "vpn")
SYSLOG_BODY_KEYS = ("key", "enabled", "this_controller", "this_controller_encrypted_only", "debug", "log_all_contents", "contents",
                    "netconsole_enabled", "netconsole_host", "netconsole_port", "ip", "port")
_HOST = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$")

HOURS = ("data_retention_time_in_hours_for_5minutes_scale", "data_retention_time_in_hours_for_hourly_scale",
         "data_retention_time_in_hours_for_daily_scale", "data_retention_time_in_hours_for_monthly_scale",
         "data_retention_time_in_hours_for_others")
RETENTION_VIEW = ("data_retention_setting_preference", *HOURS)
MAX_HOURS = 24 * 365 * 5


# ------------------------------------------------------------------------------------------------ syslog
def syslog_prepare(action: str, before: dict[str, Any] | None, changes: dict[str, Any]) -> dict[str, Any]:
    out = dict(changes)
    if "netconsole_host" in out:
        out["netconsole_host"] = str(out["netconsole_host"]).strip()
        out["ip"] = out["netconsole_host"]
    if "netconsole_port" in out:
        out["netconsole_port"] = str(out["netconsole_port"]).strip()
        out["port"] = out["netconsole_port"]
    if "contents" in out:
        seen: list[str] = []
        for c in out["contents"]:
            c = str(c).strip().lower()
            if c not in seen:
                seen.append(c)
        out["contents"] = seen
    return out


def syslog_validate(action: str, before: dict[str, Any] | None, after: dict[str, Any], others: list[dict[str, Any]]) -> Findings:
    f = Findings()
    b = before or {}
    bad = [c for c in after.get("contents") or [] if c not in CONTENTS]
    if bad:
        f.errors.append(f"Unknown content type(s): {', '.join(bad)}. Choose from: {', '.join(CONTENTS)}.")
    if after.get("netconsole_enabled"):
        host = str(after.get("netconsole_host") or "")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not host or not _HOST.match(host):
                f.errors.append("netconsole_host must be the IP address or host name of the syslog server.")
        port = str(after.get("netconsole_port") or "")
        if not (port.isdigit() and 1 <= int(port) <= 65535):
            f.errors.append("netconsole_port must be a port number from 1 to 65535.")
        if not after.get("enabled"):
            f.warnings.append("netconsole is on but the syslog group is not enabled, so nothing is sent.")
        if not after.get("log_all_contents") and not after.get("contents"):
            f.errors.append("Choose at least one content type in contents, or set log_all_contents=true.")
    if not f.errors:
        old = (b.get("enabled") and b.get("netconsole_enabled"), b.get("netconsole_host"), str(b.get("netconsole_port")))
        new = (after.get("enabled") and after.get("netconsole_enabled"), after.get("netconsole_host"), str(after.get("netconsole_port")))
        if old[0] and old != new:
            f.warnings.append(f"The console currently sends syslog to {old[1]}:{old[2]}. Changing or stopping that ends the feed there "
                              "(for example a log collector or Insights), and logs from the gap are not replayed.")
        if after.get("debug") and not b.get("debug"):
            f.warnings.append("Debug adds a lot of detail to the log stream; switch it off again once the diagnosis is done.")
        if after.get("log_all_contents") and not b.get("log_all_contents"):
            f.warnings.append("log_all_contents sends every category, which raises the volume at the receiver.")
        if after.get("this_controller") and not b.get("this_controller"):
            f.warnings.append("this_controller is on: logs are also kept on the console itself.")
    return f


SYSLOG_SPEC = EntitySpec(
    key=SYSLOG_KEY, label="syslog setting", tier="B", list_op="getSiteSetting", update_op="updateSiteSetting",
    whole_object=True, id_field="_id", name_field="key", prepare=syslog_prepare, validate=syslog_validate,
    singleton=True, list_path_params={"key": "rsyslogd"}, fixed_path_params={"key": "rsyslogd"}, body_keys=SYSLOG_BODY_KEYS,
)


class SyslogInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    action: Literal["update"] = Field(default="update", description="Only update exists: syslog is a single settings group.")
    target: str | None = Field(default=None, description="Leave empty. Accepted only so a rollback call can be replayed.")
    enabled: bool | None = Field(default=None, description="Turn the syslog group on or off.")
    netconsole_enabled: bool | None = Field(default=None, description="Send logs to a remote syslog server.")
    netconsole_host: str | None = Field(default=None, description="Remote syslog server IP address or host name.")
    netconsole_port: int | str | None = Field(default=None, description="Remote syslog port, normally 514.")
    contents: list[str] | None = Field(default=None, description=f"Categories to send: {', '.join(CONTENTS)}. Replaces the list.")
    log_all_contents: bool | None = Field(default=None, description="Send every category instead of the contents list.")
    this_controller: bool | None = Field(default=None, description="Also keep the logs on the console itself.")
    this_controller_encrypted_only: bool | None = Field(default=None, description="Encrypted transport only for the console copy.")
    debug: bool | None = Field(default=None, description="Include debug detail in the stream.")
    confirm: bool = Field(default=False, description="false (default) returns a read-only preview. true applies the change and needs fingerprint.")
    fingerprint: str | None = Field(default=None, description="From the preview of exactly this change; required with confirm=true.")

    def changes(self) -> dict[str, Any]:
        out = {k: getattr(self, k) for k in ("enabled", "netconsole_enabled", "netconsole_host", "netconsole_port", "contents",
                                             "log_all_contents", "this_controller", "this_controller_encrypted_only", "debug")
               if getattr(self, k) is not None}
        return out


# ------------------------------------------------------------------------------------------------ data retention
def retention_prepare(action: str, before: dict[str, Any] | None, changes: dict[str, Any]) -> dict[str, Any]:
    out = dict(changes)
    b = before or {}
    pref = out.get("data_retention_setting_preference", b.get("data_retention_setting_preference"))
    given = [k for k in HOURS if k in out]
    if pref == "auto" and given:
        raise UniFiError("The retention hours only apply when data_retention_setting_preference is manual; with auto the console "
                         "chooses them. Pass preference=manual with the hours, or leave the hours out.")
    return out


def retention_validate(action: str, before: dict[str, Any] | None, after: dict[str, Any], others: list[dict[str, Any]]) -> Findings:
    f = Findings()
    if after.get("data_retention_setting_preference") not in ("auto", "manual"):
        f.errors.append("data_retention_setting_preference must be auto or manual.")
    for k in HOURS:
        v = after.get(k)
        if not isinstance(v, int) or isinstance(v, bool) or not 1 <= v <= MAX_HOURS:
            f.errors.append(f"{k} must be a whole number of hours from 1 to {MAX_HOURS}.")
    if not f.errors and after.get("data_retention_setting_preference") == "manual":
        five, hourly, daily, monthly = (after[k] for k in HOURS[:4])
        if not five <= hourly <= daily <= monthly:
            f.warnings.append("Coarser scales normally keep data at least as long as finer ones (5 minutes <= hourly <= daily <= monthly).")
        b = before or {}
        if any(isinstance(b.get(k), int) and after[k] > b[k] for k in HOURS):
            f.warnings.append("Keeping data longer uses more storage on the console; check free space (a full disk is worse than lost history).")
        if any(isinstance(b.get(k), int) and after[k] < b[k] for k in HOURS):
            f.warnings.append("Shortening retention deletes older statistics the next time the console prunes them. That cannot be undone.")
    if not f.errors and before and before.get("data_retention_setting_preference") == "manual" and after.get("data_retention_setting_preference") == "auto":
        f.warnings.append("Switching to auto lets the console reset the hours itself; the manual values are then lost.")
    return f


def retention_focus(before: dict[str, Any] | None, after: dict[str, Any] | None):
    pick = lambda row: None if row is None else {k: row.get(k) for k in RETENTION_VIEW}  # noqa: E731
    return pick(before), pick(after)


RETENTION_SPEC = EntitySpec(
    key=RETENTION_KEY, label="data retention setting", tier="B", list_op="getSiteSetting", update_op="updateSiteSetting",
    whole_object=True, id_field="_id", name_field="key", body_drop=frozenset({"site_id"}),
    prepare=retention_prepare, validate=retention_validate, singleton=True, list_path_params={"key": "super_mgmt"},
    fixed_path_params={"key": "super_mgmt"}, focus=retention_focus,
)


class RetentionInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    action: Literal["update"] = Field(default="update", description="Only update exists: data retention is a single settings group.")
    target: str | None = Field(default=None, description="Leave empty. Accepted only so a rollback call can be replayed.")
    data_retention_setting_preference: Literal["auto", "manual"] | None = Field(
        default=None, description="auto lets the console choose; manual uses the hours below.")
    hours_5minutes: int | None = Field(default=None, description="Hours to keep 5-minute statistics (captured manual value 24).")
    hours_hourly: int | None = Field(default=None, description="Hours to keep hourly statistics (captured manual value 168).")
    hours_daily: int | None = Field(default=None, description="Hours to keep daily statistics (captured manual value 2160).")
    hours_monthly: int | None = Field(default=None, description="Hours to keep monthly statistics (captured manual value 8760).")
    hours_others: int | None = Field(default=None, description="Hours to keep other data such as events (captured manual value 8760).")
    confirm: bool = Field(default=False, description="false (default) returns a read-only preview. true applies the change and needs fingerprint.")
    fingerprint: str | None = Field(default=None, description="From the preview of exactly this change; required with confirm=true.")

    def changes(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.data_retention_setting_preference is not None:
            out["data_retention_setting_preference"] = self.data_retention_setting_preference
        for field_name, key in zip(("hours_5minutes", "hours_hourly", "hours_daily", "hours_monthly", "hours_others"), HOURS):
            if getattr(self, field_name) is not None:
                out[key] = getattr(self, field_name)
        return out


def register(mcp: MCPServer, engine: WriteEngine) -> None:
    @mcp.tool(
        name=SYSLOG_TOOL,
        annotations={"title": "Change the remote syslog setting", "readOnlyHint": False, "destructiveHint": True,
                     "idempotentHint": True, "openWorldHint": False},
    )
    async def unifi_console_syslog(params: SyslogInput) -> str:
        """Preview, then apply, a change to the console's remote syslog setting (where logs are sent and which categories).

        Two steps, always: call with confirm=false to get a read-only preview (before, after, diff, warnings, a fingerprint);
        call again with the same fields plus confirm=true and that fingerprint to apply. Fields: enabled, netconsole_enabled,
        netconsole_host, netconsole_port, contents, log_all_contents, this_controller, this_controller_encrypted_only, debug.
        The host and port are also written to ip and port as the UI does. Changing or stopping the destination ends the feed
        to the current receiver, and the preview says so. Applying also needs UNIFI_CONSOLE_ENABLE_WRITES=true and 'syslog'
        in UNIFI_CONSOLE_WRITE_ENTITIES. The group is read back and verified. Every write is journalled.
        """
        try:
            changes = params.changes()
            if not changes:
                return json.dumps({"ok": False, "error": "Nothing to change: pass at least one syslog field."})
            result = await engine.execute(SYSLOG_SPEC, action="update", target=params.target, changes=changes,
                                          confirm=params.confirm, fingerprint=params.fingerprint)
            return json.dumps(result, separators=(",", ":"), default=str)
        except Exception as exc:  # noqa: BLE001 - converted to an actionable message
            return error_text(exc)

    @mcp.tool(
        name=RETENTION_TOOL,
        annotations={"title": "Change data retention", "readOnlyHint": False, "destructiveHint": True,
                     "idempotentHint": True, "openWorldHint": False},
    )
    async def unifi_console_data_retention(params: RetentionInput) -> str:
        """Preview, then apply, a change to how long the console keeps statistics and events (Control Plane > Network data retention).

        Two steps, always: call with confirm=false to get a read-only preview (the retention fields only: before, after, diff,
        warnings, a fingerprint); call again with the same fields plus confirm=true and that fingerprint to apply. Fields:
        data_retention_setting_preference (auto or manual) and, with manual, hours_5minutes, hours_hourly, hours_daily,
        hours_monthly, hours_others. The rest of the group (auto-backup, analytics and a Google Maps key) is sent back exactly
        as read and never shown. Shortening retention deletes older data at the next prune; longer retention uses more
        storage. Applying also needs UNIFI_CONSOLE_ENABLE_WRITES=true and 'data_retention' in UNIFI_CONSOLE_WRITE_ENTITIES.
        Every write is journalled.
        """
        try:
            changes = params.changes()
            if not changes:
                return json.dumps({"ok": False, "error": "Nothing to change: pass the preference or at least one hours_* value."})
            result = await engine.execute(RETENTION_SPEC, action="update", target=params.target, changes=changes,
                                          confirm=params.confirm, fingerprint=params.fingerprint)
            return json.dumps(result, separators=(",", ":"), default=str)
        except Exception as exc:  # noqa: BLE001 - converted to an actionable message
            return error_text(exc)
