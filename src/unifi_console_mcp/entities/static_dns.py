"""Local DNS records on the gateway (v2 `static-dns`): A, AAAA, CNAME, MX, SRV and TXT. Tier A.

Verified before building (2026-10-17): create takes `{record_type, value, key, enabled}` (HTTP 200); a partial PUT is
rejected with HTTP 400, so every update sends the whole record (`whole_object=True`); the UI toggles `enabled` the same way.

The gateway answers these names itself, for every client, instead of public DNS. So the preview says what a record
overrides, refuses duplicates and the CNAME rule (a name with a CNAME can have no other record), and refuses a name that a
client already publishes through its own Local DNS record. Wildcards are not offered (unverified).
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel, ConfigDict, Field

from ..api import error_text
from ..client import UniFiError
from ..writes import EntitySpec, Findings, WriteEngine

KEY = "static_dns"
TOOL = "unifi_console_static_dns"
TYPES = ("A", "AAAA", "CNAME", "MX", "SRV", "TXT")
HOME_DOMAIN = os.environ.get("UNIFI_HOME_DOMAIN", "example.home").lower()   # names outside this domain override public DNS: the preview warns
_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
FIELDS = ("record_type", "key", "value", "enabled", "ttl", "priority", "port", "weight")
HOST_TYPES = ("CNAME", "MX", "SRV")


def _valid_name(value: str) -> bool:
    labels = value.split(".")
    return 0 < len(value) <= 253 and all(_LABEL.match(x) for x in labels)


def _rtype(before: dict[str, Any] | None, changes: dict[str, Any]) -> str:
    return str(changes.get("record_type") or (before or {}).get("record_type") or "")


def prepare(action: str, before: dict[str, Any] | None, changes: dict[str, Any]) -> dict[str, Any]:
    out = dict(changes)
    rtype = _rtype(before, out)
    if "record_type" in out:
        out["record_type"] = str(out["record_type"]).upper()
        if before is not None and out["record_type"] != before.get("record_type"):
            raise UniFiError("The type of an existing record cannot be changed; create a new record and delete this one.")
    if "key" in out:
        out["key"] = str(out["key"]).strip().lower().rstrip(".")
    if "value" in out:
        v = str(out["value"]).strip()
        if rtype in HOST_TYPES:
            v = v.lower().rstrip(".")
        elif rtype == "AAAA":
            try:
                v = str(ipaddress.IPv6Address(v))
            except ValueError:
                pass                      # reported by validate
        out["value"] = v
    return out


def _check_shape(f: Findings, rec: dict[str, Any], changed: set[str]) -> None:
    rtype, key, value = str(rec.get("record_type") or ""), str(rec.get("key") or ""), str(rec.get("value") or "")
    if rtype not in TYPES:
        f.errors.append(f"record_type must be one of: {', '.join(TYPES)}.")
        return
    if changed & {"key", "record_type"}:
        if "*" in key:
            f.errors.append("Wildcard names are not offered here (their behaviour on this console is unverified); add one in the console if needed.")
        elif not _valid_name(key):
            f.errors.append(f"'{key}' is not a valid DNS name (letters, digits, '-' and '_' in labels of up to 63 characters).")
    if changed & {"value", "record_type"}:
        if rtype == "A":
            try:
                ipaddress.IPv4Address(value)
            except ValueError:
                f.errors.append(f"An A record needs an IPv4 address, not '{value}'.")
        elif rtype == "AAAA":
            try:
                ipaddress.IPv6Address(value)
            except ValueError:
                f.errors.append(f"An AAAA record needs an IPv6 address, not '{value}'.")
        elif rtype in HOST_TYPES:
            if not _valid_name(value):
                f.errors.append(f"A {rtype} record needs a host name as its value, not '{value}'.")
        elif not value or len(value) > 255:
            f.errors.append("A TXT record needs text of 1 to 255 characters.")
    for fld, lo, hi in (("ttl", 0, 604800), ("priority", 0, 65535), ("port", 0, 65535), ("weight", 0, 65535)):
        if fld in changed and not (isinstance(rec.get(fld), int) and lo <= rec[fld] <= hi):
            f.errors.append(f"{fld} must be a whole number from {lo} to {hi}.")
    if rtype == "SRV" and "record_type" in changed and not (rec.get("port") or 0):
        f.errors.append("An SRV record needs a port (and normally a priority and weight).")
    for fld in ("priority", "port", "weight"):
        if fld in changed and rtype not in ("MX", "SRV") and rec.get(fld):
            f.errors.append(f"{fld} only applies to MX and SRV records.")


def validate(action: str, before: dict[str, Any] | None, after: dict[str, Any], others: list[dict[str, Any]],
             ctx: dict[str, list[dict[str, Any]]]) -> Findings:
    f = Findings()
    before = before or {}
    if action == "delete":
        pointing = [r for r in others if r.get("record_type") == "CNAME" and str(r.get("value") or "").lower() == str(before.get("key")).lower()]
        if pointing:
            f.warnings.append(f"{len(pointing)} CNAME record(s) point at {before.get('key')}: "
                              f"{', '.join(str(r.get('key')) for r in pointing[:5])}. They will stop resolving.")
        return f
    changed = {k for k in FIELDS if before.get(k) != after.get(k)} if before else set(FIELDS) & set(after)
    _check_shape(f, after, changed)
    if f.errors:
        return f
    rtype, key, value = after["record_type"], str(after.get("key")), str(after.get("value"))
    enabled = bool(after.get("enabled"))
    if enabled and (changed & {"key", "value", "record_type", "enabled"}):
        same_key = [r for r in others if str(r.get("key") or "").lower() == key]
        for r in same_key:
            if r.get("record_type") == rtype and str(r.get("value")).lower() == value.lower():
                f.errors.append(f"An identical {rtype} record for {key} already exists.")
        clash = [r for r in same_key if (r.get("record_type") == "CNAME") != (rtype == "CNAME") and r.get("enabled")]
        if clash:
            f.errors.append(f"{key} already has a {clash[0].get('record_type')} record, and a name with a CNAME can have no other record type.")
        twins = [r for r in same_key if r.get("record_type") == rtype and r.get("enabled")
                 and str(r.get("value")).lower() != value.lower()]
        if twins and rtype in ("CNAME",):
            f.errors.append(f"{key} already has a CNAME record; a name can have only one.")
        elif twins and rtype in ("A", "AAAA"):
            f.warnings.append(f"{key} already has {len(twins)} enabled {rtype} record(s); clients will receive all of the addresses.")
        if rtype in ("A", "AAAA", "CNAME"):
            for c in ctx.get("clients", []):
                if c.get("local_dns_record_enabled") and str(c.get("local_dns_record") or "").lower() == key:
                    f.errors.append(f"'{c.get('name') or c.get('mac')}' already publishes {key} through its own Local DNS record.")
        if rtype == "A":
            try:
                ip = ipaddress.IPv4Address(value)
                nets = [ipaddress.IPv4Network(n["ip_subnet"], strict=False) for n in ctx.get("networks", []) if n.get("ip_subnet")]
                if nets and not any(ip in n for n in nets):
                    f.warnings.append(f"{ip} is not inside any of your LAN subnets; clients will be sent to an address outside the home network.")
            except ValueError:
                pass
        if not (key == HOME_DOMAIN or key.endswith("." + HOME_DOMAIN)) and "." in key:
            f.warnings.append(f"{key} is outside {HOME_DOMAIN}: while this record is enabled, every client gets this answer "
                              "instead of the real public one.")
    if before and (changed & {"key", "value"} or ("enabled" in changed and not enabled)):
        pointing = [r for r in others if r.get("record_type") == "CNAME" and str(r.get("value") or "").lower() == str(before.get("key")).lower()]
        if pointing and (before.get("key") != after.get("key") or not enabled):
            f.warnings.append(f"{len(pointing)} CNAME record(s) point at {before.get('key')}: "
                              f"{', '.join(str(r.get('key')) for r in pointing[:5])}.")
    return f


SPEC = EntitySpec(
    key=KEY, label="static DNS record", tier="A", list_op="listStaticDns", create_op="createStaticDns",
    update_op="updateStaticDns", delete_op="deleteStaticDns", whole_object=True, id_field="_id", name_field="key",
    defaults={"enabled": True}, prepare=prepare, validate_ctx=validate,
    context_ops=(("clients", "listKnownClients"), ("networks", "listNetworkConfig")),
    empty_values={"ttl": 0, "priority": 0, "port": 0, "weight": 0},
)


class StaticDnsInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    action: Literal["create", "update", "enable", "disable", "delete"] = Field(
        ..., description="create a record, update fields of one, enable or disable it, or delete it.")
    target: str | None = Field(default=None, description="Existing record: its _id or exact name (key). A name shared by several records is refused with their ids. Not used by create.")
    record_type: Literal["A", "AAAA", "CNAME", "MX", "SRV", "TXT"] | None = Field(default=None, description="create only; fixed afterwards.")
    key: str | None = Field(default=None, description="Record name, e.g. nas.example.home. Lower-cased; no wildcards.")
    value: str | None = Field(default=None, description="IPv4 for A, IPv6 for AAAA, a host name for CNAME/MX/SRV, text for TXT.")
    enabled: bool | None = Field(default=None, description="create: defaults to true. For an existing record prefer the enable and disable actions.")
    ttl: int | None = Field(default=None, description="Seconds, 0 to 604800; 0 means the console default.")
    priority: int | None = Field(default=None, description="MX and SRV only.")
    port: int | None = Field(default=None, description="SRV only.")
    weight: int | None = Field(default=None, description="SRV only.")
    confirm: bool = Field(default=False, description="false (default) returns a read-only preview. true applies the change and needs fingerprint.")
    fingerprint: str | None = Field(default=None, description="From the preview of exactly this change; required with confirm=true.")

    def changes(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in FIELDS if getattr(self, k) is not None}


def register(mcp: MCPServer, engine: WriteEngine) -> None:
    @mcp.tool(
        name=TOOL,
        annotations={"title": "Create, change or delete a Local DNS record", "readOnlyHint": False, "destructiveHint": True,
                     "idempotentHint": False, "openWorldHint": False},
    )
    async def unifi_console_static_dns(params: StaticDnsInput) -> str:
        """Preview, then apply, a change to the gateway's Local DNS records (A, AAAA, CNAME, MX, SRV, TXT).

        Two steps, always: call with confirm=false to get a read-only preview (before, after, diff, warnings, a
        fingerprint); call again with the same fields plus confirm=true and that fingerprint to apply. The record is
        re-read first, so a stale preview is refused. The gateway answers these names for every client, so the preview
        warns when a name is outside example.home (it replaces the public answer), refuses duplicates, the CNAME
        rule and names a client already publishes, and lists CNAME records that point at a record you change or remove.
        The console only accepts the whole record, so updates send all of it. Applying also needs
        UNIFI_CONSOLE_ENABLE_WRITES=true and 'static_dns' in UNIFI_CONSOLE_WRITE_ENTITIES. After applying, the record is
        read back and the result reports verified true/false, the diff, and the exact rollback call. Every write is journalled.
        """
        try:
            if params.action == "delete" and params.changes():
                return json.dumps({"ok": False, "error": "delete takes no field values."})
            if params.action in ("enable", "disable") and params.changes():
                return json.dumps({"ok": False, "error": f"{params.action} takes no field values; use update to change fields."})
            if params.action == "create" and not (params.record_type and params.key and params.value is not None):
                return json.dumps({"ok": False, "error": "create needs record_type, key and value."})
            result = await engine.execute(
                SPEC, action=params.action, target=params.target, changes=params.changes(),
                confirm=params.confirm, fingerprint=params.fingerprint,
            )
            return json.dumps(result, separators=(",", ":"), default=str)
        except Exception as exc:  # noqa: BLE001 - converted to an actionable message
            return error_text(exc)
