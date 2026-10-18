"""Known clients (legacy `rest/user`): name, note, fixed IP and Local DNS record of one client. Tier A.

Verified before building (2026-10-17 HAR capture and partial-body test): `PUT rest/user/{id}` merges a partial body, so
only the fields that change are sent. Not offered here: block/unblock, forget, reconnect, device-type override, moving a
client to another network, bandwidth profile, access-point lock. Group membership belongs to the client group (the
record has no membership field).

The console's own records are untidy: many clients have no `network_id` or a stale one (a legacy 24-hex id for a
network that no longer exists). So the address is checked against the real networks, not against the record.
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

KEY = "client"
TOOL = "unifi_console_client"
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
FIELDS = ("name", "note", "noted", "use_fixedip", "fixed_ip", "local_dns_record", "local_dns_record_enabled")

# Fields that change on their own while a client is connected. They must not make a preview go stale.
LIVE = frozenset({
    "site_id", "attr_hidden_id", "attr_no_delete", "attr_no_edit", "last_seen", "first_seen", "last_ip", "disconnect_timestamp",
    "last_uplink_name", "last_uplink_mac", "last_radio", "last_connection_network_id", "last_connection_network_name",
    "confidence", "fingerprint_engine_version", "fingerprint_source", "uptime", "assoc_time", "latest_assoc_time",
    "rx_bytes", "tx_bytes", "priority", "dev_id", "dev_cat", "dev_family", "dev_vendor", "os_name", "os_class", "oui",
})


def _valid_name(value: str) -> bool:
    return len(value) <= 128 and "\n" not in value


def _valid_fqdn(value: str) -> bool:
    labels = value.rstrip(".").split(".")
    return len(value) <= 253 and all(_LABEL.match(x) for x in labels)


def prepare(action: str, before: dict[str, Any] | None, changes: dict[str, Any]) -> dict[str, Any]:
    if action == "create" or before is None:
        raise UniFiError("Known clients cannot be created here; they appear when the device connects. Use update.")
    out = dict(changes)
    if "fixed_ip" in out:
        out["fixed_ip"] = str(out["fixed_ip"]).strip()
        if not out["fixed_ip"]:
            raise UniFiError("fixed_ip cannot be empty. To stop using a fixed IP set use_fixedip=false.")
        out.setdefault("use_fixedip", True)
    if out.get("use_fixedip") is True and not out.get("fixed_ip") and not before.get("fixed_ip"):
        raise UniFiError("use_fixedip=true needs a fixed_ip: this client has none stored.")
    if "local_dns_record" in out:
        out["local_dns_record"] = str(out["local_dns_record"]).strip().lower().rstrip(".")
        out.setdefault("local_dns_record_enabled", bool(out["local_dns_record"]))
        if out["local_dns_record"] == "" and out["local_dns_record_enabled"]:
            raise UniFiError("An empty local_dns_record cannot be enabled; give the name or set local_dns_record_enabled=false.")
    if out.get("local_dns_record_enabled") is True and not out.get("local_dns_record") and not before.get("local_dns_record"):
        raise UniFiError("local_dns_record_enabled=true needs a local_dns_record: this client has none stored.")
    if ("name" in out or "note" in out) and "noted" not in out and not before.get("noted"):
        out["noted"] = True          # the console marks a client as noted when its alias or note is set
    return out


def _network_for(ip: ipaddress.IPv4Address, networks: list[dict[str, Any]]) -> dict[str, Any] | None:
    for n in networks:
        if n.get("purpose") not in ("corporate", "guest") or not n.get("ip_subnet"):
            continue
        try:
            if ip in ipaddress.IPv4Network(n["ip_subnet"], strict=False):
                return n
        except ValueError:
            continue
    return None


def _check_fixed_ip(f: Findings, before: dict[str, Any], after: dict[str, Any], others: list[dict[str, Any]],
                    ctx: dict[str, list[dict[str, Any]]]) -> None:
    raw = str(after.get("fixed_ip") or "")
    try:
        ip = ipaddress.IPv4Address(raw)
    except ValueError:
        f.errors.append(f"'{raw}' is not an IPv4 address.")
        return
    nets = ctx.get("networks", [])
    net = _network_for(ip, nets)
    if net is None:
        f.errors.append(f"{ip} is not inside any of the console's LAN subnets "
                        f"({', '.join(f'{n.get('name')} {n.get('ip_subnet')}' for n in nets if n.get('ip_subnet')) or 'none found'}).")
        return
    iface = ipaddress.IPv4Interface(net["ip_subnet"])
    if ip == iface.ip:
        f.errors.append(f"{ip} is the gateway address of {net.get('name')}.")
    if ip in (iface.network.network_address, iface.network.broadcast_address):
        f.errors.append(f"{ip} is the network or broadcast address of {net.get('name')} ({iface.network}).")
    try:
        lo, hi = ipaddress.IPv4Address(net["dhcpd_start"]), ipaddress.IPv4Address(net["dhcpd_stop"])
        if net.get("dhcpd_enabled") and lo <= ip <= hi:
            f.warnings.append(f"{ip} is inside the DHCP pool of {net.get('name')} ({lo}-{hi}). Fixed addresses are normally "
                              "kept outside the pool so a dynamic lease cannot take them first.")
    except (KeyError, ValueError):
        pass
    known = next((n for n in nets if n.get("_id") in (before.get("network_id"), before.get("last_connection_network_id"))), None)
    if known and known.get("_id") != net.get("_id"):
        f.warnings.append(f"This client last used {known.get('name')}, but {ip} belongs to {net.get('name')}. "
                          "It will only get this address if it joins that network.")
    mac = str(after.get("mac") or "").lower()
    for row in others:
        if row.get("use_fixedip") and str(row.get("fixed_ip") or "") == raw and str(row.get("mac") or "").lower() != mac:
            f.errors.append(f"{ip} is already the fixed IP of '{row.get('name') or row.get('mac')}' ({row.get('mac')}).")
    for row in ctx.get("active", []):
        if str(row.get("ip") or "") == raw and str(row.get("mac") or "").lower() != mac:
            f.errors.append(f"{ip} is in use right now by '{row.get('name') or row.get('hostname') or row.get('mac')}' ({row.get('mac')}).")


def _check_dns(f: Findings, after: dict[str, Any], others: list[dict[str, Any]], ctx: dict[str, list[dict[str, Any]]]) -> None:
    record = str(after.get("local_dns_record") or "")
    if not after.get("local_dns_record_enabled") or not record:
        return
    if not _valid_fqdn(record):
        f.errors.append(f"'{record}' is not a valid DNS name (letters, digits and hyphens in labels of up to 63 characters).")
        return
    for row in others:
        if str(row.get("local_dns_record") or "").lower() == record and row.get("local_dns_record_enabled"):
            f.errors.append(f"'{record}' is already the Local DNS record of '{row.get('name') or row.get('mac')}'.")
    for row in ctx.get("static_dns", []):
        if str(row.get("key") or "").lower() == record and row.get("enabled"):
            f.errors.append(f"'{record}' already exists as a static DNS {row.get('record_type')} record.")
    if not after.get("use_fixedip"):
        f.warnings.append("This client has no fixed IP, so the record would follow whatever address it is given. "
                          "The console's own screen only offers a Local DNS record with a fixed IP.")


def validate(action: str, before: dict[str, Any] | None, after: dict[str, Any], others: list[dict[str, Any]],
             ctx: dict[str, list[dict[str, Any]]]) -> Findings:
    f = Findings()
    before = before or {}
    if action == "delete":
        return f
    for key in ("name", "note"):
        if key in after and not _valid_name(str(after.get(key) or "")):
            f.errors.append(f"{key} is longer than 128 characters or has line breaks.")
    if after.get("use_fixedip") and (not before.get("use_fixedip") or before.get("fixed_ip") != after.get("fixed_ip")):
        _check_fixed_ip(f, before, after, others, ctx)
    changed_dns = (before.get("local_dns_record"), before.get("local_dns_record_enabled")) != (
        after.get("local_dns_record"), after.get("local_dns_record_enabled"))
    if changed_dns:
        _check_dns(f, after, others, ctx)
    if before.get("use_fixedip") and after.get("use_fixedip") is False:
        f.warnings.append(f"The fixed IP {before.get('fixed_ip')} is released; the client will take an address from the DHCP pool "
                          "the next time it renews.")
    return f


SPEC = EntitySpec(
    key=KEY, label="client", tier="A", list_op="listKnownClients", update_op="updateKnownClient", whole_object=False,
    id_field="_id", name_field="name", match_fields=("mac",), ignore=LIVE, prepare=prepare, validate_ctx=validate,
    context_ops=(("networks", "listNetworkConfig"), ("active", "listActiveClientsLegacy"), ("static_dns", "listStaticDns")),
    empty_values={"name": "", "note": "", "noted": False, "use_fixedip": False, "local_dns_record": "",
                  "local_dns_record_enabled": False},
)


class ClientInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    action: Literal["update"] = Field(default="update", description="Only update is offered: a client appears when the device connects.")
    target: str = Field(..., description="The client's MAC address (any case, ':' or '-'), its _id, or its exact name.")
    name: str | None = Field(default=None, description="Alias shown in the console. Empty text removes the alias.")
    note: str | None = Field(default=None, description="Free-text note.")
    noted: bool | None = Field(default=None, description="Normally set for you when a name or note is set.")
    use_fixedip: bool | None = Field(default=None, description="Turn the fixed IP on or off. Setting fixed_ip turns it on.")
    fixed_ip: str | None = Field(default=None, description="IPv4 address inside one of the console's LAN subnets, normally outside the DHCP pool.")
    local_dns_record: str | None = Field(default=None, description="Local DNS name such as nuc.example.home. Empty text disables it.")
    local_dns_record_enabled: bool | None = Field(default=None, description="Publish the record. Setting a non-empty record turns it on.")
    confirm: bool = Field(default=False, description="false (default) returns a read-only preview. true applies the change and needs fingerprint.")
    fingerprint: str | None = Field(default=None, description="From the preview of exactly this change; required with confirm=true.")

    def changes(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in FIELDS if getattr(self, k) is not None}


def register(mcp: MCPServer, engine: WriteEngine) -> None:
    @mcp.tool(
        name=TOOL,
        annotations={"title": "Change a client's name, note, fixed IP or Local DNS record", "readOnlyHint": False,
                     "destructiveHint": True, "idempotentHint": False, "openWorldHint": False},
    )
    async def unifi_console_client(params: ClientInput) -> str:
        """Preview, then apply, a change to one known client: alias, note, fixed IP and Local DNS record.

        Two steps, always: call with confirm=false to get a read-only preview (before, after, diff, warnings, a
        fingerprint); call again with the same fields plus confirm=true and that fingerprint to apply. The client is
        re-read first, so a stale preview is refused. A fixed IP is checked against the real LAN subnets, the gateway
        and broadcast addresses, other clients' fixed IPs and the addresses in use right now; a Local DNS name is checked
        against other clients and the static DNS records. Applying also needs UNIFI_CONSOLE_ENABLE_WRITES=true and
        'client' in UNIFI_CONSOLE_WRITE_ENTITIES. After applying, the client is read back and the result reports
        verified true/false, the diff, and the exact rollback call. Every write is journalled. A fixed IP takes
        effect when the client next renews its lease.
        """
        try:
            if not params.changes():
                return json.dumps({"ok": False, "error": "Nothing to change: pass at least one of "
                                   "name, note, use_fixedip, fixed_ip, local_dns_record, local_dns_record_enabled."})
            result = await engine.execute(
                SPEC, action="update", target=params.target, changes=params.changes(),
                confirm=params.confirm, fingerprint=params.fingerprint,
            )
            return json.dumps(result, separators=(",", ":"), default=str)
        except Exception as exc:  # noqa: BLE001 - converted to an actionable message
            return error_text(exc)
