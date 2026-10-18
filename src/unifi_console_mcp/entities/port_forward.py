"""Port forwards (legacy `rest/portforward`). Tier A, but enabling one exposes a host to the internet.

Verified live on 11.0.81 (2026-10-17): create with the 11 keys below, partial update merges, delete returns 200.
Source limiting captured 2026-10-18: `src_limiting_enabled: true`, `src_limiting_type: "ip"` and `src` (a CIDR) on the rule.
Only `destination_ip: any` and `pfwd_interface: wan` have been exercised; the tool does not offer anything else
for destination, and accepts `wan2`/`both` only because the UI offers them.
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel, ConfigDict, Field

from ..api import error_text
from ..writes import EntitySpec, Findings, WriteEngine

KEY = "port_forward"
TOOL = "unifi_console_port_forward"

# Ports that are almost never meant to face the internet, or that the console itself uses.
RISKY_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 135: "Windows RPC", 137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS",
    445: "SMB file sharing", 1433: "SQL Server", 3306: "MySQL", 3389: "Remote Desktop", 5432: "PostgreSQL",
    5900: "VNC", 8123: "Home Assistant", 27017: "MongoDB",
}
CONSOLE_PORTS = {443, 8443, 8080, 8880, 8843, 6789, 3478, 10001}

DEFAULTS = {
    "enabled": False, "pfwd_interface": "wan", "destination_ip": "any", "destination_ips": [],
    "proto": "tcp_udp", "src_limiting_enabled": False, "log": True,
}
_PORT = re.compile(r"^(\d{1,5})(?:-(\d{1,5}))?$")


def parse_ports(value: Any) -> tuple[int, int] | None:
    m = _PORT.match(str(value or "").strip())
    if not m:
        return None
    lo = int(m.group(1))
    hi = int(m.group(2) or lo)
    if not (1 <= lo <= hi <= 65535):
        return None
    return lo, hi


def _protos(proto: str | None) -> set[str]:
    return {"tcp", "udp"} if proto == "tcp_udp" else {proto or "tcp_udp"}


def _overlap(a: dict[str, Any], b: dict[str, Any]) -> bool:
    pa, pb = parse_ports(a.get("dst_port")), parse_ports(b.get("dst_port"))
    if not pa or not pb or pa[1] < pb[0] or pb[1] < pa[0]:
        return False
    ia, ib = a.get("pfwd_interface", "wan"), b.get("pfwd_interface", "wan")
    if "both" not in (ia, ib) and ia != ib:
        return False
    return bool(_protos(a.get("proto")) & _protos(b.get("proto")))


def prepare(action: str, before: dict[str, Any] | None, changes: dict[str, Any]) -> dict[str, Any]:
    """Turning source limiting on also sets its type, as the UI does (captured 2026-10-18)."""
    changes = dict(changes)
    if changes.get("src_limiting_enabled") and "src_limiting_type" not in (before or {}):
        changes["src_limiting_type"] = "ip"
    return changes


def validate(action: str, before: dict[str, Any] | None, after: dict[str, Any], others: list[dict[str, Any]]) -> Findings:
    f = Findings()
    name = str(after.get("name") or "").strip()
    if not name:
        f.errors.append("A name is required.")
    elif len(name) > 128:
        f.errors.append("The name is longer than 128 characters.")
    elif any(r.get("name") == name for r in others):
        f.errors.append(f"Another port forward is already called '{name}'. Names must be unique so a rule can be addressed by name.")

    ext = parse_ports(after.get("dst_port"))
    internal = parse_ports(after.get("fwd_port"))
    if not ext:
        f.errors.append("dst_port must be a port (1-65535) or a range such as 58690-58699.")
    if not internal:
        f.errors.append("fwd_port must be a port (1-65535) or a range such as 58690-58699.")
    if ext and internal and (ext[1] - ext[0]) != (internal[1] - internal[0]) and ext[0] != ext[1] and internal[0] != internal[1]:
        f.errors.append("dst_port and fwd_port are ranges of different lengths.")

    host = str(after.get("fwd") or "")
    try:
        addr = ipaddress.ip_address(host)
        if addr.version != 4:
            f.errors.append("fwd must be an IPv4 address.")
        elif not addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
            f.errors.append("fwd must be a private LAN address (10/8, 172.16/12 or 192.168/16), not a public, loopback or link-local one.")
    except ValueError:
        f.errors.append("fwd must be the internal IPv4 address of the host, e.g. 10.88.1.15.")

    if after.get("proto") not in ("tcp", "udp", "tcp_udp"):
        f.errors.append("proto must be tcp, udp or tcp_udp.")
    if after.get("pfwd_interface") not in ("wan", "wan2", "both"):
        f.errors.append("pfwd_interface must be wan, wan2 or both.")

    if after.get("src_limiting_enabled"):
        src = str(after.get("src") or "").strip()
        if after.get("src_limiting_type", "ip") != "ip":
            f.errors.append("src_limiting_type must be ip.")
        try:
            net = ipaddress.ip_network(src, strict=False)
            if net.version != 4:
                f.errors.append("src must be an IPv4 address or CIDR, e.g. 142.250.0.0/15.")
            elif net.prefixlen == 0:
                f.warnings.append("src 0.0.0.0/0 matches every address, so source limiting does nothing.")
        except ValueError:
            f.errors.append("src must be an IPv4 address or CIDR, e.g. 142.250.0.0/15, when source limiting is on.")
    elif after.get("src"):
        f.warnings.append("src is set but source limiting is off, so it has no effect.")

    clashes = [r for r in others if _overlap(after, r)]
    for r in clashes:
        msg = f"Port range overlaps '{r.get('name')}' ({r.get('proto')} {r.get('dst_port')} on {r.get('pfwd_interface')})."
        if after.get("enabled") and r.get("enabled"):
            f.errors.append(msg + " Two enabled rules cannot share a port; disable one first.")
        else:
            f.warnings.append(msg + " They cannot both be enabled.")

    if after.get("enabled") and not f.errors and ext:
        scope = (f"internet addresses in {after.get('src')}" if after.get("src_limiting_enabled") and after.get("src")
                 else "the whole internet")
        f.warnings.append(
            f"Enabling this exposes {after.get('proto')} port {after.get('dst_port')} on {after.get('pfwd_interface')} to "
            f"{scope} and forwards it to {host}:{after.get('fwd_port')}. Confirm that host is the intended one, that the "
            "service is patched and authenticated, and test from outside. How the zone-based firewall treats this forward has "
            "not been verified on this console.")
        for port in range(ext[0], min(ext[1], ext[0] + 200) + 1):
            if port in RISKY_PORTS:
                f.warnings.append(f"Port {port} is {RISKY_PORTS[port]}, which is normally not exposed to the internet.")
                break
        if any(p in CONSOLE_PORTS for p in range(ext[0], min(ext[1], ext[0] + 200) + 1)):
            f.warnings.append("The range includes a port the UniFi console itself uses (443, 8443, 8080, 8880, 8843, 6789, 3478 or 10001).")
    return f


SPEC = EntitySpec(
    key=KEY, label="port forward", tier="A", list_op="listPortForwards", create_op="createPortForward",
    update_op="updatePortForward", delete_op="deletePortForward", whole_object=False, defaults=DEFAULTS, validate=validate, prepare=prepare,
)

FIELDS = ("name", "enabled", "pfwd_interface", "proto", "dst_port", "fwd", "fwd_port", "log",
          "src_limiting_enabled", "src")


class PortForwardInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    action: Literal["create", "update", "enable", "disable", "delete"] = Field(
        ..., description="create a rule (disabled unless enabled=true), update fields of one, enable or disable it, or delete it.")
    target: str | None = Field(default=None, description="Existing rule: its _id or its exact name. Not used by create.")
    name: str | None = Field(default=None, description="Rule name (unique).")
    enabled: bool | None = Field(default=None, description="create only; a new rule is disabled unless this is true. Use the enable/disable actions for existing rules.")
    pfwd_interface: str | None = Field(default=None, description="wan (default and the only value verified here), wan2 or both.")
    proto: Literal["tcp", "udp", "tcp_udp"] | None = Field(default=None, description="Default tcp_udp.")
    dst_port: str | None = Field(default=None, description="External port or range, e.g. '58699' or '58690-58699'.")
    fwd: str | None = Field(default=None, description="Internal host: private IPv4 address.")
    fwd_port: str | None = Field(default=None, description="Internal port or range. Defaults to dst_port on create.")
    log: bool | None = Field(default=None, description="Log forwarded traffic. Default true.")
    src_limiting_enabled: bool | None = Field(default=None, description="Only forward traffic from the source in src. Default false.")
    src: str | None = Field(default=None, description="Allowed internet source: an IPv4 address or CIDR, e.g. 142.250.0.0/15. Needs src_limiting_enabled=true.")
    confirm: bool = Field(default=False, description="false (default) returns a read-only preview. true applies the change and needs fingerprint.")
    fingerprint: str | None = Field(default=None, description="From the preview of exactly this change; required with confirm=true.")

    def changes(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in FIELDS if getattr(self, k) is not None}


def register(mcp: MCPServer, engine: WriteEngine) -> None:
    @mcp.tool(
        name=TOOL,
        annotations={"title": "Create, change or delete a port forward", "readOnlyHint": False, "destructiveHint": True,
                     "idempotentHint": False, "openWorldHint": False},
    )
    async def unifi_console_port_forward(params: PortForwardInput) -> str:
        """Preview, then apply, a change to the console's port forwards (internet-to-LAN rules).

        Two steps, always: call with confirm=false to get a read-only preview (before, after, diff, warnings, a
        fingerprint); call again with the same fields plus confirm=true and that fingerprint to apply. The rule is
        re-read first, so a stale preview is refused. Applying also needs UNIFI_CONSOLE_ENABLE_WRITES=true and
        'port_forward' in UNIFI_CONSOLE_WRITE_ENTITIES. A new rule is created disabled; enabling one exposes a
        host to the internet and the preview says exactly what. After applying, the rule is read back and the
        result reports verified true/false, the diff, and the exact rollback call. Every write is journalled.
        """
        try:
            if params.action in ("enable", "disable", "delete") and params.changes():
                return json.dumps({"ok": False, "error": f"{params.action} takes no field values; use update to change fields."})
            if params.action != "create" and params.enabled is not None:
                return json.dumps({"ok": False, "error": "Use the enable or disable action to change whether an existing rule is on."})
            changes = params.changes()
            if params.action == "create" and "fwd_port" not in changes and "dst_port" in changes:
                changes["fwd_port"] = changes["dst_port"]
            result = await engine.execute(
                SPEC, action=params.action, target=params.target, changes=changes,
                confirm=params.confirm, fingerprint=params.fingerprint,
            )
            return json.dumps(result, separators=(",", ":"), default=str)
        except Exception as exc:  # noqa: BLE001 - converted to an actionable message
            return error_text(exc)



