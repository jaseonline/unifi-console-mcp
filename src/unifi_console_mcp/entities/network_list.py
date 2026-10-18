"""Network lists (legacy `rest/firewallgroup`): port, address and domain lists used by firewall policies. Tier A.

Verified on 11.0.81 (2026-10-17): create with `{_id: null, name, description, group_type, group_members, source: "static"}`,
partial update merges (`{description}` alone), `group_members` is replaced whole, delete returns 200.
Editing a list that a policy uses changes that policy's behaviour at once, so the preview names what uses it and a list
that is still in use cannot be deleted. IPv6 address lists (`group_type: ipv6-address-group`, captured 2026-10-18) use the same endpoint and body.
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
from .port_forward import parse_ports

KEY = "network_list"
TOOL = "unifi_console_network_list"
TYPES = ("port-group", "address-group", "ipv6-address-group", "domain-group")
_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


def _valid_address(value: str) -> bool:
    try:
        if "-" in value:
            lo, hi = (ipaddress.IPv4Address(p.strip()) for p in value.split("-", 1))
            return lo <= hi
        ipaddress.IPv4Network(value, strict=False)
        return True
    except ValueError:
        return False


def _valid_ipv6(value: str) -> bool:
    try:
        if "-" in value:
            lo, hi = (ipaddress.IPv6Address(p.strip()) for p in value.split("-", 1))
            return lo <= hi
        ipaddress.IPv6Network(value, strict=False)
        return True
    except ValueError:
        return False


def _valid_domain(value: str) -> bool:
    labels = value.rstrip(".").split(".")
    return len(value) <= 253 and len(labels) >= 2 and all(_LABEL.match(x) for x in labels)


CHECKS = {
    "port-group": (lambda v: parse_ports(v) is not None, "a port (1-65535) or a range such as 58690-58699"),
    "address-group": (_valid_address, "an IPv4 address, a CIDR such as 10.88.1.0/24, or a range such as 10.88.1.10-10.88.1.20"),
    "ipv6-address-group": (_valid_ipv6, "an IPv6 address, a prefix such as 2a01:4b00:85c9::/48, or a range"),
    "domain-group": (_valid_domain, "a domain name such as example.com"),
}


def prepare(action: str, before: dict[str, Any] | None, changes: dict[str, Any]) -> dict[str, Any]:
    changes = dict(changes)
    add, remove = changes.pop("add_members", None), changes.pop("remove_members", None)
    if add is None and remove is None:
        return changes
    if action == "create":
        raise UniFiError("add_members and remove_members only apply to an existing list; use group_members to create one.")
    if "group_members" in changes:
        raise UniFiError("Use either group_members (replace the whole list) or add_members/remove_members, not both.")
    members = [str(m) for m in (before or {}).get("group_members", [])]
    drop = {str(m).strip() for m in (remove or [])}
    missing = sorted(drop - set(members))
    if missing:
        raise UniFiError(f"Cannot remove members that are not in the list: {', '.join(missing)}.")
    members = [m for m in members if m not in drop]
    members += [str(m).strip() for m in (add or []) if str(m).strip() not in members]
    changes["group_members"] = members
    return changes


def validate(action: str, before: dict[str, Any] | None, after: dict[str, Any], others: list[dict[str, Any]]) -> Findings:
    f = Findings()
    name = str(after.get("name") or "").strip()
    if not name:
        f.errors.append("A name is required.")
    elif len(name) > 128:
        f.errors.append("The name is longer than 128 characters.")
    elif any(r.get("name") == name for r in others):
        f.errors.append(f"Another list is already called '{name}'. Names must be unique so a list can be addressed by name.")

    gtype = after.get("group_type")
    if gtype not in TYPES:
        f.errors.append(f"group_type must be one of: {', '.join(TYPES)}.")
        return f
    if before and before.get("group_type") != gtype:
        f.errors.append("The type of an existing list cannot be changed; create a new list instead.")

    members = [str(m).strip() for m in after.get("group_members") or []]
    if not members:
        f.errors.append("A list needs at least one member.")
    ok, expected = CHECKS[gtype]
    bad = [m for m in members if not ok(m)]
    if bad:
        f.errors.append(f"Not valid for a {gtype}: {', '.join(bad[:10])}. Each member must be {expected}.")
    dupes = sorted({m for m in members if members.count(m) > 1})
    if dupes:
        f.errors.append(f"Duplicate members: {', '.join(dupes)}.")
    if gtype == "address-group" and any(m in ("0.0.0.0/0", "0.0.0.0") or m.endswith("/0") for m in members):
        f.warnings.append("This list matches every IPv4 address. Check the policies that use it.")
    if gtype == "ipv6-address-group" and any(m in ("::/0", "::") or m.endswith("/0") for m in members):
        f.warnings.append("This list matches every IPv6 address. Check the policies that use it.")
    return f


SPEC = EntitySpec(
    key=KEY, label="network list", tier="A", list_op="listFirewallGroups", create_op="createFirewallGroup",
    update_op="updateFirewallGroup", delete_op="deleteFirewallGroup", whole_object=False, defaults={},
    validate=validate, prepare=prepare, create_extra={"_id": None, "source": "static"},
    reference_ops=(("listFirewallPoliciesWithHits", "firewall policy"), ("listTrafficPolicyObjects", "traffic object")),
)

FIELDS = ("name", "description", "group_type", "group_members", "add_members", "remove_members")


class NetworkListInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    action: Literal["create", "update", "delete"] = Field(..., description="create a list, update fields or members of one, or delete it.")
    target: str | None = Field(default=None, description="Existing list: its _id or exact name. Not used by create.")
    name: str | None = Field(default=None, description="List name (unique).")
    description: str | None = Field(default=None, description="Free text.")
    group_type: Literal["port-group", "address-group", "ipv6-address-group", "domain-group"] | None = Field(
        default=None, description="create only; fixed afterwards. Port list, IPv4 address list, IPv6 address list or domain list.")
    group_members: list[str] | None = Field(
        default=None, description="Full member list; replaces the existing members. Ports/ranges ('3400-3405'), IPv4 or IPv6 addresses/CIDR/ranges, or domains.")
    add_members: list[str] | None = Field(default=None, description="update only: members to add to the existing list.")
    remove_members: list[str] | None = Field(default=None, description="update only: members to remove (must be present).")
    confirm: bool = Field(default=False, description="false (default) returns a read-only preview. true applies the change and needs fingerprint.")
    fingerprint: str | None = Field(default=None, description="From the preview of exactly this change; required with confirm=true.")

    def changes(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in FIELDS if getattr(self, k) is not None}


def register(mcp: MCPServer, engine: WriteEngine) -> None:
    @mcp.tool(
        name=TOOL,
        annotations={"title": "Create, change or delete a network list", "readOnlyHint": False, "destructiveHint": True,
                     "idempotentHint": False, "openWorldHint": False},
    )
    async def unifi_console_network_list(params: NetworkListInput) -> str:
        """Preview, then apply, a change to the console's network lists (port, address and domain lists used by firewall policies).

        Two steps, always: call with confirm=false to get a read-only preview (before, after, diff, warnings, what
        uses the list, a fingerprint); call again with the same fields plus confirm=true and that fingerprint to apply.
        The list is re-read first, so a stale preview is refused. Applying also needs UNIFI_CONSOLE_ENABLE_WRITES=true
        and 'network_list' in UNIFI_CONSOLE_WRITE_ENTITIES. A list that firewall policies or traffic objects still use
        cannot be deleted, and editing one warns that the change takes effect for them at once. After applying, the
        list is read back and the result reports verified true/false, the diff, and the exact rollback call. Every write
        is journalled.
        """
        try:
            if params.action == "delete" and params.changes():
                return json.dumps({"ok": False, "error": "delete takes no field values."})
            if params.action == "update" and params.group_type is not None:
                return json.dumps({"ok": False, "error": "The type of an existing list cannot be changed; create a new list instead."})
            result = await engine.execute(
                SPEC, action=params.action, target=params.target, changes=params.changes(),
                confirm=params.confirm, fingerprint=params.fingerprint,
            )
            return json.dumps(result, separators=(",", ":"), default=str)
        except Exception as exc:  # noqa: BLE001 - converted to an actionable message
            return error_text(exc)
