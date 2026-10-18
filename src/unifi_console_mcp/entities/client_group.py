"""Client groups (v2 `network-members-group`): named sets of client MAC addresses used by policies. Tier A.

Captured 2026-10-17: create is POST `{name, members[], type: "CLIENTS"}` (HTTP 201); update is PUT with the whole group
including `id`; delete answers 204. A partial PUT (`{id, name}` without `members`) is rejected with HTTP 400, so every
update sends the whole group (`whole_object=True`). The list route is the plural `network-members-groups`, and the id
field is `id` (not `_id`).

A policy that names the group changes behaviour as soon as its members change, so the preview names what uses the group
and a group that is still in use cannot be deleted. Whether the console accepts an empty group or a MAC it has never seen
is unverified, so an empty group is refused and an unknown MAC is allowed with a warning.
"""

from __future__ import annotations

import json
import re
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel, ConfigDict, Field

from ..api import error_text
from ..client import UniFiError
from ..writes import EntitySpec, Findings, WriteEngine

KEY = "client_group"
TOOL = "unifi_console_client_group"
GROUP_TYPE = "CLIENTS"
_MAC = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
FIELDS = ("name", "members", "add_members", "remove_members", "type")


def norm_mac(value: Any) -> str:
    """Lower-case, colon-separated form of a MAC; anything that is not a MAC is returned stripped and lower-cased."""
    text = str(value).strip().lower()
    if re.fullmatch(r"([0-9a-f]{2}[:-]){5}[0-9a-f]{2}", text):
        return text.replace("-", ":")
    if re.fullmatch(r"[0-9a-f]{12}", text):
        return ":".join(text[i:i + 2] for i in range(0, 12, 2))
    return text


def prepare(action: str, before: dict[str, Any] | None, changes: dict[str, Any]) -> dict[str, Any]:
    out = dict(changes)
    add, remove = out.pop("add_members", None), out.pop("remove_members", None)
    if "name" in out:
        out["name"] = str(out["name"]).strip()
    if "type" in out:
        out["type"] = str(out["type"]).upper()
        if before is not None and out["type"] != before.get("type"):
            raise UniFiError("The type of an existing group cannot be changed.")
    if "members" in out:
        out["members"] = [norm_mac(m) for m in out["members"]]
    if add is None and remove is None:
        return out
    if action == "create":
        raise UniFiError("add_members and remove_members only apply to an existing group; use members to create one.")
    if "members" in out:
        raise UniFiError("Use either members (replace the whole group) or add_members/remove_members, not both.")
    current = [str(m) for m in (before or {}).get("members", [])]
    present = {norm_mac(m) for m in current}
    drop = {norm_mac(m) for m in (remove or [])}
    missing = sorted(drop - present)
    if missing:
        raise UniFiError(f"Cannot remove members that are not in the group: {', '.join(missing)}.")
    members = [m for m in current if norm_mac(m) not in drop]
    have = {norm_mac(m) for m in members}
    for m in (norm_mac(x) for x in (add or [])):
        if m not in have:
            members.append(m)
            have.add(m)
    out["members"] = members
    return out


def validate(action: str, before: dict[str, Any] | None, after: dict[str, Any], others: list[dict[str, Any]],
             ctx: dict[str, list[dict[str, Any]]]) -> Findings:
    f = Findings()
    if action == "delete":
        return f                      # what uses the group is checked by the engine's reference check
    before = before or {}
    name = str(after.get("name") or "").strip()
    if not name:
        f.errors.append("A name is required.")
    elif len(name) > 128:
        f.errors.append("The name is longer than 128 characters.")
    elif name != before.get("name") and any(str(r.get("name") or "").lower() == name.lower() for r in others):
        f.errors.append(f"Another group is already called '{name}'. Names must be unique so a group can be addressed by name.")

    if after.get("type") != GROUP_TYPE:
        f.errors.append(f"Only client groups (type {GROUP_TYPE}) are supported here; this group is '{after.get('type')}'.")
        return f

    members = [str(m) for m in after.get("members") or []]
    old = {norm_mac(m) for m in before.get("members") or []}
    if not members:
        f.errors.append("A group needs at least one member (an empty group is unverified on this console).")
    bad = [m for m in members if norm_mac(m) not in old and not _MAC.match(m)]
    if bad:
        f.errors.append(f"Not a MAC address: {', '.join(bad[:10])}. Use the form aa:bb:cc:dd:ee:ff.")
    seen = [norm_mac(m) for m in members]
    dupes = sorted({m for m in seen if seen.count(m) > 1})
    if dupes:
        f.errors.append(f"Duplicate members: {', '.join(dupes)}.")
    known = {norm_mac(c.get("mac")): c for c in ctx.get("clients", []) if c.get("mac")}
    fresh = [m for m in seen if m not in old and _MAC.match(m)]
    unknown = [m for m in fresh if m not in known]
    if unknown:
        f.warnings.append(f"{len(unknown)} new member(s) are not clients this console has seen: {', '.join(unknown[:10])}.")
    return f


SPEC = EntitySpec(
    key=KEY, label="client group", tier="A", list_op="listNetworkMemberGroups", create_op="createNetworkMemberGroup",
    update_op="updateNetworkMemberGroup", delete_op="deleteNetworkMemberGroup", whole_object=True, id_field="id",
    name_field="name", defaults={"type": GROUP_TYPE}, prepare=prepare, validate_ctx=validate,
    context_ops=(("clients", "listKnownClients"),),
    reference_ops=(("listFirewallPoliciesWithHits", "firewall policy"), ("listTrafficPolicyObjects", "traffic object")),
)


class ClientGroupInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    action: Literal["create", "update", "delete"] = Field(..., description="create a group, change its name or members, or delete it.")
    target: str | None = Field(default=None, description="Existing group: its id or exact name. Not used by create.")
    name: str | None = Field(default=None, description="Group name (unique).")
    members: list[str] | None = Field(default=None, description="Full member list of client MAC addresses; replaces the existing members.")
    add_members: list[str] | None = Field(default=None, description="update only: MAC addresses to add.")
    remove_members: list[str] | None = Field(default=None, description="update only: MAC addresses to remove (must be present).")
    type: Literal["CLIENTS"] | None = Field(default=None, description="Always CLIENTS; accepted so a recorded rollback can be replayed.")
    confirm: bool = Field(default=False, description="false (default) returns a read-only preview. true applies the change and needs fingerprint.")
    fingerprint: str | None = Field(default=None, description="From the preview of exactly this change; required with confirm=true.")

    def changes(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in FIELDS if getattr(self, k) is not None}


def register(mcp: MCPServer, engine: WriteEngine) -> None:
    @mcp.tool(
        name=TOOL,
        annotations={"title": "Create, change or delete a client group", "readOnlyHint": False, "destructiveHint": True,
                     "idempotentHint": False, "openWorldHint": False},
    )
    async def unifi_console_client_group(params: ClientGroupInput) -> str:
        """Preview, then apply, a change to the console's client groups (named sets of client MAC addresses used by policies).

        Two steps, always: call with confirm=false to get a read-only preview (before, after, diff, warnings, what
        uses the group, a fingerprint); call again with the same fields plus confirm=true and that fingerprint to apply.
        The group is re-read first, so a stale preview is refused. Members are MAC addresses (any common spelling is
        normalised to aa:bb:cc:dd:ee:ff); use add_members/remove_members to change a few, or members to replace all.
        Applying also needs UNIFI_CONSOLE_ENABLE_WRITES=true and 'client_group' in UNIFI_CONSOLE_WRITE_ENTITIES. A group
        that firewall policies or traffic objects still use cannot be deleted, and editing one warns that the change takes
        effect for them at once. The console only accepts the whole group, so updates send all of it. After applying, the
        group is read back and the result reports verified true/false, the diff, and the exact rollback call. Every
        write is journalled.
        """
        try:
            if params.action == "delete" and params.changes():
                return json.dumps({"ok": False, "error": "delete takes no field values."})
            if params.action == "create" and not (params.name and params.members):
                return json.dumps({"ok": False, "error": "create needs name and members."})
            result = await engine.execute(
                SPEC, action=params.action, target=params.target, changes=params.changes(),
                confirm=params.confirm, fingerprint=params.fingerprint,
            )
            return json.dumps(result, separators=(",", ":"), default=str)
        except Exception as exc:  # noqa: BLE001 - converted to an actionable message
            return error_text(exc)
