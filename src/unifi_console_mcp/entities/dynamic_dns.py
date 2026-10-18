"""Dynamic DNS entries (legacy `rest/dynamicdns`): the gateway keeps a public host name pointing at the WAN address. Tier B.

Captured 2026-10-17: create is POST `{service, host_name, interface, login, x_password, server}` with the usual
`{meta, data[]}` reply; delete is DELETE `/{id}`. Captured 2026-10-18 (rotating the Cloudflare key in the UI):
**update is PUT `/{id}`** with the same six keys (no `_id`, no `site_id`) and the same envelope reply, and the entry keeps
its id. Re-confirmed 2026-10-18 (`dynamic-dns-update-existing.har`): renaming `host_name` on an existing entry is the same
in-place PUT, and the id is unchanged. The list redacts the token, so an update cannot send the stored one back: it must carry the token explicitly
(`token_env`), whether or not the token is what changes.

The provider token (`x_password`) is write-only: the list never shows it. So
  * the token is never a tool argument. The tool takes the NAME of an environment variable in the server's own
    environment (`token_env`, which must start with UNIFI_DDNS_) and reads the token from there, so it never appears in
    chat, a preview, a fingerprint's visible text, the result or the journal (the journal redacts `x_*` fields);
  * it is never read back or compared; the result lists it under `secret_fields_not_verified`;
  * deleting an entry discards its token for good, so a rollback can only recreate the entry if a fresh token is
    supplied, and the delete must be acknowledged with `discard_token=true`;
  * an update replaces the stored token with the one from `token_env`, so its rollback cannot restore the old token
    either (the note says to re-enter it).
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel, ConfigDict, Field

from ..api import error_text
from ..client import UniFiError
from ..writes import EntitySpec, Findings, WriteEngine

KEY = "dynamic_dns"
TOOL = "unifi_console_dynamic_dns"
ENV_PREFIX = "UNIFI_DDNS_"
_ENV_NAME = re.compile(r"^UNIFI_DDNS_[A-Z0-9_]{1,64}$")
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_IFACE = re.compile(r"^wan[0-9]?$")
FIELDS = ("service", "host_name", "interface", "login", "server", "token_env")


def _valid_host(value: str) -> bool:
    labels = value.split(".")
    return len(value) <= 253 and len(labels) >= 2 and all(_LABEL.match(x) for x in labels)


def prepare(action: str, before: dict[str, Any] | None, changes: dict[str, Any]) -> dict[str, Any]:
    out = dict(changes)
    env_name = out.pop("token_env", None)
    for k in ("service", "host_name", "interface"):
        if k in out:
            out[k] = str(out[k]).strip().lower().rstrip(".") if k != "service" else str(out[k]).strip().lower()
    for k in ("login", "server"):
        if k in out:
            out[k] = str(out[k]).strip()
    if env_name is not None:
        name = str(env_name).strip()
        if not _ENV_NAME.match(name):
            raise UniFiError(f"token_env must be the name of an environment variable starting with {ENV_PREFIX} "
                             "(capital letters, digits and underscores).")
        token = os.environ.get(name, "")
        if not token.strip():
            raise UniFiError(f"The environment variable {name} is not set (or is empty) in the server's environment. "
                             "Set it in the server configuration, restart, and try again. Nothing was changed.")
        out["x_password"] = token.strip()
    return out


def validate(action: str, before: dict[str, Any] | None, after: dict[str, Any], others: list[dict[str, Any]],
             ctx: dict[str, list[dict[str, Any]]]) -> Findings:
    f = Findings()
    if action == "delete":
        b = before or {}
        f.warnings.append(
            f"Deleting '{b.get('host_name')}' ({b.get('service')} on {b.get('interface')}) discards its stored token, which the "
            "console never shows again. The entry can only be recreated with a fresh token, and the host name stops "
            "following the WAN address until then.")
        return f
    service, host, iface = str(after.get("service") or ""), str(after.get("host_name") or ""), str(after.get("interface") or "")
    known = sorted({s for row in ctx.get("services", []) for s in (row.get("ddns") or [])})
    if not service:
        f.errors.append("A service is required.")
    elif known and service not in known:
        f.errors.append(f"'{service}' is not a service this console offers. Choose one of: {', '.join(known)}.")
    if not _valid_host(host):
        f.errors.append(f"'{host}' is not a valid host name (for example home.example.com).")
    if not _IFACE.match(iface):
        f.errors.append("interface must be wan, wan2 and so on.")
    if not str(after.get("login") or "").strip():
        f.errors.append("A login is required (for Cloudflare it is the zone name; for most providers the account name).")
    if not after.get("x_password"):
        f.errors.append("A token is required: pass token_env, the name of a UNIFI_DDNS_ environment variable holding it.")
    server = str(after.get("server") or "")
    if service == "custom" and not server:
        f.errors.append("The custom service needs a server (the update URL host).")
    elif server and service != "custom":
        f.warnings.append(f"A server is set for the '{service}' service; the console normally leaves it empty except for custom.")
    for r in others:
        if str(r.get("host_name") or "").lower() == host and str(r.get("interface") or "") == iface:
            f.errors.append(f"An entry for {host} on {iface} already exists. Update that entry instead of creating another.")
    same_wan = [r for r in others if str(r.get("interface") or "") == iface]
    if same_wan and not f.errors:
        f.warnings.append(f"{iface} already has {len(same_wan)} Dynamic DNS entr{'y' if len(same_wan) == 1 else 'ies'} "
                          f"({', '.join(str(r.get('host_name')) for r in same_wan[:5])}); whether the console supports several per WAN is unverified.")
    if not f.errors:
        if action == "update":
            b = before or {}
            moved = [k for k in ("service", "host_name", "interface", "login", "server") if str(after.get(k) or "") != str(b.get(k) or "")]
            f.warnings.append("The stored token is replaced by the one in the environment variable named in token_env, and the old one "
                              "cannot be shown or restored. Use the current token if only other fields change.")
            if moved:
                f.warnings.append(f"Changing {', '.join(moved)} makes the gateway start updating a different record: "
                                  f"{b.get('host_name')} stops following the WAN address if the host name or service changes.")
        else:
            f.warnings.append(f"Once created, the gateway sends this token to {service} to keep {host} pointing at the {iface} address.")
    return f


SPEC = EntitySpec(
    key=KEY, label="Dynamic DNS entry", tier="B", list_op="listDynamicDns", create_op="createDynamicDns",
    update_op="updateDynamicDns", delete_op="deleteDynamicDns", whole_object=True, id_field="_id", name_field="host_name",
    body_drop=frozenset({"_id", "site_id"}), defaults={"server": ""}, prepare=prepare, validate_ctx=validate,
    context_ops=(("services", "listDdnsServices"),),
)


class DynamicDnsInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    action: Literal["create", "update", "delete"] = Field(..., description="create an entry, update one (needs target and token_env), or delete one.")
    target: str | None = Field(default=None, description="Existing entry for update or delete: its _id or exact host name. Not used by create.")
    service: str | None = Field(default=None, description="Provider, for example cloudflare, noip, duckdns or custom (create or update).")
    host_name: str | None = Field(default=None, description="The public host name to keep updated, e.g. home.example.com (create or update).")
    interface: str | None = Field(default=None, description="wan, wan2 ... (create or update).")
    login: str | None = Field(default=None, description="Account or zone name the provider expects (create or update).")
    server: str | None = Field(default=None, description="Update server; only for the custom service. Defaults to empty.")
    token_env: str | None = Field(
        default=None,
        description=f"Name of an environment variable in the server's own environment, starting with {ENV_PREFIX}, that holds the "
                    "provider token (required for create and update). The token is never passed through chat.")
    discard_token: bool = Field(default=False, description="delete only, with confirm=true: acknowledges that the stored token is lost for good.")
    confirm: bool = Field(default=False, description="false (default) returns a read-only preview. true applies the change and needs fingerprint.")
    fingerprint: str | None = Field(default=None, description="From the preview of exactly this change; required with confirm=true.")

    def changes(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in FIELDS if getattr(self, k) is not None}


def register(mcp: MCPServer, engine: WriteEngine) -> None:
    @mcp.tool(
        name=TOOL,
        annotations={"title": "Create, update or delete a Dynamic DNS entry", "readOnlyHint": False, "destructiveHint": True,
                     "idempotentHint": False, "openWorldHint": False},
    )
    async def unifi_console_dynamic_dns(params: DynamicDnsInput) -> str:
        """Preview, then apply, the creation, update or deletion of a Dynamic DNS entry on the gateway.

        Two steps, always: call with confirm=false to get a read-only preview (after, warnings, errors, a fingerprint);
        call again with the same fields plus confirm=true and that fingerprint to apply. An update keeps the entry's id and
        sends the whole entry; because the console never shows the stored token, an update must be given token_env too
        (the current token if only other fields change, or the new one when rotating it). The provider token is never a tool argument: pass
        token_env, the name of a UNIFI_DDNS_* environment variable in the server's environment. The token is write-only,
        so it is not read back (the result lists it under secret_fields_not_verified) and it is not journalled.
        Deleting an entry discards its token for good: the delete needs discard_token=true, and its rollback can only
        recreate the entry with a fresh token. Applying also needs UNIFI_CONSOLE_ENABLE_WRITES=true and 'dynamic_dns' in
        UNIFI_CONSOLE_WRITE_ENTITIES. Every write is journalled.
        """
        try:
            if params.action == "delete":
                if params.changes():
                    return json.dumps({"ok": False, "error": "delete takes no field values."})
                if params.confirm and not params.discard_token:
                    return json.dumps({"ok": False, "error": "Deleting discards the stored token, which cannot be recovered. "
                                       "Repeat with discard_token=true to confirm that is intended. Nothing was changed."})
            elif params.action == "update":
                if params.discard_token:
                    return json.dumps({"ok": False, "error": "discard_token only applies to delete."})
                if not params.target:
                    return json.dumps({"ok": False, "error": "update needs a target (the entry's _id or exact host name)."})
                if not params.token_env:
                    return json.dumps({"ok": False, "error": "update needs token_env: the console never shows the stored token, "
                                       "so the token has to be supplied again (the current one if you are not rotating it)."})
            else:
                if params.discard_token:
                    return json.dumps({"ok": False, "error": "discard_token only applies to delete."})
                missing = [k for k in ("service", "host_name", "interface", "login", "token_env") if not getattr(params, k)]
                if missing:
                    return json.dumps({"ok": False, "error": f"create needs {', '.join(missing)}."})
            result = await engine.execute(
                SPEC, action=params.action, target=params.target, changes=params.changes(),
                confirm=params.confirm, fingerprint=params.fingerprint,
            )
            return json.dumps(result, separators=(",", ":"), default=str)
        except Exception as exc:  # noqa: BLE001 - converted to an actionable message
            return error_text(exc)
