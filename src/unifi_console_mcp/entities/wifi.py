"""Wi-Fi networks / SSIDs (legacy `rest/wlanconf`). Tier C.

Captured 2026-10-18 from the UI: create is POST with a 53-key object (no `_id`), edit is PUT `/{id}` with the whole object
(62 keys, secrets included, as read), delete is DELETE `/{id}`; replies use the legacy `{meta, data[]}` envelope. Enable and
disable were not captured separately, so they send the whole-object PUT with `enabled` changed.

Why tier C: an SSID change drops every client on it (Sonos, IoT, family devices) and the one doing the change may be on it.
So:
  * a new SSID is created disabled;
  * changes that force a reconnect (name, security, passphrase, network, bands, PMF, hide SSID, disabling) and deletes on an
    SSID that has connected clients are refused unless `acknowledge_disconnect=true`; the preview lists the clients;
  * open security is refused unless `acknowledge_open=true`; switching an existing WPA SSID to open is not offered;
  * the passphrase is never a tool argument: `passphrase_env` names a UNIFI_WIFI_* variable in the server's environment. It
    is write-only, never read back, compared, previewed or journalled;
  * there is no automatic restore: nothing on the controller can confirm a Wi-Fi change, and a restore would drop the
    clients a second time.
Not offered (left exactly as read on edit, UI defaults on create): AP groups other than all, MAC filter, schedules, RADIUS,
private pre-shared keys, hotspot, minimum rates, roaming and IoT tuning, MLO, 6 GHz.
"""

from __future__ import annotations

import copy
import json
import os
import re
from dataclasses import replace
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel, ConfigDict, Field

from ..api import error_text
from ..client import UniFiError
from ..writes import VOLATILE, EntitySpec, Findings, Plan, WriteEngine, same

KEY = "wifi"
TOOL = "unifi_console_wifi"
ENV_PREFIX = "UNIFI_WIFI_"
_ENV_NAME = re.compile(r"^UNIFI_WIFI_[A-Z0-9_]{1,64}$")
FIELDS = ("name", "network", "security", "passphrase_env", "bands", "hide_ssid", "guest", "l2_isolation", "pmf_mode", "enabled")
SECURITY = {
    "wpa2": {"security": "wpapsk", "wpa_mode": "wpa2", "wpa3_support": False, "wpa3_transition": False},
    "wpa2_wpa3": {"security": "wpapsk", "wpa_mode": "wpa2", "wpa3_support": True, "wpa3_transition": True},
    "wpa3": {"security": "wpapsk", "wpa_mode": "wpa2", "wpa3_support": True, "wpa3_transition": False},
    "open": {"security": "open", "wpa3_support": False, "wpa3_transition": False},
}
DISRUPTIVE = ("name", "security", "wpa_mode", "wpa3_support", "wpa3_transition", "x_passphrase", "networkconf_id", "wlan_bands",
              "pmf_mode", "hide_ssid")

CORE = frozenset({"enabled", "hide_ssid", "is_guest", "l2_isolation", "pmf_mode", "wlan_bands", "wpa_mode", "security", "wpa3_support", "wpa3_transition"})

# The UI's own create body (53 keys), minus the per-SSID fields filled in by the tool.
DEFAULTS: dict[str, Any] = {
    "enabled": False, "setting_preference": "auto", "mcastenhance_enabled": False, "bc_filter_enabled": False, "bc_filter_list": [],
    "mlo_enabled": False, "no2ghz_oui": True, "hide_ssid": False, "proxy_arp": False, "bss_transition": True, "uapsd_enabled": False,
    "fast_roaming_enabled": False, "usergroup_id": "", "dtim_mode": "default", "wlan_bands": ["2g", "5g"], "iapp_enabled": True,
    "schedule_with_duration": [], "wpa3_enhanced_192": False, "group_rekey": 0, "radius_das_enabled": False, "sae_anti_clogging": 5,
    "sae_sync": 5, "pmf_mode": "optional", "wpa_mode": "wpa2", "security": "wpapsk", "wpa3_support": True, "wpa3_transition": True,
    "minrate_setting_preference": "auto", "minrate_ng_enabled": False, "minrate_ng_advertising_rates": False,
    "minrate_na_enabled": False, "minrate_na_advertising_rates": False, "mdns_proxy_mode": "off", "mac_filter_enabled": False,
    "mac_filter_list": [], "private_preshared_keys_enabled": False, "private_preshared_keys": [], "radius_mac_auth_enabled": False,
    "enhanced_iot": False, "hotspot2conf_enabled": False, "is_guest": False, "l2_isolation": False, "iot_channel_lock": False,
    "iot_dtim_lock": False, "advertise_device_name_in_beacon": False, "dns_assistance_mode": "off", "ap_group_mode": "all",
    "roaming_assistant_na_enabled": False, "roaming_assistant_6e_enabled": False,
}


def _net(nets: list[dict[str, Any]], ref: str) -> dict[str, Any] | None:
    for n in nets:
        if str(n.get("_id")) == ref:
            return n
    hits = [n for n in nets if str(n.get("name") or "").lower() == ref.strip().lower()]
    return hits[0] if len(hits) == 1 else None


def _passphrase(env_name: str) -> str:
    name = str(env_name).strip()
    if not _ENV_NAME.match(name):
        raise UniFiError(f"passphrase_env must be the name of an environment variable starting with {ENV_PREFIX} "
                         "(capital letters, digits and underscores).")
    value = os.environ.get(name, "")
    if not value.strip():
        raise UniFiError(f"The environment variable {name} is not set (or is empty) in the server's environment. "
                         "Set it in the server configuration, restart, and try again. Nothing was changed.")
    return value


def prepare_ctx(action: str, before: dict[str, Any] | None, changes: dict[str, Any], ctx: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    nets = [n for n in ctx.get("networks", []) if n.get("purpose") != "wan"]
    bad = set(changes) - set(FIELDS)
    if bad:
        raise UniFiError(f"Unknown field(s): {', '.join(sorted(bad))}. Use: {', '.join(FIELDS)}.")
    if "enabled" in changes and action != "create":
        raise UniFiError("Use the enable or disable action to change whether an existing SSID is on.")
    if "name" in changes:
        out["name"] = str(changes["name"]).strip()
    if "network" in changes:
        n = _net(nets, str(changes["network"]))
        if not n:
            raise UniFiError(f"network '{changes['network']}' is not a network on this console (names are matched exactly).")
        out["networkconf_id"] = str(n["_id"])
    if "security" in changes:
        mode = changes["security"]
        if mode not in SECURITY:
            raise UniFiError("security must be wpa2, wpa2_wpa3, wpa3 or open.")
        if mode == "open" and before is not None and before.get("security") != "open":
            raise UniFiError("Switching an existing SSID to open security is not offered here. Use the UI, or create a new open SSID.")
        out.update(SECURITY[mode])
        cur = (before or {}).get("pmf_mode")
        if "pmf_mode" not in changes:
            if mode == "wpa3":
                out["pmf_mode"] = "required"
            elif mode == "wpa2_wpa3" and cur in (None, "disabled"):
                out["pmf_mode"] = "optional"
            elif before is None:
                out["pmf_mode"] = "disabled" if mode in ("wpa2", "open") else "optional"
    if "pmf_mode" in changes:
        if changes["pmf_mode"] not in ("disabled", "optional", "required"):
            raise UniFiError("pmf_mode must be disabled, optional or required.")
        out["pmf_mode"] = changes["pmf_mode"]
    if "passphrase_env" in changes:
        out["x_passphrase"] = _passphrase(changes["passphrase_env"])
    if "bands" in changes:
        bands = list(changes["bands"])
        if not bands or set(bands) - {"2g", "5g"}:
            raise UniFiError("bands must be a non-empty list of 2g and/or 5g.")
        out["wlan_bands"] = bands
    for k_in, k_out in (("hide_ssid", "hide_ssid"), ("guest", "is_guest"), ("l2_isolation", "l2_isolation"), ("enabled", "enabled")):
        if k_in in changes:
            out[k_out] = bool(changes[k_in])
    if action == "create":
        groups = [str(g.get("_id") or g.get("id")) for g in ctx.get("apgroups", []) if g.get("_id") or g.get("id")]
        if not groups:
            raise UniFiError("Could not find an AP group to broadcast the SSID from. Nothing was changed.")
        out["ap_group_ids"] = groups
        ug = next((str(w["usergroup_id"]) for w in ctx.get("wlans", []) if w.get("usergroup_id")), "")
        if ug:
            out["usergroup_id"] = ug
        if "networkconf_id" not in out:
            raise UniFiError("create needs network: the network (name or id) the SSID puts its clients on.")
        if "name" not in out:
            raise UniFiError("create needs name.")
        if "security" not in changes:
            raise UniFiError("create needs security: wpa2, wpa2_wpa3, wpa3 or open.")
        if changes["security"] != "open" and "x_passphrase" not in out:
            raise UniFiError("create needs passphrase_env: the name of a UNIFI_WIFI_ environment variable holding the passphrase.")
        if changes["security"] == "open" and "x_passphrase" in out:
            raise UniFiError("An open SSID takes no passphrase.")
        if "pmf_mode" not in out:
            out["pmf_mode"] = "optional"
    elif not out:
        raise UniFiError("Nothing to change.")
    elif before is not None and before.get("security") == "open" and "x_passphrase" in out and "security" not in changes:
        raise UniFiError("This SSID is open; to protect it, pass security as well as passphrase_env.")
    return out


def make_validate(ack_disconnect: bool, ack_open: bool, snap: dict[str, Any] | None = None):
    def validate(action: str, before: dict[str, Any] | None, after: dict[str, Any], others: list[dict[str, Any]],
                 ctx: dict[str, list[dict[str, Any]]]) -> Findings:
        f = Findings()
        b = before or {}
        if snap is not None:
            snap["others"] = copy.deepcopy(others)
        name = str(b.get("name") if action == "delete" else after.get("name") or "")
        clients = [c for c in ctx.get("clients", []) if b and str(c.get("essid") or "") == str(b.get("name"))]
        who = ", ".join(str(c.get("name") or c.get("hostname") or c.get("mac")) for c in clients[:6]) + (" and more" if len(clients) > 6 else "")
        if action == "delete":
            f.warnings.append(f"Deleting '{name}' removes the SSID for good; devices set to join it must be set up again. "
                              "The passphrase is write-only, so a rollback needs it supplied again.")
            if clients:
                f.warnings.append(f"{len(clients)} client(s) are connected to it now: {who}.")
                if not ack_disconnect:
                    f.errors.append("Disconnect stop: the SSID has connected clients. Repeat with acknowledge_disconnect=true to delete it anyway.")
            return f
        if not name or len(name.encode()) > 32:
            f.errors.append("name must be 1 to 32 bytes.")
        if any(str(o.get("name") or "") == name for o in others):
            f.errors.append(f"Another SSID is already called '{name}'.")
        nets = ctx.get("networks", [])
        net = next((n for n in nets if n.get("_id") == after.get("networkconf_id")), None)
        if net is None or net.get("purpose") == "wan":
            f.errors.append("The network is not a LAN or VLAN on this console.")
        if set(after.get("wlan_bands") or []) - {"2g", "5g"} or not after.get("wlan_bands"):
            f.errors.append("bands must be 2g and/or 5g.")
        sec = after.get("security")
        if sec == "open":
            if action == "create" and not ack_open:
                f.errors.append("Open security stop: anyone in range could join this SSID. Repeat with acknowledge_open=true if that is intended (for example a captive-portal guest network).")
            elif action == "create":
                f.warnings.append("Acknowledged: this SSID is open. Anyone in range can join and the traffic is unencrypted.")
        else:
            pw = str(after.get("x_passphrase") or "")
            if pw and not 8 <= len(pw) <= 63:
                f.errors.append("The passphrase must be 8 to 63 characters (the value is not shown).")
        if after.get("wpa3_support") and not after.get("wpa3_transition") and sec != "open":
            f.warnings.append("WPA3-only: older Sonos, IoT and other devices will not be able to join. Prefer wpa2_wpa3 unless every client supports WPA3.")
        if action == "create":
            f.warnings.append("The SSID is created disabled." if not after.get("enabled") else
                              "Enabled on creation: the access points start broadcasting it as soon as this is applied.")
            return f
        keys = [k for k in DISRUPTIVE if not same(b.get(k), after.get(k))]
        if b.get("enabled") and not after.get("enabled"):
            keys.append("enabled")
        if keys:
            shown = [k for k in keys if k != "x_passphrase"] + (["passphrase"] if "x_passphrase" in keys else [])
            f.warnings.append(f"This change makes clients reconnect ({', '.join(shown)}). The session doing the change may be on this SSID.")
            if clients:
                f.warnings.append(f"{len(clients)} client(s) are connected to '{b.get('name')}' now: {who}.")
                if not ack_disconnect:
                    f.errors.append("Disconnect stop: this change drops clients that are connected now. Repeat with acknowledge_disconnect=true to apply it.")
        if "networkconf_id" in keys:
            old = next((n.get("name") for n in nets if n.get("_id") == b.get("networkconf_id")), "?")
            f.warnings.append(f"Clients move from network {old} to {net.get('name') if net else '?'}: addressing, firewall zone and DHCP all change for them.")
        return f
    return validate


def make_verify(snap: dict[str, Any]):
    def verify(plan: Plan, rows: list[dict[str, Any]], stored: dict[str, Any] | None) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        now = {str(r.get("_id")): r for r in rows}
        for old in snap.get("others", []):
            cur = now.get(str(old.get("_id")))
            if cur is None:
                out.append({"field": f"(other SSID {old.get('name')})", "requested": "unchanged", "stored": "missing on read-back"})
                continue
            changed = sorted(k for k in set(old) | set(cur) if k not in VOLATILE and not same(old.get(k), cur.get(k)))
            if changed:
                out.append({"field": f"(other SSID {old.get('name')})", "requested": "unchanged", "stored": f"changed: {', '.join(changed)}"})
        return out
    return verify


def rollback(plan: Plan, new_id: str | None) -> dict[str, Any]:
    before, after = plan.before or {}, plan.after or {}
    if plan.action == "create":
        return {"tool": TOOL, "arguments": {"action": "delete", "target": new_id}}

    def friendly(row: dict[str, Any]) -> dict[str, Any]:
        mode = "open" if row.get("security") == "open" else ("wpa3" if row.get("wpa3_support") and not row.get("wpa3_transition")
                                                                else "wpa2_wpa3" if row.get("wpa3_support") else "wpa2")
        return {"name": row.get("name"), "network_id": row.get("networkconf_id"), "security": mode, "bands": row.get("wlan_bands"),
                "hide_ssid": row.get("hide_ssid"), "guest": row.get("is_guest"), "l2_isolation": row.get("l2_isolation"),
                "pmf_mode": row.get("pmf_mode"), "enabled": row.get("enabled")}
    if plan.action == "delete":
        return {"tool": TOOL, "arguments": {"action": "create", **friendly(before)},
                "note": "The passphrase is write-only and was not recorded: set a UNIFI_WIFI_ variable to it and pass passphrase_env."}
    fb, fa = friendly(before), friendly(after)
    args: dict[str, Any] = {"action": "update", "target": plan.ident}
    args.update({k: v for k, v in fb.items() if not same(v, fa.get(k)) and k not in ("enabled", "network_id")})
    if not same(fb["network_id"], fa["network_id"]):
        args["network"] = fb["network_id"]
    out: dict[str, Any] = {"tool": TOOL, "arguments": args}
    if "x_passphrase" in after and not same(before.get("x_passphrase"), after.get("x_passphrase")):
        out["note"] = "The passphrase was changed and the previous one was not recorded: re-enter it via passphrase_env."
    if before.get("enabled") != after.get("enabled"):
        out["arguments"] = {"action": "enable" if before.get("enabled") else "disable", "target": plan.ident}
    return out


SPEC = EntitySpec(
    key=KEY, label="SSID", tier="C", list_op="listWlanConfigLegacy", create_op="createWlanConfig", update_op="updateWlanConfig",
    delete_op="deleteWlanConfig", whole_object=True, id_field="_id", name_field="name", defaults=DEFAULTS, prepare_ctx=prepare_ctx,
    context_ops=(("networks", "listNetworkConfig"), ("clients", "listActiveClientsLegacy"), ("apgroups", "listApGroups"),
                 ("wlans", "listWlanConfigLegacy")),
    ignore=VOLATILE | (frozenset(DEFAULTS) - CORE), rollback=rollback,
)


class WifiInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    action: Literal["create", "update", "enable", "disable", "delete"] = Field(..., description="create (disabled unless enabled=true), update fields, enable, disable or delete an SSID.")
    target: str | None = Field(default=None, description="Existing SSID: its _id or exact name. Not used by create.")
    name: str | None = Field(default=None, description="SSID name, 1 to 32 bytes, unique.")
    network: str | None = Field(default=None, description="Network (name or id) the SSID puts its clients on.")
    security: Literal["wpa2", "wpa2_wpa3", "wpa3", "open"] | None = Field(default=None, description="open needs acknowledge_open=true and is only for new SSIDs.")
    passphrase_env: str | None = Field(default=None, description=f"Name of an environment variable in the server's environment, starting with {ENV_PREFIX}, holding the passphrase. Never typed in chat.")
    bands: list[Literal["2g", "5g"]] | None = Field(default=None, description="2g and/or 5g.")
    hide_ssid: bool | None = None
    guest: bool | None = Field(default=None, description="Mark as a guest network.")
    l2_isolation: bool | None = Field(default=None, description="Client isolation.")
    pmf_mode: Literal["disabled", "optional", "required"] | None = None
    enabled: bool | None = Field(default=None, description="create only; a new SSID is disabled unless this is true.")
    acknowledge_disconnect: bool = Field(default=False, description="Accept that clients connected now are dropped (disruptive edits and deletes).")
    acknowledge_open: bool = Field(default=False, description="Accept creating an open (unencrypted) SSID.")
    approval_note: str | None = Field(default=None, description="Required with confirm=true: where the approval for this tier C change was given.")
    confirm: bool = Field(default=False, description="false (default) returns a read-only preview. true applies and needs fingerprint.")
    fingerprint: str | None = Field(default=None, description="From the preview of exactly this change; required with confirm=true.")

    def changes(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in FIELDS if getattr(self, k) is not None}


def register(mcp: MCPServer, engine: WriteEngine) -> None:
    @mcp.tool(
        name=TOOL,
        annotations={"title": "Create, change or delete a Wi-Fi network (SSID)", "readOnlyHint": False, "destructiveHint": True,
                     "idempotentHint": False, "openWorldHint": False},
    )
    async def unifi_console_wifi(params: WifiInput) -> str:
        """Preview, then apply, a change to a Wi-Fi network (SSID). Tier C: changes drop the clients on it.

        Two steps, always: confirm=false returns a read-only preview (before, after, diff, the clients connected now, warnings,
        errors, a fingerprint); then call again with the same fields plus confirm=true, that fingerprint and an approval_note.
        A new SSID is created disabled. The passphrase is never an argument: pass passphrase_env, the name of a UNIFI_WIFI_*
        environment variable in the server's environment; it is write-only and is not read back, previewed or journalled.
        Changes that force clients to reconnect, and deletes, are refused while clients are connected unless
        acknowledge_disconnect=true; open security needs acknowledge_open=true. There is no automatic restore. Applying also
        needs UNIFI_CONSOLE_ENABLE_WRITES=true and 'wifi' in UNIFI_CONSOLE_WRITE_ENTITIES. Every write is journalled.
        """
        try:
            if params.action in ("enable", "disable", "delete") and params.changes():
                return json.dumps({"ok": False, "error": f"{params.action} takes no field values; use update to change fields."})
            if params.action == "create" and params.target:
                return json.dumps({"ok": False, "error": "create takes no target."})
            snap: dict[str, Any] = {}
            spec = replace(SPEC, validate_ctx=make_validate(params.acknowledge_disconnect, params.acknowledge_open, snap),
                           verify=make_verify(snap))
            result = await engine.execute(
                spec, action=params.action, target=params.target, changes=params.changes(),
                confirm=params.confirm, fingerprint=params.fingerprint, approval_note=params.approval_note,
            )
            return json.dumps(result, separators=(",", ":"), default=str)
        except Exception as exc:  # noqa: BLE001 - converted to an actionable message
            return error_text(exc)
