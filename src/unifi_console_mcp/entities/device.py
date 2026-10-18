"""UniFi devices (access points, switches, gateway): locate, restart, disable, enable, update, adopt and remove.

Captured 2026-10-18 (`device-disable-enable-restart.har`, `device-remove.har` and the operator's own curls and PowerShell test):
  * locate / unlocate / restart / adopt: `POST cmd/devmgr` with the device **MAC** (`set-locate`, `unset-locate`, `restart` with
    `reboot_type: "hard"` - there is no soft reset - and `adopt` with `client: "web"`).
  * remove: `POST cmd/sitemgr {"macs": [mac], "cmd": "delete-device"}`.
  * disable / enable / update: `PUT rest/device/{device _id}`. The console accepts a **partial body**, so only the changed fields
    are sent (`{"disabled": true}`, or for example `{"name": ..., "mgmt_network_id": ...}`). The `_id` changes after a remove and
    re-adopt, so it is always read live.

These are commands and small edits of one device, not edits of a stored list, so they do not use the entity engine's update path.
They use the same gates, lock, journal and two-step fingerprint, under the `device` write switch:
  * locate / unlocate (tier A): flash the LED. Gated, but no fingerprint is needed.
  * restart (tier B for a leaf access point, tier C for a switch, the gateway or anything with devices behind it).
  * enable (tier B). disable (tier C).
  * update (tier B; tier C when the management network or IP changes). A whitelist of fields only.
  * adopt (tier B): only a device the console lists as not adopted.
  * remove (tier C): forgets the device. Needs approval_note and acknowledge_removal=true; there is no undo short of re-adopting.
The device running the console (matched by IP) is refused for everything except locate. Firmware updates are not offered.
Device records hold secrets (`x_authkey`, `syslog_key`, SSH host key); this module only ever builds its own small views.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import re
import socket
import uuid
from dataclasses import dataclass, field, replace
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel, ConfigDict, Field

from ..api import error_text
from ..client import UniFiError
from ..redact import redact
from ..writes import EntitySpec, WriteEngine, _canon, covers, same

KEY = "device"
TOOL = "unifi_console_device"
ACTIONS = ("locate", "unlocate", "restart", "disable", "enable", "update", "adopt", "remove")
GATEWAY_TYPES = frozenset({"ugw", "udm", "uxg"})
SPEC = EntitySpec(key=KEY, label="device", tier="B", list_op="listDevicesDetailed", name_field="name", match_fields=("mac",))
_MAC = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
POLL_INTERVAL = 5.0
LED_VALUES = ("on", "off", "default")
# What the fingerprint covers: stable settings only (never uptime, state or client counts, which change by themselves).
STABLE = ("_id", "mac", "name", "type", "adopted", "disabled", "locating", "led_override", "snmp_contact", "snmp_location",
          "stp_priority", "mgmt_network_id", "config_network")
UPDATE_FIELDS = ("name", "led_override", "snmp_contact", "snmp_location", "stp_priority", "management_network",
                 "ip_mode", "ip", "netmask", "gateway", "dns1", "dns2")
NETWORK_FIELDS = frozenset({"management_network", "ip_mode", "ip", "netmask", "gateway", "dns1", "dns2"})


async def _sleep(seconds: float) -> None:       # a seam for tests
    await asyncio.sleep(seconds)


# ----------------------------------------------------------------------------------------------- helpers
def norm_mac(value: str) -> str | None:
    mac = value.strip().lower().replace("-", ":")
    return mac if _MAC.match(mac) else None


def _lower(value: Any) -> str:
    return str(value or "").lower()


def role(row: dict[str, Any], console_ip: str | None) -> str:
    if console_ip and row.get("ip") == console_ip:
        return "console"
    kind = row.get("type")
    return "gateway" if kind in GATEWAY_TYPES else "switch" if kind == "usw" else "ap" if kind == "uap" else "other"


def view(row: dict[str, Any]) -> dict[str, Any]:
    """A small, secret-free view of a device record."""
    out = {
        "name": row.get("name"), "mac": row.get("mac"), "_id": row.get("_id"), "model": row.get("model"), "type": row.get("type"),
        "ip": row.get("ip"), "version": row.get("version"), "state": row.get("state"), "adopted": row.get("adopted"),
        "disabled": bool(row.get("disabled")), "locating": bool(row.get("locating")), "led_override": row.get("led_override"),
    }
    return {k: v for k, v in out.items() if v is not None}


def stable(row: dict[str, Any] | None) -> dict[str, Any]:
    return {k: (row or {}).get(k) for k in STABLE}


def dependents(row: dict[str, Any], rows: list[dict[str, Any]]) -> dict[str, Any]:
    mac = _lower(row.get("mac"))
    down = [str(d.get("name") or d.get("mac")) for d in rows
            if d is not row and _lower((d.get("uplink") or {}).get("uplink_mac")) == mac]
    watts, ports = 0.0, 0
    for p in row.get("port_table") or []:
        try:
            w = float(p.get("poe_power") or 0)
        except (TypeError, ValueError):
            w = 0.0
        if p.get("poe_enable") and w > 0:
            ports, watts = ports + 1, watts + w
    clients = int(row.get("num_sta") or 0) if row.get("type") == "uap" else 0
    return {"downlinks": down, "poe_ports": ports, "poe_watts": round(watts, 1), "wireless_clients": clients}


def _impact(row: dict[str, Any], deps: dict[str, Any], what: str) -> list[str]:
    out: list[str] = []
    name = row.get("name") or row.get("mac")
    if deps["downlinks"]:
        out.append(f"{what} {name} takes {len(deps['downlinks'])} device(s) behind it offline: {', '.join(deps['downlinks'][:8])}.")
    if deps["poe_ports"]:
        out.append(f"{deps['poe_ports']} PoE port(s) are delivering {deps['poe_watts']} W; devices they power may lose power.")
    if deps["wireless_clients"]:
        out.append(f"{deps['wireless_clients']} wireless client(s) are connected to {name} and will be dropped.")
    if role(row, None) == "gateway":
        out.append(f"{name} is the gateway: the whole network and its internet access go down with it.")
    return out


@dataclass
class DPlan:
    action: str
    tier: str
    row: dict[str, Any] | None
    mac: str
    ident: str | None
    op: str
    body: Any
    path_params: dict[str, Any] = field(default_factory=dict)
    changes: dict[str, Any] = field(default_factory=dict)      # field -> {"from", "to"}
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    no_change: bool = False
    note: str | None = None
    deps: dict[str, Any] = field(default_factory=dict)


# ----------------------------------------------------------------------------------------------- update planning
def _net(nets: list[dict[str, Any]], ref: str) -> dict[str, Any] | None:
    for n in nets:
        if str(n.get("_id")) == ref:
            return n
    hits = [n for n in nets if str(n.get("name") or "").lower() == ref.strip().lower()]
    return hits[0] if len(hits) == 1 else None


def _ipv4(value: Any) -> ipaddress.IPv4Address | None:
    try:
        return ipaddress.IPv4Address(str(value))
    except ValueError:
        return None


def _config_network(row: dict[str, Any], f: dict[str, Any], rows: list[dict[str, Any]], console_ip: str | None,
                    errors: list[str], warnings: list[str]) -> dict[str, Any] | None:
    cur = dict(row.get("config_network") or {})
    new = dict(cur)
    if f.get("ip_mode"):
        new["type"] = f["ip_mode"]
    for k in ("ip", "netmask", "gateway", "dns1", "dns2"):
        if f.get(k) is not None:
            new[k] = f[k]
    for k in ("dns1", "dns2"):
        if new.get(k) and _ipv4(new[k]) is None:
            errors.append(f"{k} '{new[k]}' is not an IPv4 address.")
    if new.get("type") == "static":
        ip, gw = _ipv4(new.get("ip")), _ipv4(new.get("gateway"))
        try:
            iface = ipaddress.ip_interface(f"{new.get('ip')}/{new.get('netmask')}")
        except ValueError:
            iface = None
        if ip is None or gw is None or iface is None or iface.version != 4:
            errors.append("A static address needs a valid IPv4 ip, netmask and gateway.")
            return None
        net = iface.network
        if gw not in net or ip in (net.network_address, net.broadcast_address) or gw == ip:
            errors.append(f"The address {ip} and gateway {gw} do not fit the subnet {net} (gateway must be inside it, and not the device itself).")
        if console_ip and str(ip) == console_ip:
            errors.append(f"{ip} is the console's own address.")
        taken = [d for d in rows if d is not row and str(ip) in (d.get("ip"), (d.get("config_network") or {}).get("ip"))]
        if taken:
            errors.append(f"{ip} is already used by {taken[0].get('name') or taken[0].get('mac')}.")
        if str(ip) != str(row.get("ip") or ""):
            warnings.append(f"The management address changes from {row.get('ip')} to {ip}. The device re-addresses itself and is "
                            "unreachable at the old address, so it may show as disconnected for a minute or two.")
    elif new.get("type") == "dhcp" and cur.get("type") != "dhcp":
        warnings.append("Switching to DHCP: the device takes whatever address the DHCP server gives it, which may differ from today's.")
    return None if same(cur, new) else new


def plan_update(row: dict[str, Any], f: dict[str, Any], rows: list[dict[str, Any]], nets: list[dict[str, Any]],
                console_ip: str | None, errors: list[str], warnings: list[str]) -> dict[str, Any]:
    """The partial body for rest/device/{id}: changed fields only."""
    bad = set(f) - set(UPDATE_FIELDS)
    if bad:
        raise UniFiError(f"Unknown field(s): {', '.join(sorted(bad))}. Use: {', '.join(UPDATE_FIELDS)}.")
    if not f:
        raise UniFiError("Nothing to change: pass at least one of " + ", ".join(UPDATE_FIELDS) + ".")
    body: dict[str, Any] = {}
    kind = role(row, console_ip)
    if "name" in f:
        name = str(f["name"]).strip()
        if not name or len(name) > 64:
            errors.append("name must be 1 to 64 characters.")
        elif name != row.get("name"):
            body["name"] = name
            if any(d is not row and d.get("name") == name for d in rows):
                warnings.append(f"Another device is already called '{name}'.")
    if "led_override" in f:
        if f["led_override"] not in LED_VALUES:
            errors.append(f"led_override must be one of {', '.join(LED_VALUES)}.")
        elif f["led_override"] != row.get("led_override"):
            body["led_override"] = f["led_override"]
    for k in ("snmp_contact", "snmp_location"):
        if k in f:
            if len(str(f[k])) > 255:
                errors.append(f"{k} is limited to 255 characters.")
            elif str(f[k]) != str(row.get(k) or ""):
                body[k] = str(f[k])
    if "stp_priority" in f:
        v = f["stp_priority"]
        if kind != "switch":
            errors.append("stp_priority only applies to a switch.")
        elif not isinstance(v, int) or not 0 <= v <= 61440 or v % 4096:
            errors.append("stp_priority must be a multiple of 4096 from 0 to 61440.")
        elif str(v) != str(row.get("stp_priority")):
            body["stp_priority"] = str(v)
            warnings.append(f"Changing the spanning-tree priority ({row.get('stp_priority')} -> {v}) can re-elect the STP root and briefly "
                            "block ports. The lowest priority wins the root; check the Sonos/STP notes before lowering it.")
    if "management_network" in f:
        n = _net([x for x in nets if x.get("purpose") != "wan"], str(f["management_network"]))
        if n is None:
            errors.append(f"management_network '{f['management_network']}' is not a network on this console (names are matched exactly).")
        elif str(n["_id"]) != str(row.get("mgmt_network_id")):
            body["mgmt_network_id"] = str(n["_id"])
            warnings.append(f"The management network moves to {n.get('name')}: the device changes VLAN and can drop off the network "
                            "if its address, the switch port and the DHCP scope do not match.")
    if NETWORK_FIELDS & set(f) - {"management_network"}:
        cn = _config_network(row, f, rows, console_ip, errors, warnings)
        if cn is not None:
            body["config_network"] = cn
    if not errors and not body:
        pass                                  # already in the requested state: handled by the caller as no_change
    return body


def _update_tier(body: dict[str, Any], kind: str) -> str:
    return "C" if kind == "gateway" or {"mgmt_network_id", "config_network"} & set(body) else "B"


# ----------------------------------------------------------------------------------------------- planning
def build_plan(action: str, target: str, fields: dict[str, Any], rows: list[dict[str, Any]], basic: list[dict[str, Any]],
               nets: list[dict[str, Any]], console_ip: str | None) -> DPlan:
    if action not in ACTIONS:
        raise UniFiError(f"action must be one of: {', '.join(ACTIONS)}.")
    if not target:
        raise UniFiError("target is required: the device's name, MAC or id.")
    errors: list[str] = []
    warnings: list[str] = []

    if action == "adopt":
        mac = norm_mac(target)
        if not mac:
            raise UniFiError("adopt needs the device's MAC address (aa:bb:cc:dd:ee:ff) as the target.")
        row = next((r for r in basic if _lower(r.get("mac")) == mac), None)
        if row is None:
            errors.append(f"The console does not list a device with MAC {mac}. It must be powered, on the network and discovered first.")
        elif row.get("adopted"):
            errors.append(f"{row.get('name') or mac} is already adopted.")
        else:
            warnings.append("Adoption takes a minute or two and the device may restart and update. It joins with the console's default "
                            "settings, so check its name, management network and uplink afterwards.")
        return DPlan("adopt", "B", row, mac, (row or {}).get("_id"), "deviceManagerCommand",
                     {"mac": mac, "client": "web", "cmd": "adopt"}, errors=errors, warnings=warnings, deps={})

    row = WriteEngine._resolve(SPEC, rows, target)
    mac = _lower(row.get("mac"))
    ident = str(row.get("_id"))
    kind = role(row, console_ip)
    deps = dependents(row, rows)
    name = row.get("name") or mac
    if kind == "console" and action not in ("locate", "unlocate"):
        errors.append(f"{name} is the device running the console (its address matches the console's). Only locate is allowed on it; "
                      "manage it in the UniFi UI.")
    if not row.get("adopted", True) and action not in ("remove", "locate", "unlocate"):
        errors.append(f"{name} is not adopted. Use adopt first.")

    if action in ("locate", "unlocate"):
        want = action == "locate"
        no_change = bool(row.get("locating")) == want
        return DPlan(action, "A", row, mac, ident, "deviceManagerCommand",
                     {"mac": mac, "cmd": "set-locate" if want else "unset-locate"}, errors=errors, warnings=warnings, no_change=no_change,
                     note=("Already " + ("flashing" if want else "not flashing") + "; nothing would be sent.") if no_change else None,
                     deps=deps, changes={"locating": {"from": bool(row.get("locating")), "to": want}})

    if action == "restart":
        tier = "C" if kind in ("gateway", "switch") or deps["downlinks"] else "B"
        if row.get("state") != 1:
            warnings.append(f"{name} is not connected (state {row.get('state')}), so it may not receive the restart.")
        warnings += _impact(row, deps, "Restarting")
        warnings.append("This is a hard restart (the only kind the console has): it also power-cycles the PoE ports on a switch.")
        return DPlan("restart", tier, row, mac, ident, "deviceManagerCommand",
                     {"mac": mac, "reboot_type": "hard", "cmd": "restart"}, errors=errors, warnings=warnings, deps=deps)

    if action in ("disable", "enable"):
        want = action == "disable"
        no_change = bool(row.get("disabled")) == want
        if want:
            warnings += _impact(row, deps, "Disabling")
            warnings.append(f"A disabled device stops serving traffic and is removed from the network until it is enabled again.")
        return DPlan(action, "C" if want else "B", row, mac, ident, "updateDeviceSettings", {"disabled": want},
                     {"id": ident}, errors=errors, warnings=warnings, no_change=no_change, deps=deps,
                     note=("Already " + ("disabled" if want else "enabled") + "; nothing would be sent.") if no_change else None,
                     changes={"disabled": {"from": bool(row.get("disabled")), "to": want}})

    if action == "update":
        body = plan_update(row, fields, rows, nets, console_ip, errors, warnings)
        tier = _update_tier(body, kind)
        if kind == "gateway":
            warnings.append("Saving settings on a gateway re-provisions it. Treat any gateway change as a firewall change.")
        changes = {k: {"from": (row.get(k) if k != "stp_priority" else row.get(k)), "to": v} for k, v in body.items()}
        return DPlan("update", tier, row, mac, ident, "updateDeviceSettings", body, {"id": ident}, changes=changes,
                     errors=errors, warnings=warnings, no_change=not body and not errors, deps=deps,
                     note="Already in the requested state; nothing would be sent." if not body and not errors else None)

    # remove
    warnings += _impact(row, deps, "Removing")
    warnings.append(f"Removing {name} forgets it: it leaves the console and its settings there are deleted. It must be adopted again "
                    "(and may need a factory reset first) to rejoin. This cannot be undone from here.")
    return DPlan("remove", "C", row, mac, ident, "siteManagerCommand", {"macs": [mac], "cmd": "delete-device"},
                 errors=errors, warnings=warnings, deps=deps)


def rollback_for(plan: DPlan) -> dict[str, Any] | None:
    target = plan.mac
    if plan.action == "locate":
        return {"tool": TOOL, "arguments": {"action": "unlocate", "target": target}}
    if plan.action == "unlocate":
        return {"tool": TOOL, "arguments": {"action": "locate", "target": target}}
    if plan.action == "disable":
        return {"tool": TOOL, "arguments": {"action": "enable", "target": target}}
    if plan.action == "enable":
        return {"tool": TOOL, "arguments": {"action": "disable", "target": target}}
    if plan.action == "adopt":
        return {"tool": TOOL, "arguments": {"action": "remove", "target": target, "acknowledge_removal": True}}
    if plan.action == "update" and plan.row is not None:
        args: dict[str, Any] = {"action": "update", "target": target}
        cur = plan.row
        for k in plan.body:
            if k == "mgmt_network_id":
                args["management_network"] = cur.get("mgmt_network_id")
            elif k == "config_network":
                c = cur.get("config_network") or {}
                args.update({"ip_mode": c.get("type"), **{x: c.get(x) for x in ("ip", "netmask", "gateway", "dns1", "dns2") if c.get(x)}})
            elif k == "stp_priority":
                args["stp_priority"] = int(cur.get("stp_priority") or 32768)
            else:
                args[k] = cur.get(k) if cur.get(k) is not None else ""
        return {"tool": TOOL, "arguments": args}
    return None            # restart and remove cannot be undone


# ----------------------------------------------------------------------------------------------- verification
async def _find(engine: WriteEngine, op_id: str, mac: str) -> tuple[dict[str, Any] | None, bool]:
    """(row, reachable). A failed read counts as not reachable, which is normal while a device or its switch restarts."""
    try:
        rows = await engine._read_list(op_id)
    except Exception:  # noqa: BLE001 - the console itself can be unreachable during a restart
        return None, False
    return next((r for r in rows if _lower(r.get("mac")) == mac), None), True


async def _poll(engine: WriteEngine, plan: DPlan, wait_seconds: int) -> tuple[bool, dict[str, Any]]:
    polls = max(1, -(-int(wait_seconds) // int(POLL_INTERVAL)))
    seen_down = False
    before_uptime = (plan.row or {}).get("uptime")
    row: dict[str, Any] | None = None
    for i in range(polls):
        await _sleep(POLL_INTERVAL)
        if plan.action == "restart":
            row, ok = await _find(engine, "listDevicesDetailed", plan.mac)
            if not ok or row is None or row.get("state") != 1:
                seen_down = True
                continue
            up = row.get("uptime")
            rebooted = isinstance(up, (int, float)) and isinstance(before_uptime, (int, float)) and up < before_uptime
            if seen_down or rebooted:
                return True, {"polls": i + 1, "waited_seconds": int((i + 1) * POLL_INTERVAL)}
        elif plan.action == "adopt":
            row, ok = await _find(engine, "listDevicesBasic", plan.mac)
            if ok and row and row.get("adopted") and row.get("state") == 1:
                return True, {"polls": i + 1, "waited_seconds": int((i + 1) * POLL_INTERVAL)}
        else:                                               # remove
            row, ok = await _find(engine, "listDevicesBasic", plan.mac)
            if ok and (row is None or not row.get("adopted")):
                return True, {"polls": i + 1, "waited_seconds": int((i + 1) * POLL_INTERVAL)}
    return False, {"polls": polls, "waited_seconds": int(polls * POLL_INTERVAL), "last_state": (row or {}).get("state")}


async def verify(engine: WriteEngine, plan: DPlan, wait_seconds: int) -> tuple[bool | None, list[dict[str, Any]], dict[str, Any]]:
    mismatches: list[dict[str, Any]] = []
    extra: dict[str, Any] = {}
    if plan.action in ("restart", "adopt", "remove"):
        ok, extra = await _poll(engine, plan, wait_seconds)
        if not ok:
            want = {"restart": "back online after the restart", "adopt": "adopted and connected", "remove": "removed"}[plan.action]
            mismatches.append({"field": "(device)", "requested": want, "stored": f"not seen within {extra['waited_seconds']} s"})
        elif plan.action == "adopt":
            row, _ok = await _find(engine, "listDevicesDetailed", plan.mac)
            if row:
                extra["new_id"] = row.get("_id")
                extra["device"] = view(row)
        return ok, mismatches, extra
    row, ok = await _find(engine, "listDevicesDetailed", plan.mac)
    if row is None:
        return False, [{"field": "(device)", "requested": "present", "stored": "not found on read-back" if ok else "console not reachable"}], extra
    for key, change in plan.changes.items():
        wanted = change["to"]
        stored = row.get(key)
        if key in ("disabled", "locating"):
            stored = bool(stored)
        if not (covers(stored, wanted) if isinstance(wanted, dict) else same(stored, wanted)):
            mismatches.append({"field": key, "requested": wanted, "stored": stored})
    extra["device"] = view(row)
    return not mismatches, mismatches, extra


def _console_ip(engine: WriteEngine) -> str | None:
    try:
        return socket.gethostbyname(engine.api.settings.host)
    except (OSError, TypeError, AttributeError):
        return None


# ----------------------------------------------------------------------------------------------- run
async def run(engine: WriteEngine, *, action: str, target: str, fields: dict[str, Any], confirm: bool, fingerprint: str | None,
              approval_note: str | None, acknowledge_removal: bool, wait_seconds: int) -> dict[str, Any]:
    async with engine._lock:
        console_ip = _console_ip(engine)
        rows = await engine._read_list("listDevicesDetailed") if action != "adopt" else []
        basic = await engine._read_list("listDevicesBasic") if action == "adopt" else []
        nets = await engine._read_list("listNetworkConfig") if action == "update" and "management_network" in fields else []
        plan = build_plan(action, target, fields, rows, basic, nets, console_ip)
        op = engine.api.registry.get(plan.op)
        path = op.build_path(dict(plan.path_params), engine.api.settings.site)
        fp = hashlib.sha256(_canon({"entity": TOOL, "action": action, "tier": plan.tier, "path": path, "body": plan.body,
                                    "before": stable(plan.row)}).encode()).hexdigest()[:16]
        blocked = engine.blocked_reason(replace(SPEC, tier=plan.tier), approval_note)
        needs_fp = action not in ("locate", "unlocate")
        if not confirm:
            out: dict[str, Any] = {
                "ok": True, "applied": False, "preview": True, "entity": TOOL, "tier": plan.tier, "action": action,
                "device": view(plan.row) if plan.row else {"mac": plan.mac},
                "request": {"method": op.method, "path": path, "body": redact(plan.body)},
                "diff": redact(plan.changes), "warnings": plan.warnings, "errors": plan.errors, "fingerprint": fp,
                "apply_blocked_reason": blocked or ("; ".join(plan.errors) or None),
            }
            if plan.deps and (plan.deps["downlinks"] or plan.deps["poe_ports"] or plan.deps["wireless_clients"]):
                out["dependents"] = plan.deps
            if plan.note:
                out["note"] = plan.note
            else:
                extra = (" and acknowledge_removal=true" if action == "remove" else "") + (", plus approval_note" if plan.tier == "C" else "")
                out["next_step"] = ("To apply, call again with the same fields and confirm=true" +
                                    (f", fingerprint='{fp}'" if needs_fp else "") + extra + ".")
            return out
        if blocked:
            raise UniFiError(blocked)
        if plan.errors:
            raise UniFiError("Refused: " + " ".join(plan.errors))
        if needs_fp:
            if not fingerprint:
                raise UniFiError("confirm=true needs the fingerprint from a preview of exactly this change. Preview first.")
            if fingerprint != fp:
                raise UniFiError("The device, or the requested change, differs from the preview you confirmed. Run the preview again and review it.")
        if action == "remove" and not acknowledge_removal:
            raise UniFiError("Removing forgets the device and cannot be undone from here. Repeat with acknowledge_removal=true. Nothing was changed.")
        if plan.no_change:
            return {"ok": True, "applied": False, "entity": TOOL, "action": action, "id": plan.mac, "note": plan.note}

        journal_id = uuid.uuid4().hex[:12]
        engine._journal({"event": "attempt", "journal_id": journal_id, "entity": TOOL, "tier": plan.tier, "action": action, "id": plan.mac,
                         "method": op.method, "path": path, "approval_note": approval_note, "before": view(plan.row) if plan.row else None,
                         "body": plan.body})
        status, _data, problem = await engine._send_json(op.method, path, plan.body, op.needs_session)
        if problem:
            engine._journal({"event": "failed", "journal_id": journal_id, "http_status": status, "error": problem})
            raise UniFiError(f"The console rejected the {action}: {problem} Re-run the preview to see the current state.")
        verified, mismatches, extra = await verify(engine, plan, wait_seconds)
        result: dict[str, Any] = {"ok": True, "applied": True, "entity": TOOL, "tier": plan.tier, "action": action, "id": plan.mac,
                                  "http_status": status, "verified": verified, "diff": redact(plan.changes),
                                  "rollback": rollback_for(plan), "journal_id": journal_id, **extra}
        if mismatches:
            result["mismatches"] = redact(mismatches)
            result["attention"] = ("The console accepted the request but the device does not show the expected result. "
                                   "Nothing was retried. Check the device in the UniFi UI before doing anything else.")
        engine._journal({"event": "result", "journal_id": journal_id, "http_status": status, "verified": verified, "mismatches": mismatches})
        return result


# ----------------------------------------------------------------------------------------------- tool
class DeviceInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    action: Literal["locate", "unlocate", "restart", "disable", "enable", "update", "adopt", "remove"] = Field(
        ..., description="locate/unlocate flash the LED; restart (hard); disable/enable; update settings; adopt a pending device; remove (forget) a device.")
    target: str = Field(..., description="The device: name, MAC or id. adopt and remove: the MAC address.")
    name: str | None = Field(default=None, description="update: the device's name.")
    led_override: Literal["on", "off", "default"] | None = Field(default=None, description="update: LED mode.")
    snmp_contact: str | None = Field(default=None, description="update: SNMP contact.")
    snmp_location: str | None = Field(default=None, description="update: SNMP location.")
    stp_priority: int | None = Field(default=None, description="update, switches: STP priority, a multiple of 4096 (0 to 61440).")
    management_network: str | None = Field(default=None, description="update (tier C): management network, by name or id.")
    ip_mode: Literal["static", "dhcp"] | None = Field(default=None, description="update (tier C): management address mode.")
    ip: str | None = Field(default=None, description="update (tier C): static IPv4 address.")
    netmask: str | None = Field(default=None, description="update (tier C): static netmask.")
    gateway: str | None = Field(default=None, description="update (tier C): static gateway.")
    dns1: str | None = Field(default=None, description="update (tier C): first DNS server.")
    dns2: str | None = Field(default=None, description="update (tier C): second DNS server.")
    acknowledge_removal: bool = Field(default=False, description="remove, with confirm=true: acknowledges the device is forgotten and must be re-adopted.")
    wait_seconds: int = Field(default=180, ge=10, le=600, description="restart, adopt, remove: how long to wait for the result to show.")
    approval_note: str | None = Field(default=None, description="Required with confirm=true for tier C actions: where the approval was given.")
    confirm: bool = Field(default=False, description="false (default) returns a read-only preview. true applies; needs fingerprint (except locate/unlocate).")
    fingerprint: str | None = Field(default=None, description="From the preview of exactly this action; required with confirm=true (except locate/unlocate).")

    def fields(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in UPDATE_FIELDS if getattr(self, k) is not None}


def register(mcp: MCPServer, engine: WriteEngine) -> None:
    @mcp.tool(
        name=TOOL,
        annotations={"title": "Locate, restart, disable, update, adopt or remove a UniFi device", "readOnlyHint": False,
                     "destructiveHint": True, "idempotentHint": False, "openWorldHint": False},
    )
    async def unifi_console_device(params: DeviceInput) -> str:
        """Preview, then apply, an action on ONE UniFi device (access point, switch, gateway).

        Two steps, always: confirm=false returns a read-only preview (the device, the request, warnings, what depends on it, a
        fingerprint); call again with the same fields plus confirm=true and that fingerprint to apply. locate/unlocate flash the LED
        (tier A, no fingerprint). restart is a hard restart and is tier C for a switch, the gateway or anything with devices behind it.
        enable is tier B; disable is tier C. update changes only the fields you pass (name, LED, SNMP, STP priority; the management
        network and IP are tier C). adopt takes a device the console lists as not adopted. remove forgets a device: tier C, needs
        acknowledge_removal=true and has no undo short of adopting it again. Tier C actions also need approval_note. The device running
        the console is refused (except locate). Firmware updates are not offered. Applying needs UNIFI_CONSOLE_ENABLE_WRITES=true and
        'device' in UNIFI_CONSOLE_WRITE_ENTITIES. Every action is journalled and read back where the console shows a result.
        """
        try:
            result = await run(engine, action=params.action, target=params.target, fields=params.fields(), confirm=params.confirm,
                               fingerprint=params.fingerprint, approval_note=params.approval_note,
                               acknowledge_removal=params.acknowledge_removal, wait_seconds=params.wait_seconds)
            return json.dumps(result, separators=(",", ":"), default=str)
        except Exception as exc:  # noqa: BLE001 - converted to an actionable message
            return error_text(exc)
