"""Switch port settings (legacy `rest/device/{id}`, the whole `port_overrides` array). Tier C.

Captured 2026-10-17: the UI saves a port edit as PUT `rest/device/{device _id}` with the **entire `port_overrides` array**
(nothing else). The array is sparse (a port with no saved settings has no entry) and uneven (entries carry 20 to 40 keys and
the key set differs per entry). An entry left out presumably returns that port to defaults, so every entry must be sent back
exactly as read. This tool therefore changes ONE port of ONE switch per call, shows only that port in the preview and diff,
and after the write proves that every other entry is identical to what it was.

Why tier C: a wrong native VLAN, PoE off, isolation or storm-control setting on an uplink, gateway, switch, access point or
Cloud Key port can strand a device, and the console itself sits on a switch port (so a restore request could not get through
either). Ports are classified from live data (uplink, infrastructure, client, unused). Risky fields on uplink and infrastructure
ports are refused unless `acknowledge_infrastructure=true`; a name change is always allowed. Disabling a port is not offered.
`reset` removes an override entry only when it is still exactly what this tool would create.

Safety net: a health guard. Before the change the adopted devices that are connected are noted; after it they are polled and,
if one that was connected is not connected any more, the previous array is put back once and the result says so. The guard
cannot see a problem that only shows up later (for example a PoE-off access point is noticed only after the controller's own
timeout), so the protections above carry most of the weight.

Not offered (values or meaning not yet confirmed on this console): STP edge mode, port profiles, port security, 802.1X, egress
rate limits, the forwarding mode, tagged-VLAN management other than blocking networks on an entry already in `customize` mode.
"""

from __future__ import annotations

import asyncio
import copy
import ipaddress
import json
import socket
import time
from dataclasses import replace
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel, ConfigDict, Field

from ..api import error_text
from ..client import UniFiError
from ..writes import EntitySpec, Findings, Guard, Plan, WriteEngine, covers, same

KEY = "switch_port"
TOOL = "unifi_console_switch_port"
FRIENDLY = ("port", "name", "poe_mode", "native_network", "blocked_networks", "isolation", "bpdu_guard", "flow_control",
            "storm_control", "keepalive", "lldpmed", "reset")
STORM = {"broadcast": "bcast", "multicast": "mcast", "unicast": "ucast"}
RISKY = frozenset({"poe_mode", "native_networkconf_id", "excluded_networkconf_ids", "isolation", "stp_bpdu_guard_enabled",
                   "flow_control_enabled", "stormctrl_bcast_enabled", "stormctrl_mcast_enabled", "stormctrl_ucast_enabled",
                   "stormctrl_bcast_rate", "stormctrl_mcast_rate", "stormctrl_ucast_rate"})
MAX_RATE = 100000
GUARD_TEXT = ("Safety net: every adopted device that is connected now must still be connected after the change; if one is not, the "
              "previous port settings are put back automatically, once, and the result says so.")
IGNORE = frozenset({"site_id", "attr_hidden_id", "attr_no_delete", "attr_no_edit", "port_overrides", "port_table", "uplink",
                    "last_seen", "uptime", "state", "sys_stats", "system-stats", "stat", "tx_bytes", "rx_bytes", "bytes"})


# ----------------------------------------------------------------------------------------------- helpers
def _entry_map(arr: list[dict[str, Any]] | None) -> dict[int, dict[str, Any]]:
    return {int(e.get("port_idx")): e for e in (arr or []) if isinstance(e, dict) and e.get("port_idx") is not None}


def changed_ports(before: dict[str, Any] | None, after: dict[str, Any] | None) -> list[int]:
    b, a = _entry_map((before or {}).get("port_overrides")), _entry_map((after or {}).get("port_overrides"))
    return sorted(i for i in set(b) | set(a) if i not in b or i not in a or not same(b[i], a[i]))


def focus(before: dict[str, Any] | None, after: dict[str, Any] | None) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    ports = changed_ports(before, after)
    b, a = _entry_map((before or {}).get("port_overrides")), _entry_map((after or {}).get("port_overrides"))
    if len(ports) == 1:
        return b.get(ports[0]), a.get(ports[0])
    return ({f"port {i}": b.get(i) for i in ports} or None, {f"port {i}": a.get(i) for i in ports} or None)


def _port_row(device: dict[str, Any], idx: int) -> dict[str, Any] | None:
    return next((p for p in device.get("port_table") or [] if int(p.get("port_idx", -1)) == idx), None)


def _net(nets: list[dict[str, Any]], ref: str) -> dict[str, Any] | None:
    ref_l = ref.strip().lower()
    for n in nets:
        if str(n.get("_id")) == ref:
            return n
    hits = [n for n in nets if str(n.get("name") or "").lower() == ref_l]
    return hits[0] if len(hits) == 1 else None


def _default_native(device: dict[str, Any], nets: list[dict[str, Any]]) -> str | None:
    ip = (device.get("config_network") or {}).get("ip") or device.get("ip")
    try:
        addr = ipaddress.ip_address(ip)
    except (TypeError, ValueError):
        return None
    for n in nets:
        try:
            if n.get("ip_subnet") and n.get("purpose") != "wan" and addr in ipaddress.ip_interface(n["ip_subnet"]).network:
                return str(n["_id"])
        except ValueError:
            continue
    return None


def new_entry(idx: int, device: dict[str, Any], native: str) -> dict[str, Any]:
    """The entry for a port that has none yet: what the UI saves for an ordinary client port."""
    row = _port_row(device, idx) or {}
    entry: dict[str, Any] = {
        "setting_preference": "manual", "port_idx": idx, "name": row.get("name") or f"Port {idx}", "forward": "all",
        "native_networkconf_id": native, "voice_networkconf_id": "", "tagged_vlan_mgmt": "auto", "isolation": False,
        "autoneg": True, "flow_control_enabled": True, "stp_port_mode": True, "lldpmed_enabled": True,
        "port_keepalive_enabled": False, "egress_rate_limit_kbps_enabled": False, "port_security_enabled": False,
        "port_security_mac_address": [],
    }
    if int(row.get("poe_caps") or 0) > 0:
        entry["poe_mode"] = "auto"
    return entry


def classify(device: dict[str, Any], idx: int, others: list[dict[str, Any]], clients: list[dict[str, Any]],
             console_ip: str | None) -> tuple[str, str]:
    """(kind, what): uplink, infrastructure, client or unused."""
    row = _port_row(device, idx) or {}
    mac = str(device.get("mac") or "").lower()
    if row.get("is_uplink") or int((device.get("uplink") or {}).get("port_idx") or 0) == idx and (device.get("uplink") or {}).get("type") == "wire":
        up = device.get("uplink") or {}
        return "uplink", f"uplink to {up.get('uplink_device_name') or 'the upstream device'}"
    for d in others:
        up = d.get("uplink") or {}
        if str(up.get("uplink_mac") or "").lower() == mac and int(up.get("uplink_remote_port") or 0) == idx and d.get("type") != "uap" or \
           (d.get("type") == "uap" and str(up.get("uplink_mac") or "").lower() == mac and int(up.get("uplink_remote_port") or 0) == idx):
            return "infrastructure", f"{d.get('name') or d.get('mac')} ({d.get('type')})"
    for c in clients:
        if str(c.get("sw_mac") or "").lower() == mac and int(c.get("sw_port") or 0) == idx and console_ip and c.get("ip") == console_ip:
            return "infrastructure", "the console (this server reaches it through this port)"
    if row.get("up"):
        who = [str(c.get("name") or c.get("hostname") or c.get("mac")) for c in clients
               if str(c.get("sw_mac") or "").lower() == mac and int(c.get("sw_port") or 0) == idx]
        return "client", ", ".join(who[:3]) or "a device with link"
    return "unused", "no link"


# ----------------------------------------------------------------------------------------------- prepare
def prepare_ctx(action: str, before: dict[str, Any] | None, changes: dict[str, Any], ctx: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    if action != "update" or before is None:
        raise UniFiError("Only update exists for switch ports: there is nothing to create or delete.")
    bad = set(changes) - set(FRIENDLY)
    if bad:
        raise UniFiError(f"Unknown field(s): {', '.join(sorted(bad))}. Use: {', '.join(FRIENDLY)}.")
    if before.get("type") != "usw":
        raise UniFiError(f"'{before.get('name')}' is not a switch (type {before.get('type')}).")
    if "port" not in changes:
        raise UniFiError("port is required: the port number on the switch.")
    idx = int(changes["port"])
    table = _port_row(before, idx)
    if table is None:
        raise UniFiError(f"{before.get('name')} has no port {idx}. Ports: {', '.join(str(p.get('port_idx')) for p in before.get('port_table') or [])}.")
    nets = [n for n in ctx.get("networks", []) if n.get("purpose") != "wan"]
    arr = copy.deepcopy(before.get("port_overrides") or [])
    pos = next((i for i, e in enumerate(arr) if int(e.get("port_idx", -1)) == idx), None)
    wanted = {k: v for k, v in changes.items() if k not in ("port", "reset")}
    if changes.get("reset"):
        if wanted:
            raise UniFiError("reset takes no other fields.")
        if pos is None:
            raise UniFiError(f"Port {idx} has no saved settings to reset.")
        native = arr[pos].get("native_networkconf_id") or ""
        pristine = {k: v for k, v in new_entry(idx, before, native).items() if k != "name"}
        if {k: v for k, v in arr[pos].items() if k != "name"} != pristine:
            raise UniFiError(f"Port {idx} has settings beyond what this tool creates, so it is not reset here. Use the UI's reset on that port.")
        del arr[pos]
        return {"port_overrides": arr}
    if not wanted:
        raise UniFiError("Nothing to change: pass at least one setting besides port.")
    if pos is None:
        native = None
        if "native_network" in wanted:
            n = _net(nets, str(wanted["native_network"]))
            native = str(n["_id"]) if n else None
        native = native or _default_native(before, nets)
        if not native:
            raise UniFiError(f"Port {idx} has no saved settings yet and the switch's own network could not be worked out; pass native_network.")
        arr.append(new_entry(idx, before, native))
        pos = len(arr) - 1
    e = arr[pos]
    if "name" in wanted:
        name = str(wanted["name"]).strip()
        if not name or len(name) > 64:
            raise UniFiError("name must be 1 to 64 characters.")
        e["name"] = name
    if "poe_mode" in wanted:
        if int(table.get("poe_caps") or 0) == 0:
            raise UniFiError(f"Port {idx} is not a PoE port.")
        if wanted["poe_mode"] not in ("auto", "off"):
            raise UniFiError("poe_mode must be auto or off.")
        e["poe_mode"] = wanted["poe_mode"]
    if "native_network" in wanted:
        n = _net(nets, str(wanted["native_network"]))
        if not n:
            raise UniFiError(f"native_network '{wanted['native_network']}' is not a network on this console (names are matched exactly).")
        e["native_networkconf_id"] = str(n["_id"])
    if "blocked_networks" in wanted:
        if e.get("forward") != "customize":
            raise UniFiError(f"blocked_networks only applies to a port whose forwarding mode is 'customize' (port {idx} is '{e.get('forward')}'); "
                             "the forwarding mode itself is not changed here.")
        ids = []
        for ref in wanted["blocked_networks"]:
            n = _net(nets, str(ref))
            if not n:
                raise UniFiError(f"blocked_networks: '{ref}' is not a network on this console.")
            ids.append(str(n["_id"]))
        e["excluded_networkconf_ids"] = ids
    for k_in, k_out in (("isolation", "isolation"), ("bpdu_guard", "stp_bpdu_guard_enabled"), ("flow_control", "flow_control_enabled"),
                        ("keepalive", "port_keepalive_enabled"), ("lldpmed", "lldpmed_enabled")):
        if k_in in wanted:
            e[k_out] = bool(wanted[k_in])
    if "storm_control" in wanted:
        sc = wanted["storm_control"]
        for kind, short in STORM.items():
            cfg = sc.get(kind)
            if cfg is None:
                continue
            if set(cfg) - {"enabled", "rate"}:
                raise UniFiError(f"storm_control.{kind} takes enabled and rate only.")
            if "enabled" in cfg:
                e[f"stormctrl_{short}_enabled"] = bool(cfg["enabled"])
            if "rate" in cfg:
                if not isinstance(cfg["rate"], int) or not 1 <= cfg["rate"] <= MAX_RATE:
                    raise UniFiError(f"storm_control.{kind}.rate must be a whole number from 1 to {MAX_RATE}.")
                e[f"stormctrl_{short}_rate"] = cfg["rate"]
        e.setdefault("stormctrl_type", "rate")
    arr[pos] = e
    return {"port_overrides": arr}


# ----------------------------------------------------------------------------------------------- validation
def make_validate(ack: bool, console_ip: str | None):
    def validate(action: str, before: dict[str, Any] | None, after: dict[str, Any], others: list[dict[str, Any]],
                 ctx: dict[str, list[dict[str, Any]]]) -> Findings:
        f = Findings()
        b = before or {}
        ports = changed_ports(b, after)
        if len(ports) != 1:
            f.errors.append(f"Expected exactly one port to change, found {len(ports)}.")
            return f
        idx = ports[0]
        be, ae = _entry_map(b.get("port_overrides")).get(idx), _entry_map(after.get("port_overrides")).get(idx)
        kind, what = classify(b, idx, others, ctx.get("clients", []), console_ip)
        row = _port_row(b, idx) or {}
        keys = sorted({k for k in set(be or {}) | set(ae or {}) if not same((be or {}).get(k), (ae or {}).get(k))})
        f.warnings.append(f"{b.get('name')} port {idx} ({row.get('name')}): {kind}, {what}. Changing: {', '.join(keys) or 'nothing'}.")
        risky = [k for k in keys if k in RISKY]
        if ae is None:
            f.warnings.append("Reset: the port's saved settings are removed and the port returns to the switch defaults.")
        elif be is None:
            f.warnings.append("This port has no saved settings yet; a new entry is added with the values the UI uses for a client port.")
        if risky and kind in ("uplink", "infrastructure"):
            if not ack:
                f.errors.append(f"Infrastructure stop: port {idx} is {what}. Changing {', '.join(risky)} could strand it (and possibly the "
                                "console). Only the name can be changed here without acknowledge_infrastructure=true.")
            else:
                f.warnings.append(f"Acknowledged: changing {', '.join(risky)} on {what}.")
        if kind == "client" and risky:
            f.warnings.append(f"The port has link ({what}); the change takes effect at once and may drop that device briefly.")
        if (ae or {}).get("poe_mode") == "off" and (be or {}).get("poe_mode") != "off" and row.get("poe_enable"):
            f.warnings.append(f"PoE is being switched off on a port that is delivering {row.get('poe_power')} W to {what}.")
        if "native_networkconf_id" in keys and kind in ("client", "infrastructure", "uplink"):
            old = next((n.get("name") for n in ctx.get("networks", []) if n.get("_id") == (be or {}).get("native_networkconf_id")), "?")
            new = next((n.get("name") for n in ctx.get("networks", []) if n.get("_id") == (ae or {}).get("native_networkconf_id")), "?")
            f.warnings.append(f"The native VLAN moves from {old} to {new}: the device on this port changes network.")
        if "stp_bpdu_guard_enabled" in keys and (ae or {}).get("stp_bpdu_guard_enabled") and kind != "unused":
            f.warnings.append("BPDU guard shuts the port down if it receives spanning-tree frames; do not enable it on a port that leads to another switch.")
        if any(k.startswith("stormctrl_") and k.endswith("_rate") for k in keys):
            f.warnings.append("Storm-control rate units are not confirmed on this console (existing values are 100 to 1000); check the result in the UI.")
        return f
    return validate


# ----------------------------------------------------------------------------------------------- verification and restore
def verify(plan: Plan, rows: list[dict[str, Any]], stored: dict[str, Any] | None) -> list[dict[str, Any]]:
    if stored is None:
        return []
    out: list[dict[str, Any]] = []
    b, a, s = (_entry_map((x or {}).get("port_overrides")) for x in (plan.before, plan.after, stored))
    target = changed_ports(plan.before, plan.after)
    for i in sorted(set(b) | set(s)):
        if i in target:
            continue
        if not same(b.get(i), s.get(i)):
            out.append({"field": f"port {i} (not meant to change)", "requested": b.get(i), "stored": s.get(i)})
    for i in target:
        if a.get(i) is None:
            if s.get(i) is not None:
                out.append({"field": f"port {i}", "requested": "no saved settings", "stored": s.get(i)})
        elif s.get(i) is None or not covers(s[i], a[i]):
            out.append({"field": f"port {i}", "requested": a[i], "stored": s.get(i)})
    return out


def restore_ok(plan: Plan, rows: list[dict[str, Any]], new_id: str | None) -> bool:
    cur = next((r for r in rows if str(r.get("_id")) == str(plan.ident)), None)
    if cur is None:
        return False
    b, s = _entry_map((plan.before or {}).get("port_overrides")), _entry_map(cur.get("port_overrides"))
    return set(b) == set(s) and all(same(b[i], s[i]) for i in b)


def rollback(plan: Plan, new_id: str | None) -> dict[str, Any]:
    idx = (changed_ports(plan.before, plan.after) or [0])[0]
    be = _entry_map((plan.before or {}).get("port_overrides")).get(idx)
    ae = _entry_map((plan.after or {}).get("port_overrides")).get(idx) or {}
    dev = (plan.before or {}).get("name")
    if be is None:
        return {"tool": TOOL, "arguments": {"action": "update", "target": dev, "port": idx, "reset": True}}
    args: dict[str, Any] = {"action": "update", "target": dev, "port": idx}
    for k in sorted({k for k in set(be) | set(ae) if not same(be.get(k), ae.get(k))}):
        if k == "name":
            args["name"] = be.get(k)
        elif k == "poe_mode":
            args["poe_mode"] = be.get(k)
        elif k == "native_networkconf_id":
            args["native_network"] = be.get(k)
        elif k == "excluded_networkconf_ids":
            args["blocked_networks"] = list(be.get(k) or [])
        elif k == "isolation":
            args["isolation"] = bool(be.get(k))
        elif k == "stp_bpdu_guard_enabled":
            args["bpdu_guard"] = bool(be.get(k))
        elif k == "flow_control_enabled":
            args["flow_control"] = bool(be.get(k))
        elif k == "port_keepalive_enabled":
            args["keepalive"] = bool(be.get(k))
        elif k == "lldpmed_enabled":
            args["lldpmed"] = bool(be.get(k))
        elif k.startswith("stormctrl_"):
            _, short, field = k.split("_", 2)
            kind = {v: n for n, v in STORM.items()}.get(short)
            if kind:
                args.setdefault("storm_control", {}).setdefault(kind, {})[field] = be.get(k)
    return {"tool": TOOL, "arguments": args}


# ----------------------------------------------------------------------------------------------- health guard
def make_guard() -> Guard:
    baseline: set[str] = set()

    async def states(engine: Any) -> dict[str, tuple[str, bool]]:
        rows = await engine._read_list("listDevicesBasic")
        return {str(r.get("mac")).lower(): (str(r.get("name") or r.get("mac")), r.get("state") == 1) for r in rows if r.get("adopted", True)}

    async def before(engine: Any) -> str | None:
        baseline.clear()
        baseline.update(m for m, (_n, ok) in (await states(engine)).items() if ok)
        return None

    async def after(engine: Any, phase: str) -> str | None:
        settings = engine.api.settings
        if phase == "change" and settings.dns_probe_force_fail:
            return "forced failure (UNIFI_CONSOLE_DNS_PROBE_FORCE_FAIL is set; test switch)"
        window = max(float(settings.dns_probe_window), 1.0)
        interval = min(2.0, window / 3)
        deadline = time.monotonic() + window
        good = 0
        lost: list[str] = []
        while True:
            now = await states(engine)
            lost = [now.get(m, (m, False))[0] for m in sorted(baseline) if not now.get(m, (m, False))[1]]
            good = good + 1 if not lost else 0
            if good >= 2:
                return None
            if time.monotonic() >= deadline:
                return f"device(s) no longer connected: {', '.join(lost)}" if lost else None
            await asyncio.sleep(interval)

    return Guard(describe=GUARD_TEXT, before=before, after=after)


# ----------------------------------------------------------------------------------------------- spec and tool
SPEC = EntitySpec(
    key=KEY, label="switch", tier="C", list_op="listDevicesDetailed", update_op="updateDeviceSettings", whole_object=False,
    name_field="name", match_fields=("mac",), ignore=IGNORE, body_keys=("port_overrides",), prepare_ctx=prepare_ctx,
    context_ops=(("networks", "listNetworkConfig"), ("clients", "listActiveClientsLegacy")),
    focus=focus, verify=verify, restore_ok=restore_ok, rollback=rollback, guard=None,
)


class StormRate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool | None = None
    rate: int | None = Field(default=None, description=f"1 to {MAX_RATE}; the unit is not confirmed on this console.")


class StormControl(BaseModel):
    model_config = ConfigDict(extra="forbid")
    broadcast: StormRate | None = None
    multicast: StormRate | None = None
    unicast: StormRate | None = None


class SwitchPortInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    action: Literal["update"] = Field(default="update", description="Only update exists.")
    target: str = Field(..., description="The switch: name, MAC or id.")
    port: int = Field(..., description="Port number on that switch.")
    name: str | None = Field(default=None, description="The port's label.")
    poe_mode: Literal["auto", "off"] | None = None
    native_network: str | None = Field(default=None, description="Native VLAN: network name or id.")
    blocked_networks: list[str] | None = Field(default=None, description="Networks blocked on a port in customize mode (replaces the list).")
    isolation: bool | None = None
    bpdu_guard: bool | None = None
    flow_control: bool | None = None
    storm_control: StormControl | None = None
    keepalive: bool | None = None
    lldpmed: bool | None = None
    reset: bool = Field(default=False, description="Remove the saved settings of a port this tool added (only if still untouched).")
    acknowledge_infrastructure: bool = Field(default=False, description="Accept risky changes on an uplink, gateway, switch, AP or console port.")
    approval_note: str | None = Field(default=None, description="Required with confirm=true: where the approval for this tier C change was given.")
    confirm: bool = Field(default=False, description="false (default) returns a read-only preview. true applies and needs fingerprint.")
    fingerprint: str | None = Field(default=None, description="From the preview of exactly this change; required with confirm=true.")

    def changes(self) -> dict[str, Any]:
        out: dict[str, Any] = {"port": self.port}
        for k in FRIENDLY[1:-1]:
            v = getattr(self, k)
            if v is None:
                continue
            out[k] = v.model_dump(exclude_none=True) if isinstance(v, BaseModel) else v
        if self.reset:
            out["reset"] = True
        return out


def register(mcp: MCPServer, engine: WriteEngine) -> None:
    @mcp.tool(
        name=TOOL,
        annotations={"title": "Change one switch port", "readOnlyHint": False, "destructiveHint": True,
                     "idempotentHint": True, "openWorldHint": False},
    )
    async def unifi_console_switch_port(params: SwitchPortInput) -> str:
        """Preview, then apply, a change to ONE port of ONE switch. Tier C: a wrong setting on an uplink, AP or console port can strand it.

        Two steps, always: confirm=false returns a read-only preview (only that port's before/after, how the port is classified:
        uplink, infrastructure, client or unused, what is connected, warnings, errors, a fingerprint); then call again with the
        same fields plus confirm=true, that fingerprint and an approval_note. The console needs the whole port list on every save,
        so the tool sends every other port back exactly as read and checks afterwards that none of them changed. Risky fields (PoE,
        VLANs, isolation, BPDU guard, flow control, storm control) on uplink and infrastructure ports are refused unless
        acknowledge_infrastructure=true; a name change is always allowed. After a change every device that was connected must still
        be connected, otherwise the previous settings are put back automatically, once. Disabling a port, STP edge mode, port
        profiles and the other switch settings are not offered. Applying also needs UNIFI_CONSOLE_ENABLE_WRITES=true and
        'switch_port' in UNIFI_CONSOLE_WRITE_ENTITIES. Every write is journalled.
        """
        try:
            console_ip = None
            try:
                console_ip = socket.gethostbyname(engine.api.settings.host)
            except OSError:
                pass
            spec = replace(SPEC, validate_ctx=make_validate(params.acknowledge_infrastructure, console_ip), guard=make_guard())
            result = await engine.execute(
                spec, action="update", target=params.target, changes=params.changes(),
                confirm=params.confirm, fingerprint=params.fingerprint, approval_note=params.approval_note,
            )
            return json.dumps(result, separators=(",", ":"), default=str)
        except Exception as exc:  # noqa: BLE001 - converted to an actionable message
            return error_text(exc)
