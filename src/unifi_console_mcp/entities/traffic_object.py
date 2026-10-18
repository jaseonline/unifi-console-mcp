"""Traffic policy objects (v2 `object-oriented-network-config`): per-network or per-client bandwidth limits (QoS), schedules,
internet blocking and routing. Tier B.

Captured in the batch-6 HAR: create is POST of the whole object `{enabled, name, target_type, targets, secure, route, qos}`
(HTTP 201); update is PUT of the whole object including `id` (HTTP 200); delete answers 204. Captured again on 2026-10-18
(`objects.har`, `all-objects.har`, `all-objects-inc-burst.har`):
  * targets are networks (`target_type: "NETWORKS"`, items `{type: "NETWORK_ID", value}`) or clients
    (`target_type: "CLIENTS"`, items `{type: "MAC", value}`);
  * `qos`: `mode` LIMIT or PRIORITIZE, `download_limit` / `upload_limit` `{enabled, limit, burst}` with burst DISABLED, SHORT or
    LONG, and a `schedule` of EVERY_DAY (`time_range_start`, `time_range_end`) or EVERY_WEEK (`repeat_on_days`, `time_all_day`,
    and the range when not all day);
  * `secure.internet`: `{mode: "BLOCKLIST", everything, apps, ip_addresses, domains, regions, schedule}` with schedule ALWAYS or
    EVERY_DAY; `secure.local` exists in the UI but its semantics on its own were not isolated, so it is never written;
  * `route`: `{enabled, all_traffic, apps, domains, ip_addresses, regions, kill_switch, network_id}` where `network_id` is the
    WAN (or a VPN client network) the matching traffic is sent out of.
A limit is in kbit/s: the UI offers Mbps and Kbps and its 10 Mbps default is stored as 10000.

What this tool changes: name, enabled switch, targets (networks or clients), the QoS block (mode, limits, burst, schedule), the
internet block (`block_internet`, with a schedule) and the route block (network, IP addresses, kill switch). Because blocking
and re-routing can cut a device off or send it through another link, switching either on in an ENABLED object needs
`acknowledge_blocking` / `acknowledge_reroute`. App, domain and region matchers, secure.local and matcher lists other than IP
addresses are not edited; an object that has them keeps them untouched.
"""

from __future__ import annotations

import copy
import dataclasses
import ipaddress
import json
import re
from functools import partial
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel, ConfigDict, Field

from ..api import error_text
from ..client import UniFiError
from ..writes import EntitySpec, Findings, WriteEngine, same

KEY = "traffic_object"
TOOL = "unifi_console_traffic_object"
ITEM_FOR = {"NETWORKS": "NETWORK_ID", "CLIENTS": "MAC"}
TARGET_TYPE = "NETWORKS"
TARGET_ITEM = "NETWORK_ID"
DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
BURSTS = ("DISABLED", "SHORT", "LONG")
QOS_MODES = ("LIMIT", "PRIORITIZE")
MAX_LIMIT = 10_000_000
_HHMM = re.compile(r"^([01][0-9]|2[0-3]):[0-5][0-9]$")
_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
FIELDS = ("name", "enabled", "qos_enabled", "qos_mode", "download_limit", "upload_limit", "download_burst", "upload_burst",
          "qos_schedule", "block_internet", "block_schedule", "route_enabled", "route_all_traffic", "route_ip_addresses",
          "route_kill_switch", "route_network_id", "clients", "target_type", "targets", "qos", "route", "secure")
FRIENDLY_QOS = ("qos_enabled", "qos_mode", "download_limit", "upload_limit", "download_burst", "upload_burst", "qos_schedule")
FRIENDLY_SECURE = ("block_internet", "block_schedule")
FRIENDLY_ROUTE = ("route_enabled", "route_all_traffic", "route_ip_addresses", "route_kill_switch", "route_network_id")


def _limit() -> dict[str, Any]:
    return {"enabled": False, "limit": 10000, "burst": "DISABLED"}


def _matcher() -> dict[str, Any]:
    return {"enabled": False, "values": []}


def default_qos() -> dict[str, Any]:
    return {"enabled": False, "all_traffic": True, "apps": _matcher(), "domains": _matcher(), "ip_addresses": _matcher(),
            "regions": _matcher(), "mode": "LIMIT", "download_limit": _limit(), "upload_limit": _limit(),
            "schedule": {"mode": "EVERY_WEEK", "repeat_on_days": list(DAYS), "time_all_day": True}}


def default_route() -> dict[str, Any]:
    return {"enabled": False, "apps": _matcher(), "domains": _matcher(), "ip_addresses": _matcher(), "regions": _matcher()}


def default_secure() -> dict[str, Any]:
    return {"enabled": False, "internet": {"mode": "BLOCKLIST", "everything": True}}


def _internet_block() -> dict[str, Any]:
    return {"mode": "BLOCKLIST", "everything": True, "apps": _matcher(), "ip_addresses": _matcher(), "domains": _matcher(),
            "regions": _matcher(), "schedule": {"mode": "ALWAYS"}}


def build_schedule(raw: dict[str, Any], *, for_qos: bool) -> dict[str, Any]:
    """Turn the friendly schedule {mode, days, start, end} into the captured stored shape."""
    mode = str(raw.get("mode") or "").upper()
    start, end, days = raw.get("start"), raw.get("end"), raw.get("days")
    if mode == "ALWAYS":
        if for_qos:   # the QoS block has no ALWAYS form; every day, all day is the same thing
            return {"mode": "EVERY_WEEK", "repeat_on_days": list(DAYS), "time_all_day": True}
        return {"mode": "ALWAYS"}
    if mode == "EVERY_DAY":
        if not (start and end):
            raise UniFiError("An EVERY_DAY schedule needs start and end times (HH:MM).")
        return {"mode": "EVERY_DAY", "time_range_start": start, "time_range_end": end}
    if mode == "EVERY_WEEK":
        out: dict[str, Any] = {"mode": "EVERY_WEEK", "repeat_on_days": [str(d).lower() for d in (days or DAYS)]}
        if start and end:
            out.update(time_all_day=False, time_range_start=start, time_range_end=end)
        else:
            out["time_all_day"] = True
        return out
    raise UniFiError("schedule mode must be ALWAYS, EVERY_DAY or EVERY_WEEK.")


def _merge(base: dict[str, Any], given: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in given.items():
        out[k] = _merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else copy.deepcopy(v)
    return out


def _mac(value: str) -> str:
    v = str(value).strip().lower().replace("-", ":")
    if re.fullmatch(r"[0-9a-f]{12}", v):
        v = ":".join(v[i:i + 2] for i in range(0, 12, 2))
    if not _MAC.match(v):
        raise UniFiError(f"'{value}' is not a MAC address.")
    return v


def prepare(action: str, before: dict[str, Any] | None, changes: dict[str, Any]) -> dict[str, Any]:
    out = dict(changes)
    q_in = {k: out.pop(k) for k in FRIENDLY_QOS if k in out and out[k] is not None}
    s_in = {k: out.pop(k) for k in FRIENDLY_SECURE if k in out and out[k] is not None}
    r_in = {k: out.pop(k) for k in FRIENDLY_ROUTE if k in out and out[k] is not None}
    for k in FRIENDLY_QOS + FRIENDLY_SECURE + FRIENDLY_ROUTE:
        out.pop(k, None)
    clients = out.pop("clients", None)
    for friendly, key, label in ((q_in, "qos", "qos"), (s_in, "secure", "secure"), (r_in, "route", "route")):
        if friendly and key in out:
            raise UniFiError(f"Use the {label} fields or a full {key} block, not both.")
    if "name" in out:
        out["name"] = str(out["name"]).strip()
    if "target_type" in out:
        out["target_type"] = str(out["target_type"]).upper()
    creating = action == "create"
    before = before or {}
    if clients is not None:
        if "targets" in out:
            raise UniFiError("Use clients or targets, not both.")
        macs = [_mac(m) for m in clients]
        out["target_type"] = "CLIENTS"
        out["targets"] = [{"type": "MAC", "value": m} for m in macs]
    elif out.get("targets") and creating and "target_type" not in out:
        out["target_type"] = TARGET_TYPE
    if not creating and before.get("target_type") not in ITEM_FOR and ("targets" in out or "target_type" in out):
        raise UniFiError(f"This object targets '{before.get('target_type')}', which this tool does not manage, so its "
                         "targets cannot be changed here. Other fields can still be edited.")
    if creating:
        out.setdefault("enabled", False)               # a new object starts switched off unless asked for
        out.setdefault("target_type", TARGET_TYPE)

    # ---- qos
    if creating:
        base = _merge(default_qos(), out["qos"]) if "qos" in out else default_qos()
    else:
        base = copy.deepcopy(before.get("qos") or default_qos())
        if "qos" in out:
            out["qos"] = copy.deepcopy(out["qos"])
    if q_in:
        qos_on = q_in.get("qos_enabled")
        down, up = q_in.get("download_limit"), q_in.get("upload_limit")
        if qos_on is not None:
            base["enabled"] = bool(qos_on)
        elif creating and (down or up):
            base["enabled"] = True                      # asking for a limit on a new object means it should apply
        if "qos_mode" in q_in:
            base["mode"] = str(q_in["qos_mode"]).upper()
            if base["mode"] == "PRIORITIZE" and down is None and up is None:
                for key in ("download_limit", "upload_limit"):   # the console rejects PRIORITIZE with a limit on ("Invalid QoS rule objective")
                    base.setdefault(key, _limit())["enabled"] = False
        for key, value in (("download_limit", down), ("upload_limit", up)):
            if value is None:
                continue
            block = base.setdefault(key, _limit())
            if value == 0:
                block["enabled"] = False
            else:
                block["limit"], block["enabled"] = int(value), True
        for key, burst in (("download_limit", q_in.get("download_burst")), ("upload_limit", q_in.get("upload_burst"))):
            if burst is not None:
                base.setdefault(key, _limit())["burst"] = str(burst).upper()
        if "qos_schedule" in q_in:
            base["schedule"] = build_schedule(q_in["qos_schedule"], for_qos=True)
        out["qos"] = base
    elif creating and "qos" not in out:
        out["qos"] = base
    elif creating:
        out["qos"] = base

    # ---- secure (internet block only)
    if creating:
        sec = _merge(default_secure(), out["secure"]) if "secure" in out else default_secure()
    else:
        sec = copy.deepcopy(before.get("secure") or default_secure())
    if s_in:
        if "block_internet" in s_in:
            sec["enabled"] = bool(s_in["block_internet"])
            if sec["enabled"] and "schedule" not in (sec.get("internet") or {}):
                sec["internet"] = _internet_block() | {k: v for k, v in (sec.get("internet") or {}).items() if k in ("mode", "everything")}
        if "block_schedule" in s_in:
            if not (sec.get("internet") or {}).get("apps"):
                sec["internet"] = _internet_block() | {k: v for k, v in (sec.get("internet") or {}).items() if k in ("mode", "everything")}
            sec["internet"]["schedule"] = build_schedule(s_in["block_schedule"], for_qos=False)
        out["secure"] = sec
    elif creating:
        out["secure"] = sec

    # ---- route
    if creating:
        route = _merge(default_route(), out["route"]) if "route" in out else default_route()
    else:
        route = copy.deepcopy(before.get("route") or default_route())
    if r_in:
        if "route_enabled" in r_in:
            route["enabled"] = bool(r_in["route_enabled"])
        if "route_network_id" in r_in:
            route["network_id"] = r_in["route_network_id"]
        if "route_kill_switch" in r_in:
            route["kill_switch"] = bool(r_in["route_kill_switch"])
        if "route_ip_addresses" in r_in:
            vals = [str(v).strip() for v in r_in["route_ip_addresses"]]
            route["ip_addresses"] = {"enabled": bool(vals), "values": vals}
            route.setdefault("all_traffic", False)
            if vals and "route_all_traffic" not in r_in:
                route["all_traffic"] = False
        if "route_all_traffic" in r_in:
            route["all_traffic"] = bool(r_in["route_all_traffic"])
        if route.get("enabled"):
            route.setdefault("all_traffic", False)
            route.setdefault("kill_switch", False)
        out["route"] = route
    elif creating:
        out["route"] = route
    return out


def _time_minutes(v: str) -> int:
    return int(v[:2]) * 60 + int(v[3:])


def _check_schedule(f: Findings, label: str, s: Any) -> None:
    if s is None:
        return
    if not isinstance(s, dict):
        f.errors.append(f"{label}.schedule must be an object.")
        return
    mode = s.get("mode")
    if mode not in ("ALWAYS", "EVERY_DAY", "EVERY_WEEK"):
        f.errors.append(f"{label}.schedule.mode '{mode}' is not one of ALWAYS, EVERY_DAY, EVERY_WEEK.")
        return
    start, end = s.get("time_range_start"), s.get("time_range_end")
    if mode == "EVERY_DAY" or (mode == "EVERY_WEEK" and not s.get("time_all_day", True)):
        if not (isinstance(start, str) and isinstance(end, str) and _HHMM.match(start) and _HHMM.match(end)):
            f.errors.append(f"{label}.schedule needs start and end times as HH:MM (24 hour).")
        elif start == end:
            f.errors.append(f"{label}.schedule start and end are the same time, so it would never (or always) apply.")
        elif _time_minutes(end) < _time_minutes(start):
            f.warnings.append(f"{label}.schedule ends ({end}) before it starts ({start}): it runs overnight, whether the console reads it that way is unverified.")
    if mode == "EVERY_WEEK":
        days = s.get("repeat_on_days")
        if not isinstance(days, list) or any(d not in DAYS for d in days):
            f.errors.append(f"{label}.schedule.repeat_on_days must list days from: {', '.join(DAYS)}.")
        elif not days:
            f.errors.append(f"{label}.schedule has no days, so it would never apply.")


def _check_qos(f: Findings, q: Any, before_q: Any) -> None:
    if not isinstance(q, dict):
        f.errors.append("qos must be an object.")
        return
    if not isinstance(q.get("enabled"), bool):
        f.errors.append("qos.enabled must be true or false.")
    if q.get("mode") not in QOS_MODES:
        (f.warnings if (before_q or {}).get("mode") == q.get("mode") else f.errors).append(
            f"qos.mode is '{q.get('mode')}'; only {' and '.join(QOS_MODES)} have been captured.")
    for key in ("download_limit", "upload_limit"):
        b = q.get(key)
        if not isinstance(b, dict) or not isinstance(b.get("enabled"), bool):
            f.errors.append(f"qos.{key} must be an object with enabled true/false.")
            continue
        lim = b.get("limit")
        if isinstance(lim, bool) or not isinstance(lim, int) or not 1 <= lim <= MAX_LIMIT:
            f.errors.append(f"qos.{key}.limit must be a whole number from 1 to {MAX_LIMIT}.")
        if b.get("burst") not in BURSTS and b.get("burst") != ((before_q or {}).get(key) or {}).get("burst"):
            f.errors.append(f"qos.{key}.burst '{b.get('burst')}' is not one of {', '.join(BURSTS)}.")
    _check_schedule(f, "qos", q.get("schedule"))


def _rate(kbps: Any) -> str:
    return f"{kbps} kbit/s ({kbps / 1000:g} Mbit/s)" if isinstance(kbps, int) else str(kbps)


def _names(ids: list[str], nets: dict[str, dict[str, Any]]) -> str:
    return ", ".join(str(nets.get(i, {}).get("name") or i) for i in ids)


def _when(s: Any) -> str:
    if not isinstance(s, dict) or s.get("mode") in (None, "ALWAYS"):
        return "all the time"
    if s["mode"] == "EVERY_DAY":
        return f"every day {s.get('time_range_start')}-{s.get('time_range_end')}"
    days = ",".join(s.get("repeat_on_days") or [])
    return f"on {days}" + ("" if s.get("time_all_day", True) else f" {s.get('time_range_start')}-{s.get('time_range_end')}")


def validate(action: str, before: dict[str, Any] | None, after: dict[str, Any], others: list[dict[str, Any]],
             ctx: dict[str, list[dict[str, Any]]], *, ack_block: bool = False, ack_reroute: bool = False) -> Findings:
    f = Findings()
    before = before or {}
    nets = {str(n.get("_id")): n for n in ctx.get("networks", [])}
    if action == "delete":
        ids = [str(t.get("value")) for t in before.get("targets") or [] if isinstance(t, dict)]
        q = before.get("qos") or {}
        what = _names(ids, nets) or "its targets"
        if before.get("enabled") and q.get("enabled"):
            f.warnings.append(f"Deleting this object lifts its limits on {what} at once.")
        if before.get("enabled") and (before.get("secure") or {}).get("enabled"):
            f.warnings.append(f"Deleting this object lifts its internet block on {what} at once.")
        if before.get("enabled") and (before.get("route") or {}).get("enabled"):
            f.warnings.append(f"Deleting this object stops routing {what} through its chosen link at once.")
        return f

    name = str(after.get("name") or "").strip()
    if not name:
        f.errors.append("A name is required.")
    elif len(name) > 128:
        f.errors.append("The name is longer than 128 characters.")
    elif name != before.get("name") and any(str(r.get("name") or "").lower() == name.lower() for r in others):
        f.errors.append(f"Another traffic object is already called '{name}'. Names must be unique so one can be addressed by name.")
    if not isinstance(after.get("enabled"), bool):
        f.errors.append("enabled must be true or false.")

    # ---- targets
    ttype, targets = after.get("target_type"), after.get("targets")
    target_ids: list[str] = []
    target_labels: list[str] = []
    changed = action == "create" or not same(targets, before.get("targets")) or ttype != before.get("target_type")
    if ttype not in ITEM_FOR:
        (f.errors if changed else f.warnings).append(
            f"Target type '{ttype}' is not supported here (only {', '.join(ITEM_FOR)}); "
            + ("its targets cannot be changed." if changed else "its targets are left untouched."))
    else:
        item = ITEM_FOR[ttype]
        items = targets if isinstance(targets, list) else []
        target_ids = [str(t.get("value")) for t in items if isinstance(t, dict) and t.get("type") == item]
        if not items or len(target_ids) != len(items):
            f.errors.append(f"targets must be a non-empty list of {{type: {item}, value: <{'network id' if ttype == 'NETWORKS' else 'MAC'}>}}.")
        dupes = sorted({i for i in target_ids if target_ids.count(i) > 1})
        if dupes:
            f.errors.append(f"Duplicate targets: {_names(dupes, nets)}.")
        old = {str(t.get("value")) for t in before.get("targets") or [] if isinstance(t, dict)}
        if ttype == "NETWORKS":
            target_labels = [str(nets.get(i, {}).get("name") or i) for i in target_ids]
            for i in target_ids:
                net = nets.get(i)
                if net is None:
                    (f.errors if i not in old else f.warnings).append(f"Network {i} does not exist on this console.")
                elif net.get("purpose") == "wan" and i not in old:
                    f.errors.append(f"'{net.get('name')}' is a WAN network; only LAN networks can be targeted here.")
        else:
            target_labels = target_ids
            for i in target_ids:
                if not _MAC.match(i):
                    f.errors.append(f"'{i}' is not a MAC address.")
    what = ", ".join(target_labels) or "its targets"

    # ---- secure
    sec = after.get("secure")
    if not isinstance(sec, dict) or not isinstance(sec.get("enabled"), bool):
        f.errors.append("secure.enabled must be true or false.")
    elif sec.get("enabled") and same(sec, before.get("secure")):
        f.warnings.append("This object has an internet block switched on; it is left untouched.")
    elif sec.get("enabled"):
        net_ = sec.get("internet") or {}
        if net_.get("mode") not in (None, "BLOCKLIST"):
            f.errors.append(f"secure.internet.mode '{net_.get('mode')}' has not been captured; only BLOCKLIST is supported.")
        _check_schedule(f, "secure.internet", net_.get("schedule"))
        if net_.get("everything", True):
            msg = f"This blocks all internet access for {what} ({_when(net_.get('schedule'))})."
        else:
            msg = f"This blocks part of the internet for {what} ({_when(net_.get('schedule'))}); its matchers are not edited here."
        if after.get("enabled") is True and not ack_block:
            f.errors.append(msg + " Pass acknowledge_blocking=true if that is intended, or create the object switched off first.")
        else:
            f.warnings.append(msg + ("" if after.get("enabled") else " The object is switched off, so it has no effect yet."))
        if isinstance(sec.get("local"), dict) and not same(sec.get("local"), (before.get("secure") or {}).get("local")):
            f.errors.append("secure.local cannot be edited here (its behaviour on its own has not been isolated).")

    # ---- route
    route = after.get("route")
    if not isinstance(route, dict) or not isinstance(route.get("enabled"), bool):
        f.errors.append("route.enabled must be true or false.")
    elif route.get("enabled") and same(route, before.get("route")):
        f.warnings.append("This object has route settings switched on; they are left untouched.")
    elif route.get("enabled"):
        nid = route.get("network_id")
        net = nets.get(str(nid))
        if net is None:
            f.errors.append("route.network_id must be an existing WAN or VPN client network.")
        elif net.get("purpose") not in ("wan", "vpn-client", "vpn_client"):
            f.errors.append(f"'{net.get('name')}' is not a WAN or VPN client network, so traffic cannot be routed through it.")
        ips = route.get("ip_addresses") or {}
        if not route.get("all_traffic") and not any((route.get(k) or {}).get("enabled") for k in ("apps", "domains", "ip_addresses", "regions")):
            f.errors.append("route sends nothing: all_traffic is off and no matcher is on.")
        for v in (ips.get("values") or []) if ips.get("enabled") else []:
            try:
                ipaddress.ip_network(str(v), strict=False)
            except ValueError:
                f.errors.append(f"route IP address '{v}' is not an IP address or CIDR.")
        link = (net or {}).get("name") or nid
        msg = (f"This sends {'all traffic' if route.get('all_traffic') else 'the matching traffic'} from {what} out through {link}"
               + (" with the kill switch on (traffic stops if that link is down)." if route.get("kill_switch") else " (no kill switch: traffic falls back to the normal route if it is down)."))
        if after.get("enabled") is True and not ack_reroute:
            f.errors.append(msg + " Pass acknowledge_reroute=true if that is intended, or create the object switched off first.")
        else:
            f.warnings.append(msg + ("" if after.get("enabled") else " The object is switched off, so it has no effect yet."))

    # ---- qos
    q = after.get("qos")
    if not same(q, before.get("qos")):
        _check_qos(f, q, before.get("qos"))
    if isinstance(q, dict) and not f.errors:
        down, up = q.get("download_limit") or {}, q.get("upload_limit") or {}
        limits = [f"{label} {_rate(b.get('limit'))}" + (f" burst {b.get('burst').lower()}" if b.get("burst") not in (None, "DISABLED") else "")
                  for label, b in (("download", down), ("upload", up)) if b.get("enabled")]
        if q.get("mode") == "PRIORITIZE":
            if limits:
                f.errors.append("Prioritize mode cannot have a download or upload limit switched on (the console rejects it as an invalid QoS rule objective). "
                                "Set download_limit=0 and upload_limit=0, or use LIMIT mode.")
            if q.get("enabled"):
                f.warnings.append(f"This prioritises traffic for {what} ({_when(q.get('schedule'))}).")
        else:
            if q.get("enabled") and not limits:
                f.warnings.append("QoS is on but neither the download nor the upload limit is, so this object limits nothing.")
            if not q.get("enabled") and limits:
                f.warnings.append("A limit is set but QoS is off, so it has no effect until qos_enabled is true.")
            if q.get("enabled") and limits and after.get("enabled"):
                f.warnings.append(f"This limits {what} as soon as it is applied ({', '.join(limits)}; {_when(q.get('schedule'))}).")
        if q.get("enabled") and after.get("enabled"):
            clash = [str(r.get("name")) for r in others if r.get("enabled") and (r.get("qos") or {}).get("enabled")
                     and {str(t.get("value")) for t in r.get("targets") or [] if isinstance(t, dict)} & set(target_ids)]
            if clash:
                f.warnings.append(f"Other enabled QoS object(s) already cover some of these targets ({', '.join(clash)}); "
                                  "how the console combines them is unverified.")
        if q.get("enabled") and not q.get("all_traffic"):
            hits = [k for k in ("apps", "domains", "ip_addresses", "regions") if (q.get(k) or {}).get("enabled")]
            if not hits:
                f.warnings.append("qos.all_traffic is off and no app, domain, address or region matcher is on, so nothing matches.")
    return f


SPEC = EntitySpec(
    key=KEY, label="traffic object", tier="B", list_op="listTrafficPolicyObjects", create_op="createTrafficPolicyObject",
    update_op="updateTrafficPolicyObject", delete_op="deleteTrafficPolicyObject", whole_object=True, id_field="id",
    name_field="name", prepare=prepare, validate_ctx=validate, context_ops=(("networks", "listNetworkConfig"),),
)


class TargetItem(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    type: Literal["NETWORK_ID", "MAC"]
    value: str


class ScheduleInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    mode: Literal["ALWAYS", "EVERY_DAY", "EVERY_WEEK"] = Field(..., description="ALWAYS, EVERY_DAY (needs start and end) or EVERY_WEEK (days, optionally start and end).")
    days: list[Literal["mon", "tue", "wed", "thu", "fri", "sat", "sun"]] | None = Field(default=None, description="EVERY_WEEK only; defaults to every day.")
    start: str | None = Field(default=None, pattern=r"^([01][0-9]|2[0-3]):[0-5][0-9]$", description="HH:MM, 24 hour.")
    end: str | None = Field(default=None, pattern=r"^([01][0-9]|2[0-3]):[0-5][0-9]$", description="HH:MM, 24 hour.")


class TrafficObjectInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    action: Literal["create", "update", "delete"] = Field(..., description="create an object, change it, or delete it.")
    target: str | None = Field(default=None, description="Existing object: its id or exact name. Not used by create.")
    name: str | None = Field(default=None, description="Object name (unique).")
    enabled: bool | None = Field(default=None, description="Whether the object applies. A new object is created switched off unless this is true.")
    networks: list[str] | None = Field(default=None, description="Networks to target, by name or id (LAN networks only). Replaces the targets.")
    clients: list[str] | None = Field(default=None, description="Clients to target, by MAC address. Replaces the targets (and makes the object client-based).")
    qos_enabled: bool | None = Field(default=None, description="Switch the QoS block on or off.")
    qos_mode: Literal["LIMIT", "PRIORITIZE"] | None = Field(default=None, description="LIMIT caps bandwidth; PRIORITIZE favours the targets' traffic.")
    download_limit: int | None = Field(default=None, ge=0, le=10_000_000, description="Download limit in kbit/s (10000 = 10 Mbit/s, the UI default). 0 switches the download limit off.")
    upload_limit: int | None = Field(default=None, ge=0, le=10_000_000, description="Upload limit in kbit/s. 0 switches the upload limit off.")
    download_burst: Literal["DISABLED", "SHORT", "LONG"] | None = Field(default=None, description="Burst allowance for the download limit.")
    upload_burst: Literal["DISABLED", "SHORT", "LONG"] | None = Field(default=None, description="Burst allowance for the upload limit.")
    qos_schedule: ScheduleInput | None = Field(default=None, description="When the QoS block applies. ALWAYS is stored as every day, all day.")
    block_internet: bool | None = Field(default=None, description="Block all internet access for the targets (the UI's Secure > Internet > Block list with Everything). Needs acknowledge_blocking=true when the object is switched on.")
    block_schedule: ScheduleInput | None = Field(default=None, description="When the internet block applies (ALWAYS or EVERY_DAY captured; EVERY_WEEK unverified).")
    route_enabled: bool | None = Field(default=None, description="Switch the route block on or off.")
    route_network: str | None = Field(default=None, description="WAN or VPN client network to send the matching traffic through, by name or id.")
    route_ip_addresses: list[str] | None = Field(default=None, description="Destination IP addresses or CIDRs to route through route_network (empty list clears them).")
    route_all_traffic: bool | None = Field(default=None, description="Route all of the targets' traffic through route_network.")
    route_kill_switch: bool | None = Field(default=None, description="Stop the routed traffic if the chosen link is down.")
    acknowledge_blocking: bool = Field(default=False, description="Accept an internet block on an object that is switched on.")
    acknowledge_reroute: bool = Field(default=False, description="Accept a route change on an object that is switched on.")
    target_type: Literal["NETWORKS", "CLIENTS"] | None = Field(default=None, description="Accepted so a recorded rollback can be replayed.")
    targets: list[TargetItem] | None = Field(default=None, description="Raw targets, as the console stores them; accepted so a recorded rollback can be replayed.")
    qos: dict[str, Any] | None = Field(default=None, description="Whole qos block, as the console stores it; accepted so a recorded rollback can be replayed. Prefer the friendly fields.")
    route: dict[str, Any] | None = Field(default=None, description="Whole route block; replay only. Prefer the route_* fields.")
    secure: dict[str, Any] | None = Field(default=None, description="Whole secure block; replay only. Prefer block_internet.")
    confirm: bool = Field(default=False, description="false (default) returns a read-only preview. true applies the change and needs fingerprint.")
    fingerprint: str | None = Field(default=None, description="From the preview of exactly this change; required with confirm=true.")

    def changes(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k in FIELDS:
            if k in ("targets", "qos_schedule", "block_schedule", "route_network_id"):
                continue
            v = getattr(self, k, None)
            if v is not None:
                out[k] = v
        if self.targets is not None:
            out["targets"] = [t.model_dump() for t in self.targets]
        for k in ("qos_schedule", "block_schedule"):
            v = getattr(self, k)
            if v is not None:
                out[k] = v.model_dump(exclude_none=True)
        return out


async def _rows(engine: WriteEngine) -> list[dict[str, Any]]:
    return await engine._read_list("listNetworkConfig")


def _pick(rows: list[dict[str, Any]], ref: str) -> dict[str, Any]:
    hits = ([r for r in rows if str(r.get("_id")) == ref] or [r for r in rows if r.get("name") == ref]
            or [r for r in rows if str(r.get("name") or "").lower() == ref.lower()])
    if not hits:
        raise UniFiError(f"No network with id or name '{ref}'. Known networks: {', '.join(str(r.get('name')) for r in rows)}.")
    if len(hits) > 1:
        raise UniFiError(f"{len(hits)} networks match '{ref}'; use its id instead.")
    return hits[0]


async def resolve_networks(engine: WriteEngine, refs: list[str]) -> list[dict[str, str]]:
    rows = await _rows(engine)
    out: list[dict[str, str]] = []
    for ref in refs:
        net = _pick(rows, ref)
        if net.get("purpose") == "wan":
            raise UniFiError(f"'{net.get('name')}' is a WAN network; only LAN networks can be targeted here.")
        out.append({"type": TARGET_ITEM, "value": str(net["_id"])})
    return out


async def resolve_route_network(engine: WriteEngine, ref: str) -> str:
    net = _pick(await _rows(engine), ref)
    if net.get("purpose") not in ("wan", "vpn-client", "vpn_client"):
        raise UniFiError(f"'{net.get('name')}' is not a WAN or VPN client network, so traffic cannot be routed through it.")
    return str(net["_id"])


def register(mcp: MCPServer, engine: WriteEngine) -> None:
    @mcp.tool(
        name=TOOL,
        annotations={"title": "Create, change or delete a traffic object (limits, schedules, internet block, routing)", "readOnlyHint": False,
                     "destructiveHint": True, "idempotentHint": False, "openWorldHint": False},
    )
    async def unifi_console_traffic_object(params: TrafficObjectInput) -> str:
        """Preview, then apply, a change to the console's traffic objects (Traffic Management: bandwidth limits and priority,
        schedules, internet blocking and routing for networks or clients).

        Two steps, always: call with confirm=false to get a read-only preview (before, after, diff, warnings, a
        fingerprint); call again with the same fields plus confirm=true and that fingerprint to apply. The object is
        re-read first, so a stale preview is refused. Target `networks` (by name) or `clients` (by MAC). QoS: qos_enabled,
        qos_mode (LIMIT or PRIORITIZE), download_limit / upload_limit in kbit/s (10000 = 10 Mbit/s; 0 switches one off),
        download_burst / upload_burst (DISABLED, SHORT, LONG) and qos_schedule. block_internet (with block_schedule) cuts
        internet access for the targets, and route_* sends traffic out through another WAN or VPN client network; both need
        acknowledge_blocking / acknowledge_reroute when the object is switched on. A new object starts switched off unless
        enabled=true; once enabled it takes effect at once. App, domain and region matchers and the local-network block are not
        edited. Applying also needs UNIFI_CONSOLE_ENABLE_WRITES=true and 'traffic_object' in UNIFI_CONSOLE_WRITE_ENTITIES.
        The console only accepts the whole object, so updates send all of it. After applying, the object is read back and the
        result reports verified true/false, the diff, and the exact rollback call. Every write is journalled.
        """
        try:
            changes = params.changes()
            for k in ("acknowledge_blocking", "acknowledge_reroute"):
                changes.pop(k, None)
            if params.action == "delete" and (changes or params.networks):
                return json.dumps({"ok": False, "error": "delete takes no field values."})
            if params.networks is not None:
                if params.targets is not None or params.clients is not None:
                    return json.dumps({"ok": False, "error": "Use networks, clients or targets, only one of them."})
                changes["targets"] = await resolve_networks(engine, params.networks)
                changes["target_type"] = TARGET_TYPE
            if params.route_network is not None:
                changes["route_network_id"] = await resolve_route_network(engine, params.route_network)
            changes.pop("route_network", None)
            if params.action == "create" and not (params.name and (changes.get("targets") or params.clients)):
                return json.dumps({"ok": False, "error": "create needs name and networks (or clients)."})
            spec = dataclasses.replace(SPEC, validate_ctx=partial(
                validate, ack_block=params.acknowledge_blocking, ack_reroute=params.acknowledge_reroute))
            result = await engine.execute(
                spec, action=params.action, target=params.target, changes=changes,
                confirm=params.confirm, fingerprint=params.fingerprint,
            )
            return json.dumps(result, separators=(",", ":"), default=str)
        except Exception as exc:  # noqa: BLE001 - converted to an actionable message
            return error_text(exc)
