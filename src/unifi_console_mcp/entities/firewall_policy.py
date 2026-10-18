"""Zone-based firewall policies (v2 `firewall-policies`). Tier C: a wrong policy can cut or expose the network.

Captured 2026-10-17 (see the plan doc `unifi-console-firewall-policy-plan-2026-10-18`):
  create   POST   firewall-policies                  whole object, HTTP 201 with the stored policy (`_id`, `index`)
  edit     PUT    firewall-policies/{id}             whole object including `_id` and `index`
  enable   PUT    firewall-policies/batch            `[{_id, enabled}]`
  reorder  PUT    firewall-policies/batch-reorder    `{before_predefined_ids, after_predefined_ids, source_zone_id, destination_zone_id}`
  delete   POST   firewall-policies/batch-delete     `[id, ...]`, HTTP 204

Rules this tool keeps to:
  * Only custom policies. System-defined ones, and the generated "(Return)" copies, are never changed.
  * A new policy is created switched off unless enabled=true is passed; switching it on is its own previewed step.
  * An enabled ALLOW from External that matches everything, and an enabled BLOCK or REJECT that would cut DNS/DHCP to the
    gateway or the internet for the console's own network, are refused unless explicitly acknowledged.
  * A change that touches an enabled policy runs inside the DNS safety net (see `dnsprobe.py`): tested before and after, and
    put back once, automatically, if DNS fails afterwards. The test runs from the console's own network, so it cannot see a
    problem that only affects another VLAN; the preview names the networks a policy touches for that reason.
  * Fields this tool does not offer (IID targets, schedules, custom connection states) are kept exactly as read.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
from dataclasses import replace
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel, ConfigDict, Field

from ..api import error_text
from ..client import UniFiError
from ..dnsprobe import make_guard
from ..writes import ActionOp, EntitySpec, Findings, MovePlan, Plan, RestoreStep, WriteEngine, same

KEY = "firewall_policy"
TOOL = "unifi_console_firewall_policy"
ACTIONS_ALLOWED = ("ALLOW", "BLOCK", "REJECT")
IP_VERSIONS = ("BOTH", "IPV4", "IPV6")
PROTOCOLS = ("all", "tcp", "udp", "tcp_udp", "icmp", "icmpv6")
PORT_PROTOCOLS = ("tcp", "udp", "tcp_udp")
PREDEFINED_START = 30000            # system policies start here; custom ones sit below
NO_SEND = frozenset({"hits", "last_hit"})
IGNORE = frozenset({"site_id", "attr_hidden_id", "attr_no_delete", "attr_no_edit", "hits", "last_hit"})
GUARD_TEXT = ("Safety net: DNS is tested through the gateway before and after a change that touches an enabled policy. If it "
              "fails afterwards, the previous state is put back automatically, once, and the result says so. The test runs from the "
              "console's own network only.")
_MAC = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
FRIENDLY = ("name", "description", "policy_action", "enabled", "ip_version", "protocol", "connection_state", "allow_return",
            "logging", "report_flow", "source", "destination")
ENDPOINT_KEYS = ("zone", "target", "networks", "client_macs", "ips", "ports", "opposite", "opposite_ports")
DEFAULT_ENDPOINT = {"matching_target": "ANY", "matching_target_type": "SPECIFIC", "port_matching_type": "ANY", "match_opposite_ports": False}
DEFAULTS: dict[str, Any] = {
    "action": "BLOCK", "connection_state_type": "ALL", "connection_states": [], "create_allow_respond": True, "description": "",
    "enabled": False, "icmp_typename": "ANY", "icmp_v6_typename": "ANY", "ip_version": "BOTH", "logging": False,
    "match_ip_sec": False, "match_opposite_protocol": False, "protocol": "all", "report_flow": True, "schedule": {"mode": "ALWAYS"},
}


# ----------------------------------------------------------------------------------------------- helpers
def _is_custom(row: dict[str, Any]) -> bool:
    return not row.get("predefined") and row.get("origin_type") != "custom_firewall_rule"


def _zone_of(zones: list[dict[str, Any]], ref: str) -> dict[str, Any] | None:
    ref_l = ref.strip().lower()
    for z in zones:
        if str(z.get("_id")) == ref or str(z.get("name") or "").lower() == ref_l:
            return z
    return None


def _net_of(nets: list[dict[str, Any]], ref: str) -> dict[str, Any] | None:
    ref_l = ref.strip().lower()
    for n in nets:
        if str(n.get("_id")) == ref:
            return n
    hits = [n for n in nets if str(n.get("name") or "").lower() == ref_l]
    return hits[0] if len(hits) == 1 else None


def _norm_ports(value: str) -> str:
    parts = [p.strip() for p in value.replace(" ", "").split(",") if p.strip()]
    return ",".join(parts)


def _port_problem(value: str) -> str | None:
    if not value:
        return "ports is empty"
    for part in value.split(","):
        m = re.fullmatch(r"(\d{1,5})(?:-(\d{1,5}))?", part)
        if not m:
            return f"'{part}' is not a port or a range like 1000-2000"
        lo, hi = int(m.group(1)), int(m.group(2) or m.group(1))
        if not (1 <= lo <= 65535 and 1 <= hi <= 65535) or lo > hi:
            return f"'{part}' is outside 1-65535 or reversed"
    return None


def _ip_problem(value: str) -> str | None:
    try:
        if "-" in value:
            a, b = (ipaddress.ip_address(x.strip()) for x in value.split("-", 1))
            return None if a.version == b.version and int(a) <= int(b) else f"'{value}' is not a valid address range"
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
    except ValueError:
        return f"'{value}' is not an IP address, CIDR network or range"
    return None


def _endpoint_prepare(label: str, current: dict[str, Any] | None, given: dict[str, Any], ctx: dict[str, list[dict[str, Any]]],
                      creating: bool) -> dict[str, Any]:
    bad = set(given) - set(ENDPOINT_KEYS)
    if bad:
        raise UniFiError(f"Unknown {label} field(s): {', '.join(sorted(bad))}. Use {', '.join(ENDPOINT_KEYS)}.")
    ep = dict(current) if current else {}
    zones, nets = ctx.get("zones", []), ctx.get("networks", [])
    if creating:
        if not given.get("zone"):
            raise UniFiError(f"{label}.zone is required (a zone name or id, for example 'IoT').")
        ep = {**DEFAULT_ENDPOINT}
    if given.get("zone"):
        z = _zone_of(zones, str(given["zone"]))
        if not z:
            names = ", ".join(sorted(str(x.get("name")) for x in zones))
            raise UniFiError(f"{label}.zone '{given['zone']}' is not a zone on this console. Zones: {names}.")
        if not creating and str(z["_id"]) != str(ep.get("zone_id")):
            raise UniFiError(f"{label}.zone cannot be changed on an existing policy. Create a new policy in the other zone pair instead.")
        ep["zone_id"] = z["_id"]
    target = given.get("target")
    if target is None:
        for inferred, key in (("networks", "networks"), ("clients", "client_macs"), ("ips", "ips")):
            if given.get(key):
                target = inferred
    if target is not None:
        target = str(target).lower()
        if target not in ("any", "networks", "clients", "ips"):
            raise UniFiError(f"{label}.target must be any, networks, clients or ips.")
        for k in ("network_ids", "client_macs", "ips", "iid", "match_opposite_networks", "match_opposite_ips", "match_opposite_iid"):
            ep.pop(k, None)
        if target == "any":
            ep["matching_target"] = "ANY"
        elif target == "networks":
            refs = given.get("networks") or []
            if not refs:
                raise UniFiError(f"{label}.target=networks needs {label}.networks (names or ids).")
            ids = []
            for r in refs:
                n = _net_of(nets, str(r))
                if not n:
                    raise UniFiError(f"{label}.networks: '{r}' is not a network on this console (names are matched exactly).")
                ids.append(n["_id"])
            ep.update(matching_target="NETWORK", network_ids=ids, match_opposite_networks=bool(given.get("opposite", False)))
        elif target == "clients":
            macs = [str(m).strip().lower().replace("-", ":") for m in (given.get("client_macs") or [])]
            if not macs:
                raise UniFiError(f"{label}.target=clients needs {label}.client_macs.")
            ep.update(matching_target="CLIENT", client_macs=macs)
        else:
            ips = [str(i).strip() for i in (given.get("ips") or [])]
            if not ips:
                raise UniFiError(f"{label}.target=ips needs {label}.ips.")
            ep.update(matching_target="IP", ips=ips, match_opposite_ips=bool(given.get("opposite", False)))
    elif "opposite" in given:
        if ep.get("matching_target") == "NETWORK":
            ep["match_opposite_networks"] = bool(given["opposite"])
        elif ep.get("matching_target") == "IP":
            ep["match_opposite_ips"] = bool(given["opposite"])
        else:
            raise UniFiError(f"{label}.opposite only applies to networks or ips targets.")
    if "ports" in given:
        ports = str(given["ports"] or "").strip().lower()
        if ports in ("", "any"):
            ep["port_matching_type"] = "ANY"
            ep.pop("port", None)
        else:
            ep["port_matching_type"] = "SPECIFIC"
            ep["port"] = _norm_ports(ports)
    if "opposite_ports" in given:
        ep["match_opposite_ports"] = bool(given["opposite_ports"])
    return ep


def prepare_ctx(action: str, before: dict[str, Any] | None, changes: dict[str, Any], ctx: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    bad = set(changes) - set(FRIENDLY)
    if bad:
        raise UniFiError(f"Unknown field(s): {', '.join(sorted(bad))}. Use: {', '.join(FRIENDLY)}.")
    out: dict[str, Any] = {}
    creating = action == "create"
    b = before or {}
    for k_in, k_out in (("name", "name"), ("description", "description"), ("policy_action", "action"), ("enabled", "enabled"),
                        ("ip_version", "ip_version"), ("protocol", "protocol"), ("allow_return", "create_allow_respond"),
                        ("logging", "logging"), ("report_flow", "report_flow")):
        if k_in in changes and changes[k_in] is not None:
            out[k_out] = changes[k_in]
    if "policy_action" in changes:
        out["action"] = str(changes["policy_action"]).upper()
    if "ip_version" in changes:
        out["ip_version"] = str(changes["ip_version"]).upper()
    if "protocol" in changes:
        out["protocol"] = str(changes["protocol"]).lower()
    if "name" in changes:
        out["name"] = str(changes["name"]).strip()
    if changes.get("connection_state") is not None:
        cs = str(changes["connection_state"]).lower()
        if cs not in ("all", "return_only"):
            raise UniFiError("connection_state must be 'all' or 'return_only'.")
        out["connection_state_type"] = "ALL" if cs == "all" else "RESPOND_ONLY"
        out["connection_states"] = []
    for side in ("source", "destination"):
        given = changes.get(side)
        if given is None and not creating:
            continue
        if given is None:
            raise UniFiError(f"{side} is required to create a policy: at least {{zone: ...}}.")
        out[side] = _endpoint_prepare(side, b.get(side), dict(given), ctx, creating)
    if creating:
        out = {**DEFAULTS, **out}
        out.setdefault("name", "")
    return out


# ----------------------------------------------------------------------------------------------- validation
def _endpoint_text(ep: dict[str, Any], zones: list[dict[str, Any]], nets: list[dict[str, Any]]) -> str:
    z = next((x for x in zones if x.get("_id") == ep.get("zone_id")), {})
    t = ep.get("matching_target")
    if t == "NETWORK":
        names = [str((_net_of(nets, i) or {}).get("name") or i) for i in ep.get("network_ids") or []]
        what = ("everything except " if ep.get("match_opposite_networks") else "") + "networks " + ", ".join(names)
    elif t == "CLIENT":
        what = "clients " + ", ".join(ep.get("client_macs") or [])
    elif t == "IP":
        what = ("everything except " if ep.get("match_opposite_ips") else "") + "addresses " + ", ".join(ep.get("ips") or [])
    elif t == "IID":
        what = f"IPv6 interface id {ep.get('iid')}"
    else:
        what = "everything"
    ports = f", ports {'not ' if ep.get('match_opposite_ports') else ''}{ep.get('port')}" if ep.get("port_matching_type") == "SPECIFIC" else ""
    return f"{z.get('name') or ep.get('zone_id')}: {what}{ports}"


def _covers_net(ep: dict[str, Any], zone: dict[str, Any] | None, net_id: str | None) -> bool:
    """Whether the endpoint can match traffic of the given network."""
    if not net_id or not zone or net_id not in (zone.get("network_ids") or []):
        return False
    t = ep.get("matching_target")
    if t == "ANY":
        return True
    if t == "NETWORK":
        inside = net_id in (ep.get("network_ids") or [])
        return (not inside) if ep.get("match_opposite_networks") else inside
    return False


def _ports_hit(ep: dict[str, Any], wanted: set[int]) -> bool:
    if ep.get("port_matching_type") != "SPECIFIC":
        return True
    hit = False
    for part in str(ep.get("port") or "").split(","):
        m = re.fullmatch(r"(\d+)(?:-(\d+))?", part)
        if m and any(int(m.group(1)) <= w <= int(m.group(2) or m.group(1)) for w in wanted):
            hit = True
    return (not hit) if ep.get("match_opposite_ports") else hit


def make_validate(ack_exposure: bool, ack_outage: bool, console_net: str | None):
    def validate(action: str, before: dict[str, Any] | None, after: dict[str, Any], others: list[dict[str, Any]],
                 ctx: dict[str, list[dict[str, Any]]]) -> Findings:
        f = Findings()
        zones, nets, clients = ctx.get("zones", []), ctx.get("networks", []), ctx.get("clients", [])
        b = before or {}
        if before is not None:
            if not _is_custom(before):
                f.errors.append("This is a system-defined (or generated \"(Return)\") policy. Only custom policies can be changed here; "
                                "edit the custom policy it belongs to instead.")
                return f
        if action == "move":
            return f
        src, dst = after.get("source") or {}, after.get("destination") or {}
        zname = lambda ep: str((next((z for z in zones if z.get("_id") == ep.get("zone_id")), {})).get("name") or "")  # noqa: E731

        if action != "delete":
            if not str(after.get("name") or "").strip():
                f.errors.append("name is required.")
            if after.get("action") not in ACTIONS_ALLOWED:
                f.errors.append(f"policy_action must be one of: {', '.join(ACTIONS_ALLOWED)}.")
            if after.get("ip_version") not in IP_VERSIONS:
                f.errors.append(f"ip_version must be one of: {', '.join(IP_VERSIONS)}.")
            proto = after.get("protocol")
            if proto not in PROTOCOLS and not (before and before.get("protocol") == proto):
                f.errors.append(f"protocol must be one of: {', '.join(PROTOCOLS)}.")
            for side, ep in (("source", src), ("destination", dst)):
                zone = next((z for z in zones if z.get("_id") == ep.get("zone_id")), None)
                if not zone:
                    f.errors.append(f"{side}: the zone is not on this console.")
                    continue
                if ep.get("port_matching_type") == "SPECIFIC":
                    if proto not in PORT_PROTOCOLS:
                        f.errors.append(f"{side}.ports only works with protocol tcp, udp or tcp_udp (this policy uses '{proto}').")
                    problem = _port_problem(str(ep.get("port") or ""))
                    if problem:
                        f.errors.append(f"{side}.ports: {problem}.")
                t = ep.get("matching_target")
                if t == "NETWORK":
                    for nid in ep.get("network_ids") or []:
                        if nid not in (zone.get("network_ids") or []):
                            n = _net_of(nets, nid)
                            f.errors.append(f"{side}: network '{(n or {}).get('name') or nid}' is not in the {zone.get('name')} zone.")
                elif t == "CLIENT":
                    known = {str(c.get("mac") or "").lower() for c in clients}
                    for mac in ep.get("client_macs") or []:
                        if not _MAC.match(str(mac)):
                            f.errors.append(f"{side}: '{mac}' is not a MAC address.")
                        elif clients and mac not in known:
                            f.warnings.append(f"{side}: {mac} is not a client this console knows (it may be a typo).")
                elif t == "IP":
                    for ip in ep.get("ips") or []:
                        problem = _ip_problem(str(ip))
                        if problem:
                            f.errors.append(f"{side}: {problem}.")
                            continue
                        v6 = ":" in str(ip)
                        if (v6 and after.get("ip_version") == "IPV4") or (not v6 and after.get("ip_version") == "IPV6"):
                            f.errors.append(f"{side}: {ip} does not match ip_version {after.get('ip_version')}.")
                elif t == "IID" and before is None:
                    f.errors.append(f"{side}: IPv6 interface-id targets cannot be created here.")
            if after.get("connection_state_type") == "CUSTOM":
                f.warnings.append("This policy matches custom connection states; they are kept as they are.")
            same_pair = [o for o in others if _is_custom(o) and (o.get("source") or {}).get("zone_id") == src.get("zone_id")
                         and (o.get("destination") or {}).get("zone_id") == dst.get("zone_id")]
            if any(str(o.get("name")) == str(after.get("name")) for o in same_pair):
                f.warnings.append(f"Another custom policy in {zname(src)} → {zname(dst)} already has the name '{after.get('name')}'.")

        # What it would match, in words, for review.
        shown = after if action != "delete" else b
        s_ep, d_ep = shown.get("source") or {}, shown.get("destination") or {}
        f.warnings.append(f"{shown.get('action')} {shown.get('protocol')} ({shown.get('ip_version')}): from {_endpoint_text(s_ep, zones, nets)}  →  "
                          f"to {_endpoint_text(d_ep, zones, nets)}. Policy {'is' if shown.get('enabled') else 'is not'} enabled.")
        if b:
            hits = b.get("hits")
            if hits:
                f.warnings.append(f"This policy has {hits} recorded hit(s); last hit {b.get('last_hit')}.")
            elif action in ("enable", "disable", "delete", "update"):
                f.warnings.append("This policy has no recorded hits.")
            if action in ("update", "delete", "create") or shown.get("create_allow_respond"):
                f.warnings.append("The console also regenerates or removes the generated \"(Return)\" policy for this one.")
        if action == "delete" and b.get("enabled") and b.get("action") == "ALLOW":
            f.warnings.append("Traffic this ALLOW policy permitted will fall through to the policies below it in the same zone pair.")
        if action == "create":
            f.warnings.append("A new policy is created " + ("ENABLED because enabled=true was passed." if after.get("enabled")
                                                          else "switched off. Enable it as a separate, previewed step."))
        if action == "delete":
            return f

        enabled = bool(after.get("enabled"))
        src_zone = zname(src).lower()
        dst_zone = zname(dst).lower()
        # --- exposure: ALLOW from External that matches everything
        if after.get("action") == "ALLOW" and src_zone == "external":
            wide = dst.get("matching_target") == "ANY" and dst.get("port_matching_type") != "SPECIFIC"
            if wide and enabled and not ack_exposure:
                f.errors.append("Exposure stop: this enabled ALLOW lets anything from the internet reach every address and port in the "
                                f"{zname(dst)} zone. Narrow it, or pass acknowledge_exposure=true if that is really intended.")
            elif wide and not enabled:
                f.warnings.append("When enabled this ALLOW from External would expose every address and port in the destination zone.")
            else:
                f.warnings.append("This ALLOW accepts traffic from External (the internet). Check the destination and ports.")
        # --- outage: BLOCK/REJECT that cuts the console's network off from the gateway services or the internet
        if enabled and after.get("action") in ("BLOCK", "REJECT"):
            s_zone = next((z for z in zones if z.get("_id") == src.get("zone_id")), None)
            reach_console = _covers_net(src, s_zone, console_net)
            cut = None
            if dst_zone == "gateway" and reach_console and _ports_hit(dst, {53, 67, 68}) and after.get("protocol") in ("all", "udp", "tcp_udp", "tcp"):
                cut = "DNS or DHCP to the gateway"
            elif dst_zone == "external" and reach_console and dst.get("matching_target") == "ANY" and dst.get("port_matching_type") != "SPECIFIC":
                cut = "internet access"
            if cut and not ack_outage:
                f.errors.append(f"Outage stop: this enabled {after.get('action')} would cut {cut} for the console's own network "
                                "(and so probably this tool's connection). Narrow it, or pass acknowledge_outage=true if that is intended.")
            elif cut:
                f.warnings.append(f"Acknowledged: this policy cuts {cut} for the console's own network.")
            if not cut:
                f.warnings.append("The safety net only tests DNS from the console's own network; check the networks named above for this policy.")
        return f
    return validate


# ----------------------------------------------------------------------------------------------- move
def _group(rows: list[dict[str, Any]], src: str, dst: str) -> list[dict[str, Any]]:
    g = [r for r in rows if _is_custom(r) and (r.get("source") or {}).get("zone_id") == src
         and (r.get("destination") or {}).get("zone_id") == dst]
    return sorted(g, key=lambda r: int(r.get("index") or 0))


def _reorder_body(order: list[str], src: str, dst: str) -> dict[str, Any]:
    return {"before_predefined_ids": order, "after_predefined_ids": [], "source_zone_id": src, "destination_zone_id": dst}


def move(before: dict[str, Any], rows: list[dict[str, Any]], changes: dict[str, Any]) -> MovePlan:
    if not _is_custom(before):
        raise UniFiError("This is a system-defined policy and cannot be moved.")
    bad = set(changes) - {"position", "relative_to"}
    if bad:
        raise UniFiError(f"move takes position and relative_to only (got {', '.join(sorted(bad))}).")
    src, dst = before["source"]["zone_id"], before["destination"]["zone_id"]
    group = _group(rows, src, dst)
    if any(int(r.get("index") or 0) >= PREDEFINED_START for r in group):
        raise UniFiError("This zone pair has custom policies below the system policies; reordering those is not supported here. "
                         "Nothing was changed.")
    pos = str(changes.get("position") or "").lower()
    ids = [str(r["_id"]) for r in group]
    me = str(before["_id"])
    rest = [i for i in ids if i != me]
    if pos == "first":
        new = [me] + rest
    elif pos == "last":
        new = rest + [me]
    elif pos in ("before", "after"):
        ref = str(changes.get("relative_to") or "")
        if not ref:
            raise UniFiError("position before/after needs relative_to (the other policy's id or exact name).")
        match = [r for r in group if str(r["_id"]) == ref] or [r for r in group if r.get("name") == ref]
        if len(match) != 1 or str(match[0]["_id"]) == me:
            raise UniFiError(f"relative_to '{ref}' must be one other custom policy in the same zone pair "
                             f"({len(group) - 1} others): {', '.join(str(r.get('name')) for r in group if str(r['_id']) != me) or 'none'}.")
        at = rest.index(str(match[0]["_id"])) + (1 if pos == "after" else 0)
        new = rest[:at] + [me] + rest[at:]
    else:
        raise UniFiError("position must be first, last, before or after.")
    slots = [int(r.get("index") or 0) for r in group]
    after = {**before, "index": slots[new.index(me)]}
    effective = {} if new == ids else {"order": {"from": [str(r.get("name")) for r in group],
                                                  "to": [next(str(r.get("name")) for r in group if str(r["_id"]) == i) for i in new]}}
    undo = _reorder_body(ids, src, dst)
    return MovePlan("reorderFirewallPolicies", _reorder_body(new, src, dst), after, effective, undo)


def verify(plan: Plan, rows: list[dict[str, Any]], stored: dict[str, Any] | None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if plan.action == "move":
        want = (plan.body or {}).get("before_predefined_ids") or []
        b = plan.before or {}
        got = [str(r["_id"]) for r in _group(rows, b["source"]["zone_id"], b["destination"]["zone_id"])]
        if got != want:
            out.append({"field": "order", "requested": want, "stored": got})
    return out


# ----------------------------------------------------------------------------------------------- restore and rollback
def _recreate_body(before: dict[str, Any]) -> dict[str, Any]:
    drop = NO_SEND | {"_id", "index", "predefined", "origin_type", "origin_id", "site_id"}
    return {k: v for k, v in before.items() if k not in drop}


def restore(plan: Plan, new_id: str | None) -> list[RestoreStep]:
    b = plan.before or {}
    if plan.action == "create":
        return [RestoreStep("batchDeleteFirewallPolicies", [new_id])]
    if plan.action == "delete":
        return [RestoreStep("createControllerFirewallPolicy", _recreate_body(b))]
    if plan.action == "update":
        return [RestoreStep("updateControllerFirewallPolicy", {k: v for k, v in b.items() if k not in NO_SEND}, {"id": plan.ident})]
    if plan.action in ("enable", "disable"):
        return [RestoreStep("batchUpdateFirewallPolicies", [{"_id": plan.ident, "enabled": bool(b.get("enabled"))}])]
    return [RestoreStep("reorderFirewallPolicies", plan.undo)]


def restore_ok(plan: Plan, rows: list[dict[str, Any]], new_id: str | None) -> bool:
    b = plan.before or {}
    by_id = {str(r.get("_id")): r for r in rows}
    if plan.action == "create":
        return new_id is None or new_id not in by_id
    if plan.action == "delete":
        return any(r.get("name") == b.get("name") and _is_custom(r) and (r.get("source") or {}).get("zone_id") == b["source"]["zone_id"]
                   and (r.get("destination") or {}).get("zone_id") == b["destination"]["zone_id"] for r in rows)
    cur = by_id.get(str(plan.ident))
    if cur is None:
        return False
    if plan.action in ("enable", "disable"):
        return bool(cur.get("enabled")) == bool(b.get("enabled"))
    if plan.action == "move":
        want = (plan.undo or {}).get("before_predefined_ids") or []
        return [str(r["_id"]) for r in _group(rows, b["source"]["zone_id"], b["destination"]["zone_id"])] == want
    keep = {k: v for k, v in b.items() if k not in IGNORE}
    return all(same(cur.get(k), v) for k, v in keep.items())


def to_friendly(row: dict[str, Any]) -> dict[str, Any]:
    def ep(e: dict[str, Any]) -> dict[str, Any]:
        t = {"ANY": "any", "NETWORK": "networks", "CLIENT": "clients", "IP": "ips"}.get(str(e.get("matching_target")))
        out: dict[str, Any] = {"zone": e.get("zone_id")}
        if t:
            out["target"] = t
        if t == "networks":
            out.update(networks=list(e.get("network_ids") or []), opposite=bool(e.get("match_opposite_networks")))
        elif t == "clients":
            out["client_macs"] = list(e.get("client_macs") or [])
        elif t == "ips":
            out.update(ips=list(e.get("ips") or []), opposite=bool(e.get("match_opposite_ips")))
        out["ports"] = e.get("port") if e.get("port_matching_type") == "SPECIFIC" else "any"
        out["opposite_ports"] = bool(e.get("match_opposite_ports"))
        return out
    out = {"name": row.get("name"), "description": row.get("description", ""), "policy_action": row.get("action"),
           "enabled": bool(row.get("enabled")), "ip_version": row.get("ip_version"), "protocol": row.get("protocol"),
           "allow_return": bool(row.get("create_allow_respond")), "logging": bool(row.get("logging")),
           "report_flow": bool(row.get("report_flow")), "source": ep(row.get("source") or {}), "destination": ep(row.get("destination") or {})}
    if row.get("connection_state_type") in ("ALL", "RESPOND_ONLY"):
        out["connection_state"] = "all" if row["connection_state_type"] == "ALL" else "return_only"
    return out


def rollback(plan: Plan, new_id: str | None) -> dict[str, Any]:
    b = plan.before or {}
    call = lambda **kw: {"tool": TOOL, "arguments": kw}  # noqa: E731
    if plan.action == "create":
        return call(action="delete", target=new_id)
    if plan.action == "delete":
        out = call(action="create", **to_friendly(b))
        out["note"] = ("Recreated with a new id at the end of its zone pair; use move to put it back. "
                       "Policies are created switched off unless enabled=true is in the call (it is, if the original was on).")
        return out
    if plan.action in ("enable", "disable"):
        return call(action="disable" if plan.action == "enable" else "enable", target=plan.ident)
    if plan.action == "move":
        ids = (plan.undo or {}).get("before_predefined_ids") or []
        me = str(plan.ident)
        i = ids.index(me) if me in ids else 0
        return call(action="move", target=me, **({"position": "first"} if i == 0 else {"position": "after", "relative_to": ids[i - 1]}))
    full = to_friendly(b)
    full.pop("enabled", None)
    return call(action="update", target=plan.ident, **full)


# ----------------------------------------------------------------------------------------------- spec
def _batch_enable_body(before, after, effective):
    return [{"_id": (before or {}).get("_id"), "enabled": bool((after or {}).get("enabled"))}]


def _batch_delete_body(before, after, effective):
    return [(before or {}).get("_id")]


def guard_when(plan: Plan) -> bool:
    b, a = plan.before or {}, plan.after or {}
    return bool(b.get("enabled") or a.get("enabled"))


SPEC = EntitySpec(
    key=KEY, label="firewall policy", tier="C", list_op="listFirewallPoliciesWithHits",
    create_op="createControllerFirewallPolicy", update_op="updateControllerFirewallPolicy", delete_op="batchDeleteFirewallPolicies",
    whole_object=True, ignore=IGNORE, body_drop=NO_SEND, prepare_ctx=prepare_ctx,
    context_ops=(("zones", "listFirewallZones"), ("networks", "listNetworkConfig"), ("clients", "listKnownClients")),
    action_ops={"enable": ActionOp("batchUpdateFirewallPolicies", _batch_enable_body, with_id=False),
                "disable": ActionOp("batchUpdateFirewallPolicies", _batch_enable_body, with_id=False),
                "delete": ActionOp("batchDeleteFirewallPolicies", _batch_delete_body, with_id=False)},
    move=move, loose_verify=True, verify=verify, guard=make_guard(GUARD_TEXT), guard_when=guard_when,
    restore=restore, restore_ok=restore_ok, rollback=rollback,
)


# ----------------------------------------------------------------------------------------------- tool
class Endpoint(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    zone: str | None = Field(default=None, description="Zone name or id, for example 'IoT'. Required on create; cannot change afterwards.")
    target: Literal["any", "networks", "clients", "ips"] | None = Field(default=None, description="What in the zone is matched. Inferred from the list you give.")
    networks: list[str] | None = Field(default=None, description="Network names or ids (they must belong to the zone).")
    client_macs: list[str] | None = Field(default=None, description="Client MAC addresses.")
    ips: list[str] | None = Field(default=None, description="IP addresses, CIDR networks or a-b ranges.")
    ports: str | None = Field(default=None, description="'53', '1400,1443' or '1000-2000'; 'any' or '' for all. Needs protocol tcp, udp or tcp_udp.")
    opposite: bool | None = Field(default=None, description="Match everything except the listed networks or ips.")
    opposite_ports: bool | None = Field(default=None, description="Match every port except those listed.")


class FirewallPolicyInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    action: Literal["create", "update", "enable", "disable", "delete", "move"] = Field(..., description="What to do.")
    target: str | None = Field(default=None, description="The policy's id or exact name (not for create).")
    name: str | None = None
    description: str | None = None
    policy_action: Literal["ALLOW", "BLOCK", "REJECT"] | None = Field(default=None, description="What the policy does with matching traffic.")
    enabled: bool | None = Field(default=None, description="On create only: true creates it switched on. Default false. Use enable/disable afterwards.")
    ip_version: Literal["BOTH", "IPV4", "IPV6"] | None = None
    protocol: Literal["all", "tcp", "udp", "tcp_udp", "icmp", "icmpv6"] | None = None
    connection_state: Literal["all", "return_only"] | None = None
    allow_return: bool | None = Field(default=None, description="Also allow the return traffic automatically (create_allow_respond).")
    logging: bool | None = None
    report_flow: bool | None = None
    source: Endpoint | None = None
    destination: Endpoint | None = None
    position: Literal["first", "last", "before", "after"] | None = Field(default=None, description="For move.")
    relative_to: str | None = Field(default=None, description="For move before/after: the other policy's id or exact name.")
    acknowledge_exposure: bool = Field(default=False, description="Accept an enabled ALLOW from External that matches everything.")
    acknowledge_outage: bool = Field(default=False, description="Accept an enabled BLOCK/REJECT that cuts the console's own network.")
    approval_note: str | None = Field(default=None, description="Required with confirm=true: where the approval for this tier C change was given.")
    confirm: bool = Field(default=False, description="false (default) returns a read-only preview. true applies and needs fingerprint.")
    fingerprint: str | None = Field(default=None, description="From the preview of exactly this change; required with confirm=true.")

    def changes(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k in FRIENDLY:
            v = getattr(self, k)
            if v is None:
                continue
            out[k] = v.model_dump(exclude_none=True) if isinstance(v, Endpoint) else v
        if self.action == "move":
            return {k: v for k, v in (("position", self.position), ("relative_to", self.relative_to)) if v is not None}
        if self.action in ("enable", "disable", "delete"):
            return {}
        if self.action == "update":
            out.pop("enabled", None)
        return out


async def _console_network(engine: WriteEngine) -> str | None:
    try:
        host_ip = ipaddress.ip_address(socket.gethostbyname(engine.api.settings.host))
        for net in await engine._read_list("listNetworkConfig"):
            if net.get("ip_subnet") and net.get("purpose") != "wan" and host_ip in ipaddress.ip_interface(net["ip_subnet"]).network:
                return str(net.get("_id"))
    except (OSError, ValueError, UniFiError):
        return None
    return None


def register(mcp: MCPServer, engine: WriteEngine) -> None:
    @mcp.tool(
        name=TOOL,
        annotations={"title": "Change a firewall policy", "readOnlyHint": False, "destructiveHint": True,
                     "idempotentHint": False, "openWorldHint": False},
    )
    async def unifi_console_firewall_policy(params: FirewallPolicyInput) -> str:
        """Preview, then apply, a change to one custom zone-based firewall policy. Tier C: it can cut or expose the network.

        Actions: create (switched off unless enabled=true), update, enable, disable, delete, move (position first, last,
        before or after relative_to, inside the policy's own zone pair). Two steps, always: call with confirm=false for a
        read-only preview (before, after, diff, what the policy matches in words, hits, warnings, errors, a fingerprint); call
        again with the same fields plus confirm=true, that fingerprint and an approval_note to apply. System-defined
        policies and the generated "(Return)" copies are never changed. An enabled ALLOW from External that matches everything,
        or an enabled BLOCK/REJECT that cuts DNS/DHCP/internet for the console's own network, is refused unless
        acknowledge_exposure / acknowledge_outage is passed. A change touching an enabled policy is wrapped in a DNS test
        before and after; if it fails afterwards the previous state is put back automatically, once. Applying also needs
        UNIFI_CONSOLE_ENABLE_WRITES=true and 'firewall_policy' in UNIFI_CONSOLE_WRITE_ENTITIES. Every write is journalled.
        """
        try:
            console_net = await _console_network(engine)
            spec = replace(SPEC, validate_ctx=make_validate(params.acknowledge_exposure, params.acknowledge_outage, console_net))
            result = await engine.execute(
                spec, action=params.action, target=params.target, changes=params.changes(),
                confirm=params.confirm, fingerprint=params.fingerprint, approval_note=params.approval_note,
            )
            return json.dumps(result, separators=(",", ":"), default=str)
        except Exception as exc:  # noqa: BLE001 - converted to an actionable message
            return error_text(exc)
