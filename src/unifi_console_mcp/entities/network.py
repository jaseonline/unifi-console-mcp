"""Networks and VLANs (legacy `rest/networkconf`). Tier C.

Captured 2026-10-18 from the UI: create is POST with a 53-key object (no `_id`, names `firewall_zone_id`), edit is PUT `/{id}` with
the whole object (60 keys), enable and disable are `PUT group/networkconf` with `{"id":[..],"data":{"enabled":..}}`, delete is
DELETE `/{id}`; replies use the legacy `{meta, data[]}` envelope.

Why tier C: a network change can cut DHCP, the VLAN and routing for everything on it, and the console itself sits on LAN_Private.
So:
  * a new network is created disabled;
  * only corporate and guest LAN/VLAN networks are handled; WAN, VPN and VLAN-only networks are refused;
  * the network that holds the console, a switch, an access point or the gateway cannot be disabled or deleted, nor have its VLAN,
    subnet or DHCP server changed, unless `acknowledge_infrastructure=true`;
  * a network used by an SSID or a switch port cannot be deleted; disabling it, or changes that make clients reconnect, are
    refused while clients are connected unless `acknowledge_disconnect=true` (the preview names the users);
  * a safety net: every adopted device that was connected must still be connected and DNS must work through the gateway after a
    change that touches an enabled network; otherwise the previous state is put back once, automatically.
Not offered (left exactly as read on edit, UI defaults on create): IPv6, DHCP relay, boot/TFTP/NTP/WINS options, NAT outbound
addresses, IP aliases, VPN and LTE settings, guest-portal settings, creating a guest-purpose network.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import socket
from dataclasses import replace
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel, ConfigDict, Field

from ..api import error_text
from ..client import UniFiError
from ..dnsprobe import make_guard as dns_guard
from ..writes import VOLATILE, ActionOp, EntitySpec, Findings, Guard, Plan, RestoreStep, WriteEngine, same
from .switch_port import make_guard as device_guard

KEY = "network"
TOOL = "unifi_console_network"
FIELDS = ("name", "vlan", "subnet", "zone", "dhcp_enabled", "dhcp_start", "dhcp_stop", "dhcp_lease_seconds", "dhcp_dns",
          "domain_name", "internet_access", "network_isolation", "igmp_snooping", "dhcp_guard", "enabled")
HANDLED = ("corporate", "guest")
DISRUPTIVE = ("vlan", "vlan_enabled", "ip_subnet", "dhcpd_enabled", "internet_access_enabled", "network_isolation_enabled",
              "firewall_zone_id")
INFRA_KEYS = ("vlan", "vlan_enabled", "ip_subnet", "dhcpd_enabled")
GUARD_TEXT = ("Safety net: every adopted device that is connected now must still be connected, and DNS must still work through the "
              "gateway, after a change that touches an enabled network; if not, the previous state is put back automatically, "
              "once, and the result says so.")

# The UI's own create body (53 keys) minus the per-network fields filled in by the tool.
DEFAULTS: dict[str, Any] = {
    "enabled": False, "nat_outbound_ip_addresses": [], "auto_scale_enabled": True, "domain_name": "", "dhcpd_boot_enabled": False,
    "dhcpd_enabled": True, "dhcpd_gateway_enabled": False, "dhcpd_conflict_checking": True, "dhcpd_ntp_enabled": False,
    "dhcpd_time_offset_enabled": False, "dhcp_relay_enabled": False, "dhcpguard_enabled": True, "dhcpd_dns_enabled": False,
    "dhcpd_leasetime": 86400, "networkgroup": "LAN", "network_isolation_enabled": False, "setting_preference": "manual",
    "internet_access_enabled": True, "igmp_snooping": False, "gateway_type": "default", "ipv6_interface_type": "pd",
    "lte_lan_enabled": True, "ip_aliases": [], "ipv6_aliases": [], "dhcp_relay_servers": [], "purpose": "corporate",
    "ipv6_client_address_assignment": "slaac", "dhcpdv6_dns_auto": True, "ipv6_ra_enabled": True, "ipv6_ra_priority": "high",
    "ipv6_setting_preference": "auto", "dhcpdv6_allow_slaac": True, "ipv6_pd_interface": "wan", "ipv6_pd_auto_prefixid_enabled": True,
    "ipv6_pd_start": "::2", "ipv6_pd_stop": "::7d1", "dhcpd_wins_enabled": False, "dhcpd_wins_1": "", "dhcpd_wins_2": "",
    "dhcpd_wpad_url": "", "dhcpd_tftp_server": "", "dhcpd_unifi_controller": "", "dhcpd_ip_2": "", "dhcpd_ip_3": "",
    "vlan_enabled": True, "ipv6_pd_prefixid": "",
}
PER_NETWORK = ("name", "firewall_zone_id", "ip_subnet", "dhcpd_start", "dhcpd_stop", "dhcpd_ip_1", "vlan")
CREATE_KEYS = frozenset(DEFAULTS) | frozenset(PER_NETWORK)
CORE = frozenset({"enabled", "name", "vlan", "vlan_enabled", "ip_subnet", "firewall_zone_id", "purpose", "dhcpd_enabled", "dhcpd_start",
                  "dhcpd_stop", "dhcpd_leasetime", "dhcpd_dns_enabled", "dhcpd_dns_1", "dhcpd_dns_2", "dhcpd_dns_3", "dhcpd_dns_4", "dhcpd_ip_1", "dhcpd_ip_2", "dhcpd_ip_3",
                  "domain_name",
                  "internet_access_enabled", "network_isolation_enabled", "igmp_snooping", "dhcpguard_enabled"})
NO_SEND = VOLATILE | {"attr_no_delete"}


# ----------------------------------------------------------------------------------------------- helpers
def _iface(text: str) -> ipaddress.IPv4Interface | None:
    try:
        return ipaddress.IPv4Interface(str(text))
    except ValueError:
        return None


def _ip(text: Any) -> ipaddress.IPv4Address | None:
    try:
        return ipaddress.IPv4Address(str(text))
    except ValueError:
        return None


def _zone(zones: list[dict[str, Any]], ref: str) -> dict[str, Any] | None:
    low = ref.strip().lower()
    for z in zones:
        if str(z.get("_id")) == ref or str(z.get("name") or "").lower() == low:
            return z
    return None


def _default_range(iface: ipaddress.IPv4Interface) -> tuple[str, str] | None:
    net = iface.network
    if net.prefixlen > 26:
        return None
    return str(net.network_address + 6), str(net.broadcast_address - 1)


def prepare_ctx(action: str, before: dict[str, Any] | None, changes: dict[str, Any], ctx: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    bad = set(changes) - set(FIELDS)
    if bad:
        raise UniFiError(f"Unknown field(s): {', '.join(sorted(bad))}. Use: {', '.join(FIELDS)}.")
    if "enabled" in changes and action != "create":
        raise UniFiError("Use the enable or disable action to change whether an existing network is on.")
    if before is not None and before.get("purpose") not in HANDLED:
        hint = "Use unifi_console_wan for WAN settings." if before.get("purpose") == "wan" else "Use the UI for anything else."
        raise UniFiError(f"'{before.get('name')}' is a {before.get('purpose')} network. This tool only handles corporate and guest "
                         f"LAN/VLAN networks. {hint}")
    out: dict[str, Any] = {}
    if "name" in changes:
        out["name"] = str(changes["name"]).strip()
    if "vlan" in changes:
        out["vlan"], out["vlan_enabled"] = int(changes["vlan"]), True
    if "subnet" in changes:
        out["ip_subnet"] = str(changes["subnet"]).strip()
    if "zone" in changes:
        z = _zone(ctx.get("zones", []), str(changes["zone"]))
        if not z:
            raise UniFiError(f"zone '{changes['zone']}' is not a firewall zone on this console (names are matched ignoring case).")
        out["firewall_zone_id"] = str(z["_id"])
    for k_in, k_out in (("dhcp_enabled", "dhcpd_enabled"), ("dhcp_start", "dhcpd_start"), ("dhcp_stop", "dhcpd_stop"),
                        ("dhcp_lease_seconds", "dhcpd_leasetime"), ("domain_name", "domain_name"),
                        ("internet_access", "internet_access_enabled"), ("network_isolation", "network_isolation_enabled"),
                        ("igmp_snooping", "igmp_snooping"), ("dhcp_guard", "dhcpguard_enabled"), ("enabled", "enabled")):
        if k_in in changes:
            out[k_out] = changes[k_in]
    if "dhcp_dns" in changes:
        servers = [str(x).strip() for x in changes["dhcp_dns"]]
        if len(servers) > 4:
            raise UniFiError("dhcp_dns takes at most four servers.")
        out["dhcpd_dns_enabled"] = bool(servers)
        if servers:
            for i in range(4):
                out[f"dhcpd_dns_{i + 1}"] = servers[i] if i < len(servers) else ""
    if action == "create":
        for need in ("name", "vlan", "subnet", "zone"):
            if need not in changes:
                raise UniFiError(f"create needs {need}.")
        iface = _iface(out["ip_subnet"])
        if iface is None:
            raise UniFiError("subnet must be the gateway address with its prefix, for example 10.99.1.1/24.")
        rng = _default_range(iface)
        if ("dhcpd_start" not in out or "dhcpd_stop" not in out) and rng is None:
            raise UniFiError("For a subnet smaller than /26 give dhcp_start and dhcp_stop.")
        if rng:
            out.setdefault("dhcpd_start", rng[0])
            out.setdefault("dhcpd_stop", rng[1])
        out.setdefault("dhcpd_ip_1", str(iface.ip))
    elif not out:
        raise UniFiError("Nothing to change.")
    elif "ip_subnet" in out and before is not None:
        old, new = _iface(before.get("ip_subnet", "")), _iface(out["ip_subnet"])
        if old and new and str(before.get("dhcpd_ip_1")) == str(old.ip):
            out.setdefault("dhcpd_ip_1", str(new.ip))
    return out


def _users(b: dict[str, Any], ctx: dict[str, list[dict[str, Any]]]) -> tuple[list[str], list[str]]:
    ident = b.get("_id")
    wlans = [str(w.get("name")) for w in ctx.get("wlans", []) if w.get("networkconf_id") == ident]
    ports: list[str] = []
    for d in ctx.get("devices", []):
        for e in d.get("port_overrides") or []:
            if ident in (e.get("native_networkconf_id"), e.get("voice_networkconf_id")):
                ports.append(f"{d.get('name') or d.get('mac')} port {e.get('port_idx')}")
    return wlans, ports


def _clients_on(b: dict[str, Any], ctx: dict[str, list[dict[str, Any]]]) -> list[str]:
    iface = _iface(b.get("ip_subnet", ""))
    if iface is None:
        return []
    out = []
    for c in ctx.get("clients", []):
        ip = _ip(c.get("ip"))
        if ip is not None and ip in iface.network:
            out.append(str(c.get("name") or c.get("hostname") or c.get("mac")))
    return out


def infrastructure_ids(ctx: dict[str, list[dict[str, Any]]], console_ip: str | None) -> set[str]:
    ips = [i for i in [console_ip] if i]
    for d in ctx.get("devices", []):
        ip = (d.get("config_network") or {}).get("ip") or d.get("ip")
        if ip and d.get("adopted", True):
            ips.append(str(ip))
    out: set[str] = set()
    for n in ctx.get("networks", []):
        iface = _iface(n.get("ip_subnet", ""))
        if iface and any((_ip(i) in iface.network) for i in ips if _ip(i) is not None):
            out.add(str(n.get("_id")))
    return out


def _brief(items: list[str], n: int = 6) -> str:
    return ", ".join(items[:n]) + (f" and {len(items) - n} more" if len(items) > n else "")


def make_validate(ack_disconnect: bool, ack_infra: bool, console_ip: str | None, snap: dict[str, Any] | None = None):
    def validate(action: str, before: dict[str, Any] | None, after: dict[str, Any], others: list[dict[str, Any]],
                 ctx: dict[str, list[dict[str, Any]]]) -> Findings:
        f = Findings()
        b = before or {}
        if snap is not None:
            snap["others"] = copy.deepcopy(others)
        if b and b.get("purpose") not in HANDLED:
            f.errors.append(f"This is a {b.get('purpose')} network; only corporate and guest networks are handled here."
                            + (" Use unifi_console_wan." if b.get("purpose") == "wan" else ""))
            return f
        infra = bool(b) and str(b.get("_id")) in infrastructure_ids(ctx, console_ip)
        wlans, ports = _users(b, ctx) if b else ([], [])
        clients = _clients_on(b, ctx) if b else []
        name = str(b.get("name") if action == "delete" else after.get("name") or "")
        if action == "delete" or (action == "disable"):
            verb = "Deleting" if action == "delete" else "Disabling"
            if infra:
                f.warnings.append(f"'{name}' holds the console, a switch, an access point or the gateway; {verb.lower()} it can cut the "
                                  "session doing this and strand every device on it.")
                if not ack_infra:
                    f.errors.append("Infrastructure stop: repeat with acknowledge_infrastructure=true only if that is intended.")
            if action == "delete" and (wlans or ports):
                f.errors.append("In use: " + "; ".join(x for x in (f"SSIDs {_brief(wlans)}" if wlans else "", f"switch ports {_brief(ports)}" if ports else "") if x)
                                + ". Move them to another network first.")
            elif wlans or ports:
                f.warnings.append("Used by " + "; ".join(x for x in (f"SSIDs {_brief(wlans)}" if wlans else "", f"switch ports {_brief(ports)}" if ports else "") if x) + ".")
            if clients:
                f.warnings.append(f"{len(clients)} client(s) are on it now: {_brief(clients)}.")
            if (clients or wlans or ports) and action == "disable" and not ack_disconnect:
                f.errors.append("Disconnect stop: repeat with acknowledge_disconnect=true to disable it anyway.")
            if action == "delete" and clients and not ack_disconnect:
                f.errors.append("Disconnect stop: clients are on it now. Repeat with acknowledge_disconnect=true to delete it anyway.")
            if action == "delete":
                f.warnings.append("A rollback recreates the network with a new id; references to the old id are not restored.")
            return f

        # ---- create / update / enable
        if not name or len(name) > 64:
            f.errors.append("name must be 1 to 64 characters.")
        if any(str(o.get("name") or "").lower() == name.lower() for o in others):
            f.errors.append(f"Another network is already called '{name}'.")
        vlan = after.get("vlan")
        if not after.get("vlan_enabled") and vlan is None:
            pass                                    # the untagged (default) network
        elif not isinstance(vlan, int) or isinstance(vlan, bool) or not 1 <= vlan <= 4094:
            f.errors.append("vlan must be a whole number from 1 to 4094.")
        elif any(o.get("vlan") == vlan and o.get("vlan_enabled") for o in others):
            f.errors.append(f"VLAN {vlan} is already used by another network.")
        iface = _iface(after.get("ip_subnet", ""))
        if iface is None or iface.version != 4:
            f.errors.append("subnet must be the gateway address with its prefix, for example 10.99.1.1/24.")
        else:
            net = iface.network
            if not net.is_private or net.is_loopback or net.is_link_local:
                f.errors.append("subnet must be a private (RFC 1918) range.")
            if not 16 <= net.prefixlen <= 30:
                f.errors.append("The prefix length must be 16 to 30.")
            if iface.ip in (net.network_address, net.broadcast_address):
                f.errors.append("The gateway address must be a host address inside the subnet, not the network or broadcast address.")
            for o in others:
                oi = _iface(o.get("ip_subnet", "")) if o.get("purpose") in HANDLED else None
                if oi and oi.network.overlaps(net):
                    f.errors.append(f"The subnet overlaps '{o.get('name')}' ({oi.network}).")
            if after.get("dhcpd_enabled"):
                lo, hi = _ip(after.get("dhcpd_start")), _ip(after.get("dhcpd_stop"))
                if lo is None or hi is None:
                    f.errors.append("dhcp_start and dhcp_stop must be IPv4 addresses.")
                elif lo not in net or hi not in net:
                    f.errors.append(f"The DHCP range {lo} to {hi} is not inside {net}. Give dhcp_start and dhcp_stop for the new subnet.")
                elif int(lo) > int(hi):
                    f.errors.append("dhcp_start must not be after dhcp_stop.")
                elif int(lo) <= int(iface.ip) <= int(hi):
                    f.errors.append("The DHCP range must not include the gateway address.")
            if not same(b.get("ip_subnet"), after.get("ip_subnet")) and b:
                old = _iface(b.get("ip_subnet", ""))
                moved = []
                for c in ctx.get("known", []):
                    if c.get("use_fixedip") and old and _ip(c.get("fixed_ip")) is not None and _ip(c.get("fixed_ip")) in old.network:
                        moved.append(str(c.get("name") or c.get("mac")))
                dns = [str(r.get("key") or r.get("value")) for r in ctx.get("dns", [])
                       if old and r.get("record_type") == "A" and _ip(r.get("value")) is not None and _ip(r.get("value")) in old.network]
                fwd = [str(r.get("name")) for r in ctx.get("forwards", []) if old and _ip(r.get("fwd")) is not None and _ip(r.get("fwd")) in old.network]
                for what, items in (("fixed IPs", moved), ("static DNS records", dns), ("port forwards", fwd)):
                    if items:
                        f.warnings.append(f"{len(items)} {what} point into the old range and are NOT rewritten: {_brief(items)}.")
        z = next((z for z in ctx.get("zones", []) if z.get("_id") == after.get("firewall_zone_id")), None)
        if z is None:
            f.errors.append("The firewall zone was not found.")
        elif str(z.get("zone_key") or z.get("name")).lower() == "external":
            f.errors.append("A LAN network cannot be placed in the External zone.")
        lease = after.get("dhcpd_leasetime")
        if not isinstance(lease, int) or isinstance(lease, bool) or not 60 <= lease <= 31536000:
            f.errors.append("dhcp_lease_seconds must be 60 to 31,536,000.")
        for i in (1, 2, 3, 4):
            v = after.get(f"dhcpd_dns_{i}")
            if after.get("dhcpd_dns_enabled") and v and _ip(v) is None:
                f.errors.append(f"DHCP DNS server {v!r} is not an IPv4 address.")

        if action == "create":
            f.warnings.append("The network is created disabled." if not after.get("enabled") else
                              "Enabled on creation: the gateway adds the VLAN interface and DHCP server as soon as this is applied.")
            return f
        keys = [k for k in DISRUPTIVE if not same(b.get(k), after.get(k))]
        if action == "enable" or (not b.get("enabled") and not after.get("enabled")):
            keys = []
        if keys:
            f.warnings.append(f"This change makes clients on '{name}' renew their addresses or reconnect ({', '.join(keys)}).")
            if clients:
                f.warnings.append(f"{len(clients)} client(s) are on it now: {_brief(clients)}.")
                if not ack_disconnect:
                    f.errors.append("Disconnect stop: this change disturbs clients that are connected now. Repeat with acknowledge_disconnect=true to apply it.")
        if infra and any(not same(b.get(k), after.get(k)) for k in INFRA_KEYS):
            f.warnings.append(f"'{name}' holds the console, a switch, an access point or the gateway; this can cut the session doing the change.")
            if not ack_infra:
                f.errors.append("Infrastructure stop: VLAN, subnet and DHCP server changes need acknowledge_infrastructure=true.")
        if wlans or ports:
            f.warnings.append("Used by " + "; ".join(x for x in (f"SSIDs {_brief(wlans)}" if wlans else "", f"switch ports {_brief(ports)}" if ports else "") if x) + ".")
        return f
    return validate


def make_verify(snap: dict[str, Any]):
    def verify(plan: Plan, rows: list[dict[str, Any]], stored: dict[str, Any] | None) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        now = {str(r.get("_id")): r for r in rows}
        for old in snap.get("others", []):
            cur = now.get(str(old.get("_id")))
            if cur is None:
                out.append({"field": f"(other network {old.get('name')})", "requested": "unchanged", "stored": "missing on read-back"})
                continue
            changed = sorted(k for k in set(old) | set(cur) if k not in VOLATILE and not same(old.get(k), cur.get(k)))
            if changed:
                out.append({"field": f"(other network {old.get('name')})", "requested": "unchanged", "stored": f"changed: {', '.join(changed)}"})
        return out
    return verify


# ----------------------------------------------------------------------------------------------- restore and rollback
def _recreate_body(before: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in before.items() if k in CREATE_KEYS}


def restore(plan: Plan, new_id: str | None) -> list[RestoreStep]:
    b = plan.before or {}
    if plan.action == "create":
        return [RestoreStep("deleteNetworkConfig", None, {"id": new_id})]
    if plan.action == "delete":
        return [RestoreStep("createNetworkConfig", _recreate_body(b))]
    if plan.action == "update":
        return [RestoreStep("updateNetworkConfig", {k: v for k, v in b.items() if k not in NO_SEND}, {"id": plan.ident})]
    return [RestoreStep("updateNetworkConfigGroup", {"id": [plan.ident], "data": {"enabled": bool(b.get("enabled"))}})]


def restore_ok(plan: Plan, rows: list[dict[str, Any]], new_id: str | None) -> bool:
    b = plan.before or {}
    by_id = {str(r.get("_id")): r for r in rows}
    if plan.action == "create":
        return new_id is None or new_id not in by_id
    if plan.action == "delete":
        return any(r.get("name") == b.get("name") for r in rows)
    cur = by_id.get(str(plan.ident))
    if cur is None:
        return False
    if plan.action in ("enable", "disable"):
        return bool(cur.get("enabled")) == bool(b.get("enabled"))
    return all(same(cur.get(k), b.get(k)) for k in CORE if k in b)


def to_friendly(row: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"name": row.get("name"), "vlan": row.get("vlan"), "subnet": row.get("ip_subnet"), "zone": row.get("firewall_zone_id"),
                           "dhcp_enabled": row.get("dhcpd_enabled"), "dhcp_start": row.get("dhcpd_start"), "dhcp_stop": row.get("dhcpd_stop"),
                           "dhcp_lease_seconds": row.get("dhcpd_leasetime"), "domain_name": row.get("domain_name"),
                           "internet_access": row.get("internet_access_enabled"), "network_isolation": row.get("network_isolation_enabled"),
                           "igmp_snooping": row.get("igmp_snooping"), "dhcp_guard": row.get("dhcpguard_enabled")}
    out["dhcp_dns"] = [row[k] for k in ("dhcpd_dns_1", "dhcpd_dns_2", "dhcpd_dns_3", "dhcpd_dns_4") if row.get(k)] if row.get("dhcpd_dns_enabled") else []
    return out


def rollback(plan: Plan, new_id: str | None) -> dict[str, Any]:
    b, a = plan.before or {}, plan.after or {}
    call = lambda **kw: {"tool": TOOL, "arguments": kw}  # noqa: E731
    if plan.action == "create":
        return call(action="delete", target=new_id)
    if plan.action == "delete":
        out = call(action="create", **to_friendly(b), enabled=bool(b.get("enabled")))
        out["note"] = "Recreated with a new id; SSIDs and switch ports that used the old one must be pointed at it again."
        return out
    if plan.action in ("enable", "disable"):
        return call(action="disable" if plan.action == "enable" else "enable", target=plan.ident)
    fb, fa = to_friendly(b), to_friendly(a)
    return call(action="update", target=plan.ident, **{k: v for k, v in fb.items() if not same(v, fa.get(k))})


def _enable_body(before, after, effective):
    return {"id": [(before or {}).get("_id")], "data": {"enabled": bool((after or {}).get("enabled"))}}


def guard_when(plan: Plan) -> bool:
    return bool((plan.before or {}).get("enabled") or (plan.after or {}).get("enabled"))


def make_guard() -> Guard:
    d, n = device_guard(), dns_guard(GUARD_TEXT)

    async def before(engine: Any) -> str | None:
        return await n.before(engine) or await d.before(engine)

    async def after(engine: Any, phase: str) -> str | None:
        return await d.after(engine, phase) or await n.after(engine, phase)

    return Guard(describe=GUARD_TEXT, before=before, after=after)


SPEC = EntitySpec(
    key=KEY, label="network", tier="C", list_op="listNetworkConfig", create_op="createNetworkConfig", update_op="updateNetworkConfig",
    delete_op="deleteNetworkConfig", whole_object=True, id_field="_id", name_field="name", defaults=DEFAULTS, body_drop=NO_SEND,
    prepare_ctx=prepare_ctx,
    context_ops=(("networks", "listNetworkConfig"), ("zones", "listFirewallZones"), ("wlans", "listWlanConfigLegacy"), ("devices", "listDevicesDetailed"),
                 ("clients", "listActiveClientsLegacy"), ("known", "listKnownClients"), ("dns", "listStaticDns"),
                 ("forwards", "listPortForwards")),
    reference_ops=(("listFirewallPoliciesWithHits", "firewall policy"), ("listTrafficPolicyObjects", "traffic object")),
    action_ops={"enable": ActionOp("updateNetworkConfigGroup", _enable_body, with_id=False),
                "disable": ActionOp("updateNetworkConfigGroup", _enable_body, with_id=False)},
    ignore=VOLATILE | (frozenset(DEFAULTS) - CORE) | {"external_id", "mdns_enabled", "dpi_enabled", "dhcpdv6_enabled", "dhcpdv6_start",
                                                      "dhcpdv6_stop", "dhcpdv6_leasetime", "ipv6_ra_preferred_lifetime"},
    guard=make_guard(), guard_when=guard_when, restore=restore, restore_ok=restore_ok, rollback=rollback,
)


class NetworkInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    action: Literal["create", "update", "enable", "disable", "delete"] = Field(..., description="create (disabled unless enabled=true), update fields, enable, disable or delete a network.")
    target: str | None = Field(default=None, description="Existing network: its _id or exact name. Not used by create.")
    name: str | None = Field(default=None, description="Network name, unique.")
    vlan: int | None = Field(default=None, description="VLAN id 1 to 4094, unique.")
    subnet: str | None = Field(default=None, description="Gateway address with prefix, for example 10.99.1.1/24 (private range, /16 to /30).")
    zone: str | None = Field(default=None, description="Firewall zone name or id. Required on create.")
    dhcp_enabled: bool | None = None
    dhcp_start: str | None = Field(default=None, description="First DHCP address; on create the default is the .6 address of the subnet.")
    dhcp_stop: str | None = Field(default=None, description="Last DHCP address; on create the default is the last host address.")
    dhcp_lease_seconds: int | None = Field(default=None, description="60 to 31,536,000; the UI default is 86400.")
    dhcp_dns: list[str] | None = Field(default=None, description="Up to four DNS servers for DHCP clients (stored as dhcpd_dns_1..4); empty list = the gateway.")
    domain_name: str | None = None
    internet_access: bool | None = None
    network_isolation: bool | None = None
    igmp_snooping: bool | None = None
    dhcp_guard: bool | None = None
    enabled: bool | None = Field(default=None, description="create only; a new network is disabled unless this is true.")
    acknowledge_disconnect: bool = Field(default=False, description="Accept that clients on the network are disturbed (disable, delete, disruptive edits).")
    acknowledge_infrastructure: bool = Field(default=False, description="Accept a change to the network that holds the console, switches, APs or the gateway.")
    approval_note: str | None = Field(default=None, description="Required with confirm=true: where the approval for this tier C change was given.")
    confirm: bool = Field(default=False, description="false (default) returns a read-only preview. true applies and needs fingerprint.")
    fingerprint: str | None = Field(default=None, description="From the preview of exactly this change; required with confirm=true.")

    def changes(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in FIELDS if getattr(self, k) is not None}


def register(mcp: MCPServer, engine: WriteEngine) -> None:
    @mcp.tool(
        name=TOOL,
        annotations={"title": "Create, change or delete a network / VLAN", "readOnlyHint": False, "destructiveHint": True,
                     "idempotentHint": False, "openWorldHint": False},
    )
    async def unifi_console_network(params: NetworkInput) -> str:
        """Preview, then apply, a change to a LAN/VLAN network. Tier C: a wrong change can cut DHCP, the VLAN and routing for a whole segment.

        Two steps, always: confirm=false returns a read-only preview (before, after, diff, what uses the network, the clients on
        it, warnings, errors, a fingerprint); then call again with the same fields plus confirm=true, that fingerprint and an
        approval_note. A new network is created disabled. The network that holds the console, a switch, an access point or the
        gateway needs acknowledge_infrastructure=true for disabling, deleting, or changing its VLAN, subnet or DHCP server;
        a network used by an SSID or switch port cannot be deleted; disabling it or disruptive edits with clients connected need
        acknowledge_disconnect=true. After a change that touches an enabled network every connected device must still be
        connected and DNS must still work, otherwise the previous state is restored once. WAN, VPN, IPv6 and DHCP options are not
        offered. Applying also needs UNIFI_CONSOLE_ENABLE_WRITES=true and 'network' in UNIFI_CONSOLE_WRITE_ENTITIES. Every write is journalled.
        """
        try:
            if params.action in ("enable", "disable", "delete") and params.changes():
                return json.dumps({"ok": False, "error": f"{params.action} takes no field values; use update to change fields."})
            if params.action == "create" and params.target:
                return json.dumps({"ok": False, "error": "create takes no target."})
            console_ip = None
            try:
                console_ip = socket.gethostbyname(engine.api.settings.host)
            except OSError:
                pass
            snap: dict[str, Any] = {}
            spec = replace(SPEC, validate_ctx=make_validate(params.acknowledge_disconnect, params.acknowledge_infrastructure, console_ip, snap),
                           verify=make_verify(snap))
            result = await engine.execute(
                spec, action=params.action, target=params.target, changes=params.changes(),
                confirm=params.confirm, fingerprint=params.fingerprint, approval_note=params.approval_note,
            )
            return json.dumps(result, separators=(",", ":"), default=str)
        except Exception as exc:  # noqa: BLE001 - converted to an actionable message
            return error_text(exc)
