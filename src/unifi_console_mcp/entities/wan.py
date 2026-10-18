"""WAN network settings (legacy `rest/networkconf` with `purpose: wan`). Tier C.

Captured 2026-10-18 (`wan-put.har`): the UI saves the WAN page as a whole-object `PUT rest/networkconf/{id}` (the same endpoint as
LAN networks); the gateway re-provisions on every save. `network-change.har` shows a re-provision takes about 22 seconds
(gateway state 5 = provisioning, back to 1 = connected with a newer `provisioned_at`) without the other devices dropping.

Why tier C: a wrong value can cut the internet and with it DoH, the DNS probe, DDNS and every cloud path. So:
  * only update exists; a WAN is never created, deleted or disabled here, and only `purpose: wan` networks are accepted;
  * an allowlist of settings can be edited: DNS and IPv6 DNS preferences, provider speeds, Smart Queues and egress QoS,
    DHCPv6 prefix size, failover and load-balance priorities, WAN event reporting and the DHCP class-of-service values;
  * connection-identity settings (MAC override, WAN VLAN, IPv6 type, uplink identity, switching the type back to DHCP) can
    only be changed with `acknowledge_identity=true`: a wrong value can lose the ISP session and no tool can repair that remotely;
  * everything else (zone, name, purpose, routing table, SLA, static/PPPoE settings, the uplink password) is not offered, and the
    uplink password is never sent, compared or echoed;
  * a safety net: after the change the gateway must finish re-provisioning and be connected, every device that was connected
    must still be connected, the WAN must report ok, an internet probe and DNS through the gateway must work; otherwise the
    previous state is put back once, automatically, and the same checks are repeated.
Not offered: IGMP proxy (values unconfirmed), static or PPPoE connections, a second WAN, gateway-wide settings (`set/setting/usg`).
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import socket
import time
from dataclasses import replace
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel, ConfigDict, Field

from ..api import error_text
from ..client import UniFiError
from ..dnsprobe import run_probe
from ..writes import VOLATILE, EntitySpec, Findings, Guard, Plan, RestoreStep, WriteEngine, same

KEY = "wan"
TOOL = "unifi_console_wan"
GATEWAY_TYPES = frozenset({"ugw", "uxg", "udm", "udmp"})
INTERNET_PROBE = ("1.1.1.1:443", "9.9.9.9:443")
NO_SEND = VOLATILE | {"attr_no_delete"}
GUARD_TEXT = ("Safety net: after a WAN change the gateway must finish re-provisioning and be connected, every device that is connected "
              "now must still be connected, the WAN must report ok, an internet probe and DNS through the gateway must work; if not, "
              "the previous state is put back automatically, once, and the same checks run again.")

# friendly name -> real field, for the settings that can be changed freely
SIMPLE: dict[str, str] = {
    "dns_preference": "wan_dns_preference", "dns1": "wan_dns1", "dns2": "wan_dns2",
    "ipv6_dns_preference": "wan_ipv6_dns_preference", "ipv6_dns1": "wan_ipv6_dns1", "ipv6_dns2": "wan_ipv6_dns2",
    "smart_queues": "wan_smartq_enabled", "egress_qos": "wan_egress_qos_enabled", "pd_size": "wan_dhcpv6_pd_size",
    "pd_size_auto": "wan_dhcpv6_pd_size_auto", "failover_priority": "wan_failover_priority",
    "load_balance_type": "wan_load_balance_type", "load_balance_weight": "wan_load_balance_weight",
    "report_wan_event": "report_wan_event", "dhcp_cos": "wan_dhcp_cos", "dhcpv6_cos": "wan_dhcpv6_cos",
}
SPEEDS = {"download_kbps": "download_kilobits_per_second", "upload_kbps": "upload_kilobits_per_second"}
IDENTITY: dict[str, str] = {
    "mac_override": "mac_override", "mac_override_enabled": "mac_override_enabled", "vlan": "wan_vlan", "vlan_enabled": "wan_vlan_enabled",
    "type": "wan_type", "type_v6": "wan_type_v6", "uplink_identity": "uplink_identity",
}
FIELDS = tuple(SIMPLE) + tuple(SPEEDS) + tuple(IDENTITY)
MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


# ----------------------------------------------------------------------------------------------- helpers
def _ip(text: Any, version: int) -> bool:
    try:
        return ipaddress.ip_address(str(text)).version == version
    except ValueError:
        return False


def prepare_ctx(action: str, before: dict[str, Any] | None, changes: dict[str, Any], ctx: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    if action != "update":
        raise UniFiError("Only update exists for the WAN. A WAN is never created, deleted or disabled here; use the UI for that.")
    bad = set(changes) - set(FIELDS)
    if bad:
        raise UniFiError(f"Unknown field(s): {', '.join(sorted(bad))}. Use: {', '.join(FIELDS)}.")
    if before is None or before.get("purpose") != "wan":
        raise UniFiError(f"'{(before or {}).get('name')}' is a {(before or {}).get('purpose')} network, not a WAN. "
                         "Use unifi_console_network for LAN and VLAN networks.")
    if not changes:
        raise UniFiError("Nothing to change.")
    out: dict[str, Any] = {}
    for k, v in changes.items():
        if k in SIMPLE:
            out[SIMPLE[k]] = v
        elif k in IDENTITY:
            out[IDENTITY[k]] = v.strip().lower() if k == "mac_override" and isinstance(v, str) else v
    if any(k in changes for k in SPEEDS):
        caps = dict(before.get("wan_provider_capabilities") or {})
        for k, real in SPEEDS.items():
            if k in changes:
                caps[real] = changes[k]
        out["wan_provider_capabilities"] = caps
    return out


def make_validate(ack_identity: bool):
    def validate(action: str, before: dict[str, Any] | None, after: dict[str, Any], others: list[dict[str, Any]],
                 ctx: dict[str, list[dict[str, Any]]]) -> Findings:
        f = Findings()
        b = before or {}
        name = str(b.get("name") or "")
        changed = {k for k in set(after) | set(b) if not same(b.get(k), after.get(k))}

        def whole(key: str, lo: int, hi: int, label: str) -> None:
            v = after.get(key)
            if key in changed and (not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi):
                f.errors.append(f"{label} must be a whole number from {lo} to {hi}.")

        for pref, keys, ver, label in (("wan_dns_preference", ("wan_dns1", "wan_dns2"), 4, "DNS"),
                                       ("wan_ipv6_dns_preference", ("wan_ipv6_dns1", "wan_ipv6_dns2"), 6, "IPv6 DNS")):
            if pref in changed and after.get(pref) not in ("auto", "manual"):
                f.errors.append(f"{label} preference must be auto or manual.")
            for k in keys:
                if k in changed and after.get(k) not in ("", None) and not _ip(after.get(k), ver):
                    f.errors.append(f"{k.replace('wan_', '')} must be an IPv{ver} address.")
            if after.get(pref) == "manual" and not after.get(keys[0]):
                f.errors.append(f"Manual {label} needs the first server ({keys[0].replace('wan_', '')}).")
            if after.get(pref) == "auto" and any(k in changed and after.get(k) for k in keys):
                f.errors.append(f"{label} servers only apply when the preference is manual; set the preference too.")
        caps = after.get("wan_provider_capabilities") or {}
        if "wan_provider_capabilities" in changed:
            for real in SPEEDS.values():
                v = caps.get(real)
                if not isinstance(v, int) or isinstance(v, bool) or not 1 <= v <= 100_000_000:
                    f.errors.append(f"{real} must be a whole number of kilobits per second from 1 to 100,000,000.")
            f.warnings.append("The provider speeds feed Smart Queues and the speed-based features; set them to what the line really delivers.")
        whole("wan_dhcpv6_pd_size", 48, 64, "pd_size")
        whole("wan_failover_priority", 1, 99, "failover_priority")
        whole("wan_load_balance_weight", 1, 100, "load_balance_weight")
        whole("wan_dhcp_cos", 0, 7, "dhcp_cos")
        whole("wan_dhcpv6_cos", 0, 7, "dhcpv6_cos")
        if "wan_load_balance_type" in changed and after.get("wan_load_balance_type") not in ("weighted", "failover-only"):
            f.errors.append("load_balance_type must be weighted or failover-only.")
        for k in ("wan_smartq_enabled", "wan_egress_qos_enabled", "wan_dhcpv6_pd_size_auto", "report_wan_event", "mac_override_enabled",
                  "wan_vlan_enabled"):
            if k in changed and not isinstance(after.get(k), bool):
                f.errors.append(f"{k} must be true or false.")
        if "wan_smartq_enabled" in changed and after.get("wan_smartq_enabled"):
            f.warnings.append("Smart Queues shape traffic to the provider speeds; a wrong speed throttles the whole line.")

        ident = sorted(k for k in changed if k in IDENTITY.values())
        if ident:
            f.warnings.append(f"Connection identity on '{name}' is changing ({', '.join(ident)}). The ISP session may not come back if the "
                              "value is wrong, and this tool cannot repair that remotely.")
            if not ack_identity:
                f.errors.append("Identity stop: MAC override, WAN VLAN, connection type and uplink identity need acknowledge_identity=true.")
            if "mac_override" in changed and not MAC.match(str(after.get("mac_override") or "")):
                f.errors.append("mac_override must be a MAC address such as 02:00:00:00:00:41.")
            if "wan_vlan" in changed:
                v = after.get("wan_vlan")
                if not isinstance(v, int) or isinstance(v, bool) or not 1 <= v <= 4094:
                    f.errors.append("vlan must be a whole number from 1 to 4094.")
            if "wan_type" in changed and after.get("wan_type") != "dhcp":
                f.errors.append("Only type=dhcp is offered here; static and PPPoE need settings this tool does not handle.")
            if "wan_type_v6" in changed and after.get("wan_type_v6") not in ("dhcpv6", "disabled"):
                f.errors.append("type_v6 must be dhcpv6 or disabled.")
        if changed:
            f.warnings.append("Applying re-provisions the gateway (about 20 seconds); the internet may drop briefly.")
        return f
    return validate


# ----------------------------------------------------------------------------------------------- safety net
def _tcp_ok(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _probe_targets() -> list[tuple[str, int]]:
    raw = os.environ.get("UNIFI_CONSOLE_INTERNET_PROBE", "").strip() or ",".join(INTERNET_PROBE)
    out = []
    for part in raw.split(","):
        host, _, port = part.strip().partition(":")
        if host:
            out.append((host, int(port or 443)))
    return out


async def _internet_ok() -> bool:
    for host, port in _probe_targets():
        if await asyncio.to_thread(_tcp_ok, host, port, 3.0):
            return True
    return False


def make_guard() -> Guard:
    st: dict[str, Any] = {"connected": set(), "prov": {}, "gateways": set()}

    async def devices(engine: Any) -> list[dict[str, Any]]:
        return [r for r in await engine._read_list("listDevicesBasic") if r.get("adopted", True)]

    async def provisioned(engine: Any) -> dict[str, Any]:
        rows = await engine._read_list("listDevicesDetailed")
        return {str(r.get("mac")).lower(): r.get("provisioned_at") for r in rows if r.get("type") in GATEWAY_TYPES}

    async def wan_health(engine: Any) -> str | None:
        for row in await engine._read_list("getSiteHealth"):
            if row.get("subsystem") == "wan" and str(row.get("status")) != "ok":
                return f"the WAN reports '{row.get('status')}'"
        return None

    async def before(engine: Any) -> str | None:
        rows = await devices(engine)
        st["connected"] = {str(r.get("mac")).lower() for r in rows if r.get("state") == 1}
        st["gateways"] = {str(r.get("mac")).lower() for r in rows if r.get("type") in GATEWAY_TYPES}
        if not st["gateways"]:
            return "no adopted gateway was found, so the WAN change cannot be checked. Nothing was changed."
        if not st["gateways"] <= st["connected"]:
            return "the gateway is not connected before the change. Fix that first; the change was not attempted."
        st["prov"] = await provisioned(engine)
        problem = await wan_health(engine)
        if problem:
            return f"{problem} before the change. Fix that first; the change was not attempted."
        if not await _internet_ok():
            return "the internet probe fails before the change. Fix that first; the change was not attempted."
        return None

    async def status(engine: Any, base: dict[str, Any], elapsed: float, settle: float) -> str | None:
        rows = {str(r.get("mac")).lower(): r for r in await devices(engine)}
        down = [str(rows.get(m, {}).get("name") or m) for m in sorted(st["connected"]) if rows.get(m, {}).get("state") != 1]
        if down:
            return f"device(s) not connected: {', '.join(down)}"
        now = await provisioned(engine)
        for mac in st["gateways"]:
            if elapsed < settle and now.get(mac) in (None, base.get(mac)):
                return "the gateway has not started or finished re-provisioning yet"
        problem = await wan_health(engine)
        if problem:
            return problem
        if not await _internet_ok():
            return "the internet probe fails"
        dns = await run_probe(engine, window=0, attempts=1)
        return dns

    async def after(engine: Any, phase: str) -> str | None:
        s = engine.api.settings
        if phase == "change" and s.dns_probe_force_fail:
            return "forced failure (UNIFI_CONSOLE_DNS_PROBE_FORCE_FAIL is set; test switch)"
        window = max(float(s.dns_probe_window) * 3, 1.0)
        settle = min(15.0, window / 4)
        interval = max(0.2, min(2.0, window / 6))
        base = dict(st["prov"])
        start = time.monotonic()
        good, reason = 0, None
        while True:
            reason = await status(engine, base, time.monotonic() - start, settle)
            good = good + 1 if reason is None else 0
            if good >= 2:
                break
            if time.monotonic() - start >= window:
                break
            await asyncio.sleep(interval)
        st["prov"] = await provisioned(engine)
        return None if good >= 2 else (reason or "the checks did not settle in time")

    return Guard(describe=GUARD_TEXT, before=before, after=after)


# ----------------------------------------------------------------------------------------------- restore and rollback
def restore(plan: Plan, new_id: str | None) -> list[RestoreStep]:
    b = plan.before or {}
    return [RestoreStep("updateNetworkConfig", {k: v for k, v in b.items() if k not in NO_SEND}, {"id": plan.ident})]


def restore_ok(plan: Plan, rows: list[dict[str, Any]], new_id: str | None) -> bool:
    b = plan.before or {}
    cur = next((r for r in rows if str(r.get("_id")) == str(plan.ident)), None)
    return cur is not None and all(same(cur.get(k), b.get(k)) for k in plan.changes if not k.startswith("x_"))


def to_friendly(row: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {k: row.get(real) for k, real in {**SIMPLE, **IDENTITY}.items() if real in row}
    caps = row.get("wan_provider_capabilities") or {}
    out.update({k: caps.get(real) for k, real in SPEEDS.items() if real in caps})
    return out


def rollback(plan: Plan, new_id: str | None) -> dict[str, Any]:
    fb, fa = to_friendly(plan.before or {}), to_friendly(plan.after or {})
    args = {k: v for k, v in fb.items() if k in fa and not same(v, fa.get(k))}
    if any(k in IDENTITY for k in args):
        args["acknowledge_identity"] = True
    return {"tool": TOOL, "arguments": {"action": "update", "target": plan.ident, **args}}


SPEC = EntitySpec(
    key=KEY, label="WAN", tier="C", list_op="listNetworkConfig", update_op="updateNetworkConfig", whole_object=True, id_field="_id",
    name_field="name", body_drop=NO_SEND, prepare_ctx=prepare_ctx, ignore=VOLATILE | {"external_id"},
    guard=make_guard(), guard_when=lambda plan: not plan.no_change, restore=restore, restore_ok=restore_ok, rollback=rollback,
)


class WanInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    action: Literal["update"] = Field(default="update", description="Only update exists; a WAN is never created, deleted or disabled here.")
    target: str = Field(..., description="The WAN network: its _id or exact name (for example WAN1).")
    dns_preference: Literal["auto", "manual"] | None = None
    dns1: str | None = Field(default=None, description="IPv4 DNS server; only with dns_preference=manual.")
    dns2: str | None = None
    ipv6_dns_preference: Literal["auto", "manual"] | None = None
    ipv6_dns1: str | None = None
    ipv6_dns2: str | None = None
    download_kbps: int | None = Field(default=None, description="Provider download speed in kilobits per second.")
    upload_kbps: int | None = Field(default=None, description="Provider upload speed in kilobits per second.")
    smart_queues: bool | None = None
    egress_qos: bool | None = None
    pd_size: int | None = Field(default=None, description="Requested DHCPv6 prefix-delegation size, 48 to 64.")
    pd_size_auto: bool | None = None
    failover_priority: int | None = Field(default=None, description="1 to 99.")
    load_balance_type: Literal["weighted", "failover-only"] | None = None
    load_balance_weight: int | None = Field(default=None, description="1 to 100.")
    report_wan_event: bool | None = None
    dhcp_cos: int | None = Field(default=None, description="DHCP class of service, 0 to 7.")
    dhcpv6_cos: int | None = Field(default=None, description="DHCPv6 class of service, 0 to 7.")
    # connection identity: needs acknowledge_identity=true
    mac_override: str | None = Field(default=None, description="Identity. MAC address presented to the ISP.")
    mac_override_enabled: bool | None = Field(default=None, description="Identity.")
    vlan: int | None = Field(default=None, description="Identity. WAN VLAN id.")
    vlan_enabled: bool | None = Field(default=None, description="Identity.")
    type: Literal["dhcp"] | None = Field(default=None, description="Identity. Only dhcp is offered.")
    type_v6: Literal["dhcpv6", "disabled"] | None = Field(default=None, description="Identity. IPv6 connection type.")
    uplink_identity: str | None = Field(default=None, description="Identity.")
    acknowledge_identity: bool = Field(default=False, description="Accept a change to the connection identity (MAC, VLAN, type, uplink).")
    approval_note: str | None = Field(default=None, description="Required with confirm=true: where the approval for this tier C change was given.")
    confirm: bool = Field(default=False, description="false (default) returns a read-only preview. true applies and needs fingerprint.")
    fingerprint: str | None = Field(default=None, description="From the preview of exactly this change; required with confirm=true.")

    def changes(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in FIELDS if getattr(self, k) is not None}


def register(mcp: MCPServer, engine: WriteEngine) -> None:
    @mcp.tool(
        name=TOOL,
        annotations={"title": "Change WAN settings", "readOnlyHint": False, "destructiveHint": True,
                     "idempotentHint": False, "openWorldHint": False},
    )
    async def unifi_console_wan(params: WanInput) -> str:
        """Preview, then apply, a change to the WAN network settings. Tier C: a wrong change can cut the internet.

        Two steps, always: confirm=false returns a read-only preview (before, after, diff, warnings, errors, a fingerprint, and the
        safety-net check run now); then call again with the same fields plus confirm=true, that fingerprint and an approval_note.
        Only update exists. Connection identity (MAC override, WAN VLAN, connection type, IPv6 type, uplink identity) needs
        acknowledge_identity=true. The uplink password and everything not listed are not offered. Applying re-provisions the gateway
        (about 20 seconds). After the change the gateway must be connected again, all devices that were connected must still be, the
        WAN must report ok, an internet probe and DNS must work; otherwise the previous state is restored once, automatically.
        Applying also needs UNIFI_CONSOLE_ENABLE_WRITES=true and 'wan' in UNIFI_CONSOLE_WRITE_ENTITIES. Every write is journalled.
        """
        try:
            snap_spec = replace(SPEC, validate_ctx=make_validate(params.acknowledge_identity))
            result = await engine.execute(
                snap_spec, action=params.action, target=params.target, changes=params.changes(),
                confirm=params.confirm, fingerprint=params.fingerprint, approval_note=params.approval_note,
            )
            return json.dumps(result, separators=(",", ":"), default=str)
        except Exception as exc:  # noqa: BLE001 - converted to an actionable message
            return error_text(exc)
