"""Curated tools for the gap areas: System Log, firewall hit counts, PoE, switch port detail,
backups, support files, the gateway's provisioned config and console access review. Each is a thin,
tolerant wrapper over spec operations (paths come from the registry), so field drift degrades output
rather than breaking it.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from datetime import datetime, timezone
from typing import Any, Literal, get_args

from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel, ConfigDict, Field

from . import gateway_config
from .api import Api, RunResult, error_text
from .client import UniFiError

SEVERITIES = ["LOW", "MEDIUM", "HIGH", "VERY_HIGH"]
MAC = r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$"
UPLINK_KEYS = {"uplink_mac", "uplink_device_name", "uplink_remote_port", "port_idx", "type", "speed", "max_speed",
               "full_duplex", "rx_errors", "tx_errors", "rx_dropped", "tx_dropped", "uplink_source"}
_RO = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}


def iso(value: Any) -> Any:
    """Epoch milliseconds (or seconds) -> ISO-8601 UTC; anything else unchanged."""
    if isinstance(value, (int, float)) and value > 0:
        seconds = value / 1000 if value > 1e11 else value
        return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return value


def fill_template(template: str | None, parameters: dict[str, Any] | None) -> str:
    """System Log titles/messages are templates: replace {NAME} with parameters[NAME].name."""
    if not template:
        return ""
    params = parameters or {}

    def sub(match: re.Match[str]) -> str:
        entry = params.get(match.group(1))
        if isinstance(entry, dict):
            return str(entry.get("name") or entry.get("hostname") or entry.get("id") or match.group(0))
        return match.group(0)

    return re.sub(r"\{(\w+)\}", sub, template)


# ------------------------------------------------------------------ inputs
class SystemLogInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    hours: int = Field(default=24, ge=1, le=720, description="Look back this many hours (ignored when critical_only=true).")
    min_severity: Literal["LOW", "MEDIUM", "HIGH", "VERY_HIGH"] = Field(default="MEDIUM", description="Lowest severity to include. LOW is dominated by Wi-Fi connect/roam noise.")
    categories: list[Literal["CLIENT_DEVICES", "INTERNET_AND_WAN", "POWER", "AUDIT", "SECURITY", "UNIFI_DEVICES", "SOFTWARE_UPDATES", "UNIFI_ETHERNET_PORTS", "VPN"]] | None = Field(default=None, description="Restrict to these categories.")
    search_text: str = Field(default="", description="Free-text filter.")
    client_mac: str | None = Field(default=None, pattern=MAC, description="Only entries about this client MAC.")
    critical_only: bool = Field(default=False, description="Use the Critical view (switching faults such as STP loops, BPDU guard, broadcast storms). No time window or paging.")
    page_number: int = Field(default=0, ge=0, description="Zero-based page (history view only).")
    page_size: int = Field(default=50, ge=1, le=200, description="Entries per page (history view only).")


class FirewallHitsInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    sort_by: Literal["hits", "last_hit", "index", "name"] = Field(default="hits", description="Sort order. 'hits' ascending surfaces unused rules first.")
    descending: bool = Field(default=False, description="Reverse the sort order.")
    unused_only: bool = Field(default=False, description="Only policies with zero hits.")
    min_hits: int | None = Field(default=None, ge=0, description="Only policies with at least this many hits.")
    enabled_only: bool = Field(default=False, description="Skip disabled policies.")
    include_predefined: bool = Field(default=False, description="Include system-defined policies.")
    search: str | None = Field(default=None, description="Substring match on policy name.")
    limit: int = Field(default=50, ge=1, le=300, description="Maximum policies to return.")


class DeviceMacInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    device_mac: str = Field(..., pattern=MAC, description="Device MAC, e.g. 'aa:bb:cc:dd:ee:ff' (find it with the existing device list tools).")


class SwitchPortInput(DeviceMacInput):
    ports: list[int] | None = Field(default=None, description="Only these port numbers (port_idx). Omit for all ports.")
    include_lldp: bool = Field(default=False, description="Also return the LLDP neighbour table (can be large).")


class BackupInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    action: Literal["list", "create", "download"] = Field(..., description="list = backups held on the console; create = make a new one; download = build and save an archive locally.")
    target: Literal["uos", "network", "users"] | None = Field(default=None, description="download only: limit the archive to one part. Omit for everything.")
    confirm: bool = Field(default=False, description="Required for create and download.")


class SupportFileInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    scope: Literal["console", "device"] = Field(..., description="console = combined console/Network bundle (downloaded to disk); device = one adopted device (status only: the download step is not captured in the spec yet).")
    device_mac: str | None = Field(default=None, pattern=MAC, description="Required when scope='device'.")
    targets: list[Literal["network", "uos"]] | None = Field(default=None, description="console only: parts to include. Omit for everything.")
    recreate: bool = Field(default=False, description="console only: build a fresh bundle instead of reusing a recent one.")
    wait_seconds: int = Field(default=120, ge=0, le=600, description="How long to wait for generation. 0 = start only.")
    confirm: bool = Field(default=False, description="Required. Creates a file containing secrets in plain text.")


GatewaySection = Literal["summary", "interfaces", "services", "firewall", "policy_drift"]


class GatewayConfigInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    sections: list[GatewaySection] | None = Field(default=None, description="Parts to return. Omit for all: summary (model, firmware, cfgversion, section versions), interfaces (WAN/LAN addressing, DHCPv6-PD request), services (DHCP scopes, DNS forwarder, DoH, mDNS, WAN failover, IPS, NTP, syslog), firewall (chains, rule counts, sets, field-type check), policy_drift (controller policies vs the rules sent to the gateway).")
    firewall_chain: str | None = Field(default=None, description="Also return the rules of this gateway chain, e.g. 'WAN_LOCAL' (traffic from the internet to the gateway).")
    device_mac: str | None = Field(default=None, pattern=MAC, description="Which gateway, if the bundle holds more than one.")
    refresh: bool = Field(default=False, description="Generate a new console support file first (about 90 s). Needs confirm=true, UNIFI_CONSOLE_ENABLE_WRITES=true and Control Plane = Admin.")
    max_age_minutes: int = Field(default=1440, ge=1, le=43200, description="Without refresh, use the newest support file in the download folder if it is at most this old.")
    wait_seconds: int = Field(default=180, ge=30, le=600, description="refresh only: how long to wait for the bundle.")
    confirm: bool = Field(default=False, description="Required with refresh=true.")


# ---------------------------------------------------------------- helpers
def _first(data: Any) -> dict[str, Any]:
    if isinstance(data, list) and data and isinstance(data[0], dict):
        return data[0]
    return data if isinstance(data, dict) else {}


async def _console_support_file(api: Api, *, recreate: bool, targets: list[str] | None, wait_seconds: int,
                                confirm: bool) -> RunResult:
    """Generate the console bundle and poll the download until it is ready (423/404 while it is being built)."""
    body: dict[str, Any] = {"recreate": recreate, "requiredDevices": {}}
    if targets:
        body["targets"] = targets
    await api.run("generateSupportFile", body=body, confirm=confirm)
    deadline = time.monotonic() + wait_seconds
    last_error = "Generation started but the wait was 0 seconds; call again with download via unifi_console_call_operation(operation_id='downloadSupportFile', confirm=true)."
    while wait_seconds > 0:
        try:
            return await api.run("downloadSupportFile", confirm=True)
        except UniFiError as exc:
            last_error = str(exc)
        if time.monotonic() >= deadline:
            break
        await asyncio.sleep(10)
    raise UniFiError(f"Support file not ready within {wait_seconds}s. Last response: {last_error}")


def register(mcp: MCPServer, api: Api) -> None:
    @mcp.tool(name="unifi_console_session_status", annotations=_RO)
    async def unifi_console_session_status() -> str:
        """Check the connection and report which account the server runs as, what it may do, and session facts.

        Logs in if needed. Reports the controller version, the account's permissions, the session cookie's
        lifetime and whether the CSRF token has rotated, plus the server's safety settings. Use it first
        when a call fails with a permission or authentication error.

        Returns JSON: {"ok", "controller": {...}, "account": {...}, "session": {...}, "server": {...}}.
        """
        try:
            me = await api.run("getCurrentUser")
            sysinfo = await api.run("getSysInfo")
            user = _first(me.data) if isinstance(me.data, list) else (me.data or {})
            perms = user.get("permissions") if isinstance(user, dict) else None
            info = _first(sysinfo.data)
            s = api.settings
            return json.dumps({
                "ok": True,
                "controller": {k: info.get(k) for k in ("version", "build", "hostname", "timezone", "uptime", "update_available")},
                "account": {"username": user.get("username"), "roles": [r.get("name") for r in user.get("roles", []) if isinstance(r, dict)],
                            "only_local_account": user.get("only_local_account"),
                            "network_management": (perms or {}).get("network.management") if isinstance(perms, dict) else None,
                            "control_plane_permissions": {k: v for k, v in (perms or {}).items() if k != "network.management"} if isinstance(perms, dict) else None},
                "session": api.client.session_info(),
                "server": {"host": s.host, "site": s.site, "spec_version": api.registry.spec_version,
                           "writes_enabled": s.enable_writes, "api_key_configured": bool(s.api_key),
                           "tls_verification": "pinned" if s.pinned_sha256 else ("on" if s.verify_ssl else "off"),
                           "download_dir": str(s.download_dir)},
            }, separators=(",", ":"), default=str)
        except Exception as exc:  # noqa: BLE001
            return error_text(exc)

    @mcp.tool(name="unifi_console_system_log", annotations=_RO)
    async def unifi_console_system_log(params: SystemLogInput) -> str:
        """Query the UniFi System Log (the Network app's 'System Log' page), with templates already filled in.

        This is richer than the older event list: it records STP loops, BPDU guard, PoE and port faults,
        WAN failovers, security events and admin changes. Defaults to the last 24 hours at MEDIUM severity and
        above. Use critical_only=true for switching faults (NETWORK_LOOP_DETECTED_BY_STP, BPDU_GUARD_TRIGGERED,
        PORT_BROADCAST_STORM, ROGUE_DHCP_SERVER_DETECTED, ...).

        Returns JSON: {"ok", "meta": {"total", "page", "total_pages"}, "data": [{"time", "severity", "category",
        "subcategory", "event", "target", "title", "message", "id"}]}, newest first.
        """
        try:
            severities = SEVERITIES[SEVERITIES.index(params.min_severity):]
            macs = [params.client_mac.lower()] if params.client_mac else []
            if params.critical_only:
                body: dict[str, Any] = {"searchText": params.search_text, "severities": severities}
                if params.categories:
                    body["categories"] = params.categories
                result = await api.run("querySystemLog", body=body)
                entries, extra = result.data or [], {}
            else:
                now = int(time.time() * 1000)
                body = {"searchText": params.search_text, "type": "GENERAL", "severities": severities,
                        "timestampFrom": now - params.hours * 3_600_000, "timestampTo": now,
                        "pageNumber": params.page_number, "pageSize": params.page_size,
                        "clientDeviceMacs": macs, "adminIds": []}
                if params.categories:
                    body["categories"] = params.categories
                result = await api.run("querySystemLogAll", body=body)
                payload = result.data if isinstance(result.data, dict) else {}
                entries = payload.get("data", [])
                extra = {"log_page": {"total": payload.get("total_element_count"), "page": payload.get("page_number"),
                                      "total_pages": payload.get("total_page_count")}}
            rows = [{
                "time": iso(e.get("timestamp")), "severity": e.get("severity"), "category": e.get("category"),
                "subcategory": e.get("subcategory"), "event": e.get("event"), "target": e.get("target"),
                "title": fill_template(e.get("title_raw"), e.get("parameters")),
                "message": fill_template(e.get("message_raw"), e.get("parameters")), "id": e.get("id"),
            } for e in entries if isinstance(e, dict)]
            return api.render(RunResult(result.operation_id, result.status, rows), extra=extra)
        except Exception as exc:  # noqa: BLE001
            return error_text(exc)

    @mcp.tool(name="unifi_console_firewall_policy_hits", annotations=_RO)
    async def unifi_console_firewall_policy_hits(params: FirewallHitsInput) -> str:
        """List zone-based firewall policies with hit counts and last-hit time, for audits.

        Finds unused rules (zero hits), noisy rules and stale rules. The Integration API does not expose hit
        counts. Read-only: to change policies use the existing firewall tools.

        Returns JSON: {"ok", "meta", "data": [{"name", "id", "index", "action", "enabled", "predefined",
        "hits", "last_hit", "logging", "source_zone", "destination_zone"}]}.
        """
        try:
            result = await api.run("listFirewallPoliciesWithHits")
            zones: dict[str, str] = {}
            try:
                zr = await api.run("listFirewallZones")
                zones = {z.get("_id"): z.get("name") for z in (zr.data or []) if isinstance(z, dict)}
            except UniFiError:
                pass  # zone names are a nicety; ids are still returned
            rows = []
            for p in result.data or []:
                if not isinstance(p, dict):
                    continue
                if p.get("predefined") and not params.include_predefined:
                    continue
                hits = p.get("hits") or 0
                if params.enabled_only and not p.get("enabled"):
                    continue
                if params.unused_only and hits != 0:
                    continue
                if params.min_hits is not None and hits < params.min_hits:
                    continue
                if params.search and params.search.lower() not in str(p.get("name", "")).lower():
                    continue
                src, dst = p.get("source") or {}, p.get("destination") or {}
                rows.append({
                    "name": p.get("name"), "id": p.get("_id"), "index": p.get("index"), "action": p.get("action"),
                    "enabled": p.get("enabled"), "predefined": p.get("predefined"), "hits": hits,
                    "last_hit": iso(p.get("last_hit")), "logging": p.get("logging"),
                    "source_zone": zones.get(src.get("zone_id"), src.get("zone_id")),
                    "destination_zone": zones.get(dst.get("zone_id"), dst.get("zone_id")),
                })
            key = {"hits": lambda r: r["hits"], "index": lambda r: r["index"] or 0,
                   "name": lambda r: str(r["name"]).lower(), "last_hit": lambda r: r["last_hit"] or ""}[params.sort_by]
            rows.sort(key=key, reverse=params.descending)
            return api.render(RunResult(result.operation_id, result.status, rows), limit=params.limit)
        except Exception as exc:  # noqa: BLE001
            return error_text(exc)

    @mcp.tool(name="unifi_console_poe_overview", annotations=_RO)
    async def unifi_console_poe_overview(params: DeviceMacInput) -> str:
        """PoE budget for one switch plus the site's power supervisors (watchdogs that power-cycle ports).

        Check this before diagnosing a PoE device that keeps rebooting: a supervisor with consecutive_failures
        above zero is power-cycling it. Returns JSON: {"ok", "data": {"poe_host": {...}, "power_supervisors": [...]}}.
        """
        try:
            poe = await api.run("getPoeInfo", query={"mac": params.device_mac.lower()})
            sup = await api.run("listPowerSupervisors")
            data = {"poe_host": (poe.data or {}).get("poe_host_device_info") if isinstance(poe.data, dict) else poe.data,
                    "power_supervisors": sup.data}
            return api.render(RunResult("getPoeInfo+listPowerSupervisors", 200, data))
        except Exception as exc:  # noqa: BLE001
            return error_text(exc)

    @mcp.tool(name="unifi_console_switch_port_detail", annotations=_RO)
    async def unifi_console_switch_port_detail(params: SwitchPortInput) -> str:
        """Live per-port state for a switch: link, STP state/role, flaps, errors, PoE and optionally LLDP.

        Trims the 1 MB+ device record to the useful port fields (any key starting stp_, poe_, lldp_ or
        containing error/drop/link_down is kept, so new firmware fields still appear). Read-only; secrets removed.

        Returns JSON: {"ok", "data": {"name", "model", "version", "uplink", "stp": {...}, "ports": [...]}}.
        """
        keep = re.compile(r"^(port_idx|name|up|enable|speed|full_duplex|is_uplink|op_mode|media|portconf_id|"
                          r"native_networkconf_id|masked|satisfaction|rx_bytes|tx_bytes|bytes-r|"
                          r"stp_.*|poe_.*|lldp_.*|dot1x_.*|.*error.*|.*drop.*|.*link_down.*|.*flap.*)$")
        try:
            result = await api.run("getDeviceDetail", path_params={"mac": params.device_mac.lower()})
            dev = _first(result.data)
            if not dev:
                raise UniFiError("No device returned for that MAC. Check it is an adopted device on this site.")
            ports = [
                {k: v for k, v in p.items() if keep.search(k) and not (k.startswith("lldp_") and not params.include_lldp and k == "lldp_table")}
                for p in dev.get("port_table", []) if isinstance(p, dict)
                and (not params.ports or p.get("port_idx") in params.ports)
            ]
            data = {"name": dev.get("name"), "model": dev.get("model"), "version": dev.get("version"),
                    "uplink": {k: v for k, v in (dev.get("uplink") or {}).items() if k in UPLINK_KEYS}, "stp": {k: v for k, v in dev.items() if k.startswith("stp_")},
                    "ports": ports}
            if params.include_lldp:
                data["lldp_table"] = dev.get("lldp_table")
            return api.render(RunResult(result.operation_id, result.status, data))
        except Exception as exc:  # noqa: BLE001
            return error_text(exc)

    @mcp.tool(
        name="unifi_console_backup",
        annotations={"title": "Console backups", "readOnlyHint": False, "destructiveHint": False,
                     "idempotentHint": False, "openWorldHint": False},
    )
    async def unifi_console_backup(params: BackupInput) -> str:
        """List, create or download UniFi OS console backups (whole console, not just the Network app).

        list is read-only. create makes a new backup on the console and needs UNIFI_CONSOLE_ENABLE_WRITES=true and
        confirm=true. download builds a fresh archive and saves it under the server's download folder (never
        returned here; it contains credentials) and needs confirm=true. Console-level calls need the MCP
        account's Control Plane permission raised from View to Admin.

        Returns JSON: {"ok", "data": [...]} for list, or {"ok", "saved_file": {"path", "bytes", "sha256"}}.
        """
        try:
            if params.action == "list":
                result = await api.run("listConsoleBackups")
                rows = [{"id": b.get("id"), "time": iso(b.get("time")), "frequency": b.get("frequency"),
                         "size": b.get("size"),
                         "network_version": ((b.get("metadata") or {}).get("controllers") or {}).get("network", {}).get("version")}
                        for b in (result.data or []) if isinstance(b, dict)]
                return api.render(RunResult(result.operation_id, result.status, rows))
            if params.action == "create":
                result = await api.run("createConsoleBackup", query={"destination": "local"}, confirm=params.confirm)
                return api.render(RunResult(result.operation_id, result.status, {"created": True}),
                                  extra={"note": "Appears at the top of the list shortly; run action=list to confirm."})
            query = {"target": params.target} if params.target else {}
            result = await api.run("downloadBackup", query=query, confirm=params.confirm)
            return api.render(result)
        except Exception as exc:  # noqa: BLE001
            return error_text(exc)

    @mcp.tool(
        name="unifi_console_support_file",
        annotations={"title": "Generate support file", "readOnlyHint": False, "destructiveHint": False,
                     "idempotentHint": False, "openWorldHint": False},
    )
    async def unifi_console_support_file(params: SupportFileInput) -> str:
        """Generate a support file and (for the console) download it to disk.

        The console bundle holds Network logs, remote syslog from every adopted device, configs and topology: the
        place to look when regular logs do not explain a fault (e.g. an STP problem visible only in device syslog).
        It contains secrets in plain text, so it is saved locally and never returned. Takes about a minute.
        Needs UNIFI_CONSOLE_ENABLE_WRITES=true, confirm=true, and Control Plane = Admin on the MCP account.
        scope='device' starts generation and reports status only.

        Returns JSON: {"ok", "saved_file": {...}} (console) or {"ok", "data": {"status": ...}} (device).
        """
        try:
            if params.scope == "device":
                if not params.device_mac:
                    raise UniFiError("device_mac is required when scope='device'.")
                mac = params.device_mac.lower()
                await api.run("generateDeviceSupportFile", path_params={"mac": mac}, confirm=params.confirm)
                deadline = time.monotonic() + params.wait_seconds
                status: Any = None
                while True:
                    st = await api.run("getDeviceSupportFileStatus", path_params={"mac": mac})
                    status = (st.data or {}).get("status") if isinstance(st.data, dict) else st.data
                    if status != "GENERATING" or time.monotonic() >= deadline:
                        break
                    await asyncio.sleep(5)
                return api.render(RunResult("getDeviceSupportFileStatus", 200, {"mac": mac, "status": status}),
                                  extra={"note": "The ready/download step for device files has not been captured in the spec yet."})
            result = await _console_support_file(api, recreate=params.recreate, targets=params.targets,
                                                 wait_seconds=params.wait_seconds, confirm=params.confirm)
            return api.render(result)
        except Exception as exc:  # noqa: BLE001
            return error_text(exc)

    @mcp.tool(
        name="unifi_console_gateway_config",
        annotations={"title": "Gateway provisioned config", "readOnlyHint": False, "destructiveHint": False,
                     "idempotentHint": True, "openWorldHint": False},
    )
    async def unifi_console_gateway_config(params: GatewayConfigInput) -> str:
        """What the controller actually sent the gateway, read from a console support file, and whether it matches.

        Use it when the console's view and the gateway's behaviour disagree: a policy that seems not to apply,
        a WAN or DHCPv6-PD setting in doubt, DHCP/DNS handed out differently from the network settings, or after
        a provisioning error. policy_drift lists enabled custom policies missing from the gateway config,
        disabled ones still present, action/IP version/logging mismatches and orphan rules. firewall reports the
        types seen per rule field; mixed_type_fields points at 'X must be an object' validation errors.

        Reuses the newest support file in the download folder (default: up to a day old); refresh=true with
        confirm=true builds a new one first. Read-only on the console otherwise. Credentials are never returned:
        services holding them are skipped and key-like fields are redacted. This is the config sent to the
        gateway, not the rules it loaded (that needs the device support file, not captured yet).

        Returns JSON: {"ok", "data": {"source": {...}, "summary", "interfaces", "services", "firewall",
        "policy_drift"}}.
        """
        try:
            settings = api.settings
            if params.refresh:
                result = await _console_support_file(api, recreate=True, targets=None,
                                                     wait_seconds=params.wait_seconds, confirm=params.confirm)
                archive = result.download.path if result.download else None
            else:
                archive = gateway_config.latest_support_file(settings.download_dir)
                if archive and time.time() - archive.stat().st_mtime > params.max_age_minutes * 60:
                    archive = None
            if archive is None:
                raise UniFiError(f"No console support file newer than {params.max_age_minutes} minutes in "
                                 f"{settings.download_dir}. Call again with refresh=true and confirm=true (about 90 s; "
                                 "needs UNIFI_CONSOLE_ENABLE_WRITES=true and Control Plane = Admin), or raise max_age_minutes.")
            gateways = await asyncio.to_thread(gateway_config.load_gateways, archive)
            if params.device_mac:
                gateways = [g for g in gateways if g.mac == params.device_mac.lower()]
            if not gateways:
                raise UniFiError(f"No gateway config found in {archive.name}"
                                 f"{' for ' + params.device_mac if params.device_mac else ''}.")
            if len(gateways) > 1:
                raise UniFiError("The bundle holds several gateways; pass device_mac: "
                                 + ", ".join(g.mac for g in gateways))
            gw = gateways[0]
            wanted = set(params.sections or get_args(GatewaySection))
            age_min = round((time.time() - archive.stat().st_mtime) / 60, 1)
            data: dict[str, Any] = {"source": {"file": archive.name, "saved": iso(archive.stat().st_mtime),
                                               "age_minutes": age_min}}
            if "summary" in wanted:
                summary = gateway_config.summary_view(gw)
                try:
                    dev = _first((await api.run("getDeviceDetail", path_params={"mac": gw.mac})).data)
                    summary["controller_now"] = {"cfgversion": dev.get("cfgversion"), "state": dev.get("state"),
                                                 "provisioned_at": iso(dev.get("provisioned_at"))}
                except UniFiError:
                    pass  # the bundle still answers the question without the live record
                data["summary"] = summary
            if "interfaces" in wanted:
                data["interfaces"] = gateway_config.interfaces_view(gw.udapi)
            if "services" in wanted:
                data.update(gateway_config.services_view(gw.udapi))
            if "firewall" in wanted:
                data["firewall"] = gateway_config.firewall_view(gw.udapi, params.firewall_chain)
            if "policy_drift" in wanted:
                policies = (await api.run("listFirewallPoliciesWithHits")).data or []
                data["policy_drift"] = gateway_config.compare_policies(policies, gw.udapi)
            note = ("The bundle is a snapshot: compare inform.cfgversion with controller_now.cfgversion only when it "
                    "is fresh (refresh=true); a mismatch then means the gateway has not taken the latest config.")
            return api.render(RunResult("gatewayConfig", 200, data), extra={"note": note})
        except Exception as exc:  # noqa: BLE001
            return error_text(exc)

    @mcp.tool(name="unifi_console_access_review", annotations=_RO)
    async def unifi_console_access_review() -> str:
        """Who and what can access the console: admin accounts, custom roles and API keys (keys masked).

        Useful for least-privilege reviews of integration accounts. Needs read access to UniFi OS users.
        Returns JSON: {"ok", "data": {"admins": [...], "roles": [...], "api_keys": [...]}}.
        """
        try:
            def rows(res: RunResult, keep: re.Pattern[str]) -> list[Any]:
                items = res.data if isinstance(res.data, list) else []
                return [{k: iso(v) if k.endswith("_time") or k.endswith("_at") else v for k, v in i.items() if keep.search(k)}
                        for i in items if isinstance(i, dict)]

            sections = {
                "admins": ("listConsoleAdmins", {"page_size": 100}, re.compile(r"^(unique_id|username|full_name|status|only_local_account|only_ui_account|login_time|last_activity_time|roles|permissions)$")),
                "roles": ("listRoles", None, re.compile(r"^(id|unique_id|name|display_name|users_count|permissions|system_role|type)$")),
                "api_keys": ("listApiKeys", None, re.compile(r"^(id|name|masked_api_key|permissions|scopes|creator_user_id|last_used_at|created_at|expires_at)$")),
            }
            data: dict[str, Any] = {}
            denied: dict[str, str] = {}
            for name, (op_id, query, keep) in sections.items():
                try:
                    data[name] = rows(await api.run(op_id, query=query), keep)
                except UniFiError as exc:  # one denied section must not hide the others
                    denied[name] = str(exc)
            if not data:
                raise UniFiError("; ".join(denied.values()))
            if denied:
                data["unavailable"] = denied
            return api.render(RunResult("access_review", 200, data))
        except Exception as exc:  # noqa: BLE001
            return error_text(exc)
