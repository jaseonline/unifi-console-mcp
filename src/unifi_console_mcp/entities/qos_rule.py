"""QoS rules (v2 `qos-rules`): the dashboard's "QoS" widget, separate from Traffic Management objects. Tier B.

Captured 2026-10-18 (`qos-rules.har`):
  * create is POST `qos-rules` (HTTP 201) of `{enabled, name, wan_or_vpn_network, source, destination, schedule, objective,
    download_burst, upload_burst}`; the console adds `_id` and `index`;
  * update is PUT `qos-rules/{id}` (HTTP 200) of the whole rule including `_id` and `index`;
  * delete is POST `qos-rules/batch-delete` with a list of ids (HTTP 204), even for one rule;
  * `source`: `{matching_target: "CLIENT", client_macs: [...]}` (the UI also sends `port_matching_type: "ANY"`, which the console drops);
    `destination`: `{matching_target: "APP", app_ids: [...], port_matching_type: "ANY"}`;
  * `objective` PRIORITIZE carries no limits and bursts "OFF"; LIMIT carries `download_limit_kbps`, `upload_limit_kbps`
    (kbit/s) and bursts OFF, SHORT or LONG;
  * `schedule` ALWAYS only was captured.

What this tool changes: name, enabled, the WAN or VPN link, client sources, application destinations, objective, limits and
bursts. Any other source or destination type (network, IP address, ports) and any other schedule have not been captured, so
a rule that uses them can be renamed, enabled or disabled but those parts are left untouched.
"""

from __future__ import annotations

import copy
import dataclasses
import json
import re
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel, ConfigDict, Field

from ..api import error_text
from ..client import UniFiError
from ..writes import VOLATILE, ActionOp, EntitySpec, Findings, WriteEngine, same

KEY = "qos_rule"
TOOL = "unifi_console_qos_rule"
OBJECTIVES = ("LIMIT", "PRIORITIZE")
BURSTS = ("OFF", "SHORT", "LONG")
MAX_LIMIT = 10_000_000
_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
FRIENDLY = ("source_clients", "destination_apps", "download_limit", "upload_limit", "download_burst", "upload_burst")


def _mac(value: str) -> str:
    v = str(value).strip().lower().replace("-", ":")
    if re.fullmatch(r"[0-9a-f]{12}", v):
        v = ":".join(v[i:i + 2] for i in range(0, 12, 2))
    if not _MAC.match(v):
        raise UniFiError(f"'{value}' is not a MAC address.")
    return v


def prepare(action: str, before: dict[str, Any] | None, changes: dict[str, Any]) -> dict[str, Any]:
    if not changes:
        return {}                                              # enable, disable: nothing to translate
    out = dict(changes)
    clients = out.pop("source_clients", None)
    apps = out.pop("destination_apps", None)
    down, up = out.pop("download_limit", None), out.pop("upload_limit", None)
    dburst, uburst = out.pop("download_burst", None), out.pop("upload_burst", None)
    creating = action == "create"
    base = {} if creating else dict(before or {})
    if "name" in out:
        out["name"] = str(out["name"]).strip()
    if creating:
        out.setdefault("enabled", False)                       # a new rule starts switched off unless asked for
        out.setdefault("schedule", {"mode": "ALWAYS"})
        out.setdefault("objective", "LIMIT")
    if "objective" in out:
        out["objective"] = str(out["objective"]).upper()
    if clients is not None:
        if "source" in out:
            raise UniFiError("Use source_clients or a full source block, not both.")
        macs = [_mac(m) for m in clients]
        out["source"] = {"matching_target": "CLIENT", "client_macs": macs}      # the console drops port_matching_type from a CLIENT source
    if apps is not None:
        if "destination" in out:
            raise UniFiError("Use destination_apps or a full destination block, not both.")
        out["destination"] = {"matching_target": "APP", "port_matching_type": "ANY", "app_ids": [int(a) for a in apps]}
    objective = out.get("objective", base.get("objective"))
    if objective == "PRIORITIZE":
        # the captured PRIORITIZE rule carries no limits and bursts "OFF"
        if down not in (None, 0) or up not in (None, 0):
            raise UniFiError("A PRIORITIZE rule has no limits. Use objective LIMIT to set download_limit or upload_limit.")
        for k in ("download_limit_kbps", "upload_limit_kbps"):
            out[k] = None
        out["download_burst"], out["upload_burst"] = "OFF", "OFF"
    else:
        if down is not None:
            out["download_limit_kbps"] = None if down == 0 else int(down)
        if up is not None:
            out["upload_limit_kbps"] = None if up == 0 else int(up)
        if "objective" in out and base.get("objective") != "LIMIT":    # switching to LIMIT: the console expects both limits
            out.setdefault("download_limit_kbps", base.get("download_limit_kbps") or 10000)
            out.setdefault("upload_limit_kbps", base.get("upload_limit_kbps") or 10000)
        if dburst is not None:
            out["download_burst"] = str(dburst).upper()
        if uburst is not None:
            out["upload_burst"] = str(uburst).upper()
        if creating:
            out.setdefault("download_burst", "OFF")
            out.setdefault("upload_burst", "OFF")
        if "objective" in out and base.get("objective") != "LIMIT":
            out.setdefault("download_burst", "OFF")
            out.setdefault("upload_burst", "OFF")
    # None means "remove the key" (the console omits what is not set)
    return out


def _clean(after: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in after.items() if v is not None}


def _label(rule: dict[str, Any]) -> str:
    src, dst = rule.get("source") or {}, rule.get("destination") or {}
    s = (f"{len(src.get('client_macs') or [])} client(s)" if src.get("matching_target") == "CLIENT" else str(src.get("matching_target")))
    d = (f"{len(dst.get('app_ids') or [])} application(s)" if dst.get("matching_target") == "APP" else str(dst.get("matching_target")))
    return f"{s} to {d}"


def validate(action: str, before: dict[str, Any] | None, after: dict[str, Any], others: list[dict[str, Any]],
             ctx: dict[str, list[dict[str, Any]]]) -> Findings:
    f = Findings()
    before = before or {}
    nets = {str(n.get("_id")): n for n in ctx.get("networks", [])}
    if action == "delete":
        if before.get("enabled"):
            f.warnings.append(f"Deleting this rule ends its {before.get('objective', 'QoS').lower()} for {_label(before)} at once.")
        return f
    after = _clean(after)
    name = str(after.get("name") or "").strip()
    if not name:
        f.errors.append("A name is required.")
    elif len(name) > 128:
        f.errors.append("The name is longer than 128 characters.")
    elif name != before.get("name") and any(str(r.get("name") or "").lower() == name.lower() for r in others):
        f.errors.append(f"Another QoS rule is already called '{name}'. Names must be unique so one can be addressed by name.")
    if not isinstance(after.get("enabled"), bool):
        f.errors.append("enabled must be true or false.")

    nid = after.get("wan_or_vpn_network")
    net = nets.get(str(nid))
    if net is None:
        (f.warnings if nid and nid == before.get("wan_or_vpn_network") else f.errors).append(
            "wan_or_vpn_network must be an existing WAN or VPN client network.")
    elif net.get("purpose") not in ("wan", "vpn-client", "vpn_client"):
        f.errors.append(f"'{net.get('name')}' is not a WAN or VPN client network.")

    src, dst = after.get("source") or {}, after.get("destination") or {}
    if not same(src, before.get("source")):
        if src.get("matching_target") != "CLIENT":
            f.errors.append(f"Source type '{src.get('matching_target')}' has not been captured; only CLIENT (by MAC) is supported.")
        else:
            macs = src.get("client_macs")
            if not isinstance(macs, list) or not macs:
                f.errors.append("source needs at least one client MAC.")
            else:
                bad = [m for m in macs if not _MAC.match(str(m))]
                if bad:
                    f.errors.append(f"Not a MAC address: {', '.join(map(str, bad))}.")
                if len(set(macs)) != len(macs):
                    f.errors.append("Duplicate client MACs.")
    elif src.get("matching_target") != "CLIENT":
        f.warnings.append(f"This rule's source ({src.get('matching_target')}) is not edited here and is left untouched.")
    if not same(dst, before.get("destination")):
        if dst.get("matching_target") != "APP":
            f.errors.append(f"Destination type '{dst.get('matching_target')}' has not been captured; only APP (by application id) is supported.")
        else:
            ids = dst.get("app_ids")
            if not isinstance(ids, list) or not ids or any(isinstance(i, bool) or not isinstance(i, int) or i <= 0 for i in ids):
                f.errors.append("destination needs a non-empty list of positive application ids.")
            elif len(set(ids)) != len(ids):
                f.errors.append("Duplicate application ids.")
    elif dst.get("matching_target") != "APP":
        f.warnings.append(f"This rule's destination ({dst.get('matching_target')}) is not edited here and is left untouched.")

    sch = after.get("schedule")
    if not same(sch, before.get("schedule")) and (not isinstance(sch, dict) or sch.get("mode") != "ALWAYS"):
        f.errors.append("Only schedule mode ALWAYS has been captured for QoS rules.")

    objective = after.get("objective")
    if objective not in OBJECTIVES:
        f.errors.append(f"objective '{objective}' is not one of {', '.join(OBJECTIVES)}.")
    for key in ("download_burst", "upload_burst"):
        if after.get(key) not in BURSTS:
            f.errors.append(f"{key} '{after.get(key)}' is not one of {', '.join(BURSTS)}.")
    limits = {k: after.get(k) for k in ("download_limit_kbps", "upload_limit_kbps") if after.get(k) is not None}
    for k, v in limits.items():
        if isinstance(v, bool) or not isinstance(v, int) or not 1 <= v <= MAX_LIMIT:
            f.errors.append(f"{k} must be a whole number from 1 to {MAX_LIMIT}.")
    if objective == "PRIORITIZE":
        if limits:
            f.errors.append("A PRIORITIZE rule has no limits.")
        if any(after.get(k) != "OFF" for k in ("download_burst", "upload_burst")):
            f.errors.append("A PRIORITIZE rule has bursts OFF.")
    elif objective == "LIMIT":
        if not limits:
            f.errors.append("A LIMIT rule needs download_limit and/or upload_limit (kbit/s).")
        elif len(limits) == 1:
            f.warnings.append("Only one direction has a limit; whether the console accepts that is unverified.")
    if not f.errors:
        mine = set((src.get("client_macs") or [])) if src.get("matching_target") == "CLIENT" else set()
        if after.get("enabled") and mine:
            clash = [str(r.get("name")) for r in others if r.get("enabled")
                     and mine & set((r.get("source") or {}).get("client_macs") or [])]
            if clash:
                f.warnings.append(f"Other enabled QoS rule(s) already cover some of these clients ({', '.join(clash)}); "
                                  "how the console combines them is unverified.")
        link = (net or {}).get("name") or nid
        if after.get("enabled"):
            if objective == "LIMIT":
                rates = ", ".join(f"{d} {v / 1000:g} Mbit/s" for d, v in (("download", limits.get("download_limit_kbps")), ("upload", limits.get("upload_limit_kbps"))) if v)
                f.warnings.append(f"This limits {_label(after)} on {link} as soon as it is applied ({rates}).")
            else:
                f.warnings.append(f"This prioritises {_label(after)} on {link} as soon as it is applied.")
        else:
            f.warnings.append("The rule is switched off, so it has no effect yet.")
    return f


def _batch_delete_body(before: dict[str, Any] | None, after: dict[str, Any] | None, effective: dict[str, Any]) -> Any:
    return [(before or {}).get("_id")]


def _send_body(before: dict[str, Any] | None, after: dict[str, Any] | None, effective: dict[str, Any]) -> Any:
    return _clean(after or {})


SPEC = EntitySpec(
    key=KEY, label="QoS rule", tier="B", list_op="listQosRules", create_op="createQosRule", update_op="updateQosRule",
    delete_op="batchDeleteQosRules", whole_object=True, id_field="_id", name_field="name",
    ignore=VOLATILE | frozenset({"index"}), prepare=prepare, validate_ctx=validate,
    context_ops=(("networks", "listNetworkConfig"),),
    action_ops={"create": ActionOp("createQosRule", _send_body, with_id=False),
                "update": ActionOp("updateQosRule", _send_body),
                "enable": ActionOp("updateQosRule", _send_body),
                "disable": ActionOp("updateQosRule", _send_body),
                "delete": ActionOp("batchDeleteQosRules", _batch_delete_body, with_id=False)},
)


class QosRuleInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    action: Literal["create", "update", "enable", "disable", "delete"] = Field(..., description="create a rule, change it, switch it on or off, or delete it.")
    target: str | None = Field(default=None, description="Existing rule: its id or exact name. Not used by create.")
    name: str | None = Field(default=None, description="Rule name (unique).")
    enabled: bool | None = Field(default=None, description="Whether the rule applies. A new rule is created switched off unless this is true.")
    wan_network: str | None = Field(default=None, description="WAN or VPN client network the rule applies to, by name or id (for example WAN1).")
    source_clients: list[str] | None = Field(default=None, description="Client MAC addresses the rule applies to.")
    destination_apps: list[int] | None = Field(default=None, description="Application ids (from the console's app list) the rule matches.")
    objective: Literal["LIMIT", "PRIORITIZE"] | None = Field(default=None, description="LIMIT caps bandwidth; PRIORITIZE favours the traffic. PRIORITIZE has no limits.")
    download_limit: int | None = Field(default=None, ge=0, le=10_000_000, description="Download limit in kbit/s (10000 = 10 Mbit/s). 0 removes it.")
    upload_limit: int | None = Field(default=None, ge=0, le=10_000_000, description="Upload limit in kbit/s. 0 removes it.")
    download_burst: Literal["OFF", "SHORT", "LONG"] | None = Field(default=None, description="Burst allowance for the download limit.")
    upload_burst: Literal["OFF", "SHORT", "LONG"] | None = Field(default=None, description="Burst allowance for the upload limit.")
    wan_or_vpn_network: str | None = Field(default=None, description="Raw network id; accepted so a recorded rollback can be replayed.")
    source: dict[str, Any] | None = Field(default=None, description="Raw source block; replay only. Prefer source_clients.")
    destination: dict[str, Any] | None = Field(default=None, description="Raw destination block; replay only. Prefer destination_apps.")
    schedule: dict[str, Any] | None = Field(default=None, description="Raw schedule; only {mode: ALWAYS} has been captured.")
    download_limit_kbps: int | None = Field(default=None, description="Raw stored field; replay only. Prefer download_limit.")
    upload_limit_kbps: int | None = Field(default=None, description="Raw stored field; replay only. Prefer upload_limit.")
    confirm: bool = Field(default=False, description="false (default) returns a read-only preview. true applies the change and needs fingerprint.")
    fingerprint: str | None = Field(default=None, description="From the preview of exactly this change; required with confirm=true.")

    def changes(self) -> dict[str, Any]:
        skip = {"action", "target", "confirm", "fingerprint", "wan_network"}
        return {k: v for k, v in self.model_dump().items() if k not in skip and v is not None}


async def resolve_link(engine: WriteEngine, ref: str) -> str:
    rows = await engine._read_list("listNetworkConfig")
    hits = ([r for r in rows if str(r.get("_id")) == ref] or [r for r in rows if r.get("name") == ref]
            or [r for r in rows if str(r.get("name") or "").lower() == ref.lower()])
    if not hits:
        raise UniFiError(f"No network with id or name '{ref}'. Known networks: {', '.join(str(r.get('name')) for r in rows)}.")
    if len(hits) > 1:
        raise UniFiError(f"{len(hits)} networks match '{ref}'; use its id instead.")
    net = hits[0]
    if net.get("purpose") not in ("wan", "vpn-client", "vpn_client"):
        raise UniFiError(f"'{net.get('name')}' is not a WAN or VPN client network.")
    return str(net["_id"])


def register(mcp: MCPServer, engine: WriteEngine) -> None:
    @mcp.tool(
        name=TOOL,
        annotations={"title": "Create, change or delete a QoS rule (dashboard QoS widget)", "readOnlyHint": False,
                     "destructiveHint": True, "idempotentHint": False, "openWorldHint": False},
    )
    async def unifi_console_qos_rule(params: QosRuleInput) -> str:
        """Preview, then apply, a change to the console's QoS rules (the dashboard's QoS widget; Traffic Management objects
        use unifi_console_traffic_object instead).

        Two steps, always: call with confirm=false to get a read-only preview (before, after, diff, warnings, a
        fingerprint); call again with the same fields plus confirm=true and that fingerprint to apply. The rule is
        re-read first, so a stale preview is refused. A rule names a WAN or VPN link (`wan_network`), the clients it covers
        (`source_clients`, MAC addresses), the applications it matches (`destination_apps`, application ids), and an
        objective: LIMIT (download_limit / upload_limit in kbit/s, 10000 = 10 Mbit/s, with download_burst / upload_burst OFF,
        SHORT or LONG) or PRIORITIZE (no limits). Other source and destination types and schedules other than ALWAYS have
        not been captured and are not edited. A new rule starts switched off unless enabled=true; once enabled it takes
        effect at once. Use action enable or disable to switch one. Applying also needs UNIFI_CONSOLE_ENABLE_WRITES=true and
        'qos_rule' in UNIFI_CONSOLE_WRITE_ENTITIES. The console only accepts the whole rule, so updates send all of it. After
        applying, the rule is read back and the result reports verified true/false, the diff, and the exact rollback call.
        Every write is journalled. Delete uses the console's batch-delete call.
        """
        try:
            changes = params.changes()
            if params.action in ("delete", "enable", "disable") and (changes or params.wan_network):
                return json.dumps({"ok": False, "error": f"{params.action} takes no field values."})
            if params.wan_network is not None:
                changes["wan_or_vpn_network"] = await resolve_link(engine, params.wan_network)
            if params.action == "create" and not (params.name and changes.get("wan_or_vpn_network")
                                                  and (params.source_clients or params.source)
                                                  and (params.destination_apps or params.destination)):
                return json.dumps({"ok": False, "error": "create needs name, wan_network, source_clients and destination_apps."})
            result = await engine.execute(
                SPEC, action=params.action, target=params.target, changes=changes,
                confirm=params.confirm, fingerprint=params.fingerprint,
            )
            return json.dumps(result, separators=(",", ":"), default=str)
        except Exception as exc:  # noqa: BLE001 - converted to an actionable message
            return error_text(exc)
