"""Operation registry built from the OpenAPI spec.

The spec is the source of truth for paths, parameters and request bodies. The only hand-written
knowledge is the access policy below: which operations are read-only despite using POST, which
writes are "safe" (they create files/state but change no configuration), and which operations
return binary files.

To grow the PoC towards replacing a full server, widen these sets (or add curated tools); do not
hand-copy paths into tool code.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.parse import quote

import yaml

# POST operations that only read (the controller uses POST for query bodies).
READ_ONLY_POSTS = frozenset(
    {
        "querySystemLogAll",
        "querySystemLog",
        "getSystemLogFilterData",
        "queryTrafficFlows",
        "getAppTrafficRate",
        "listDevicesDetailedFiltered",
        "listRogueAps",
        "getSystemLogCount",
        "getPortMacTables",
        "queryPortSystemLogs",
        "queryWifiConnectivityEvents",
        "cloudQueryIspMetrics",
    }
)

# Writes that create a file or entry but change no configuration. Enabled only with
# UNIFI_CONSOLE_ENABLE_WRITES=true and confirm=true.
SAFE_WRITES = frozenset(
    {
        "generateSupportFile",
        "generateDeviceSupportFile",
        "createConsoleBackup",
        "checkApplicationUpdates",
    }
)

# GET operations that return a file. They are streamed to disk. The files contain secrets, so the
# caller must pass confirm=true.
DOWNLOADS = frozenset({"downloadBackup", "downloadSupportFile"})

# POSTs the UI sends with no body at all (Content-Length: 0), and POSTs it sends with the literal JSON `null`.
EMPTY_BODY_POSTS = frozenset({"createConsoleBackup"})
NULL_BODY_POSTS = frozenset({"generateDeviceSupportFile"})

# Configuration writes that are only reachable through a typed, previewing tool (see writes.py). The generic
# unifi_console_call_operation refuses them and names the tool instead.
TYPED_WRITE_TOOLS = {
    "createPortForward": "unifi_console_port_forward",
    "updatePortForward": "unifi_console_port_forward",
    "deletePortForward": "unifi_console_port_forward",
    "createFirewallGroup": "unifi_console_network_list",
    "updateFirewallGroup": "unifi_console_network_list",
    "deleteFirewallGroup": "unifi_console_network_list",
    "updateKnownClient": "unifi_console_client",
    "createStaticDns": "unifi_console_static_dns",
    "updateStaticDns": "unifi_console_static_dns",
    "deleteStaticDns": "unifi_console_static_dns",
    "createNetworkMemberGroup": "unifi_console_client_group",
    "updateNetworkMemberGroup": "unifi_console_client_group",
    "deleteNetworkMemberGroup": "unifi_console_client_group",
    "createDynamicDns": "unifi_console_dynamic_dns",
    "updateDynamicDns": "unifi_console_dynamic_dns",
    "deleteDynamicDns": "unifi_console_dynamic_dns",
    "createTrafficPolicyObject": "unifi_console_traffic_object",
    "updateTrafficPolicyObject": "unifi_console_traffic_object",
    "deleteTrafficPolicyObject": "unifi_console_traffic_object",
    "createQosRule": "unifi_console_qos_rule",
    "updateQosRule": "unifi_console_qos_rule",
    "batchDeleteQosRules": "unifi_console_qos_rule",
    "replaceFirewallAppBlocks": "unifi_console_app_block",
    "updateDohSetting": "unifi_console_doh",
    "createControllerFirewallPolicy": "unifi_console_firewall_policy",
    "updateControllerFirewallPolicy": "unifi_console_firewall_policy",
    "batchUpdateFirewallPolicies": "unifi_console_firewall_policy",
    "reorderFirewallPolicies": "unifi_console_firewall_policy",
    "batchDeleteFirewallPolicies": "unifi_console_firewall_policy",
    "createFirewallPolicy": "unifi_console_firewall_policy",
    "updateFirewallPolicy": "unifi_console_firewall_policy",
    "patchFirewallPolicy": "unifi_console_firewall_policy",
    "deleteFirewallPolicy": "unifi_console_firewall_policy",
    "updateFirewallPolicyOrdering": "unifi_console_firewall_policy",
    "updateDeviceSettings": "unifi_console_switch_port (port settings) or unifi_console_device (name, LED, disable/enable, management)",
    "deviceManagerCommand": "unifi_console_device",
    "siteManagerCommand": "unifi_console_device",
    "createWlanConfig": "unifi_console_wifi",
    "updateWlanConfig": "unifi_console_wifi",
    "deleteWlanConfig": "unifi_console_wifi",
    "createWifiBroadcast": "unifi_console_wifi",
    "updateWifiBroadcast": "unifi_console_wifi",
    "deleteWifiBroadcast": "unifi_console_wifi",
    "createNetworkConfig": "unifi_console_network",
    "updateNetworkConfig": "unifi_console_network",
    "deleteNetworkConfig": "unifi_console_network",
    "updateNetworkConfigGroup": "unifi_console_network",
    "createNetwork": "unifi_console_network",
    "updateNetwork": "unifi_console_network",
    "deleteNetwork": "unifi_console_network",
}

# Every operation names its API in `x-unifi-api`; tags only name the resource (Devices, Firewall, ...) so viewers can
# group one resource across APIs. site_manager operations go to api.ui.com with their own key (see Api._run_cloud).
# Site Manager's Connector proxy (/v1/connector/...) is deliberately not in the spec: it forwards any method to the
# console, so it would be a way round the write gates.
KNOWN_APIS = frozenset({"integration", "controller", "unifi_os", "site_manager"})
INCLUDED_APIS = KNOWN_APIS
EXCLUDED_OPERATION_IDS = frozenset({"localLogin", "localLogout"})


@dataclass(frozen=True)
class Param:
    name: str
    location: str
    required: bool
    description: str
    schema: dict[str, Any]


@dataclass(frozen=True)
class Operation:
    operation_id: str
    method: str
    path: str
    tag: str  # first tag: the one place the operation is listed and sorted
    api: str
    summary: str
    description: str
    params: tuple[Param, ...]
    body_schema: dict[str, Any] | None
    body_required: bool
    destructive: bool
    needs_session: bool
    extra: dict[str, Any] = field(default_factory=dict)
    # Every tag, first included. Only the tag filter reads it, so an operation tagged [WiFi, Devices] is listed once
    # under WiFi but still found by a Devices filter.
    tags: tuple[str, ...] = ()

    @property
    def is_download(self) -> bool:
        return self.operation_id in DOWNLOADS

    @property
    def access(self) -> str:
        """read | sensitive_read | safe_write | blocked"""
        if self.operation_id in DOWNLOADS:
            return "sensitive_read"
        if self.method == "GET":
            return "read"
        if self.method == "POST" and self.operation_id in READ_ONLY_POSTS:
            return "read"
        if self.operation_id in SAFE_WRITES:
            return "safe_write"
        return "blocked"

    @property
    def auth(self) -> str:
        if self.api == "site_manager":
            return "Site Manager API key (UNIFI_SITE_MANAGER_API_KEY)"
        return "login session (cookie + CSRF)" if self.needs_session else "API key"

    def build_path(self, path_params: dict[str, Any], default_site: str) -> str:
        values = dict(path_params)
        if "{site}" in self.path:
            values.setdefault("site", default_site)
        missing = [p.name for p in self.params if p.location == "path" and p.name not in values]
        if missing:
            raise ValueError(f"Missing path parameter(s): {', '.join(missing)}. See unifi_console_describe_operation.")
        return re.sub(r"\{(\w+)\}", lambda m: quote(str(values[m.group(1)]), safe=""), self.path)


def _norm(s: str) -> str:
    """'UniFi OS' -> 'unifi_os', so a tag filter can name an API the way people write it."""
    return re.sub(r"[\s-]+", "_", s.strip().lower())


def _load_spec(path: Path | None) -> dict[str, Any]:
    if path is not None:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    text = resources.files("unifi_console_mcp").joinpath("openapi.yaml").read_text(encoding="utf-8")
    return yaml.safe_load(text)


def _resolve(spec: dict[str, Any], node: Any, depth: int = 0, max_depth: int = 4) -> Any:
    """Inline $refs (bounded) so describe output is self-contained but small."""
    if isinstance(node, dict):
        if "$ref" in node:
            name = node["$ref"].split("/")[-1]
            if depth >= max_depth:
                return {"$ref": name}
            target: Any = spec
            for part in node["$ref"].lstrip("#/").split("/"):
                target = target[part]
            return _resolve(spec, target, depth + 1, max_depth)
        return {k: _resolve(spec, v, depth, max_depth) for k, v in node.items() if k not in ("examples", "example")}
    if isinstance(node, list):
        return [_resolve(spec, v, depth, max_depth) for v in node]
    return node


class Registry:
    def __init__(self, spec_path: Path | None = None) -> None:
        spec = _load_spec(spec_path)
        self.spec_version = str(spec.get("info", {}).get("version", "?"))
        self._ops: dict[str, Operation] = {}
        for path, item in spec["paths"].items():
            shared = item.get("parameters", [])
            for method, op in item.items():
                if method not in ("get", "post", "put", "patch", "delete") or not isinstance(op, dict):
                    continue
                op_id = op.get("operationId")
                tags = tuple(op.get("tags") or ())
                tag = tags[0] if tags else ""
                api = op.get("x-unifi-api")
                if op_id and api not in KNOWN_APIS:
                    # A missing or misspelt value would otherwise drop the operation without a trace.
                    raise ValueError(f"{op_id}: x-unifi-api must be one of {sorted(KNOWN_APIS)}, got {api!r}")
                if not op_id or op_id in EXCLUDED_OPERATION_IDS or api not in INCLUDED_APIS:
                    continue
                params = tuple(self._param(spec, p) for p in [*shared, *op.get("parameters", [])])
                body = op.get("requestBody")
                body_schema = None
                if body:
                    raw = body.get("content", {}).get("application/json", {}).get("schema")
                    body_schema = _resolve(spec, raw, max_depth=3) if raw else None
                security = op.get("security", spec.get("security", []))
                needs_session = any("ControllerSession" in s for s in security)
                self._ops[op_id] = Operation(
                    operation_id=op_id,
                    method=method.upper(),
                    path=path,
                    tag=tag,
                    tags=tags,
                    api=api,
                    summary=op.get("summary", ""),
                    description=(op.get("description") or "").strip(),
                    params=params,
                    body_schema=body_schema,
                    body_required=bool(body and body.get("required")),
                    destructive=bool(op.get("x-destructive")),
                    needs_session=needs_session,
                )

    @staticmethod
    def _param(spec: dict[str, Any], raw: dict[str, Any]) -> Param:
        p = _resolve(spec, raw, max_depth=2)
        return Param(p["name"], p["in"], bool(p.get("required")), p.get("description", ""), p.get("schema", {}))

    def get(self, operation_id: str) -> Operation:
        try:
            return self._ops[operation_id]
        except KeyError:
            near = [o for o in self._ops if operation_id.lower() in o.lower()][:5]
            hint = f" Did you mean: {', '.join(near)}?" if near else " Use unifi_console_list_operations to search."
            raise KeyError(f"Unknown operationId '{operation_id}'.{hint}") from None

    def all(self) -> list[Operation]:
        return sorted(self._ops.values(), key=lambda o: (o.tag, o.api, o.path, o.method))

    def search(self, text: str | None = None, tag: str | None = None, access: str | None = None) -> list[Operation]:
        out = self.all()
        if tag:
            # Matches the resource tag or the API, so 'Devices', 'Integration' and 'UniFi OS' all work. The old
            # combined form 'Controller · Devices' still works: every part must match one or the other. Any of the
            # operation's tags counts, not just the first one it is listed under.
            parts = [_norm(p) for p in tag.split("·") if p.strip()]
            out = [o for o in out if all(any(p in _norm(t) for t in o.tags) or p in o.api for p in parts)]
        if access and access != "all":
            out = [o for o in out if o.access == access]
        if text:
            words = text.lower().split()
            out = [
                o
                for o in out
                if all(w in f"{o.operation_id} {o.summary} {o.path} {o.description}".lower() for w in words)
            ]
        return out
