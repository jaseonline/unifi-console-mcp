"""The gateway's provisioned config, read out of a console support file.

The console bundle holds, for each adopted gateway, `unifi/devices/<type>/<mac>/system.cfg`: the udapi config the
controller sends to the gateway (interfaces, services, firewall chains with each rule tagged by the policy it came
from) and `last.inform`, the gateway's own last report. Comparing that config with the controller's policies shows
whether every policy reached the gateway. It is still the controller's output, not the rules the gateway loaded.

UniFi's own support-file sanitiser breaks the JSON where it masks values (`"key" : "**REDACTED-...**` loses its
closing quote and comma), so `repair_json` mends those lines before parsing. Secrets are removed here by key name
and value shape, then again by `redact.redact` in the caller, and whole services that hold credentials are never read.
"""

from __future__ import annotations

import json
import re
import tarfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .redact import REDACTED, redact

SUPPORT_GLOB = "support-*.tgz"
MEMBER = re.compile(r"/unifi/devices/([^/]+)/([0-9a-f]{2}(?:-[0-9a-f]{2}){5})/(system\.cfg|last\.inform)$")
MAX_MEMBER_BYTES = 20_000_000

# Services worth reading. Anything not listed (unifiNetwork holds the inform token and certificate, sshServer,
# snmpAgent, ddns, wifiman, ...) is skipped, so a service added by new firmware stays out until reviewed.
SAFE_SERVICES = ("dhcpServers", "dnsForwarder", "dohProxy", "mdns", "wanFailover", "idsIps", "ntpClient",
                 "systemLog", "dpi", "arpInspection", "lldp")
_SECRET_KEY = re.compile(r"password|passphrase|secret|token|psk|preshared|privatekey|private_key|apikey|api_key|"
                         r"community|certificate|^key$|^crt$|^cert$|^users$", re.IGNORECASE)
INFORM_KEYS = ("model", "model_display", "version", "cfgversion", "state", "uptime", "required_version")
ACTION_TARGET = {"ALLOW": "ACCEPT", "BLOCK": "DROP", "REJECT": "REJECT"}
IP_VERSION = {"IPV4": {"v4only"}, "IPV6": {"v6only"}}
LIST_CAP = 50


@dataclass
class GatewayFiles:
    mac: str
    device_type: str
    udapi: dict[str, Any]
    inform: dict[str, Any] | None


# ----------------------------------------------------------------- reading
_KV = re.compile(r'^(\s*"[^"]+"\s*:\s*)(.+?)\s*$')
_OPENERS = {"{", "[", "{ }", "{ },", "[ ]", "[ ],"}


def repair_json(text: str) -> str:
    """Mend lines whose value the support-file sanitiser left unquoted or unterminated."""
    lines = text.split("\n")
    out = []
    for i, line in enumerate(lines):
        m = _KV.match(line)
        if m and m.group(2) not in _OPENERS:
            value = m.group(2)
            try:
                json.loads(value[:-1] if value.endswith(",") else value)
            except json.JSONDecodeError:
                following = next((x.strip() for x in lines[i + 1:] if x.strip()), "")
                inner = value.rstrip(",").strip().strip('"').replace("\\", "\\\\").replace('"', '\\"')
                line = f'{m.group(1)}"{inner}"' + ("," if following.startswith('"') else "")
        out.append(line)
    return "\n".join(out)


def parse_json(raw: bytes) -> Any:
    text = raw.decode("utf-8", "replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return json.loads(repair_json(text))


def latest_support_file(download_dir: Path) -> Path | None:
    files = sorted(download_dir.glob(SUPPORT_GLOB), key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0] if files else None


def load_gateways(archive: Path) -> list[GatewayFiles]:
    """Every device in the bundle whose system.cfg is udapi JSON (switches and APs use other formats)."""
    found: dict[tuple[str, str], dict[str, Any]] = defaultdict(dict)
    with tarfile.open(archive, mode="r|gz") as tar:
        for member in tar:
            m = MEMBER.search(member.name)
            if not m or not member.isfile() or member.size > MAX_MEMBER_BYTES:
                continue
            handle = tar.extractfile(member)
            if handle is None:
                continue
            try:
                found[(m.group(1), m.group(2))][m.group(3)] = parse_json(handle.read())
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue  # not JSON: a switch or AP config
    gateways = []
    for (device_type, mac), files in found.items():
        cfg = files.get("system.cfg")
        if isinstance(cfg, dict) and isinstance(cfg.get("udapi"), dict):
            inform = files.get("last.inform")
            gateways.append(GatewayFiles(mac.replace("-", ":"), device_type, cfg["udapi"],
                                         inform if isinstance(inform, dict) else None))
    return gateways


# ---------------------------------------------------------------- shaping
def scrub(value: Any) -> Any:
    """Drop credential-looking keys, DNS stamps and PEM blocks, then apply the server-wide redaction."""
    def walk(v: Any) -> Any:
        if isinstance(v, dict):
            return {k: (REDACTED if _SECRET_KEY.search(str(k)) and v2 not in (None, "", [], {}) else walk(v2))
                    for k, v2 in v.items()}
        if isinstance(v, list):
            return [walk(x) for x in v]
        if isinstance(v, str):
            if v.startswith("sdns://"):
                return "sdns://" + REDACTED  # a DoH stamp can carry a private resolver address
            if "-----BEGIN" in v:
                return REDACTED
        return v
    return redact(walk(value))


def summary_view(gw: GatewayFiles) -> dict[str, Any]:
    u = gw.udapi
    return {
        "mac": gw.mac, "device_type": gw.device_type,
        "inform": {k: (gw.inform or {}).get(k) for k in INFORM_KEYS} if gw.inform else None,
        "config_version": u.get("version"), "version_format": u.get("versionFormat"),
        "section_versions": u.get("versionDetail"),
        "system": scrub({k: v for k, v in (u.get("system") or {}).items() if k in ("hostname", "timezone", "fwReleaseChannel", "dnsServers")}),
    }


def interfaces_view(udapi: dict[str, Any]) -> list[Any]:
    return scrub([i for i in udapi.get("interfaces") or [] if isinstance(i, dict)])


def services_view(udapi: dict[str, Any]) -> dict[str, Any]:
    services = udapi.get("services") or {}
    data = {name: services[name] for name in SAFE_SERVICES if name in services}
    return {"services": scrub(data), "services_omitted": sorted(set(services) - set(SAFE_SERVICES))}


def _filter_rules(udapi: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    return [(str((c.get("config") or {}).get("name")), r)
            for c in udapi.get("firewall/filter") or [] if isinstance(c, dict)
            for r in c.get("rules") or [] if isinstance(r, dict)]


def _type_name(v: Any) -> str:
    return {bool: "bool", int: "int", float: "number", str: "string", list: "list", dict: "object"}.get(type(v), "null")


def field_types(rules: list[dict[str, Any]]) -> dict[str, Any]:
    """Types seen per rule field. A field with two non-null types is the shape of the 'X must be an object' errors."""
    seen: dict[str, Counter[str]] = defaultdict(Counter)
    for r in rules:
        for k, v in r.items():
            seen[k][_type_name(v)] += 1
    for c in seen.values():
        if (absent := len(rules) - sum(c.values())) > 0:
            c["absent"] = absent
    types = {k: dict(c) for k, c in sorted(seen.items())}
    mixed = sorted(k for k, c in seen.items() if len(set(c) - {"null", "absent"}) > 1)
    return {"field_types": types, "mixed_type_fields": mixed}


def firewall_view(udapi: dict[str, Any], chain: str | None = None) -> dict[str, Any]:
    rules = _filter_rules(udapi)
    per_chain: dict[str, dict[str, Any]] = {}
    for c in udapi.get("firewall/filter") or []:
        if isinstance(c, dict):
            cfg = c.get("config") or {}
            body = [r for r in c.get("rules") or [] if isinstance(r, dict)]
            per_chain[str(cfg.get("name"))] = {"policy": cfg.get("policy"), "rules": len(body),
                                               "from_policies": sum(1 for r in body if r.get("originId"))}
    all_sets = [{"name": str((s.get("identification") or {}).get("name")), "description": s.get("description"),
                 "entries": len(s.get("entries") or [])} for s in udapi.get("firewall/sets") or [] if isinstance(s, dict)]
    # One generated set per policy match (policy_src_net_12, ...): count them, list the rest.
    sets = [s for s in all_sets if not s["name"].startswith("policy_")]
    data: dict[str, Any] = {
        "chains": {k: v for k, v in per_chain.items() if v["rules"]},
        "empty_chains": sorted(k for k, v in per_chain.items() if not v["rules"]),
        "rule_count": len(rules), "sets": sets, "policy_sets": len(all_sets) - len(sets),
        "nat_rules": len(udapi.get("firewall/nat") or []),
        **field_types([r for _, r in rules]),
    }
    if chain:
        data["chain_rules"] = scrub([r for name, r in rules if name.lower() == chain.lower()])
    return data


# ----------------------------------------------------------- policy drift
def _rule_ref(chain: str, r: dict[str, Any]) -> dict[str, Any]:
    return {"chain": chain, "id": r.get("id"), "target": r.get("target"), "description": r.get("description")}


def compare_policies(policies: list[dict[str, Any]], udapi: dict[str, Any]) -> dict[str, Any]:
    """Match controller policies to gateway rules by policy id (rule originId = policy origin_id or _id)."""
    by_origin: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for chain, r in _filter_rules(udapi):
        origin = r.get("originId") or (r.get("triggerTag") or {}).get("id")
        if origin:
            by_origin[str(origin)].append((chain, r))

    known: set[str] = set()
    missing, predefined_missing, disabled_present, mismatches = [], [], [], []
    custom_enabled = matched = 0
    for p in policies:
        if not isinstance(p, dict):
            continue
        ids = {str(x) for x in (p.get("_id"), p.get("origin_id")) if x}
        known |= ids
        found = [hit for i in ids for hit in by_origin.get(i, [])]
        ref = {"name": p.get("name"), "id": p.get("_id"), "action": p.get("action")}
        if not p.get("enabled"):
            if found:
                disabled_present.append({**ref, "rules": [_rule_ref(c, r) for c, r in found[:5]]})
            continue
        if p.get("predefined"):
            # Every predefined policy is a tagged rule on Network 11 / UXG 5.1; their fields are generated, so only presence is checked.
            if not found:
                predefined_missing.append(ref)
            continue
        custom_enabled += 1
        if not found:
            missing.append(ref)
            continue
        matched += 1
        rules = [r for _, r in found]
        targets = {r.get("target") for r in rules}
        want = ACTION_TARGET.get(str(p.get("action")))
        if want and want not in targets:
            mismatches.append({**ref, "field": "action", "controller": p.get("action"), "gateway": sorted(map(str, targets))})
        versions = {r.get("ipVersion") for r in rules}
        allowed = IP_VERSION.get(str(p.get("ip_version")))
        if allowed and not versions & allowed:
            mismatches.append({**ref, "field": "ip_version", "controller": p.get("ip_version"), "gateway": sorted(map(str, versions))})
        if p.get("ip_version") == "BOTH" and not ("both" in versions or {"v4only", "v6only"} <= versions):
            mismatches.append({**ref, "field": "ip_version", "controller": "BOTH", "gateway": sorted(map(str, versions))})
        logged = any(r.get("log") is True for r in rules)
        if bool(p.get("logging")) != logged:
            mismatches.append({**ref, "field": "logging", "controller": bool(p.get("logging")), "gateway": logged})

    orphans = [_rule_ref(chain, r) for origin, hits in by_origin.items() if origin not in known
               for chain, r in hits if (r.get("triggerTag") or {}).get("type") == "FIREWALL_POLICY"]
    return {
        "policies_checked": len(policies), "custom_enabled": custom_enabled, "custom_matched": matched,
        "missing_on_gateway": missing[:LIST_CAP], "disabled_but_on_gateway": disabled_present[:LIST_CAP],
        "mismatches": mismatches[:LIST_CAP], "orphan_rules": orphans[:LIST_CAP],
        "predefined_missing_on_gateway": predefined_missing[:LIST_CAP],
        "in_sync": not (missing or predefined_missing or disabled_present or mismatches or orphans),
        "note": ("Compares the controller's policies with the config it sent the gateway (support file), not the "
                 "rules the gateway loaded. Custom policies are checked field by field; predefined ones for presence."),
    }
