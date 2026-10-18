"""Application blocks (Simple App Blocking, v2 `firewall-app-blocks`). Tier B.

Captured 2026-10-18 (`app-traffic-stats.har`, `app-traffic-schedule.har`, and a captured delete-all call):
  * the console keeps ONE collection. Every write is `POST firewall-app-blocks` with the COMPLETE array: an entry without
    `_id` is created, an entry with its `_id` is updated, an entry left out is deleted, `[]` deletes them all. The UI edits
    its table locally and sends everything at once when Apply is pressed, so 1 or 10 changes are one request;
  * an entry is `{name, type, target_type, app_ids, app_category_ids, client_macs, network_ids, schedule}`. `type` is DEVICE
    (clients, by MAC) or NETWORK; `target_type` is APP_ID or APP_CATEGORY. The UI sends all five lists on every entry, with
    the ones that do not apply holding stale values; this tool sends `[]` for them;
  * `schedule.mode` is ALWAYS, EVERY_DAY, EVERY_WEEK, ONE_TIME_ONLY or CUSTOM (shapes in `normalise_schedule`);
  * the console generates a `simple_app_block` firewall policy per entry (`origin_id` is the entry's `_id`).

Because a write replaces everything, the engine treats the collection as one object: it is folded into a pseudo-row
(`wrap_rows`), the fingerprint covers every entry, and a preview or apply is refused if any entry changed meanwhile.
Application and category ids are used as the console stores them; the mapping to the DPI lists is not verified.
"""

from __future__ import annotations

import copy
import dataclasses
import json
import re
from datetime import date
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel, ConfigDict, Field

from ..api import error_text
from ..client import UniFiError
from ..writes import VOLATILE, ActionOp, EntitySpec, Findings, WriteEngine, covers, same

KEY = "app_block"
TOOL = "unifi_console_app_block"
ROW_ID = "app_blocks"
DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
MODES = ("ALWAYS", "EVERY_DAY", "EVERY_WEEK", "ONE_TIME_ONLY", "CUSTOM")
_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
_TIME = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
PROTECTED_NETWORKS = ("LAN_Private",)       # blocking a whole network of this name needs approval_note


# ----------------------------------------------------------------------------------------------- normalising
def _mac(value: str) -> str:
    v = str(value).strip().lower().replace("-", ":")
    if re.fullmatch(r"[0-9a-f]{12}", v):
        v = ":".join(v[i:i + 2] for i in range(0, 12, 2))
    if not _MAC.match(v):
        raise UniFiError(f"'{value}' is not a MAC address.")
    return v


def normalise_schedule(s: dict[str, Any]) -> dict[str, Any]:
    """Turn the caller's schedule into exactly the shape the console's UI sends (see the module docstring)."""
    mode = str(s.get("mode") or "").upper()
    if mode not in MODES:
        raise UniFiError(f"schedule.mode must be one of {', '.join(MODES)}.")
    days = s.get("repeat_on_days")
    t0, t1 = s.get("time_range_start"), s.get("time_range_end")
    all_day = s.get("time_all_day")
    out: dict[str, Any] = {"mode": mode}

    def need_times() -> None:
        if not (t0 and t1):
            raise UniFiError(f"schedule {mode} needs time_range_start and time_range_end (HH:MM, 24 hour).")
        out["time_range_start"], out["time_range_end"] = str(t0), str(t1)

    def need_days() -> None:
        if not days:
            raise UniFiError(f"schedule {mode} needs repeat_on_days (any of {', '.join(DAYS)}).")
        d = [str(x).lower()[:3] for x in days]
        if any(x not in DAYS for x in d) or len(set(d)) != len(d):
            raise UniFiError(f"repeat_on_days must be unique days from {', '.join(DAYS)}.")
        out["repeat_on_days"] = d

    if mode == "ALWAYS":
        pass
    elif mode == "EVERY_DAY":
        need_times()
    elif mode == "EVERY_WEEK":
        need_days()
        out["time_all_day"] = bool(all_day)
        if not all_day:
            need_times()
    elif mode == "ONE_TIME_ONLY":
        if not s.get("date"):
            raise UniFiError("schedule ONE_TIME_ONLY needs date (YYYY-MM-DD).")
        out["date"] = str(s["date"])
        need_times()
    else:   # CUSTOM
        if not (s.get("date_start") and s.get("date_end")):
            raise UniFiError("schedule CUSTOM needs date_start and date_end (YYYY-MM-DD).")
        out["date_start"], out["date_end"] = str(s["date_start"]), str(s["date_end"])
        out["time_all_day"] = bool(all_day)
        need_days()
        if not all_day:
            need_times()
    # keep the key order the console returns, so an unchanged schedule compares equal
    return {k: out[k] for k in ("mode", "date", "date_start", "date_end", "repeat_on_days", "time_all_day",
                                "time_range_start", "time_range_end") if k in out}


def _schedule_findings(sch: Any, f: Findings, name: str) -> None:
    if not isinstance(sch, dict) or sch.get("mode") not in MODES:
        f.errors.append(f"'{name}': schedule.mode must be one of {', '.join(MODES)}.")
        return
    for key in ("time_range_start", "time_range_end"):
        if key in sch and not _TIME.match(str(sch[key])):
            f.errors.append(f"'{name}': {key} '{sch[key]}' is not HH:MM (24 hour).")
    for key in ("date", "date_start", "date_end"):
        if key in sch:
            try:
                date.fromisoformat(str(sch[key]))
            except ValueError:
                f.errors.append(f"'{name}': {key} '{sch[key]}' is not a date (YYYY-MM-DD).")
    if sch.get("mode") == "CUSTOM" and not f.errors and str(sch.get("date_end")) < str(sch.get("date_start")):
        f.errors.append(f"'{name}': date_end is before date_start.")
    if "time_range_start" in sch and "time_range_end" in sch and sch["time_range_end"] <= sch["time_range_start"]:
        f.warnings.append(f"'{name}': the time range ends at or before it starts, so it crosses midnight; whether the console "
                          "accepts that is unverified.")
    if sch.get("mode") == "ALWAYS":
        f.warnings.append(f"'{name}' blocks all the time once applied.")


# ----------------------------------------------------------------------------------------------- building the new collection
def _find(blocks: list[dict[str, Any]], target: str) -> int:
    hits = [i for i, b in enumerate(blocks) if str(b.get("_id")) == target]
    if not hits:
        hits = [i for i, b in enumerate(blocks) if b.get("name") == target]
    if not hits:
        raise UniFiError(f"No application block with id or exact name '{target}'. Read the current blocks first.")
    if len(hits) > 1:
        raise UniFiError(f"{len(hits)} application blocks are called '{target}'. Use the id instead.")
    return hits[0]


def _resolve_networks(refs: list[str], rows: list[dict[str, Any]]) -> list[str]:
    ids: list[str] = []
    for ref in refs:
        hits = ([r for r in rows if str(r.get("_id")) == ref] or [r for r in rows if r.get("name") == ref]
                or [r for r in rows if str(r.get("name") or "").lower() == str(ref).lower()])
        if len(hits) != 1:
            known = ", ".join(str(r.get("name")) for r in rows)
            raise UniFiError(f"{'No network' if not hits else str(len(hits)) + ' networks'} match '{ref}'. Known networks: {known}.")
        ids.append(str(hits[0]["_id"]))
    return ids


def build_blocks(live: list[dict[str, Any]], ops: list[dict[str, Any]], networks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Apply the requested operations, in order, to a copy of the live collection and return the complete new collection."""
    blocks = copy.deepcopy(live)
    for n, op in enumerate(ops, 1):
        kind, where = op["op"], f"change {n} ({op['op']})"
        try:
            if kind == "delete":
                extra = {k for k in op if k not in ("op", "target") and op[k] is not None}
                if extra:
                    raise UniFiError("delete takes only a target.")
                if not op.get("target"):
                    raise UniFiError("delete needs a target: the block's id or exact name.")
                blocks.pop(_find(blocks, op["target"]))
                continue
            if kind == "create":
                if op.get("target"):
                    raise UniFiError("create does not take a target.")
                entry: dict[str, Any] = {"name": "", "app_ids": [], "client_macs": [], "network_ids": [], "type": "",
                                         "target_type": "", "app_category_ids": [], "schedule": {}}
                idx = None
                if not op.get("name"):
                    raise UniFiError("create needs a name.")
                if not op.get("schedule"):
                    raise UniFiError("create needs an explicit schedule (a new block starts blocking at once).")
                if bool(op.get("clients")) == bool(op.get("networks")):
                    raise UniFiError("create needs exactly one of clients (MAC addresses) or networks.")
                if bool(op.get("apps")) == bool(op.get("categories")):
                    raise UniFiError("create needs exactly one of apps (application ids) or categories (category ids).")
            else:
                if not op.get("target"):
                    raise UniFiError("update needs a target: the block's id or exact name.")
                idx = _find(blocks, op["target"])
                entry = copy.deepcopy(blocks[idx])
            if op.get("clients") and op.get("networks"):
                raise UniFiError("Give clients or networks, not both.")
            if op.get("apps") and op.get("categories"):
                raise UniFiError("Give apps or categories, not both.")
            if op.get("name") is not None:
                entry["name"] = str(op["name"]).strip()
            if op.get("clients") is not None:
                entry.update(type="DEVICE", client_macs=[_mac(m) for m in op["clients"]], network_ids=[])
            if op.get("networks") is not None:
                entry.update(type="NETWORK", network_ids=_resolve_networks(list(op["networks"]), networks), client_macs=[])
            want = op.get("applies_to")
            if want and {"clients": "DEVICE", "networks": "NETWORK"}[want] != entry.get("type"):
                raise UniFiError(f"applies_to {want} needs {'clients' if want == 'clients' else 'networks'} to be given as well.")
            if op.get("apps") is not None:
                entry.update(target_type="APP_ID", app_ids=[int(a) for a in op["apps"]], app_category_ids=[])
            if op.get("categories") is not None:
                entry.update(target_type="APP_CATEGORY", app_category_ids=[int(c) for c in op["categories"]], app_ids=[])
            if op.get("schedule") is not None:
                entry["schedule"] = normalise_schedule(dict(op["schedule"]))
            if idx is None:
                blocks.append(entry)
            else:
                blocks[idx] = entry
        except UniFiError as exc:
            raise UniFiError(f"{where}: {exc}") from None
    return blocks


# ----------------------------------------------------------------------------------------------- validation
def _label(b: dict[str, Any], names: dict[str, str]) -> str:
    who = (f"{len(b.get('client_macs') or [])} client(s)" if b.get("type") == "DEVICE"
           else ", ".join(names.get(i, i) for i in b.get("network_ids") or []) or "no network")
    what = (f"{len(b.get('app_ids') or [])} application(s)" if b.get("target_type") == "APP_ID"
            else f"{len(b.get('app_category_ids') or [])} categor(y/ies)")
    return f"{what} for {who}"


def validate(action: str, before: dict[str, Any] | None, after: dict[str, Any], others: list[dict[str, Any]],
             ctx: dict[str, list[dict[str, Any]]]) -> Findings:
    f = Findings()
    old = {str(b.get("_id")): b for b in (before or {}).get("blocks", [])}
    new: list[dict[str, Any]] = after.get("blocks") or []
    nets = {str(n.get("_id")): n for n in ctx.get("networks", [])}
    names = {i: str(n.get("name")) for i, n in nets.items()}
    device_macs = {str(d.get("mac") or "").lower() for d in ctx.get("devices", [])}
    seen: set[str] = set()
    for b in new:
        nm = str(b.get("name") or "").strip()
        if not nm:
            f.errors.append("Every block needs a name.")
        elif len(nm) > 128:
            f.errors.append(f"'{nm[:20]}...': the name is longer than 128 characters.")
        elif nm.lower() in seen:
            f.errors.append(f"Two blocks are called '{nm}'. Names must be unique so a block can be addressed by name.")
        seen.add(nm.lower())
        if str(b.get("_id")) in old and same(old[str(b["_id"])], b):
            continue                                   # untouched: not re-validated, so an odd old entry cannot block other changes
        if b.get("type") not in ("DEVICE", "NETWORK"):
            f.errors.append(f"'{nm}': type must be DEVICE or NETWORK.")
        if b.get("target_type") not in ("APP_ID", "APP_CATEGORY"):
            f.errors.append(f"'{nm}': target_type must be APP_ID or APP_CATEGORY.")
        for key in ("app_ids", "app_category_ids", "client_macs", "network_ids"):
            if not isinstance(b.get(key), list):
                f.errors.append(f"'{nm}': {key} must be a list.")
        if f.errors:
            continue
        if b["type"] == "DEVICE":
            macs = b["client_macs"]
            if not macs:
                f.errors.append(f"'{nm}': a DEVICE block needs at least one client MAC.")
            if b["network_ids"]:
                f.errors.append(f"'{nm}': a DEVICE block has no networks.")
            bad = [m for m in macs if not _MAC.match(str(m))]
            if bad:
                f.errors.append(f"'{nm}': not a MAC address: {', '.join(map(str, bad))}.")
            if len(set(macs)) != len(macs):
                f.errors.append(f"'{nm}': duplicate client MACs.")
            devs = [m for m in macs if str(m).lower() in device_macs]
            if devs:
                f.errors.append(f"'{nm}': {', '.join(devs)} belongs to a UniFi device, not a client. Blocking apps for it is refused.")
        else:
            ids = b["network_ids"]
            if not ids:
                f.errors.append(f"'{nm}': a NETWORK block needs at least one network.")
            if b["client_macs"]:
                f.errors.append(f"'{nm}': a NETWORK block has no client MACs.")
            missing = [i for i in ids if i not in nets]
            if missing:
                f.errors.append(f"'{nm}': unknown network id(s): {', '.join(missing)}.")
            if len(ids) > 1:
                f.warnings.append(f"'{nm}': several networks in one block; the capture only had one.")
            if b["target_type"] == "APP_ID":
                f.warnings.append(f"'{nm}': a NETWORK block for specific applications was not captured; the console may refuse it.")
            protected = [names[i] for i in ids if names.get(i) in PROTECTED_NETWORKS]
            if protected:
                f.warnings.append(f"'{nm}' blocks traffic for the whole {', '.join(protected)} network.")
        key, other = (("app_ids", "app_category_ids") if b["target_type"] == "APP_ID" else ("app_category_ids", "app_ids"))
        vals = b[key]
        if not vals or any(isinstance(v, bool) or not isinstance(v, int) or v <= 0 for v in vals):
            f.errors.append(f"'{nm}': {key} must be a non-empty list of positive whole numbers.")
        elif len(set(vals)) != len(vals):
            f.errors.append(f"'{nm}': duplicate {key}.")
        if b[other]:
            f.errors.append(f"'{nm}': {other} must be empty for {b['target_type']}.")
        _schedule_findings(b.get("schedule"), f, nm)
        if not f.errors:
            f.warnings.append(f"'{nm}': blocks {_label(b, names)}, starting as soon as it is applied "
                              f"(schedule {b['schedule']['mode']}).")
    removed = [b for i, b in old.items() if i not in {str(x.get("_id")) for x in new}]
    if removed:
        f.warnings.append("These blocks will be deleted (their generated firewall policies go with them): "
                          + ", ".join(f"'{b.get('name')}'" for b in removed) + ".")
    if old and not new:
        f.warnings.append("This leaves NO application blocks at all.")
    return f


def _views(before: dict[str, Any] | None, after: dict[str, Any] | None) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    def view(row: dict[str, Any] | None) -> dict[str, Any] | None:
        if row is None:
            return None
        out: dict[str, Any] = {}
        for b in row.get("blocks") or []:
            key = str(b.get("name"))
            out[key if key not in out else f"{key} ({b.get('_id')})"] = {k: v for k, v in b.items() if k != "_id"}
        return out
    return view(before), view(after)


def _strip(b: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in b.items() if k != "_id"}


def verify(plan: Any, rows: list[dict[str, Any]], stored: dict[str, Any] | None) -> list[dict[str, Any]]:
    if stored is None:
        return []
    want: list[dict[str, Any]] = (plan.after or {}).get("blocks") or []
    got: list[dict[str, Any]] = stored.get("blocks") or []
    if len(got) != len(want):
        return [{"field": "blocks", "requested": f"{len(want)} block(s)", "stored": f"{len(got)} block(s)"}]
    out: list[dict[str, Any]] = []
    for w, g in zip(want, got):
        if not covers(_strip(g), _strip(w)):
            out.append({"field": f"block '{w.get('name')}'", "requested": _strip(w), "stored": _strip(g)})
        elif w.get("_id") and str(g.get("_id")) != str(w["_id"]):
            out.append({"field": f"block '{w.get('name')}'", "requested": f"id {w['_id']}", "stored": f"id {g.get('_id')}"})
        elif not w.get("_id") and not g.get("_id"):
            out.append({"field": f"block '{w.get('name')}'", "requested": "an id from the console", "stored": "none"})
    return out


def rollback(plan: Any, new_id: str | None) -> dict[str, Any]:
    previous = (plan.before or {}).get("blocks") or []
    # Replayable as is. Blocks that were deleted come back under new ids (the tool drops ids the console no longer has).
    return {"replace_all": previous}


def _body(before: dict[str, Any] | None, after: dict[str, Any] | None, effective: dict[str, Any]) -> Any:
    return list((after or {}).get("blocks") or [])


SPEC = EntitySpec(
    key=KEY, label="application block set", tier="B", list_op="listFirewallAppBlocks", update_op="replaceFirewallAppBlocks",
    singleton=True, id_field="_id", name_field="name", ignore=VOLATILE, validate_ctx=validate, verify=verify,
    verify_skip=frozenset({"blocks"}), focus=_views, rollback=rollback,
    wrap_rows=lambda rows: [{"_id": ROW_ID, "blocks": rows}],
    context_ops=(("networks", "listNetworkConfig"), ("devices", "listDevicesBasic")),
    action_ops={"update": ActionOp("replaceFirewallAppBlocks", _body, with_id=False)},
)


# ----------------------------------------------------------------------------------------------- tool
class ScheduleInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    mode: Literal["ALWAYS", "EVERY_DAY", "EVERY_WEEK", "ONE_TIME_ONLY", "CUSTOM"] = Field(
        ..., description="ALWAYS; EVERY_DAY (needs a time range); EVERY_WEEK (days, and a time range unless time_all_day); "
                         "ONE_TIME_ONLY (date and a time range); CUSTOM (date_start, date_end, days, and a time range unless time_all_day).")
    time_range_start: str | None = Field(default=None, description="HH:MM, 24 hour.")
    time_range_end: str | None = Field(default=None, description="HH:MM, 24 hour.")
    time_all_day: bool | None = Field(default=None, description="EVERY_WEEK and CUSTOM only: the whole day, no time range.")
    repeat_on_days: list[Literal["mon", "tue", "wed", "thu", "fri", "sat", "sun"]] | None = Field(default=None, description="EVERY_WEEK and CUSTOM.")
    date: str | None = Field(default=None, description="ONE_TIME_ONLY: YYYY-MM-DD.")
    date_start: str | None = Field(default=None, description="CUSTOM: YYYY-MM-DD.")
    date_end: str | None = Field(default=None, description="CUSTOM: YYYY-MM-DD.")


class BlockChange(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    op: Literal["create", "update", "delete"] = Field(..., description="Add a block, change one, or remove one.")
    target: str | None = Field(default=None, description="Existing block: its id or exact name. Not used by create.")
    name: str | None = Field(default=None, description="Block name (unique).")
    applies_to: Literal["clients", "networks"] | None = Field(default=None, description="Optional check that the block is for clients or for networks.")
    clients: list[str] | None = Field(default=None, description="Client MAC addresses to block (a DEVICE block). UniFi devices are refused.")
    networks: list[str] | None = Field(default=None, description="Networks to block, by name or id (a NETWORK block).")
    apps: list[int] | None = Field(default=None, description="Application ids to block, as the console stores them.")
    categories: list[int] | None = Field(default=None, description="Application category ids to block, as the console stores them.")
    schedule: ScheduleInput | None = Field(default=None, description="When the block applies. Required for create.")


class AppBlockInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    changes: list[BlockChange] | None = Field(
        default=None, description="One or more changes, applied together in a single request (as the UI's Apply button does).")
    replace_all: list[dict[str, Any]] | None = Field(
        default=None, description="Replace the whole set with exactly this list (used by a recorded rollback). [] removes every block.")
    approval_note: str | None = Field(default=None, description="Reference to the approved plan. Required to block a whole protected network such as LAN_Private.")
    confirm: bool = Field(default=False, description="false (default) returns a read-only preview. true applies the change and needs fingerprint.")
    fingerprint: str | None = Field(default=None, description="From the preview of exactly this change; required with confirm=true.")


def _needs_approval(blocks: list[dict[str, Any]], live: list[dict[str, Any]], networks: list[dict[str, Any]]) -> list[str]:
    names = {str(n.get("_id")): str(n.get("name")) for n in networks}
    old = {str(b.get("_id")): b for b in live}
    hits: list[str] = []
    for b in blocks:
        if b.get("type") != "NETWORK" or (str(b.get("_id")) in old and same(old[str(b["_id"])], b)):
            continue
        if any(names.get(i) in PROTECTED_NETWORKS for i in b.get("network_ids") or []):
            hits.append(str(b.get("name")))
    return hits


def _summary(live: list[dict[str, Any]], new: list[dict[str, Any]]) -> dict[str, list[str]]:
    old = {str(b.get("_id")): b for b in live}
    ids = {str(b.get("_id")) for b in new}
    return {
        "create": [str(b.get("name")) for b in new if str(b.get("_id")) not in old],
        "update": [str(b.get("name")) for b in new if str(b.get("_id")) in old and not same(old[str(b["_id"])], b)],
        "delete": [str(b.get("name")) for i, b in old.items() if i not in ids],
    }


async def _policy_check(engine: WriteEngine, blocks: list[dict[str, Any]]) -> dict[str, Any]:
    """After applying: do the generated `simple_app_block` policies exist for the stored blocks? Informational."""
    try:
        policies = await engine._read_list("listFirewallPoliciesWithHits")
    except UniFiError as exc:
        return {"checked": False, "reason": str(exc)}
    have = {str(p.get("origin_id")) for p in policies if p.get("origin_type") == "simple_app_block"}
    missing = [str(b.get("name")) for b in blocks if str(b.get("_id")) not in have]
    return {"checked": True, "blocks": len(blocks), "with_generated_policy": len(blocks) - len(missing), "missing": missing}


def register(mcp: MCPServer, engine: WriteEngine) -> None:
    @mcp.tool(
        name=TOOL,
        annotations={"title": "Add, change or remove application blocks (Simple App Blocking)", "readOnlyHint": False,
                     "destructiveHint": True, "idempotentHint": False, "openWorldHint": False},
    )
    async def unifi_console_app_block(params: AppBlockInput) -> str:
        """Preview, then apply, changes to the console's application blocks (Settings > Security > Simple App Blocking). Reading
        the current blocks is unifi_console_call_operation with listFirewallAppBlocks.

        Two steps, always: call with confirm=false for a read-only preview (the blocks before and after, a diff, warnings, a
        fingerprint); call again with the same changes plus confirm=true and that fingerprint to apply. The console stores
        all blocks as one set that every write replaces, so this tool reads the whole set, applies your `changes` to it and
        sends it back in a single request, exactly as the UI's Apply button does; the fingerprint covers every block, so
        a preview is refused if any block changed meanwhile. Each change is create, update or delete. A block is for clients
        (`clients`: MAC addresses; UniFi devices are refused) or for networks (`networks`: names or ids), and names
        applications (`apps`: application ids) or categories (`categories`: category ids), with a `schedule` (ALWAYS,
        EVERY_DAY, EVERY_WEEK, ONE_TIME_ONLY or CUSTOM). A new block starts blocking as soon as it is applied, so create
        needs an explicit schedule. Blocking a whole protected network such as LAN_Private also needs approval_note.
        `replace_all` sets the exact list (this is what a recorded rollback uses; [] removes every block). Applying also needs
        UNIFI_CONSOLE_ENABLE_WRITES=true and 'app_block' in UNIFI_CONSOLE_WRITE_ENTITIES. After applying, the set is read
        back and checked, the generated firewall policies are checked, the result reports verified true/false, the diff and
        the rollback call, and the change is journalled.
        """
        try:
            if bool(params.changes) == (params.replace_all is not None):
                return json.dumps({"ok": False, "error": "Give either changes (a non-empty list) or replace_all, not both and not neither."})
            live = await engine._read_list("listFirewallAppBlocks")
            networks = await engine._read_list("listNetworkConfig")
            if params.replace_all is not None:
                known = {str(b.get("_id")) for b in live}
                new = []
                for b in params.replace_all:
                    b = copy.deepcopy(b)
                    if b.get("_id") is not None and str(b["_id"]) not in known:
                        b.pop("_id")                        # a deleted block comes back under a new id
                    new.append(b)
            else:
                new = build_blocks(live, [c.model_dump(exclude_none=True) for c in params.changes or []], networks)
            protected = _needs_approval(new, live, networks)
            if protected and not (params.approval_note or "").strip():
                return json.dumps({"ok": False, "error": f"Blocking a whole protected network ({', '.join(protected)}) needs approval_note "
                                                         "naming the plan that was approved."})
            result = await engine.execute(SPEC, action="update", target=None, changes={"blocks": new},
                                          confirm=params.confirm, fingerprint=params.fingerprint,
                                          approval_note=params.approval_note)
            result["summary"] = _summary(live, new)
            if result.get("applied"):
                stored = await engine._read_list("listFirewallAppBlocks")
                result["generated_policies"] = await _policy_check(engine, stored)
            return json.dumps(result, separators=(",", ":"), default=str)
        except Exception as exc:  # noqa: BLE001 - converted to an actionable message
            return error_text(exc)
