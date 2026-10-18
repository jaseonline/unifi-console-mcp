"""Managed configuration writes.

Every configuration write goes through `WriteEngine.execute`, which does the same things in the same order:

    read -> validate -> preview -> (confirm) -> journal -> send -> read back -> verify -> report

Nothing here is specific to one entity. An entity is described by an `EntitySpec` (which spec operations to use,
how its update body is shaped, how to validate it); the typed MCP tool for the entity lives in its own module.

Gates, all of which must pass before anything is sent:
  1. UNIFI_CONSOLE_ENABLE_WRITES=true
  2. the entity key is listed in UNIFI_CONSOLE_WRITE_ENTITIES
  3. confirm=true together with the fingerprint of the preview (the object is re-read, so a stale preview is refused)
  4. tier "C" entities also need a non-empty approval_note (the reference to the plan the operator approved)

A preview (confirm=false) is read-only and always allowed; it says whether applying would currently be refused.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .client import UniFiError, explain_status
from .redact import is_secret_key, redact, unwrap

ACTIONS = ("create", "update", "enable", "disable", "delete", "move")
# Fields the console maintains itself; never compared, never sent as a change, never part of a fingerprint.
VOLATILE = frozenset({"site_id", "attr_hidden_id", "attr_no_delete", "attr_no_edit"})


@dataclass
class Findings:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


Validator = Callable[[str, "dict[str, Any] | None", "dict[str, Any]", "list[dict[str, Any]]"], Findings]
# Same, plus the rows of the extra read-only lists named in `EntitySpec.context_ops`, keyed by the name given there.
ContextValidator = Callable[
    [str, "dict[str, Any] | None", "dict[str, Any]", "list[dict[str, Any]]", "dict[str, list[dict[str, Any]]]"], Findings]


@dataclass(frozen=True)
class Guard:
    """A live safety net for a setting whose change can cut something the operator depends on (for example DNS).

    `before(engine)` runs just before applying and returns a problem text, or None when all is well; a problem refuses
    the change. `after(engine, phase)` runs after the write is read back (phase "change"), and again after an automatic
    restore (phase "restore"). If it reports a problem after the change, the engine puts the previous values back once,
    journals it and says so. This does not depend on the caller being reachable.
    """

    describe: str
    before: Callable[[Any], Awaitable[str | None]]
    after: Callable[[Any, str], Awaitable[str | None]]


@dataclass(frozen=True)
class ActionOp:
    """Use another spec operation (and body) for one action, for endpoints that batch (a list body, no id in the path)."""

    op: str
    body: Callable[["dict[str, Any] | None", "dict[str, Any] | None", dict[str, Any]], Any] | None = None   # (before, after, effective) -> body
    with_id: bool = True              # whether the path carries the object's id


@dataclass(frozen=True)
class MovePlan:
    """What a reorder would send. `after` is the object as it should look afterwards (informational); `effective` is
    shown as the change; verification is left to `EntitySpec.verify`."""

    op: str
    body: Any
    after: dict[str, Any]
    effective: dict[str, Any]
    undo: Any = None                  # what the restore needs to put the order back (kept on the plan)


@dataclass(frozen=True)
class RestoreStep:
    op: str
    body: Any = None
    path_params: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EntitySpec:
    key: str                          # name used in UNIFI_CONSOLE_WRITE_ENTITIES, e.g. "port_forward"
    label: str                        # for messages, e.g. "port forward"
    tier: str                         # "A" reversible and local, "B" affects several clients, "C" can cut or expose the network
    list_op: str
    create_op: str | None = None
    update_op: str | None = None
    delete_op: str | None = None
    id_field: str = "_id"
    name_field: str = "name"
    whole_object: bool = False        # True: updates send the whole object (v2 endpoints, arrays); False: changed fields only
    defaults: Mapping[str, Any] = field(default_factory=dict)
    validate: Validator | None = None
    ignore: frozenset[str] = VOLATILE
    # Fields the console's own UI sends on create (for example `_id: null`). Sent, never compared on read-back.
    create_extra: Mapping[str, Any] = field(default_factory=dict)
    # Turns convenience inputs into real fields (for example add_members -> group_members) before planning.
    prepare: Callable[[str, "dict[str, Any] | None", dict[str, Any]], dict[str, Any]] | None = None
    # Same, but also given the rows of `context_ops` (for example to turn zone and network names into ids).
    prepare_ctx: Callable[[str, "dict[str, Any] | None", dict[str, Any], "dict[str, list[dict[str, Any]]]"], dict[str, Any]] | None = None
    # (operationId, label) pairs for lists whose objects may reference this one by id; checked on update and delete.
    reference_ops: tuple[tuple[str, str], ...] = ()
    # Alternative ways to address an existing object besides id and name (for example "mac"); compared case-insensitively.
    match_fields: tuple[str, ...] = ()
    # (key, operationId) pairs of read-only lists the validator needs (networks, active clients...). A failed read blocks the write.
    context_ops: tuple[tuple[str, str], ...] = ()
    validate_ctx: ContextValidator | None = None
    # Value that means "not set" for a field the console omits when empty; lets the rollback put it back.
    empty_values: Mapping[str, Any] = field(default_factory=dict)
    # A settings group rather than a list of objects: one row, no create or delete, no id in the update path.
    singleton: bool = False
    list_path_params: Mapping[str, str] = field(default_factory=dict)    # path parameters of the list operation (e.g. the setting key)
    fixed_path_params: Mapping[str, str] = field(default_factory=dict)   # path parameters always sent to update (e.g. the setting key)
    body_keys: tuple[str, ...] = ()   # when set, the update body is exactly these keys of the new object (as the UI sends it)
    guard: Guard | None = None
    # ---- entities whose actions use different endpoints (firewall policies)
    action_ops: Mapping[str, ActionOp] = field(default_factory=dict)         # action -> other operation and body
    body_drop: frozenset[str] = frozenset()                                  # read-only keys the list returns but a write must not send
    move: Callable[["dict[str, Any]", "list[dict[str, Any]]", dict[str, Any]], MovePlan] | None = None
    loose_verify: bool = False        # read-back may hold more nested keys than were sent (the console fills defaults)
    verify: Callable[["Plan", "list[dict[str, Any]]", "dict[str, Any] | None"], "list[dict[str, Any]]"] | None = None
    guard_when: Callable[["Plan"], bool] | None = None                       # default: update, enable and disable that change something
    restore: Callable[["Plan", "str | None"], "list[RestoreStep]"] | None = None   # compensating requests for the automatic restore
    restore_ok: Callable[["Plan", "list[dict[str, Any]]", "str | None"], bool] | None = None
    rollback: Callable[["Plan", "str | None"], "dict[str, Any] | None"] | None = None   # the tool call that undoes this change
    # Shows only the part of a big object that changes (one port of a switch): (before, after) -> (before view, after view).
    focus: Callable[["dict[str, Any] | None", "dict[str, Any] | None"], "tuple[dict[str, Any] | None, dict[str, Any] | None]"] | None = None


# ----------------------------------------------------------------------------------------------- helpers
def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def same(a: Any, b: Any) -> bool:
    """Equality that tolerates the console returning numbers as strings (and the reverse)."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, (list, tuple)) and isinstance(b, (list, tuple)):
        return len(a) == len(b) and all(same(x, y) for x, y in zip(a, b))
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(same(a[k], b[k]) for k in a)
    if a is None or b is None:
        return a is b
    return str(a) == str(b)


def covers(stored: Any, wanted: Any) -> bool:
    """`stored` contains everything in `wanted` (nested objects may hold more keys, for example defaults the console adds)."""
    if isinstance(stored, dict) and isinstance(wanted, dict):
        return all(k in stored and covers(stored[k], v) for k, v in wanted.items())
    if isinstance(stored, (list, tuple)) and isinstance(wanted, (list, tuple)):
        return len(stored) == len(wanted) and all(covers(x, y) for x, y in zip(stored, wanted))
    return same(stored, wanted)


def diff(before: dict[str, Any] | None, after: dict[str, Any] | None, ignore: frozenset[str] = VOLATILE) -> dict[str, Any]:
    b = {k: v for k, v in (before or {}).items() if k not in ignore}
    a = {k: v for k, v in (after or {}).items() if k not in ignore}
    return {k: {"from": b.get(k), "to": a.get(k)} for k in sorted(set(b) | set(a)) if not same(b.get(k), a.get(k))}


def _reply_error(data: Any) -> str | None:
    """Legacy endpoints can answer HTTP 200 with meta.rc == 'error'."""
    if isinstance(data, dict) and isinstance(data.get("meta"), dict) and data["meta"].get("rc") not in (None, "ok"):
        return str(data["meta"].get("msg") or data["meta"].get("rc"))
    return None


@dataclass
class Plan:
    spec: EntitySpec
    action: str
    method: str
    path: str
    needs_session: bool
    body: Any
    changes: dict[str, Any]
    before: dict[str, Any] | None
    after: dict[str, Any] | None
    ident: str | None
    findings: Findings
    fingerprint: str
    no_change: bool = False
    used_by: list[str] = field(default_factory=list)
    guard_info: dict[str, Any] | None = None
    undo: Any = None


# ----------------------------------------------------------------------------------------------- engine
class WriteEngine:
    def __init__(self, api: Any) -> None:
        self.api = api
        self._lock = asyncio.Lock()

    # ---- reading
    async def _read_list(self, op_id: str, path_params: Mapping[str, str] | None = None) -> list[dict[str, Any]]:
        op = self.api.registry.get(op_id)
        path = op.build_path(dict(path_params or {}), self.api.settings.site)
        resp = await self.api.client.request("GET", path, needs_session=op.needs_session)
        if resp.status_code >= 400:
            raise UniFiError(explain_status(resp.status_code, path, resp.text))
        data = unwrap(resp.json()) if resp.content else []
        if isinstance(data, dict):
            data = [data]
        return [r for r in (data or []) if isinstance(r, dict)]

    async def _rows(self, spec: EntitySpec) -> list[dict[str, Any]]:
        return await self._read_list(spec.list_op, spec.list_path_params)

    async def _context(self, spec: EntitySpec) -> dict[str, list[dict[str, Any]]]:
        out: dict[str, list[dict[str, Any]]] = {}
        for key, op_id in spec.context_ops:
            try:
                out[key] = await self._read_list(op_id)
            except UniFiError as exc:
                raise UniFiError(f"Could not read {key} to check this {spec.label} ({op_id}): {exc} Nothing was changed.") from None
        return out

    @staticmethod
    def _resolve(spec: EntitySpec, rows: list[dict[str, Any]], target: str) -> dict[str, Any]:
        by_id = [r for r in rows if str(r.get(spec.id_field)) == target]
        if by_id:
            return by_id[0]
        norm = target.strip().lower().replace("-", ":")
        for fld in spec.match_fields:
            hits = [r for r in rows if str(r.get(fld) or "").lower().replace("-", ":") == norm]
            if len(hits) == 1:
                return hits[0]
        by_name = [r for r in rows if r.get(spec.name_field) == target]
        if len(by_name) == 1:
            return by_name[0]
        if len(by_name) > 1:
            ids = ", ".join(str(r.get(spec.id_field)) for r in by_name)
            raise UniFiError(f"{len(by_name)} {spec.label}s are called '{target}'. Use one of these ids instead: {ids}.")
        raise UniFiError(f"No {spec.label} with id or exact name '{target}'. List them first to see what exists.")

    # ---- planning
    def _plan(self, spec: EntitySpec, rows: list[dict[str, Any]], action: str, target: str | None,
              changes: dict[str, Any], ctx: dict[str, list[dict[str, Any]]] | None = None) -> Plan:
        if action not in ACTIONS:
            raise UniFiError(f"Unknown action '{action}'. Use one of: {', '.join(ACTIONS)}.")
        ao = spec.action_ops.get(action)
        if action == "move":
            if not spec.move:
                raise UniFiError(f"The {spec.label} cannot be moved here.")
            wanted_op = None
        else:
            wanted_op = ao.op if ao else {"create": spec.create_op, "update": spec.update_op, "enable": spec.update_op,
                                          "disable": spec.update_op, "delete": spec.delete_op}[action]
            if not wanted_op:
                raise UniFiError(f"The {spec.label} cannot be {action}d here (the console has no such operation).")
        op = self.api.registry.get(wanted_op) if wanted_op else None
        site = self.api.settings.site
        findings = Findings()

        undo: Any = None
        if action == "create":
            if target:
                raise UniFiError("create does not take a target; pass the new values as fields.")
            before = None
            if spec.prepare:
                changes = spec.prepare(action, None, changes)
            if spec.prepare_ctx:
                changes = spec.prepare_ctx(action, None, changes, ctx or {})
            after = {**spec.defaults, **changes}
            ident = None
            path = op.build_path({}, site)
            body: Any = {**spec.create_extra, **{k: v for k, v in after.items() if k not in spec.body_drop}}
            if ao and ao.body:
                body = ao.body(None, after, dict(after))
            effective = dict(after)
        else:
            if spec.singleton:
                if len(rows) != 1:
                    raise UniFiError(f"Expected one {spec.label} but the console returned {len(rows)}. Nothing was changed.")
                before = rows[0]
                if target and target not in (str(before.get(spec.id_field)), spec.key):
                    raise UniFiError(f"The {spec.label} is a single settings group, so target '{target}' does not match it. Leave target empty.")
            else:
                if not target:
                    raise UniFiError(f"{action} needs a target: the {spec.label}'s id or exact name.")
                before = self._resolve(spec, rows, target)
            ident = str(before[spec.id_field])
            if action != "move":
                use_id = ao.with_id if ao else True
                path = op.build_path(dict(spec.fixed_path_params) if spec.singleton else
                                     ({"id": ident, **spec.fixed_path_params} if use_id else {}), site)
            if action == "delete" and before.get("attr_no_delete"):
                raise UniFiError(f"This {spec.label} is system-defined (the console marks it no-delete) and cannot be deleted.")
            if action != "delete" and before.get("attr_no_edit"):
                raise UniFiError(f"This {spec.label} is system-defined (the console marks it no-edit) and cannot be changed.")
            if action not in ("delete", "move") and spec.prepare:
                changes = spec.prepare(action, before, changes)
            if action not in ("delete", "move", "enable", "disable") and spec.prepare_ctx:
                changes = spec.prepare_ctx(action, before, changes, ctx or {})
            if action == "move":
                mp = spec.move(before, rows, changes)
                op = self.api.registry.get(mp.op)
                path = op.build_path({}, site)
                after, body, effective, undo = mp.after, mp.body, dict(mp.effective), mp.undo
            elif action == "delete":
                if changes:
                    raise UniFiError("delete takes no field changes.")
                after, body, effective = None, None, {}
                if ao and ao.body:
                    body = ao.body(before, None, {})
            else:
                if action in ("enable", "disable"):
                    if changes:
                        raise UniFiError(f"{action} takes no field changes; use update to change fields.")
                    changes = {"enabled": action == "enable"}
                effective = {k: v for k, v in changes.items() if not same(before.get(k), v)}
                after = {**before, **effective}
                body = ({k: v for k, v in after.items() if k not in spec.body_drop} if spec.whole_object else dict(effective))
                if spec.body_keys:
                    body = {k: after[k] for k in spec.body_keys if k in after}
                if ao and ao.body:
                    body = ao.body(before, after, effective)

        others = [r for r in rows if before is None or r.get(spec.id_field) != before.get(spec.id_field)]
        if spec.validate_ctx:           # also runs for delete, so it can warn about what depends on the object
            findings = spec.validate_ctx(action, before, after or {}, others, ctx or {})
        elif spec.validate and action != "delete":
            findings = spec.validate(action, before, after or {}, others)

        no_change = action in ("update", "enable", "disable", "move") and not effective
        stable_before = {k: v for k, v in (before or {}).items() if k not in spec.ignore}
        fingerprint = hashlib.sha256(_canon({
            "entity": spec.key, "action": action, "path": path, "before": stable_before, "body": body,
        }).encode()).hexdigest()[:16]
        return Plan(spec, action, op.method, path, op.needs_session, body, effective, before, after, ident,
                    findings, fingerprint, no_change, undo=undo)

    async def _check_references(self, plan: Plan) -> None:
        spec = plan.spec
        if not spec.reference_ops or plan.action == "create" or not plan.ident:
            return
        for op_id, label in spec.reference_ops:
            op = self.api.registry.get(op_id)
            path = op.build_path({}, self.api.settings.site)
            resp = await self.api.client.request("GET", path, needs_session=op.needs_session)
            if resp.status_code >= 400:
                raise UniFiError(f"Could not check what uses this {spec.label} (reading {label}s failed: {op_id}, HTTP {resp.status_code}). "
                                 "Nothing was changed.")
            data = unwrap(resp.json()) if resp.content else []
            for row in ([data] if isinstance(data, dict) else data or []):
                if isinstance(row, dict) and plan.ident in _canon(row):
                    who = row.get("name") or row.get("description") or row.get(spec.id_field) or row.get("id") or "(unnamed)"
                    plan.used_by.append(f"{label}: {who}")
        if not plan.used_by:
            return
        listing = "; ".join(plan.used_by[:10]) + (f" and {len(plan.used_by) - 10} more" if len(plan.used_by) > 10 else "")
        if plan.action == "delete":
            plan.findings.errors.append(
                f"This {spec.label} is still used by {len(plan.used_by)} object(s): {listing}. Remove it from those first.")
        else:
            plan.findings.warnings.append(
                f"This {spec.label} is used by {len(plan.used_by)} object(s): {listing}. The change takes effect for them "
                "as soon as it is applied.")

    @staticmethod
    def _guarded(plan: Plan) -> bool:
        spec = plan.spec
        if not spec.guard or plan.no_change:
            return False
        if spec.guard_when:
            return bool(spec.guard_when(plan))
        return plan.action in ("update", "enable", "disable")

    # ---- gates
    def blocked_reason(self, spec: EntitySpec, approval_note: str | None) -> str | None:
        s = self.api.settings
        if not s.enable_writes:
            return "Writes are disabled: set UNIFI_CONSOLE_ENABLE_WRITES=true in the server environment."
        if spec.key not in s.write_entities:
            return (f"'{spec.key}' is not enabled for writes: add it to UNIFI_CONSOLE_WRITE_ENTITIES "
                    f"(currently: {', '.join(sorted(s.write_entities)) or 'none'}).")
        if spec.tier == "C" and not (approval_note or "").strip():
            return "This is a tier C change (it can cut or expose the network): pass approval_note naming the plan that was approved."
        return None

    # ---- journal
    def _journal(self, entry: dict[str, Any]) -> None:
        directory: Path = self.api.settings.journal_dir
        try:
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            now = datetime.now(timezone.utc)
            line = json.dumps(redact({"time": now.isoformat(timespec="seconds"), **entry}), default=str)
            with open(directory / f"{now:%Y-%m}.jsonl", "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError as exc:
            raise UniFiError(f"Cannot write the change journal ({directory}): {exc}. Nothing was changed.") from None

    # ---- public entry point
    async def execute(self, spec: EntitySpec, *, action: str, target: str | None = None,
                      changes: dict[str, Any] | None = None, confirm: bool = False,
                      fingerprint: str | None = None, approval_note: str | None = None) -> dict[str, Any]:
        async with self._lock:
            rows = await self._rows(spec)
            ctx = await self._context(spec) if spec.context_ops else None
            plan = self._plan(spec, rows, action, target, dict(changes or {}), ctx)
            await self._check_references(plan)
            if spec.guard and self._guarded(plan):
                problem = await spec.guard.before(self)
                plan.guard_info = {"safety_net": spec.guard.describe, "check_before": problem or "ok"}
                if problem:
                    plan.findings.errors.append(f"Safety probe: {problem}")
                else:
                    plan.findings.warnings.append(spec.guard.describe)
            blocked = self.blocked_reason(spec, approval_note)

            if not confirm:
                return self._preview(plan, blocked)

            if blocked:
                raise UniFiError(blocked)
            if plan.findings.errors:
                raise UniFiError("Refused: " + " ".join(plan.findings.errors))
            if not fingerprint:
                raise UniFiError("confirm=true needs the fingerprint from a preview of exactly this change. Preview first.")
            if fingerprint != plan.fingerprint:
                raise UniFiError(
                    "The object, or the requested change, differs from the preview you confirmed "
                    "(the console state may have changed). Run the preview again and review it.")
            if plan.no_change:
                return {"ok": True, "applied": False, "entity": spec.key, "action": action, "id": plan.ident,
                        "note": "Already in the requested state; nothing was sent."}
            return await self._apply(plan, approval_note)

    def _preview(self, plan: Plan, blocked: str | None) -> dict[str, Any]:
        spec = plan.spec
        bview, aview = spec.focus(plan.before, plan.after) if spec.focus else (plan.before, plan.after)
        out: dict[str, Any] = {
            "ok": True, "applied": False, "preview": True, "entity": spec.key, "tier": spec.tier,
            "action": plan.action, "id": plan.ident,
            "request": {"method": plan.method, "path": plan.path,
                        "body_fields": sorted(plan.body) if isinstance(plan.body, dict) else None,
                        "body_style": "whole object" if spec.whole_object else "changed fields only"},
            "before": redact(bview), "after": redact(aview),
            "diff": redact(diff(bview, aview, spec.ignore if not spec.focus else VOLATILE)),
            "warnings": plan.findings.warnings, "errors": plan.findings.errors,
            "used_by": plan.used_by, "fingerprint": plan.fingerprint,
            "apply_blocked_reason": blocked or ("; ".join(plan.findings.errors) or None),
        }
        if plan.guard_info:
            out["guard"] = plan.guard_info
        if plan.no_change:
            out["note"] = "Already in the requested state; applying would send nothing."
        else:
            out["next_step"] = ("Review the diff and warnings. To apply, call again with the same fields, "
                                f"confirm=true and fingerprint='{plan.fingerprint}'.")
        return out

    # ---- applying
    async def _apply(self, plan: Plan, approval_note: str | None) -> dict[str, Any]:
        spec = plan.spec
        journal_id = uuid.uuid4().hex[:12]
        base = {"journal_id": journal_id, "entity": spec.key, "tier": spec.tier, "action": plan.action,
                "id": plan.ident, "method": plan.method, "path": plan.path, "approval_note": approval_note,
                "before": plan.before, "body": plan.body}
        self._journal({"event": "attempt", **base})     # no journal, no write

        client = self.api.client
        resp = await client.request(plan.method, plan.path, json_body=plan.body,
                                    needs_session=plan.needs_session, send_body=plan.body is not None)
        data: Any = None
        if resp.content:
            try:
                data = resp.json()
            except ValueError:
                data = resp.text[:200]
        problem = explain_status(resp.status_code, plan.path, resp.text) if resp.status_code >= 400 else _reply_error(data)
        if problem:
            self._journal({"event": "failed", "journal_id": journal_id, "http_status": resp.status_code, "error": problem})
            raise UniFiError(f"The console rejected the {plan.action}: {problem} Re-run the preview to see the current state.")

        new_id = plan.ident
        if plan.action == "create":
            created = unwrap(data)
            created = created[0] if isinstance(created, list) and created else created
            if isinstance(created, dict):
                new_id = str(created.get(spec.id_field) or "") or None

        rows = await self._rows(spec)
        stored: dict[str, Any] | None = None
        if plan.action == "create" and not new_id:
            name = (plan.after or {}).get(spec.name_field)
            match = [r for r in rows if r.get(spec.name_field) == name]
            if len(match) > 1:          # several objects may share a name (DNS records): narrow by what was sent
                match = [r for r in match if all(same(r.get(k), v) for k, v in plan.changes.items())]
            stored = match[0] if len(match) == 1 else None
            new_id = str(stored[spec.id_field]) if stored else None
        elif new_id:
            stored = next((r for r in rows if str(r.get(spec.id_field)) == new_id), None)

        mismatches: list[dict[str, Any]] = []
        # Secret fields (tokens, passwords) are write-only: never compared and never echoed, even in a mismatch.
        secrets_sent = sorted(k for k in plan.changes if is_secret_key(k))
        if plan.action == "delete":
            if stored is not None:
                mismatches.append({"field": "(object)", "requested": "deleted", "stored": "still present"})
        elif stored is None:
            mismatches.append({"field": "(object)", "requested": "present", "stored": "not found on read-back"})
        elif plan.action != "move":
            for key, wanted in plan.changes.items():
                if key in spec.ignore or is_secret_key(key):
                    continue
                if not (covers if spec.loose_verify else same)(stored.get(key), wanted):
                    mismatches.append({"field": key, "requested": wanted, "stored": stored.get(key)})
        if spec.verify:
            mismatches.extend(spec.verify(plan, rows, stored))
        verified = not mismatches

        guard_result: dict[str, Any] | None = None
        if spec.guard and self._guarded(plan):
            try:
                problem = await spec.guard.after(self, "change")
            except Exception as exc:  # noqa: BLE001 - a probe that cannot run counts as a failed probe
                problem = f"the probe could not run: {exc}"
            guard_result = ({"probe_after": "ok"} if not problem else await self._auto_restore(plan, journal_id, problem, new_id))

        result: dict[str, Any] = {
            "ok": True, "applied": True, "entity": spec.key, "tier": spec.tier, "action": plan.action,
            "id": new_id, "http_status": resp.status_code, "verified": verified,
            "diff": redact(self._result_diff(plan, stored)),
            "rollback": self._rollback(plan, new_id), "journal_id": journal_id,
        }
        if secrets_sent and plan.action != "delete":
            result["secret_fields_not_verified"] = secrets_sent      # sent, but write-only: the console never returns them
        if guard_result is not None:
            result["guard"] = guard_result
            if guard_result.get("auto_restored"):
                result.update(applied=False, verified=bool(guard_result.get("restore_verified")), rollback=None,
                              diff=redact(guard_result.get("diff_after_restore", {})),
                              attention=("The safety probe failed after the change, so the previous values were put back "
                                         "automatically. Nothing is changed. See guard for the probe result and the restore check."))
            elif guard_result.get("restore_error"):
                result["attention"] = (
                    "The safety probe failed after the change AND the automatic restore failed. Restore the previous values by hand now: "
                    "run scripts/doh_restore.py --run on the machine that runs this server, or use the UniFi UI. "
                    f"Restore error: {guard_result['restore_error']}")
        if mismatches:
            result["mismatches"] = redact(mismatches)
            result["attention"] = ("The console accepted the request but the stored object does not match it. "
                                   "Nothing was retried. Review the mismatches before doing anything else.")
        self._journal({"event": "result", "journal_id": journal_id, "http_status": resp.status_code,
                       "verified": verified, "after": stored, "mismatches": mismatches,
                       "auto_restored": bool(guard_result and guard_result.get("auto_restored"))})
        return result

    @staticmethod
    def _result_diff(plan: Plan, stored: dict[str, Any] | None) -> dict[str, Any]:
        spec = plan.spec
        if spec.focus:
            bview, aview = spec.focus(plan.before, stored)
            return diff(bview, aview, VOLATILE)
        return diff(plan.before, stored, spec.ignore)

    async def _send_json(self, method: str, path: str, body: Any, needs_session: bool) -> tuple[int, Any, str | None]:
        resp = await self.api.client.request(method, path, json_body=body, needs_session=needs_session, send_body=body is not None)
        data: Any = None
        if resp.content:
            try:
                data = resp.json()
            except ValueError:
                data = resp.text[:200]
        err = explain_status(resp.status_code, path, resp.text) if resp.status_code >= 400 else _reply_error(data)
        return resp.status_code, data, err

    async def _auto_restore(self, plan: Plan, journal_id: str, problem: str, new_id: str | None = None) -> dict[str, Any]:
        """The guard's probe failed after a change: put the previous values back, once, and report it."""
        spec = plan.spec
        before = plan.before or {}
        steps: list[tuple[str, str, Any, bool]] = []     # (method, path, body, needs_session)
        keys: list[str] = []
        if spec.restore:
            site = self.api.settings.site
            for st in spec.restore(plan, new_id):
                op = self.api.registry.get(st.op)
                steps.append((op.method, op.build_path(dict(st.path_params), site), st.body, op.needs_session))
            body: Any = [s_[2] for s_ in steps]
        else:
            if spec.body_keys:
                keys = list(spec.body_keys)
                body = {k: before[k] for k in keys if k in before}
            elif spec.whole_object:
                keys, body = [k for k in before if k not in spec.ignore], dict(before)
            else:
                keys, body = list(plan.changes), {k: before.get(k) for k in plan.changes}
            steps.append((plan.method, plan.path, body, plan.needs_session))
        info: dict[str, Any] = {"probe_after": f"failed: {problem}", "auto_restored": False}
        self._journal({"event": "guard_failed", "journal_id": journal_id, "problem": problem, "restore_body": body})
        status = 0
        try:
            for method, path, step_body, needs_session in steps:
                status, _data, err = await self._send_json(method, path, step_body, needs_session)
                if err:
                    raise UniFiError(err)
            rows = await self._rows(spec)
        except Exception as exc:  # noqa: BLE001 - reported loudly in the result
            info["restore_error"] = str(exc)
            self._journal({"event": "auto_restore_failed", "journal_id": journal_id, "error": str(exc)})
            return info
        restored = next((r for r in rows if str(r.get(spec.id_field)) == (plan.ident or new_id)), None)
        if spec.restore_ok:
            ok = spec.restore_ok(plan, rows, new_id)
        else:
            ok = restored is not None and all(same(restored.get(k), before.get(k)) for k in keys if k not in spec.ignore and not is_secret_key(k))
        try:
            after_restore = await spec.guard.after(self, "restore") if spec.guard else None
        except Exception as exc:  # noqa: BLE001
            after_restore = f"the probe could not run: {exc}"
        info.update(auto_restored=True, restore_verified=ok, probe_after_restore=("ok" if not after_restore else f"failed: {after_restore}"),
                    diff_after_restore=self._result_diff(plan, restored))
        self._journal({"event": "auto_restore", "journal_id": journal_id, "http_status": status, "restore_verified": ok,
                       "probe_after_restore": info["probe_after_restore"]})
        return info

    @staticmethod
    def _rollback(plan: Plan, new_id: str | None) -> dict[str, Any] | None:
        spec = plan.spec
        if spec.rollback:
            return spec.rollback(plan, new_id)
        if plan.action == "create":
            return {"action": "delete", "target": new_id}
        before = plan.before or {}
        keep = {k: v for k, v in before.items() if k not in spec.ignore and not is_secret_key(k)}
        skipped = sorted(k for k in before if is_secret_key(k))
        note = f"Secret fields were not recorded; re-enter them: {', '.join(skipped)}." if skipped else None
        if plan.action == "delete":
            keep.pop(spec.id_field, None)
            out: dict[str, Any] = {"action": "create", "changes": keep}
        else:
            restore = {k: (keep[k] if k in keep else spec.empty_values[k]) for k in plan.changes if k in keep or k in spec.empty_values}
            out = {"action": "update", "target": plan.ident, "changes": restore}
        if note:
            out["note"] = note
        return out


__all__ = ["ACTIONS", "ActionOp", "EntitySpec", "Findings", "Guard", "MovePlan", "Plan", "RestoreStep", "WriteEngine", "covers", "diff", "same"]
