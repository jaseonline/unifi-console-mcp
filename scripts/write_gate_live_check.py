"""Prove the write gate on the real console without changing anything.

    uv run scripts/write_gate_live_check.py

SAFETY
  * Nothing is ever applied: a confirm is only sent to servers where the gate must refuse it (read-only, entity switched
    off), and the cases where it would be allowed are previewed only. A snapshot of every switch's port_overrides taken first is compared at the end.
  * Goes through the real tool in-process. The Claude Desktop configuration is not touched.
  * The change used is a rename of the unused, link-down port 12 on Switch 16 PoE (name only).

Checks
  1. default server: the preview works and the only thing standing in the way of an apply is the tier C approval note
  2. UNIFI_CONSOLE_READ_ONLY server: a confirmed apply is refused and the reason names UNIFI_CONSOLE_READ_ONLY
  3. UNIFI_CONSOLE_DISABLE_ENTITIES=switch_port server: refused, reason names UNIFI_CONSOLE_DISABLE_ENTITIES
  4. a different disabled entity (wan) leaves switch_port previews unblocked by the entity switch
  5. the deprecated variables still map: ENABLE_WRITES=false means read-only, with a deprecation note
  6. nothing changed: port_overrides of every switch match the snapshot
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import sys
from typing import Any

from mcp.client import Client

from unifi_console_mcp.config import Settings
from unifi_console_mcp.entities.switch_port import SPEC
from unifi_console_mcp.server import create_server
from unifi_console_mcp.writes import WriteEngine

TOOL = "unifi_console_switch_port"
NOTE = "write gate live check: refusal proof only, nothing is applied"
ARGS = {"target": "Switch 16 PoE", "port": 12, "name": "zz-gate-check"}


async def tool(client: Client, args: dict[str, Any]) -> Any:
    res = await client.call_tool(TOOL, {"params": args})
    text = res.content[0].text
    try:
        return json.loads(text)
    except ValueError:
        return {"ok": False, "error": text}


async def snapshot(api: Any) -> dict[str, str]:
    rows = await WriteEngine(api)._rows(SPEC)
    return {
        str(r["_id"]): json.dumps(
            sorted(r.get("port_overrides") or [], key=lambda e: e.get("port_idx", 0)), sort_keys=True
        )
        for r in rows
        if r.get("type") == "usw"
    }


async def attempt(
    client: Client, api: Any, settings: Settings, *, confirm: bool
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Preview, then (only when confirm is set, and only where the gate must refuse) try to apply it."""
    api.settings = settings
    pre = await tool(client, ARGS)
    if not confirm:
        return pre, {}
    out = await tool(client, {**ARGS, "confirm": True, "fingerprint": pre.get("fingerprint"), "approval_note": NOTE})
    return pre, out


def check(label: str, ok: bool, detail: str = "") -> bool:
    print(f"  {'PASS' if ok else 'FAIL'}  {label}" + (f"  [{detail}]" if detail else ""))
    return ok


async def main() -> int:
    mcp, api = create_server(Settings.from_env())
    try:
        async with Client(mcp) as client:
            return await run(client, api)
    finally:
        await api.client.aclose()


async def run(client: Client, api: Any) -> int:
    base = dataclasses.replace(
        Settings.from_env(), enable_writes=True, write_entities=frozenset(), disabled_entities=frozenset()
    )
    before = await snapshot(api)
    results: list[bool] = []

    print("[1] default server (writes on)")
    pre, _ = await attempt(client, api, base, confirm=False)
    results.append(check("preview works", bool(pre.get("ok") and pre.get("preview")), str(pre.get("error"))))
    results.append(
        check(
            "only the tier C approval note blocks it (not the gate)",
            "approval_note" in str(pre.get("apply_blocked_reason")) and not pre.get("errors"),
            str(pre.get("errors") or pre.get("apply_blocked_reason"))[:200],
        )
    )

    print("[2] UNIFI_CONSOLE_READ_ONLY")
    pre, out = await attempt(client, api, dataclasses.replace(base, enable_writes=False), confirm=True)
    results.append(check("preview still works", bool(pre.get("ok") and pre.get("preview"))))
    reason = str(pre.get("apply_blocked_reason"))
    results.append(check("preview says why it cannot apply", "UNIFI_CONSOLE_READ_ONLY" in reason, reason[:90]))
    results.append(
        check("confirmed apply refused", not out.get("applied") and "READ_ONLY" in json.dumps(out), str(out)[:90])
    )

    print("[3] UNIFI_CONSOLE_DISABLE_ENTITIES=switch_port")
    pre, out = await attempt(
        client, api, dataclasses.replace(base, disabled_entities=frozenset({"switch_port"})), confirm=True
    )
    reason = str(pre.get("apply_blocked_reason"))
    results.append(
        check("preview says the entity is switched off", "UNIFI_CONSOLE_DISABLE_ENTITIES" in reason, reason[:90])
    )
    results.append(
        check(
            "confirmed apply refused", not out.get("applied") and "DISABLE_ENTITIES" in json.dumps(out), str(out)[:90]
        )
    )

    print("[4] a different entity disabled (wan)")
    pre, _ = await attempt(client, api, dataclasses.replace(base, disabled_entities=frozenset({"wan"})), confirm=False)
    reason = str(pre.get("apply_blocked_reason"))
    results.append(check("switch_port not blocked by the entity switch", "DISABLE_ENTITIES" not in reason, reason[:90]))

    print("[5] deprecated variables")
    saved = {k: os.environ.get(k) for k in ("UNIFI_CONSOLE_ENABLE_WRITES", "UNIFI_CONSOLE_READ_ONLY")}
    try:
        os.environ["UNIFI_CONSOLE_ENABLE_WRITES"] = "false"
        os.environ.pop("UNIFI_CONSOLE_READ_ONLY", None)
        s = Settings.from_env()
        results.append(
            check(
                "ENABLE_WRITES=false still means read-only, with a note",
                s.enable_writes is False and any("READ_ONLY" in n for n in s.deprecations),
                "; ".join(s.deprecations)[:90],
            )
        )
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    print("[6] nothing changed")
    api.settings = base
    after = await snapshot(api)
    results.append(check("every switch's port_overrides match the snapshot", before == after))

    ok = all(results)
    print("\nRESULT:", "all checks passed" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
