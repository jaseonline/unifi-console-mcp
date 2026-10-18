"""Prove the Dynamic DNS tool on the real console using one inert throwaway entry, and show the token never leaks.

    uv run scripts/dynamic_dns_live_check.py            # dry run: prints the plan, touches nothing
    uv run scripts/dynamic_dns_live_check.py --run      # performs it

SAFETY
  * Goes through the real tool (preview, then confirm with the fingerprint, journal, read-back), in-process. Writes are
    enabled for THIS process only; the Claude Desktop server configuration is not changed.
  * Creates exactly one entry (and updates its login once): service "custom", host "zz-ddnscheck.invalid", server "zz-ddnscheck.invalid", on "wan2".
    ".invalid" never resolves, so even if the gateway tried to use the entry it could not reach any provider, and this
    gateway has no second WAN. The token is a made-up value placed in this process's environment only
    (UNIFI_DDNS_ZZCHECK); no real token is read or sent.
  * The real Cloudflare entry is never edited or deleted. Before and after, all other entries are compared field by field.
  * The script asserts that the made-up token appears nowhere in anything the tool returned or in the journal files.
  * The delete is first tried WITHOUT discard_token (it must be refused), then applied with it. The entry is deleted in a
    finally block, also when a step fails; leftovers named zz-ddnscheck* are removed first.
"""
from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import secrets
import sys
from typing import Any

from mcp.client import Client

from unifi_console_mcp.config import Settings
from unifi_console_mcp.entities.dynamic_dns import SPEC
from unifi_console_mcp.server import create_server
from unifi_console_mcp.writes import WriteEngine

PREFIX = "zz-ddnscheck"
HOST = f"{PREFIX}.invalid"
ENV = "UNIFI_DDNS_ZZCHECK"
TOOL = "unifi_console_dynamic_dns"
KEYS = ("_id", "service", "host_name", "interface", "login", "server")

PLAN = f"""\
1. list the Dynamic DNS entries (read only) and remember each one, field by field (the real Cloudflare entry included)
2. create "{HOST}" (service custom, server {HOST}, interface wan2) with a made-up token from {ENV}; preview then apply;
   the result must say the token was not verified and must not contain it
3. read the entry back through listDynamicDns and check every non-secret field
4. update it (login zz-check to zz-check-2, token supplied again from the same variable): the id must stay the same, the
   stored login must change, nothing else may, and the token must not appear anywhere
5. try to delete it without discard_token (must be refused), then delete it with discard_token and check it is gone
6. confirm every other entry is exactly as it was, no leftovers remain, and the token is in no output or journal file"""


async def tool(client: Client, args: dict[str, Any], seen: list[str]) -> dict[str, Any]:
    res = await client.call_tool(TOOL, {"params": args})
    text = res.content[0].text
    seen.append(text)
    return json.loads(text)


async def apply(client: Client, args: dict[str, Any], seen: list[str]) -> dict[str, Any]:
    pre = await tool(client, args, seen)
    if not pre.get("ok"):
        raise RuntimeError(f"preview failed: {pre.get('error')}")
    if pre["errors"] or pre["apply_blocked_reason"]:
        raise RuntimeError(f"preview not applicable: {pre['errors'] or pre['apply_blocked_reason']}")
    out = await tool(client, {**args, "confirm": True, "fingerprint": pre["fingerprint"]}, seen)
    if not out.get("ok"):
        raise RuntimeError(f"apply failed: {out.get('error')}")
    out["_preview"] = pre
    return out


def snapshot(rows: list[dict[str, Any]]) -> list[tuple]:
    return sorted(tuple(str(r.get(k)) for k in KEYS) for r in rows if not str(r.get("host_name", "")).startswith(PREFIX))


async def main(run: bool, transport: Any = None) -> int:
    print("Plan:\n" + PLAN)
    if not run:
        print("\nDry run only. Add --run to perform it.")
        return 0
    token = "zz-" + secrets.token_hex(12)
    os.environ[ENV] = token
    settings = dataclasses.replace(Settings.from_env(), enable_writes=True, write_entities=frozenset({"dynamic_dns"}))
    mcp, api = create_server(settings, transport=transport)
    engine = WriteEngine(api)
    failures = 0
    seen: list[str] = []
    try:
        async with Client(mcp) as client:
            before = await engine._rows(SPEC)
            others_before = snapshot(before)
            print(f"\n[1] {len(before)} existing entr{'y' if len(before) == 1 else 'ies'}; {len(others_before)} are not ours")
            for r in before:
                print(f"    {r.get('host_name')} ({r.get('service')} on {r.get('interface')})")
                if str(r.get("host_name", "")).startswith(PREFIX):
                    out = await apply(client, {"action": "delete", "target": r["_id"], "discard_token": True}, seen)
                    print(f"  removed leftover {r.get('host_name')}: verified={out['verified']}")

            created_id: str | None = None
            try:
                print("\n[2] create")
                out = await apply(client, {"action": "create", "service": "custom", "host_name": HOST, "interface": "wan2",
                                           "login": "zz-check", "server": HOST, "token_env": ENV}, seen)
                created_id = out["id"]
                print(f"  verified={out['verified']} id={created_id} not verified (write-only): {out.get('secret_fields_not_verified')}")
                failures += not out["verified"] or out.get("secret_fields_not_verified") != ["x_password"]

                print("\n[3] read back")
                row = next((r for r in await engine._rows(SPEC) if r.get("_id") == created_id), None)
                want = {"service": "custom", "host_name": HOST, "interface": "wan2", "login": "zz-check", "server": HOST}
                ok = row is not None and all(row.get(k) == v for k, v in want.items())
                print(f"  stored fields match: {ok}")
                failures += not ok

                print("\n[4] update (same token supplied again, login changes)")
                out = await apply(client, {"action": "update", "target": created_id, "login": "zz-check-2", "token_env": ENV}, seen)
                row = next((r for r in await engine._rows(SPEC) if r.get("_id") == created_id), None)
                want = {"service": "custom", "host_name": HOST, "interface": "wan2", "login": "zz-check-2", "server": HOST}
                ok = row is not None and all(row.get(k) == v for k, v in want.items()) and out["id"] == created_id
                print(f"  verified={out['verified']} same id={out['id'] == created_id} stored fields match: {ok} "
                      f"diff keys={sorted(out['diff'])} not verified (write-only): {out.get('secret_fields_not_verified')}")
                failures += not (out["verified"] and ok)

                print("\n[5] delete: refused without discard_token, then applied with it")
                pre = await tool(client, {"action": "delete", "target": created_id}, seen)
                refused = await tool(client, {"action": "delete", "target": created_id, "confirm": True,
                                              "fingerprint": pre["fingerprint"]}, seen)
                print(f"  refused without discard_token: {refused.get('ok') is False}; warning shown: {bool(pre['warnings'])}")
                failures += refused.get("ok") is not False
                out = await apply(client, {"action": "delete", "target": created_id, "discard_token": True}, seen)
                print(f"  verified={out['verified']} rollback={out['rollback']['action']} note={out['rollback'].get('note')!r}")
                failures += not out["verified"]
                created_id = None
            except Exception as exc:  # report, then fall through to cleanup
                failures += 1
                print(f"  ERROR: {type(exc).__name__}: {exc}")
            finally:
                if created_id:
                    try:
                        out = await apply(client, {"action": "delete", "target": created_id, "discard_token": True}, seen)
                        print(f"  cleanup delete: verified={out['verified']}")
                    except Exception as exc:  # noqa: BLE001
                        failures += 1
                        print(f"  CLEANUP FAILED, remove '{PREFIX}*' by hand: {exc}")

            after = await engine._rows(SPEC)
            leftovers = [r.get("host_name") for r in after if str(r.get("host_name", "")).startswith(PREFIX)]
            print(f"\n[6] other entries unchanged: {snapshot(after) == others_before}; leftovers: {leftovers or 'none'}")
            failures += snapshot(after) != others_before or bool(leftovers)
            journal = "".join(p.read_text(encoding="utf-8", errors="replace") for p in settings.journal_dir.glob("*.jsonl")) \
                if settings.journal_dir.exists() else ""
            leaked = any(token in text for text in seen) or token in journal
            print(f"    made-up token found in any tool output or journal file: {leaked}")
            failures += leaked
    finally:
        os.environ.pop(ENV, None)
        await api.client.aclose()
    print("\nRESULT:", "all checks passed" if not failures else f"{failures} check(s) FAILED")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main("--run" in sys.argv)))
