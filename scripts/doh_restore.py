"""Put the DNS over HTTPS setting back to what it was before the last change this server journalled.

    uv run scripts/doh_restore.py            # dry run: shows the last journalled values and the current ones, sends nothing
    uv run scripts/doh_restore.py --run      # posts the journalled values back and reads them back to check

For an emergency when a DoH change has broken DNS and the automatic restore did not (or could not) put it right. It does not go
through the tool's gates or the DNS probe, because it is the way out of a bad state; it only ever sends the four DoH keys
(`key`, `state`, `server_names`, `custom_servers`) taken from the `before` of the newest DoH `attempt` in the journal. If the
journal has none, it stops. The UniFi UI (Settings > Security > DNS over HTTPS ... or Internet > DNS) is the other way out.
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from unifi_console_mcp.client import explain_status
from unifi_console_mcp.config import Settings
from unifi_console_mcp.redact import unwrap
from unifi_console_mcp.server import create_server

KEYS = ("state", "server_names", "custom_servers")


def last_attempt(journal_dir: Path) -> dict[str, Any] | None:
    found = None
    for path in sorted(journal_dir.glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if entry.get("event") == "attempt" and entry.get("entity") == "doh" and isinstance(entry.get("before"), dict):
                found = entry
    return found


def show(label: str, group: dict[str, Any]) -> None:
    names = ", ".join(group.get("server_names") or []) or "-"
    custom = ", ".join(str(c.get("server_name")) for c in group.get("custom_servers") or []) or "-"
    print(f"{label}: state={group.get('state')} server_names=[{names}] custom_servers=[{custom}]")


async def read_group(api: Any) -> dict[str, Any]:
    op = api.registry.get("getSiteSetting")
    path = op.build_path({"key": "doh"}, api.settings.site)
    resp = await api.client.request("GET", path, needs_session=op.needs_session)
    if resp.status_code >= 400:
        raise RuntimeError(explain_status(resp.status_code, path, resp.text))
    data = unwrap(resp.json())
    return (data[0] if isinstance(data, list) and data else data) or {}


async def main(run: bool, transport: Any = None, journal_dir: Path | None = None) -> int:
    settings = Settings.from_env()
    entry = last_attempt(journal_dir or settings.journal_dir)
    if entry is None:
        print(f"STOP: no DoH change found in the journal at {journal_dir or settings.journal_dir}. Nothing was sent. "
              "Use the UniFi UI to set DNS over HTTPS by hand.")
        return 1
    before = entry["before"]
    body = {"key": "doh", **{k: before.get(k, [] if k != "state" else "off") for k in KEYS}}
    print(f"Last journalled DoH change: {entry.get('journal_id')} ({entry.get('approval_note') or 'no note'})")
    show("Values before that change", body)
    _, api = create_server(settings, transport=transport)
    try:
        current = await read_group(api)
        show("Current values            ", current)
        if all(current.get(k) == body[k] for k in KEYS):
            print("Already the same. Nothing to do.")
            return 0
        if not run:
            print("Dry run only. Add --run to post the earlier values back.")
            return 0
        op = api.registry.get("updateDohSetting")
        path = op.build_path({}, settings.site)
        resp = await api.client.request(op.method, path, json_body=body, needs_session=op.needs_session, send_body=True)
        if resp.status_code >= 400:
            print("FAILED:", explain_status(resp.status_code, path, resp.text))
            return 1
        after = await read_group(api)
        show("Now                       ", after)
        ok = all(after.get(k) == body[k] for k in KEYS)
        print("RESULT:", "restored and verified" if ok else "sent, but the console does not show the earlier values; check the UI")
        return 0 if ok else 1
    finally:
        await api.client.aclose()


if __name__ == "__main__":
    sys.exit(asyncio.run(main("--run" in sys.argv)))
