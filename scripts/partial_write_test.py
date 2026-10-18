"""Find out how the console treats a PARTIAL body on update (which omitted fields are kept, cleared or rejected).

    uv run scripts/partial_write_test.py            # dry run: prints the plan, touches nothing
    uv run scripts/partial_write_test.py --run      # performs the test

SAFETY
  * Only creates, edits and deletes objects whose name starts with "zz-partial-". Nothing that already exists is read
    for modification, edited or deleted.
  * Objects are created disabled or inert (documentation IP address, fake locally administered MAC addresses,
    an unused high port range, a disabled port forward).
  * Does not touch firewall policies, networks (VLANs), WLANs, devices, switch ports or real clients.
  * Everything created is deleted again, also when a step fails (try/finally), and leftovers from an earlier
    aborted run are removed first. A final check lists any "zz-partial-" object still present.
  * Uses the same account and settings as the MCP server (UNIFI_LOCAL_HOST, UNIFI_MCP_USERNAME, UNIFI_MCP_PASSWORD).
  * Prints field names and short values only. No secrets are involved.
"""
from __future__ import annotations

import asyncio
import json
import sys
from typing import Any

from unifi_console_mcp.client import UniFiClient
from unifi_console_mcp.config import Settings

PREFIX = "zz-partial-"
L = "/proxy/network/api/s/default"       # legacy API
V2 = "/proxy/network/v2/api/site/default"
VOLATILE = {"site_id", "attr_hidden_id", "attr_no_delete", "attr_no_edit"}

PLAN = """\
1. static DNS record   create -> PUT {value} only -> PUT {enabled} only -> read back -> delete
2. port forward        create (disabled) -> PUT {name} only -> read back -> delete
3. client group        create (2 fake MACs) -> PUT {id, name} without members -> read back -> delete
4. network (port) list create -> PUT {description} only -> read back -> delete
For each partial update the report says: HTTP status, fields that changed, fields that disappeared or were reset."""


class Runner:
    def __init__(self, client: UniFiClient) -> None:
        self.c = client
        self.cleanup: list[tuple[str, str]] = []   # (label, delete path)

    async def call(self, method: str, path: str, body: Any = None) -> tuple[int, Any]:
        resp = await self.c.request(method, path, json_body=body, send_body=body is not None)
        try:
            data = resp.json() if resp.content else None
        except ValueError:
            data = resp.text[:200]
        return resp.status_code, data

    @staticmethod
    def rows(data: Any) -> list[dict]:
        """Legacy replies are {meta, data: [...]}; v2 replies are the list or object itself."""
        if isinstance(data, dict) and "data" in data:
            data = data["data"]
        if isinstance(data, dict):
            return [data]
        return [d for d in (data or []) if isinstance(d, dict)]

    async def find(self, list_path: str, ident: str, key: str = "_id") -> dict | None:
        _, data = await self.call("GET", list_path)
        for row in self.rows(data):
            if row.get(key) == ident:
                return row
        return None

    @staticmethod
    def diff(before: dict, after: dict | None) -> str:
        if after is None:
            return "object not found after update"
        b = {k: v for k, v in before.items() if k not in VOLATILE}
        a = {k: v for k, v in after.items() if k not in VOLATILE}
        changed = {k: (b[k], a[k]) for k in b if k in a and b[k] != a[k]}
        gone = sorted(k for k in b if k not in a)
        new = sorted(k for k in a if k not in b)
        return json.dumps({"changed": changed, "disappeared": gone, "new": new}, default=str)

    async def step(self, label: str, method: str, path: str, body: Any, list_path: str, ident: str,
                   before: dict, key: str = "_id") -> dict | None:
        status, data = await self.call(method, path, body)
        note = "" if status < 300 else f"  reply: {str(data)[:200]}"
        after = await self.find(list_path, ident, key)
        print(f"  {label}: body keys {sorted(body)} -> HTTP {status}{note}")
        print(f"    result: {self.diff(before, after)}")
        return after if after is not None else before

    async def remove_leftovers(self) -> None:
        specs = [
            ("static DNS", f"{V2}/static-dns", "key", f"{V2}/static-dns/"),
            ("port forward", f"{L}/rest/portforward", "name", f"{L}/rest/portforward/"),
            ("client group", f"{V2}/network-members-group", "name", f"{V2}/network-members-group/"),
            ("network list", f"{L}/rest/firewallgroup", "name", f"{L}/rest/firewallgroup/"),
        ]
        for label, lpath, namekey, dpath in specs:
            _, data = await self.call("GET", lpath)
            for row in self.rows(data):
                ident = row.get("_id") or row.get("id")
                if str(row.get(namekey, "")).startswith(PREFIX) and ident:
                    status, _ = await self.call("DELETE", dpath + ident)
                    print(f"  removed leftover {label} {row.get(namekey)} -> HTTP {status}")

    async def delete_all(self) -> None:
        for label, path in reversed(self.cleanup):
            status, _ = await self.call("DELETE", path)
            print(f"  cleanup {label}: HTTP {status}")
        self.cleanup.clear()


async def test_static_dns(r: Runner) -> None:
    print("\n[1] static DNS record")
    body = {"record_type": "A", "value": "192.0.2.1", "key": f"{PREFIX}dns.example.home", "enabled": True}
    status, data = await r.call("POST", f"{V2}/static-dns", body)
    print(f"  create -> HTTP {status}")
    rec = (r.rows(data) or [None])[0]
    if not rec or "_id" not in rec:
        rec = next((x for x in r.rows((await r.call("GET", f"{V2}/static-dns"))[1]) if x.get("key") == body["key"]), None)
    if not rec:
        print("  could not find the created record; stopping this test")
        return
    ident = rec["_id"]
    r.cleanup.append(("static DNS", f"{V2}/static-dns/{ident}"))
    cur = await r.find(f"{V2}/static-dns", ident)
    cur = await r.step("partial: value only", "PUT", f"{V2}/static-dns/{ident}", {"value": "192.0.2.2"},
                       f"{V2}/static-dns", ident, cur)
    cur = await r.step("partial: enabled only", "PUT", f"{V2}/static-dns/{ident}", {"enabled": False},
                       f"{V2}/static-dns", ident, cur)
    await r.delete_all()


async def test_port_forward(r: Runner) -> None:
    print("\n[2] port forward (created disabled)")
    body = {"enabled": False, "name": f"{PREFIX}pf", "pfwd_interface": "wan", "destination_ip": "any",
            "destination_ips": [], "dst_port": "58699", "fwd": "10.88.1.15", "fwd_port": "58699",
            "proto": "tcp_udp", "src_limiting_enabled": False, "log": True}
    status, data = await r.call("POST", f"{L}/rest/portforward", body)
    print(f"  create -> HTTP {status}")
    rec = (r.rows(data) or [None])[0]
    if not rec or "_id" not in rec:
        print("  could not find the created rule; stopping this test")
        return
    ident = rec["_id"]
    r.cleanup.append(("port forward", f"{L}/rest/portforward/{ident}"))
    cur = await r.find(f"{L}/rest/portforward", ident)
    await r.step("partial: name only", "PUT", f"{L}/rest/portforward/{ident}", {"name": f"{PREFIX}pf-renamed"},
                 f"{L}/rest/portforward", ident, cur or rec)
    await r.delete_all()


async def test_client_group(r: Runner) -> None:
    print("\n[3] client group")
    body = {"name": f"{PREFIX}grp", "members": ["02:00:00:00:00:01", "02:00:00:00:00:02"], "type": "CLIENTS"}
    status, data = await r.call("POST", f"{V2}/network-members-group", body)
    print(f"  create -> HTTP {status}")
    rec = (r.rows(data) or [None])[0]
    if not rec or "id" not in rec:
        print("  could not find the created group; stopping this test")
        return
    ident = rec["id"]
    r.cleanup.append(("client group", f"{V2}/network-members-group/{ident}"))
    cur = await r.find(f"{V2}/network-members-group", ident, key="id") or rec
    await r.step("partial: id + name, members omitted", "PUT", f"{V2}/network-members-group/{ident}",
                 {"id": ident, "name": f"{PREFIX}grp-renamed"}, f"{V2}/network-members-group", ident, cur, key="id")
    await r.delete_all()


async def test_network_list(r: Runner) -> None:
    print("\n[4] network (port) list")
    body = {"_id": None, "name": f"{PREFIX}list", "group_type": "port-group",
            "group_members": ["58690-58699", "58700"], "source": "static", "description": "zz test"}
    status, data = await r.call("POST", f"{L}/rest/firewallgroup", body)
    print(f"  create -> HTTP {status}")
    rec = (r.rows(data) or [None])[0]
    if not rec or "_id" not in rec:
        print("  could not find the created list; stopping this test")
        return
    ident = rec["_id"]
    r.cleanup.append(("network list", f"{L}/rest/firewallgroup/{ident}"))
    cur = await r.find(f"{L}/rest/firewallgroup", ident) or rec
    await r.step("partial: description only", "PUT", f"{L}/rest/firewallgroup/{ident}",
                 {"description": "zz changed"}, f"{L}/rest/firewallgroup", ident, cur)
    await r.delete_all()


async def main(run: bool, transport: Any = None) -> None:
    print("Plan:\n" + PLAN)
    if not run:
        print("\nDry run only. Add --run to perform it.")
        return
    client = UniFiClient(Settings.from_env(), transport)
    r = Runner(client)
    try:
        print("\nRemoving leftovers from any earlier aborted run:")
        await r.remove_leftovers()
        for test in (test_static_dns, test_port_forward, test_client_group, test_network_list):
            try:
                await test(r)
            except Exception as exc:  # report and carry on; cleanup runs below
                print(f"  ERROR in {test.__name__}: {type(exc).__name__}: {exc}")
            finally:
                await r.delete_all()
        print("\nFinal check, anything left behind:")
        await r.remove_leftovers()
        print("done")
    finally:
        await r.delete_all()
        await client.aclose()


if __name__ == "__main__":
    asyncio.run(main("--run" in sys.argv))
