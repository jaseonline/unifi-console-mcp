"""Simulate how an MCPB host launches the bundle, then talk MCP to it over stdio.

    uv run mcpb/smoke_test.py [path/to/unifi-console-mcp-X.mcpb]

Steps: unpack the .mcpb into a temp dir exactly as a host would, read manifest.json, substitute
${__dirname} and ${user_config.*}, spawn mcp_config.command with its args and env, then initialize,
list tools and call a few. Two scenarios:
  1. a filled-in configuration;
  2. optional fields left blank, once as "" and once as an unsubstituted literal ${user_config.KEY},
     which some hosts leave behind. The server must treat both as unset.
No console is needed: the host address is a closed local port, so calls that reach for the console return
a structured {"ok": false, "error": ...} instead of hanging.
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
import tempfile
import zipfile
from pathlib import Path

from mcp.client import Client
from mcp.client.stdio import StdioServerParameters

ROOT = Path(__file__).resolve().parent.parent
FIRST_RUN_TIMEOUT = 300  # uv creates the environment on first launch


def substitute(value: str, dirname: Path, config: dict[str, str]) -> str:
    def repl(m: re.Match[str]) -> str:
        key = m.group(1)
        if key == "__dirname":
            return str(dirname)
        if key.startswith("user_config."):
            return config.get(key.split(".", 1)[1], m.group(0))
        return m.group(0)

    return re.sub(r"\$\{([^}]+)\}", repl, value)


def params_for(
    manifest: dict, dirname: Path, config: dict[str, str], system_env: dict[str, str] | None = None
) -> StdioServerParameters:
    cfg = manifest["server"]["mcp_config"]
    return StdioServerParameters(
        command=cfg["command"],
        args=[substitute(a, dirname, config) for a in cfg.get("args", [])],
        # A host starts the server with its own environment plus the manifest env block, which wins.
        env={**(system_env or {}), **{k: substitute(v, dirname, config) for k, v in cfg.get("env", {}).items()}},
        cwd=str(dirname),
    )


def registry_has(name: str) -> bool:
    if sys.platform != "win32":
        return False
    import winreg

    for hive, sub in (
        (winreg.HKEY_CURRENT_USER, "Environment"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"),
    ):
        try:
            with winreg.OpenKey(hive, sub) as key:
                winreg.QueryValueEx(key, name)
                return True
        except OSError:
            continue
    return False


def parse(result) -> dict:
    assert result.content, "empty tool result"
    text = result.content[0].text
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        raise AssertionError(f"tool did not return JSON: {text[:300]}") from None


async def scenario(
    name: str, manifest: dict, dirname: Path, config: dict[str, str], system_env: dict[str, str] | None = None
) -> None:
    print(f"\n== {name}")
    async with Client(
        params_for(manifest, dirname, config, system_env), read_timeout_seconds=FIRST_RUN_TIMEOUT
    ) as client:
        info = client.server_info if hasattr(client, "server_info") else None
        if info is not None:
            print("server:", getattr(info, "name", info), getattr(info, "version", ""))
        tools = (await client.list_tools()).tools
        names = {t.name for t in tools}
        declared = {t["name"] for t in manifest["tools"]}
        assert names == declared, f"manifest/server tool mismatch: {sorted(names ^ declared)}"
        assert all(t.annotations and t.annotations.title for t in tools), "tool without a title"
        read_only = sorted(t.name for t in tools if t.annotations.read_only_hint)
        print(f"{len(tools)} tools, {len(read_only)} read-only, manifest matches")

        listed = parse(
            await client.call_tool("unifi_console_list_operations", {"params": {"search": "system log", "limit": 3}})
        )
        assert listed["ok"] is True and listed["operations"], listed
        print("list_operations ->", [o["operation_id"] for o in listed["operations"]])

        denied = parse(
            await client.call_tool("unifi_console_read_operation", {"params": {"operation_id": "no_such_operation"}})
        )
        assert denied["ok"] is False and denied["error"], denied
        print("unknown operation ->", denied["error"][:90])

        status = parse(await client.call_tool("unifi_console_session_status", {}))
        assert isinstance(status, dict) and "ok" in status, status
        assert "system-key" not in json.dumps(status), "secret leaked into a tool result"
        print("session_status (no console) ->", json.dumps(status)[:120])


async def main() -> None:
    bundle = (
        Path(sys.argv[1]) if len(sys.argv) > 1 else max((ROOT / "dist").glob("*.mcpb"), key=lambda p: p.stat().st_mtime)
    )
    print("bundle:", bundle)
    with tempfile.TemporaryDirectory(prefix="mcpb-smoke-") as tmp:
        dirname = Path(tmp) / "unifi-console-mcp"
        with zipfile.ZipFile(bundle) as z:
            z.extractall(dirname)
        manifest = json.loads((dirname / "manifest.json").read_text(encoding="utf-8"))
        for rel in [manifest["server"]["entry_point"], *(i["src"] for i in manifest.get("icons", []))]:
            assert (dirname / rel).is_file(), f"manifest references missing file {rel}"
        leaked = [p.name for p in dirname.rglob("*") if re.search(r"\.env|\.har$|journal|probe_out", p.name)]
        assert not leaked, f"unexpected files in bundle: {leaked}"

        base = {"console_host": "127.0.0.1", "port": "9", "verify_ssl": "false", "log_level": "DEBUG"}
        await scenario("filled configuration, writes off", manifest, dirname, {**base, "enable_writes": "false"})

        blanks = {k: "" for k in manifest["user_config"] if k not in base}
        await scenario("optional fields blank (empty strings)", manifest, dirname, {**base, **blanks})

        # Unsubstituted placeholders: leave every optional key out of the mapping so the literal ${user_config.X} survives.
        await scenario("optional fields unsubstituted (literal placeholders)", manifest, dirname, base)

        # Everything blank in the form. A host passes only a short whitelist of variables (PATH, APPDATA, ...), so the
        # settings must come from the persistent Windows environment. Only meaningful when the machine has one.
        if registry_has("UNIFI_LOCAL_HOST"):
            await scenario(
                "form blank, settings from the Windows user/system environment",
                manifest,
                dirname,
                {k: "" for k in manifest["user_config"]},
            )
        else:
            print("\n== skipped: UNIFI_LOCAL_HOST is not in the Windows environment on this machine")
    print("\nOK: bundle launches from a clean unpack and behaves.")


if __name__ == "__main__":
    asyncio.run(main())
