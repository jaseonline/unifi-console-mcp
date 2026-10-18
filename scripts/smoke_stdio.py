"""Start the real server over stdio and list its tools (no console needed).

    uv run python scripts/smoke_stdio.py
"""
from __future__ import annotations

import asyncio
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main() -> None:
    env = {**os.environ, "UNIFI_LOCAL_HOST": os.environ.get("UNIFI_LOCAL_HOST", "console.invalid")}
    params = StdioServerParameters(command=sys.executable, args=["-m", "unifi_console_mcp"], env=env)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = (await session.list_tools()).tools
            print(f"{len(tools)} tools:")
            for t in tools:
                print(f"  {t.name}")


asyncio.run(main())
