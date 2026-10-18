"""A small DNS probe: asks the gateway's resolver for a name nobody has asked for, to prove DNS still works end to end.

Used as the safety net (`writes.Guard`) for settings whose change can stop DNS, such as DNS over HTTPS. A random label under
a big public zone cannot be answered from any cache, so a good reply (NOERROR or NXDOMAIN) shows the whole path works:
client → gateway → its upstream resolver (DoH, when enabled) → back. SERVFAIL, REFUSED, a timeout or no reply is a failure.

The probe talks plain UDP/53 to the gateway on the console's LAN (or `UNIFI_CONSOLE_DNS_PROBE_SERVER`), so it needs no
extra dependency and sends nothing about the user.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import struct
import time
from typing import Any

from .writes import Guard

# A random label under a big public zone cannot be answered from a cache. On this console the gateway answers such names under
# cloudflare.com with REFUSED (checked 2026-10-18), so a reply that is not a good one makes the probe try the next zone before it
# counts as a failure; only a failure on every zone, or no reply at all, is a failed probe.
PROBE_ZONES = ("google.com", "amazon.com", "ubuntu.com", "iana.org")


def build_query(name: str, qid: int) -> bytes:
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)       # recursion desired, one question
    qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.split(".")) + b"\x00"
    return header + qname + struct.pack(">HH", 1, 1)               # type A, class IN


def reply_ok(data: bytes, qid: int) -> bool:
    if len(data) < 12:
        return False
    rid, flags = struct.unpack(">HH", data[:4])
    return rid == qid and bool(flags & 0x8000) and (flags & 0x000F) in (0, 3)    # a reply, NOERROR or NXDOMAIN


def _ask(host: str, port: int, timeout: float) -> bool:
    """True when any of the probe zones gets a good answer. No reply at all ends the round at once (it would only time out again)."""
    for zone in PROBE_ZONES:
        qid = int.from_bytes(os.urandom(2), "big")
        name = f"{os.urandom(6).hex()}.{zone}"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            try:
                sock.sendto(build_query(name, qid), (host, port))
                data, _ = sock.recvfrom(2048)
            except OSError:
                return False
        if reply_ok(data, qid):
            return True
    return False


def split_server(value: str) -> tuple[str, int]:
    host, _, port = value.strip().partition(":")
    return host, int(port or 53)


async def resolve_server(engine: Any) -> tuple[str, int] | None:
    """The configured probe server, else the gateway address of the network the console itself sits on."""
    settings = engine.api.settings
    if settings.dns_probe_server:
        return split_server(settings.dns_probe_server)
    try:
        host_ip = ipaddress.ip_address(await asyncio.to_thread(socket.gethostbyname, settings.host))
    except (OSError, ValueError):
        return None
    for net in await engine._read_list("listNetworkConfig"):
        subnet = net.get("ip_subnet")
        if not subnet or net.get("purpose") == "wan":
            continue
        try:
            iface = ipaddress.ip_interface(subnet)
        except ValueError:
            continue
        if host_ip in iface.network:
            return str(iface.ip), 53
    return None


async def run_probe(engine: Any, *, window: float, attempts: int | None = None, timeout: float = 2.0) -> str | None:
    """None when DNS works, else a short reason. Retries until `window` seconds pass (or `attempts` tries)."""
    server = await resolve_server(engine)
    if server is None:
        return ("could not work out which DNS server to test (the console's own network was not found). "
                "Set UNIFI_CONSOLE_DNS_PROBE_SERVER to the gateway address, for example 192.168.1.1")
    host, port = server
    deadline = time.monotonic() + max(window, 0.0)
    tries = 0
    interval = max(0.2, min(2.0, window / 3 if window else 0.2))
    while True:
        tries += 1
        if await asyncio.to_thread(_ask, host, port, timeout):
            return None
        if (attempts is not None and tries >= attempts) or time.monotonic() >= deadline:
            return f"no good DNS answer from {host}:{port} after {tries} attempt(s)"
        await asyncio.sleep(interval)


def make_guard(describe: str) -> Guard:
    async def before(engine: Any) -> str | None:
        problem = await run_probe(engine, window=min(engine.api.settings.dns_probe_window, 6.0), attempts=3)
        return f"DNS is not working before the change ({problem}). Fix that first; the change was not attempted." if problem else None

    async def after(engine: Any, phase: str) -> str | None:
        settings = engine.api.settings
        if phase == "change" and settings.dns_probe_force_fail:
            return "forced failure (UNIFI_CONSOLE_DNS_PROBE_FORCE_FAIL is set; test switch)"
        return await run_probe(engine, window=settings.dns_probe_window)

    return Guard(describe=describe, before=before, after=after)
