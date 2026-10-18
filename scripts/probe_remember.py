"""Compare session lifetime with rememberMe false and true. Prints lifetimes and header NAMES only.

    uv run python scripts/probe_remember.py

Performs exactly two logins (well inside the back-off limit). Reads no data, writes nothing.
"""
from __future__ import annotations

import base64
import json

import httpx

from unifi_console_mcp.config import Settings


def claims(token: str) -> dict:
    seg = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))


def main() -> None:
    s = Settings.from_env()
    base = f"https://{s.host}:{s.port}"
    for remember in (False, True):
        with httpx.Client(verify=s.verify_ssl, timeout=15) as c:
            r = c.post(f"{base}/api/auth/login", json={"username": s.username, "password": s.password, "rememberMe": remember})
            tok = c.cookies.get("TOKEN") or ""
            cl = claims(tok) if tok.count(".") == 2 else {}
            ck = [x for x in c.cookies.jar if x.name == "TOKEN"]
            interesting = {k: v for k, v in r.headers.items() if k.lower().startswith(("x-csrf", "x-updated", "x-token", "set-cookie"))}
            # never print values of csrf/cookie headers; only the names, plus x-token-expire-time
            print(f"rememberMe={remember}: HTTP {r.status_code}")
            print("  header names:", sorted(h.lower() for h in interesting))
            print("  x-token-expire-time:", r.headers.get("x-token-expire-time"))
            print("  jwt lifetime s:", (cl.get("exp", 0) - cl.get("iat", 0)) if cl else None,
                  "| claims:", sorted(cl))
            if ck:
                print("  cookie expires (epoch):", ck[0].expires)
            c.post(f"{base}/api/auth/logout")


main()
