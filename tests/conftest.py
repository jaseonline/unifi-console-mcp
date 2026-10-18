from __future__ import annotations

import base64
import json
import time

import httpx
import pytest

from unifi_console_mcp.config import Settings


def make_jwt(lifetime: int = 3600) -> str:
    def enc(obj: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    now = int(time.time())
    return f"{enc({'alg': 'HS256'})}.{enc({'iat': now, 'exp': now + lifetime, 'csrfToken': 'csrf-jwt'})}.sig"


class FakeConsole:
    """Just enough of a UniFi OS console to exercise the client and tools."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.login_status = 200
        self.logins = 0
        self.expire_next = False
        self.csrf = "csrf-1"
        self.routes: dict[tuple[str, str], object] = {}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if path == "/api/auth/login":
            self.logins += 1
            if self.login_status != 200:
                return httpx.Response(self.login_status, json={"message": "no"})
            return httpx.Response(200, json={"ok": True}, headers={
                "set-cookie": f"TOKEN={make_jwt()}; Path=/; HttpOnly", "x-csrf-token": self.csrf})
        if "TOKEN" not in (request.headers.get("cookie") or "") and not request.headers.get("x-api-key"):
            return httpx.Response(401, json={"message": "unauthorized"})
        if self.expire_next:
            self.expire_next = False
            return httpx.Response(401, json={"message": "expired"})
        handler = self.routes.get((request.method, path))
        if handler is None:
            return httpx.Response(404, json={"message": "nope"})
        if callable(handler):
            return handler(request)
        return httpx.Response(200, json=handler, headers={"x-updated-csrf-token": "csrf-2"} if request.method == "POST" else {})


@pytest.fixture
def console() -> FakeConsole:
    return FakeConsole()


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(host="console.test", username="mcp", password="pw", api_key="key123",
                    download_dir=tmp_path / "dl", enable_writes=False)
