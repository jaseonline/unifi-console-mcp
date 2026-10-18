"""HTTP client for the UniFi OS console.

Handles the parts a generated client cannot:
  * cookie login (`POST /api/auth/login`) with the CSRF token taken from the response header
  * CSRF rotation (`X-Updated-Csrf-Token`)
  * one transparent re-login on 401, serialised so parallel calls do not stampede the login
  * login-failure back-off, so a wrong password cannot trip the console's account lockout
  * optional certificate pinning for the console's self-signed certificate
  * streaming downloads to disk (backups and support files are binary and can be large)
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
import ssl
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from .config import Settings

LOGIN_PATH = "/api/auth/login"
MAX_LOGIN_FAILURES = 2
LOGIN_FAILURE_WINDOW_S = 300


class UniFiError(Exception):
    """An error with a message written for the model: it says what happened and what to try."""


class AuthError(UniFiError):
    pass


@dataclass
class DownloadResult:
    path: Path
    size: int
    sha256: str
    content_type: str


def _decode_jwt_claims(token: str) -> dict[str, Any]:
    """Read the (unverified) claims of the TOKEN cookie. Used only to report lifetime."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:  # noqa: BLE001 - any malformed token just means "unknown"
        return {}


def _safe_filename(name: str) -> str:
    base = Path(name.replace("\\", "/")).name
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base).strip("._")
    return base or "download.bin"


class UniFiClient:
    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.settings = settings
        self._transport = transport
        self._http: httpx.AsyncClient | None = None
        self._csrf: str | None = None
        self._login_lock = asyncio.Lock()
        self._login_failures: list[float] = []
        self._pin_checked = False
        # Evidence for the open "session lifetime / CSRF rotation" questions.
        self.stats: dict[str, Any] = {
            "logins": 0,
            "relogins_after_401": 0,
            "csrf_rotations": 0,
            "last_login_at": None,
        }

    # ------------------------------------------------------------------ setup
    async def _client(self) -> httpx.AsyncClient:
        if self._http is None:
            verify: bool | ssl.SSLContext = self.settings.verify_ssl
            if self.settings.pinned_sha256:
                verify = False  # identity is established by the pin check instead
            self._http = httpx.AsyncClient(
                base_url=self.settings.base_url,
                verify=verify,
                timeout=httpx.Timeout(30.0, connect=10.0),
                transport=self._transport,
                headers={"Accept": "application/json", "User-Agent": "unifi-console-mcp/0.1"},
            )
        return self._http

    async def aclose(self) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    async def _check_pin(self) -> None:
        if not self.settings.pinned_sha256 or self._pin_checked or self._transport is not None:
            return
        pem = await asyncio.to_thread(ssl.get_server_certificate, (self.settings.host, self.settings.port))
        fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()
        if fingerprint != self.settings.pinned_sha256:
            raise UniFiError(
                "The console presented a different TLS certificate from the pinned one "
                f"(got sha256 {fingerprint[:16]}...). If the certificate was rotated on purpose, "
                "update UNIFI_CONSOLE_CERT_SHA256; otherwise treat this as a possible interception."
            )
        self._pin_checked = True

    # ------------------------------------------------------------------ login
    @property
    def logged_in(self) -> bool:
        return self._http is not None and "TOKEN" in self._http.cookies

    async def login(self) -> None:
        if not self.settings.has_session_credentials:
            raise AuthError(
                "This operation needs a login session but UNIFI_MCP_USERNAME / UNIFI_MCP_PASSWORD are not set."
            )
        now = time.time()
        self._login_failures = [t for t in self._login_failures if now - t < LOGIN_FAILURE_WINDOW_S]
        if len(self._login_failures) >= MAX_LOGIN_FAILURES:
            raise AuthError(
                f"Login has failed {len(self._login_failures)} times in the last few minutes, so further attempts "
                "are paused to avoid locking the account. Check UNIFI_MCP_USERNAME / UNIFI_MCP_PASSWORD, "
                "then restart the server."
            )
        await self._check_pin()
        http = await self._client()
        http.cookies.clear()
        self._csrf = None
        resp = await http.post(
            LOGIN_PATH,
            json={"username": self.settings.username, "password": self.settings.password, "rememberMe": False},
        )
        if resp.status_code != 200:
            self._login_failures.append(time.time())
            hint = {
                400: "The console rejected the login request (is the account local-only, without MFA?).",
                401: "Wrong username or password.",
                403: "The account is not allowed to log in (disabled, or MFA is required).",
                429: "The console is rate-limiting logins; wait a few minutes.",
            }.get(resp.status_code, "Unexpected response from the console.")
            raise AuthError(f"Login failed with HTTP {resp.status_code}. {hint}")
        csrf = resp.headers.get("x-csrf-token")
        if not csrf:
            token = http.cookies.get("TOKEN") or ""
            csrf = _decode_jwt_claims(token).get("csrfToken")
        self._csrf = csrf
        self.stats["logins"] += 1
        self.stats["last_login_at"] = int(time.time())

    def session_info(self) -> dict[str, Any]:
        """Lifetime facts about the current session, without exposing the token."""
        info: dict[str, Any] = {"logged_in": self.logged_in, "csrf_present": bool(self._csrf), **self.stats}
        if self._http is not None and "TOKEN" in self._http.cookies:
            claims = _decode_jwt_claims(self._http.cookies.get("TOKEN") or "")
            iat, exp = claims.get("iat"), claims.get("exp")
            if iat and exp:
                info.update(token_issued_at=iat, token_expires_at=exp, token_lifetime_s=exp - iat,
                            token_remaining_s=int(exp - time.time()))
        return info

    # ---------------------------------------------------------------- request
    def _headers(self, method: str, needs_session: bool, extra: dict[str, str] | None) -> dict[str, str]:
        headers: dict[str, str] = dict(extra or {})
        if needs_session:
            if method.upper() != "GET" and self._csrf:
                headers["X-CSRF-Token"] = self._csrf
        elif self.settings.api_key:
            headers["X-API-KEY"] = self.settings.api_key
        return headers

    def _absorb(self, resp: httpx.Response) -> None:
        updated = resp.headers.get("x-updated-csrf-token")
        if updated and updated != self._csrf:
            self._csrf = updated
            self.stats["csrf_rotations"] += 1

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
        needs_session: bool = True,
        send_body: bool = False,
    ) -> httpx.Response:
        if needs_session and not self.logged_in:
            async with self._login_lock:
                if not self.logged_in:
                    await self.login()
        elif not needs_session and not self.settings.api_key:
            raise AuthError("This operation needs an API key but UNIFI_MCP_API_KEY is not set.")
        await self._check_pin()
        http = await self._client()

        for attempt in (1, 2):
            headers = self._headers(method, needs_session, None)
            kwargs: dict[str, Any] = {"params": _clean_params(params)}
            if send_body:
                # Serialise by hand so a literal JSON `null` body (what the UI sends for some calls) is sent.
                kwargs["content"] = json.dumps(json_body).encode()
                headers["Content-Type"] = "application/json"
            resp = await http.request(method, path, headers=headers, **kwargs)
            self._absorb(resp)
            if resp.status_code == 401 and needs_session and attempt == 1:
                async with self._login_lock:
                    # Another task may already have refreshed the session while we waited for the lock.
                    await self.login()
                    self.stats["relogins_after_401"] += 1
                continue
            return resp
        return resp  # pragma: no cover - loop always returns

    async def download(self, path: str, params: dict[str, Any] | None, dest_dir: Path, fallback_name: str,
                       needs_session: bool = True) -> DownloadResult:
        """Stream a binary response to disk. Never returns file content."""
        if needs_session and not self.logged_in:
            async with self._login_lock:
                if not self.logged_in:
                    await self.login()
        await self._check_pin()
        http = await self._client()
        dest_dir.mkdir(parents=True, exist_ok=True)
        for attempt in (1, 2):
            async with http.stream("GET", path, params=_clean_params(params),
                                   headers=self._headers("GET", needs_session, {"Accept": "*/*"})) as resp:
                self._absorb(resp)
                if resp.status_code == 401 and needs_session and attempt == 1:
                    async with self._login_lock:
                        await self.login()
                        self.stats["relogins_after_401"] += 1
                    continue
                if resp.status_code != 200:
                    body = (await resp.aread())[:300].decode("utf-8", "replace")
                    raise UniFiError(explain_status(resp.status_code, path, body))
                name = (resp.headers.get("filename")
                        or _filename_from_disposition(resp.headers.get("content-disposition", ""))
                        or fallback_name)
                target = dest_dir / _safe_filename(name)
                digest = hashlib.sha256()
                size = 0
                with target.open("wb") as fh:
                    async for chunk in resp.aiter_bytes():
                        fh.write(chunk)
                        digest.update(chunk)
                        size += len(chunk)
                try:
                    target.chmod(0o600)
                except OSError:
                    pass
                return DownloadResult(target, size, digest.hexdigest(), resp.headers.get("content-type", ""))
        raise UniFiError("Download failed after re-login.")  # pragma: no cover


def _clean_params(params: dict[str, Any] | None) -> dict[str, Any] | None:
    if not params:
        return None
    out: dict[str, Any] = {}
    for key, value in params.items():
        if value is None:
            continue
        out[key] = str(value).lower() if isinstance(value, bool) else value
    return out


def _filename_from_disposition(value: str) -> str:
    match = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)"?', value, re.I)
    return match.group(1) if match else ""


def explain_status(status: int, path: str, body: str = "") -> str:
    """Turn an HTTP status into a message that tells the model what to do next."""
    short = body.strip().replace("\n", " ")[:200]
    if status == 401:
        return "401 Unauthorized even after re-login. Check the account credentials / API key."
    if status == 403:
        return (f"403 Forbidden for {path}. The MCP account probably lacks the permission. Console-level calls "
                "(backups, support files, API keys) need Control Plane = Admin; Network calls need Network admin "
                "or view access.")
    if status == 404:
        return (f"404 Not Found for {path}. The endpoint may not exist on this firmware (the spec was captured on "
                "Network 11.0.81), or an id in the path is wrong.")
    if status == 429:
        return "429 Too Many Requests. Wait a minute before retrying."
    if status >= 500:
        return f"{status} from the console for {path}: {short}. Retry once; if it persists the console may be busy."
    return f"HTTP {status} for {path}: {short}"
