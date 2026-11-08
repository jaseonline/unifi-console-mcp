"""Site Manager (api.ui.com): read-only, its own key, its own client, server-side paging."""

from __future__ import annotations

import contextlib
import dataclasses
import json

import httpx
import pytest
from conftest import FakeConsole
from mcp.client import Client

from unifi_console_mcp.config import Settings
from unifi_console_mcp.registry import Registry
from unifi_console_mcp.server import create_server

CLOUD_KEY = "cloud-key-456"
HOST = {
    "id": "HOSTID:1",
    "hardwareId": "hw-1",
    "type": "console",
    "ipAddress": "203.0.113.7",
    "reportedState": {"hostname": "ckg2", "password": "should-not-leak"},
}


class FakeCloud:
    """api.ui.com in front of the console fake; requests for any other host go to the console."""

    def __init__(self, console: FakeConsole) -> None:
        self.console = console
        self.requests: list[httpx.Request] = []
        self.routes: dict[tuple[str, str], object] = {}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.url.host != "api.ui.com":
            return self.console(request)
        self.requests.append(request)
        if request.headers.get("x-api-key") != CLOUD_KEY:
            return httpx.Response(401, json={"code": "unauthorized", "httpStatusCode": 401, "message": "unauthorized"})
        handler = self.routes.get((request.method, request.url.path))
        if handler is None:
            return httpx.Response(404, json={"code": "not_found", "httpStatusCode": 404, "message": "not found"})
        if callable(handler):
            return handler(request)
        return httpx.Response(200, json=handler)


@pytest.fixture
def cloud(console) -> FakeCloud:
    return FakeCloud(console)


@pytest.fixture
def open_client(settings, cloud):
    @contextlib.asynccontextmanager
    async def opener(key: str = CLOUD_KEY):
        s = dataclasses.replace(settings, site_manager_api_key=key)
        mcp, api = create_server(s, transport=httpx.MockTransport(cloud))
        try:
            async with Client(mcp) as client:
                yield client
        finally:
            await api.client.aclose()

    return opener


async def read(client, operation_id: str, **kw) -> dict:
    res = await client.call_tool("unifi_console_read_operation", {"params": {"operation_id": operation_id, **kw}})
    assert not res.is_error, res
    return json.loads(res.content[0].text)


# ---------------------------------------------------------------- registry
def test_site_manager_operations_are_served_and_read_only():
    ops = [o for o in Registry().all() if o.api == "site_manager"]
    assert {o.operation_id for o in ops} >= {"cloudListHosts", "cloudListDevices", "cloudQueryIspMetrics"}
    assert all(o.access == "read" for o in ops), [(o.operation_id, o.access) for o in ops]
    assert all(not o.needs_session and "UNIFI_SITE_MANAGER_API_KEY" in o.auth for o in ops)
    assert not [o.path for o in ops if o.path.startswith("/ea/")], "official v1.0.0 moved these to /v1"


def test_connector_proxy_is_not_exposed():
    """The Connector forwards any method to the console, so it would bypass the write gates."""
    assert not [o for o in Registry().all() if "connector" in o.path]


def test_tag_filter_finds_site_manager():
    found = Registry().search(tag="Site Manager", access="all")
    assert found and {o.api for o in found} == {"site_manager"}


# ---------------------------------------------------------------- config
def test_key_comes_from_form_then_environment(monkeypatch):
    monkeypatch.setenv("UNIFI_LOCAL_HOST", "console.test")
    monkeypatch.setenv("UNIFI_SITE_MANAGER_API_KEY", "from-env")
    assert Settings.from_env().site_manager_api_key == "from-env"
    monkeypatch.setenv("UNIFI_BUNDLE_SITE_MANAGER_API_KEY", "from-form")
    assert Settings.from_env().site_manager_api_key == "from-form"
    assert "from-form" not in repr(Settings.from_env())


# ---------------------------------------------------------------- calls
async def test_list_hosts_uses_cloud_key_and_keeps_next_token(open_client, cloud, console):
    cloud.routes[("GET", "/v1/hosts")] = {
        "data": [HOST],
        "httpStatusCode": 200,
        "traceId": "t1",
        "nextToken": "page-2",
    }
    async with open_client() as c:
        out = await read(c, "cloudListHosts", query={"pageSize": 1})
    assert out["ok"] and out["next_token"] == "page-2"
    assert out["data"][0]["ipAddress"] == "203.0.113.7"  # the user's own data stays visible
    assert out["data"][0]["reportedState"]["password"] == "[redacted]"
    (req,) = cloud.requests
    assert req.url.scheme == "https" and req.url.params["pageSize"] == "1"
    assert req.headers["x-api-key"] == CLOUD_KEY and "cookie" not in req.headers
    assert console.requests == [], "a cloud call must not touch the console (no login, no console key)"


async def test_last_page_has_no_next_token(open_client, cloud):
    cloud.routes[("GET", "/v1/sites")] = {"data": [], "httpStatusCode": 200, "traceId": "t", "nextToken": None}
    async with open_client() as c:
        out = await read(c, "cloudListSites")
    assert out["ok"] and "next_token" not in out


async def test_devices_repeats_host_ids_and_passes_next_token(open_client, cloud):
    cloud.routes[("GET", "/v1/devices")] = {"data": [], "httpStatusCode": 200, "traceId": "t"}
    async with open_client() as c:
        await read(c, "cloudListDevices", query={"hostIds[]": ["a", "b"], "nextToken": "page-2"})
    (req,) = cloud.requests
    assert req.url.params.get_list("hostIds[]") == ["a", "b"]
    assert req.url.params["nextToken"] == "page-2"


async def test_isp_metrics_query_is_a_read_with_a_body(open_client, cloud):
    cloud.routes[("POST", "/v1/isp-metrics/5m/query")] = {"data": {"metrics": []}, "httpStatusCode": 200}
    body = {"sites": [{"hostId": "HOSTID:1", "siteId": "s1"}]}
    async with open_client() as c:
        out = await read(c, "cloudQueryIspMetrics", path_params={"type": "5m"}, body=body)
    assert out["ok"], out
    assert json.loads(cloud.requests[0].content) == body


async def test_missing_key_is_refused_before_any_request(open_client, cloud):
    async with open_client(key="") as c:
        out = await read(c, "cloudListHosts")
    assert not out["ok"] and "UNIFI_SITE_MANAGER_API_KEY" in out["error"]
    assert cloud.requests == []


async def test_rate_limit_reports_retry_after(open_client, cloud):
    cloud.routes[("GET", "/v1/hosts")] = lambda r: httpx.Response(
        429,
        headers={"Retry-After": "6"},
        json={"code": "rate_limit", "httpStatusCode": 429, "message": "rate limit exceeded"},
    )
    async with open_client() as c:
        out = await read(c, "cloudListHosts")
    assert not out["ok"] and "at least 6 seconds" in out["error"]
    assert len(cloud.requests) == 1, "no automatic retry"


async def test_wrong_key_says_which_key(open_client, cloud):
    async with open_client(key="bad-key-789") as c:
        out = await read(c, "cloudListHosts")
    assert not out["ok"] and "UNIFI_SITE_MANAGER_API_KEY" in out["error"] and "bad-key-789" not in out["error"]


async def test_console_calls_never_carry_the_cloud_key(open_client, cloud, console):
    console.routes[("GET", "/proxy/network/integration/v1/sites")] = {"data": [], "count": 0}
    async with open_client() as c:
        await read(c, "listLocalSites")
    assert console.requests and all(r.headers.get("x-api-key") != CLOUD_KEY for r in console.requests)
    assert cloud.requests == []
