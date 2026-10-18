"""Unit checks for the 2026-10-18 capture batch: DoH Auto, port forward source limiting."""
from __future__ import annotations

import pytest

from unifi_console_mcp.client import UniFiError
from unifi_console_mcp.entities import doh, port_forward


def test_doh_auto_sends_the_captured_resolvers_and_clears_custom():
    out = doh.prepare("update", {"state": "custom", "server_names": [], "custom_servers": [{"server_name": "a", "sdns_stamp": "x", "enabled": True}]},
                      {"state": "auto"})
    assert out == {"state": "auto", "server_names": ["cloudflare", "google"], "custom_servers": []}


def test_doh_auto_refuses_other_names():
    with pytest.raises(UniFiError):
        doh.prepare("update", None, {"state": "auto", "server_names": ["quad9"]})


def test_doh_auto_validates_with_a_note_and_no_errors():
    after = doh.prepare("update", None, {"state": "auto"})
    f = doh.validate("update", {"state": "off"}, after, [], {"names": []})
    assert not f.errors and any("Auto" in w for w in f.warnings)


BASE = {"name": "n", "dst_port": "5847", "fwd_port": "2020", "fwd": "10.88.1.15", "proto": "tcp_udp", "pfwd_interface": "wan",
        "enabled": True, "src_limiting_enabled": True, "src": "142.250.0.0/15"}


def test_port_forward_source_limit_sets_the_type_and_names_the_scope():
    ch = port_forward.prepare("create", None, {"src_limiting_enabled": True, "src": "142.250.0.0/15"})
    assert ch["src_limiting_type"] == "ip"
    f = port_forward.validate("create", None, {**BASE, "src_limiting_type": "ip"}, [])
    assert not f.errors and any("142.250.0.0/15" in w for w in f.warnings)


@pytest.mark.parametrize("src", ["", "not-an-ip", "2001:db8::/32"])
def test_port_forward_source_limit_needs_a_valid_ipv4_source(src):
    f = port_forward.validate("create", None, {**BASE, "src": src, "src_limiting_type": "ip"}, [])
    assert any("src must be an IPv4" in e for e in f.errors)


def test_port_forward_src_without_limiting_warns():
    f = port_forward.validate("create", None, {**BASE, "src_limiting_enabled": False}, [])
    assert any("no effect" in w for w in f.warnings)
