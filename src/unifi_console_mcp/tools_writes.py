"""Registers the typed configuration-write tools. Each entity lives in `entities/`."""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from .api import Api
from .entities import client, client_command, client_group, doh, dynamic_dns, firewall_policy, logging_levels, network, network_list, port_forward, qos_rule, site_settings, static_dns, switch_port, traffic_object, wan, wifi
from .writes import WriteEngine


def register(mcp: MCPServer, api: Api) -> WriteEngine:
    engine = WriteEngine(api)
    port_forward.register(mcp, engine)
    network_list.register(mcp, engine)
    client.register(mcp, engine)
    client_command.register(mcp, engine)
    static_dns.register(mcp, engine)
    client_group.register(mcp, engine)
    dynamic_dns.register(mcp, engine)
    traffic_object.register(mcp, engine)
    qos_rule.register(mcp, engine)
    doh.register(mcp, engine)
    site_settings.register(mcp, engine)
    logging_levels.register(mcp, engine)
    firewall_policy.register(mcp, engine)
    switch_port.register(mcp, engine)
    wifi.register(mcp, engine)
    network.register(mcp, engine)
    wan.register(mcp, engine)
    return engine
