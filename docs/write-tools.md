# Write tools

All are off until `UNIFI_CONSOLE_ENABLE_WRITES=true` and the entity key is listed in `UNIFI_CONSOLE_WRITE_ENTITIES`.
"Proven live" means the tool was run against a real console using throwaway objects (or one nominated client restored
afterwards); see [verified behaviours](verified-behaviours.md) for what was found.

| Tool (entity key) | Edits | Tier | Notes |
|---|---|---|---|
| `unifi_console_port_forward` (`port_forward`) | Port forward rules | A | New rules start disabled. Optional source IP/CIDR limit. Enabling states what becomes reachable. |
| `unifi_console_network_list` (`network_list`) | Port, IPv4, IPv6 and domain lists | A | Member helpers; deletion blocked while a policy uses the list. |
| `unifi_console_client` (`client`) | Alias, note, fixed IP, local DNS name | A | Checks the address is free, in range, and not the gateway. |
| `unifi_console_client_command` (`client`) | Block, unblock, forget, reconnect | A | Refuses UniFi device MACs; forget needs the client offline. |
| `unifi_console_static_dns` (`static_dns`) | Static DNS records (A, AAAA, CNAME, MX, SRV, TXT) | A | Warns about names outside `UNIFI_HOME_DOMAIN`, which override public DNS. |
| `unifi_console_client_group` (`client_group`) | Client groups | A | Add/remove member helpers. |
| `unifi_console_dynamic_dns` (`dynamic_dns`) | Dynamic DNS entries | B | Token only from `UNIFI_DDNS_<NAME>`; every update must supply it again. |
| `unifi_console_traffic_object` (`traffic_object`) | Traffic management objects: QoS limits/priority, schedules, internet block, route via WAN or VPN | B | Network or client targets. App, domain and region matchers are not edited. |
| `unifi_console_qos_rule` (`qos_rule`) | Dashboard QoS rules | B | Client source, application destination, limit or prioritise via a WAN/VPN link. New rules start disabled. |
| `unifi_console_doh` (`doh`) | DNS over HTTPS mode and resolvers | C | DNS probe before and after, with automatic restore. Off, Auto, Predefined and Custom. |
| `unifi_console_firewall_policy` (`firewall_policy`) | Custom zone-based firewall policies: create, edit, enable/disable, reorder, delete | C | New policies start disabled; automatic restore on DNS failure. |
| `unifi_console_switch_port` (`switch_port`) | One port of one switch per call | C | Lock-out guard with automatic restore. |
| `unifi_console_wifi` (`wifi`) | SSIDs | C | Passphrases from `UNIFI_WIFI_<NAME>`; warns when clients would disconnect. |
| `unifi_console_network` (`network`) | Networks / VLANs, DHCP, DNS servers | C | WAN networks are refused (use the WAN tool). |
| `unifi_console_wan` (`wan`) | WAN network settings (update only) | C | Gateway re-provision guard, internet probe, automatic restore. |
| `unifi_console_syslog` (`syslog`) | Syslog debug and content flags | B | |
| `unifi_console_data_retention` (`data_retention`) | Data retention (manual mode) | B | The settings object holds an API key that is redacted everywhere. |
| `unifi_console_logging_levels` (`logging_levels`) | Per-service debug levels | B | The console has no read for this, so `verified` is null; rollback is the defaults. |

## Not offered
VPN and tunnels, device adoption/restart/upgrade, backup restore, hotspot and vouchers, RADIUS, user and admin
management, gateway-wide settings (UPnP, MSS, timeouts), SSL inspection writes, device-type override. Use another tool
for these, or see [adding an entity](adding-an-entity.md).
