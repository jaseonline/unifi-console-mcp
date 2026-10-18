# Getting started

## 1. Create a dedicated account
In the console, create a **local-only** user (no cloud sign-in, no MFA) for the server. Do not reuse your own admin
account. Give it:

* **Network:** Admin if you want configuration writes; View is enough for read-only use.
* **Control Plane:** View for most reads. Backups, support files, API keys, firmware and syslog settings need it raised
  to Admin, and backups also needed the wider role that includes `system.management.location` in testing. Raise it only
  for those calls. A `403` message tells you when this is the cause.

## 2. Pin the certificate
The console uses a self-signed certificate. Prefer pinning it to turning verification off:

```bash
openssl s_client -connect 192.168.1.2:443 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256
```

Set `UNIFI_CONSOLE_CERT_SHA256` to the fingerprint without colons.

## 3. Set the environment
Put the variables from the README in the `env` block of your MCP client's server entry, not in a shell session (a
value in a terminal does not reach a server started by a desktop app). Restart the client after changes.

## 4. Check read access first
Ask the client to run `unifi_console_session_status`, then `unifi_console_list_operations`. If these work, reads are
configured correctly.

## 5. Enable writes, one entity at a time
Set `UNIFI_CONSOLE_ENABLE_WRITES=true` and list only the entities you need in `UNIFI_CONSOLE_WRITE_ENTITIES`.
Previews work without either; they state why applying would be refused. Take a console backup first
(`unifi_console_backup`).

Entity keys: `port_forward`, `network_list`, `client`, `static_dns`, `client_group`, `dynamic_dns`, `traffic_object`,
`qos_rule`, `doh`, `firewall_policy`, `switch_port`, `wifi`, `network`, `wan`, `syslog`, `data_retention`,
`logging_levels`. Client commands (block, unblock, forget, reconnect) share the `client` switch.

## 6. Running the live checks (optional)
`scripts/*_live_check.py` prove a tool on a real console using throwaway objects. Run one without `--run` first: it
prints its plan and touches nothing. Scripts that need a real client take its MAC address as an argument or from an
environment variable named in the script; use a harmless device.
