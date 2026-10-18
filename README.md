# unifi-console-mcp

An [MCP](https://modelcontextprotocol.io) server for the **undocumented** UniFi OS and Network console APIs, with
typed, gated write tools. Most UniFi MCP servers use the supported Integration API or a fixed set of legacy calls.
This one is driven by an OpenAPI spec of the console's own API (`src/unifi_console_mcp/openapi.yaml`), so the tool
surface can keep growing, and it adds safe, previewed configuration changes for the things the supported API does not
cover.

> **Read this first.** The APIs this server uses are not documented or supported by Ubiquiti and can change with any
> update. The write tools were proven live against **one console (Cloud Key Gen2 Plus) running Network 11.0.81**.
> Anything else is untested. Writes are **off by default**. If you turn them on, an AI client can change your network,
> including DNS, firewall rules and the WAN. Start with read-only, use a dedicated account, keep a backup, and read
> every preview before confirming. Provided as-is, without warranty (see [LICENSE](LICENSE)).

## What it does

**Generic tools** reach every operation in the spec (about 180) without registering 180 tools:

| Tool | Purpose |
|---|---|
| `unifi_console_list_operations` | Search the spec by words, tag or access level |
| `unifi_console_describe_operation` | Parameters, body schema and the spec's own warnings |
| `unifi_console_call_operation` | Call one operation (reads and read-only queries; refuses configuration writes) |

**Curated read tools** for areas other servers skip: `unifi_console_session_status`, `unifi_console_system_log`,
`unifi_console_firewall_policy_hits` (find unused rules), `unifi_console_poe_overview`,
`unifi_console_switch_port_detail`, `unifi_console_backup`, `unifi_console_support_file`, `unifi_console_access_review`.

**Typed write tools** (all off until enabled; see [docs/write-tools.md](docs/write-tools.md)): port forwards, network
lists, clients (edit and block/unblock/forget/reconnect), static DNS, client groups, Dynamic DNS, traffic and QoS
objects, dashboard QoS rules, DNS over HTTPS, firewall policies, switch ports, Wi-Fi, networks/VLANs, the WAN, syslog,
data retention and logging levels.

## How writes stay safe

Every write is two steps: `confirm=false` returns a read-only preview (before, after, diff, warnings, a fingerprint);
`confirm=true` with that fingerprint applies it. The server re-reads the object first (a stale preview is refused),
journals the attempt, sends the change, reads it back, verifies it, and returns the diff plus the exact rollback call.
Risky entities (tier C) also need an `approval_note`, and the riskiest have an automatic restore if a DNS or
connectivity check fails afterwards. Details: [docs/write-safety.md](docs/write-safety.md).

## Quick start

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/jaseonline/unifi-console-mcp.git
cd unifi-console-mcp
uv sync
uv run pytest            # unit tests, no console needed
uv run unifi-console-mcp # stdio server
```

Create a dedicated **local** UniFi account for the server, then set the environment variables below and add the server
to your MCP client. Claude Desktop example (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "unifi-console": {
      "command": "uv",
      "args": ["--directory", "/path/to/unifi-console-mcp", "run", "unifi-console-mcp"],
      "env": {
        "UNIFI_LOCAL_HOST": "192.168.1.2",
        "UNIFI_MCP_USERNAME": "your-local-account",
        "UNIFI_MCP_PASSWORD": "from-your-password-manager",
        "UNIFI_CONSOLE_CERT_SHA256": "pin-the-console-certificate-here"
      }
    }
  }
}
```

More in [docs/getting-started.md](docs/getting-started.md).

## Configuration

| Variable | Meaning |
|---|---|
| `UNIFI_LOCAL_HOST` | Console address, e.g. `192.168.1.2` |
| `UNIFI_NETWORK_PORT` / `UNIFI_NETWORK_SITE` | HTTPS port (default 443) / site name (default `default`) |
| `UNIFI_MCP_USERNAME` / `UNIFI_MCP_PASSWORD` | Dedicated local account (no MFA) |
| `UNIFI_MCP_API_KEY` | Integration API key (only for Integration operations) |
| `UNIFI_CONSOLE_CERT_SHA256` | Pin the console certificate by SHA-256 fingerprint (preferred) |
| `UNIFI_LOCAL_VERIFY_SSL` | `false` to skip certificate checks (not recommended) |
| `UNIFI_CONSOLE_ENABLE_WRITES` | `true` to allow writes (default `false`) |
| `UNIFI_CONSOLE_WRITE_ENTITIES` | Comma-separated entities that may be written, e.g. `port_forward,static_dns,qos_rule` (default none) |
| `UNIFI_CONSOLE_JOURNAL_DIR` | Change journal (default `~/.unifi-console-mcp/journal`) |
| `UNIFI_CONSOLE_DOWNLOAD_DIR` | Where backups and support files are saved (default `~/.unifi-console-mcp/downloads`) |
| `UNIFI_HOME_DOMAIN` | Your local DNS domain; static DNS names outside it trigger a warning (default `example.home`) |
| `UNIFI_CONSOLE_DNS_PROBE_SERVER` / `_WINDOW` | DNS safety probe server and retry window (seconds) |
| `UNIFI_CONSOLE_INTERNET_PROBE` | TCP endpoints the WAN safety net must reach (default `1.1.1.1:443,9.9.9.9:443`) |
| `UNIFI_CONSOLE_MAX_CHARS` | Response size budget (default 40000) |
| `UNIFI_CONSOLE_SPEC_PATH` | Use a spec file other than the bundled one |

Secrets for Wi-Fi passphrases and Dynamic DNS tokens come from `UNIFI_WIFI_<NAME>` and `UNIFI_DDNS_<NAME>`
environment variables only; they are never accepted as tool arguments and never appear in previews or the journal.

## Documentation

* [Getting started](docs/getting-started.md): account, permissions, certificate pinning, enabling writes
* [Write safety](docs/write-safety.md): the preview, confirm, verify, rollback flow and its guards
* [Write tools](docs/write-tools.md): what each typed tool edits and what it leaves alone
* [Verified behaviours](docs/verified-behaviours.md): console quirks found by live testing
* [Adding an entity](docs/adding-an-entity.md): capture, spec, build, test

## Status

Proof of concept, actively developed. Unit tests use an in-memory fake console. Live checks (`scripts/*_live_check.py`)
create and delete only throwaway objects with a `zz-` prefix, except where a script says otherwise. Run them against
your own console only after reading them.

## Licence

[MIT](LICENSE)
