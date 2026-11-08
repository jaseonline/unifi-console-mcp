# Changelog

All notable changes to this project. Versions follow `__version__` in `src/unifi_console_mcp/__init__.py`.

## Unreleased

- Spec: operations are regrouped by function into 40 tags (was 20), e.g. Backup, Firmware, Logs, Ports & PoE, WAN,
  VPN, DoH, Firewall policies, Groups, SSL inspection, Device management. The largest tag is now 17 operations (Firewall
  was 60, Networks 44, Devices 38). `x-tagGroups` nests them under nine sections for Redocly-style viewers. Each
  operation keeps one tag; `getRadioIsolationMatrix` loses a stray `Controller` tag left from the old naming.
- `unifi_console_list_operations` tag filter matches any of an operation's tags, not only the first; listing and
  sorting still use the first. `unifi_console_describe_operation` returns `tags` alongside `tag`.
- A failed login now says what the console reported: HTTP 499 gets its own hint (usually MFA required or a temporary
  lock), and the console's error code is appended when it is a plain identifier, e.g. `MFA_AUTH_REQUIRED`.
- `unifi_console_firewall_policy_hits` accepts `offset`, so the `meta.next_offset` it returns can be followed. Before, a
  page could not be continued, and because the default sort is hits ascending, the busiest rules were the ones a short
  page left out.
- Credentials (username, password, API key, Site Manager API key) are also read from a password-manager credential cache in
  the OS credential store (service "unifi-mcp-cache", entries "unifi-mcp/<field>"). Order: filled-in form field, cache, then
  system variables, so a stale variable cannot override a rotated secret. Needs the optional `keyring` package; set
  UNIFI_CONSOLE_KEYRING=off to skip it.
- Spec: response schemas for 12 controller v2 reads that had none, captured live on 2026-11-08 (SSL inspection defaults
  and certificates, client 24-hour satisfaction, per-AP session time and connection log, content-filtering categories,
  WLAN defaults, single firewall policy). Four returned empty on this site (wireless links, power-supervisor links,
  per-port anomalies, replacement candidates), so only their outer shape is recorded.
- Redaction no longer hides boolean fields whose names look secret, so flags such as `private_preshared_keys_enabled`
  are visible. Every other secret-named value is still redacted.
- Spec: system-defined firewall policies have a composite `_id` (two zone UUIDs plus the index) and
  `getControllerFirewallPolicy` returns 404 for them; it works only for custom policies.
- Spec: every operation now has a description (76 were missing), and 7 summaries no longer contain `/`, `"` or `>`.
  Raised by an APIMatic audit; its remaining findings are false positives, APIMatic-only extensions or field names the
  API dictates.
- Spec: `deviceManagerCommand` documents `upgrade-external` (install firmware from a `url`), used by the UI for custom
  updates and for Revert with the URL from `getFirmwareRevertOptions`. No tool exposes it. `listScheduledTasks` now
  describes the weekly upgrade and nightly `radio-ai` tasks seen on a single-site console.

## 0.2.0

- Claude Desktop extension (MCP Bundle, `uv` server type) with a settings form; blank fields fall back to environment
  variables, including persistent Windows user and system variables read from the registry.
- `unifi_console_read_operation`: a read-only generic tool, annotated so a client can allow it without prompting.
- `UNIFI_CONSOLE_LOG_LEVEL` sets the server log level (stderr only).
- Spec tags now name the resource (`Devices`, `Firewall`, ...) instead of `API · Resource`, so one resource's
  operations from every API sit together in a viewer. Each operation's API is in a new `x-unifi-api` extension
  (`integration`, `controller`, `unifi_os`, `site_manager`), which the registry now uses instead of the tag prefix.
  `unifi_console_list_operations` and `unifi_console_describe_operation` return an `api` field, and the `tag` filter
  matches either the resource or the API (`Controller · Devices` still works).
- Site Manager (`api.ui.com`), read-only: hosts, sites, devices, ISP metrics and SD-WAN across every console on the UI
  account, through the generic tools. Uses its own key (`UNIFI_SITE_MANAGER_API_KEY`, new settings-form field) and its
  own HTTP client with full certificate checks. Server-side paging comes back as `next_token`; a 429 reports
  `Retry-After` without retrying. Paths follow the official v1.0.0 spec (ISP metrics and SD-WAN moved from `/ea/` to
  `/v1/`). The Connector proxy is left out because it would bypass the write gates.

## 0.1.0

- First release: generic tools over the console's OpenAPI spec, curated read tools, and typed write tools with
  preview, confirm, verify and rollback, all off by default.
