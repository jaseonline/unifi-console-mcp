# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub's **"Report a vulnerability"** option on the Security tab of
this repository rather than opening a public issue. Include the version, what you did and what you expected.

## Scope and risks to be aware of

* This server talks to **undocumented** console APIs with a real account. Run it with a dedicated, least-privilege
  local account, never your own admin account.
* Configuration writes are off by default. Turning them on (`UNIFI_CONSOLE_ENABLE_WRITES=true`) and listing entities
  in `UNIFI_CONSOLE_WRITE_ENTITIES` lets an MCP client change your network, including DNS, firewall and WAN settings.
  Enable only the entities you need, and read the preview before confirming.
* Backups and support files contain credentials in plain text. They are saved to disk, never returned to the
  conversation. Store them in an encrypted location and do not commit them.
* Never commit HAR captures, journals or logs. They contain session cookies, tokens and details of your network.
* Secrets (`x_*` fields, passphrases, API keys, tokens) are redacted from tool output and the change journal.
  Wi-Fi passphrases and Dynamic DNS tokens are read only from environment variables, never from tool arguments.

## Supported versions

Only the latest release is supported. The write tools were proven against one console and one Network application
version (see `docs/verified-behaviours.md`); treat anything else as untested.
