# UniFi Console as an MCP Bundle (MCPB)

`unifi-console-mcp-<version>.mcpb` packages the server so Claude Desktop (or any MCPB host) can install it with a
double-click and a settings form, with no JSON editing and no environment variables to manage by hand.

## What the bundle is

- **Server type `uv` (manifest 0.4).** The bundle ships the Python source and `uv.lock`; the host runs
  `uv run --directory <bundle> unifi-console-mcp`, and `uv` builds the environment on first launch.
  The server is the same Python MCP server as in `src/`, not a rewrite: the MCP Python SDK 2.x is what it is built on,
  and bundling the compiled dependencies (pydantic-core, and so on) for three operating systems is what the `uv` type avoids.
- **stdio transport.** stdout carries the protocol, logs go to stderr (the host writes them to its MCP log).
- **Local only.** It talks to your console's address and nowhere else.
- **Settings form.** Everything configurable is a `user_config` field. Passwords and the API key are marked `sensitive`,
  so the host keeps them in the operating system's secure storage, not in a plain config file.
- **Read-only by default.** `Allow configuration changes` is off. Turning it on still requires a listed entity,
  a preview, and an explicit confirm for each change.

## Install

Requirements on the machine running Claude Desktop: [`uv`](https://docs.astral.sh/uv/) on the PATH and network access to
PyPI for the first launch (about a minute). Python 3.12+ is fetched by `uv` if needed.

1. Open the `.mcpb` file (double-click, or Claude Desktop > Settings > Extensions > Advanced > Install Extension).
2. Fill in the form. The minimum is **Console address** plus either an **Integration API key** or a **local admin
   username and password** (the controller and UniFi OS endpoints, such as the system log, need the login).
3. Restart Claude Desktop if it asks. If you already have `unifi-console-mcp` in `claude_desktop_config.json`,
   remove it first so the two do not both register the same tools.

### Settings

| Field | System variables used when the field is blank, in order | Default |
|---|---|---|
| Console address | `UNIFI_LOCAL_HOST` | none: needed in the field or the variable |
| Integration API key | `UNIFI_MCP_API_KEY` | none |
| Local admin username / password | `UNIFI_MCP_USERNAME` / `UNIFI_MCP_PASSWORD` | none |
| Site | `UNIFI_DEFAULT_SITE`, `UNIFI_NETWORK_SITE` | `default` |
| HTTPS port | `UNIFI_LOCAL_PORT`, `UNIFI_NETWORK_PORT` | `443` |
| Verify TLS certificate | `UNIFI_LOCAL_VERIFY_SSL` | on |
| Pinned certificate fingerprint | `UNIFI_CONSOLE_CERT_SHA256` | none |
| Allow configuration changes | `UNIFI_CONSOLE_ENABLE_WRITES` | off |
| Entities that may be changed | `UNIFI_CONSOLE_WRITE_ENTITIES` | none |
| Download folder | `UNIFI_CONSOLE_DOWNLOAD_DIR` | `~/.unifi-console-mcp/downloads` |
| Change journal folder | `UNIFI_CONSOLE_JOURNAL_DIR` | `~/.unifi-console-mcp/journal` |
| Log level | `UNIFI_CONSOLE_LOG_LEVEL` | `INFO` |

### Form first, then your system environment variables

Every form field is passed to the server as `UNIFI_BUNDLE_<NAME>`. A filled-in field wins. A **blank** field (or an
unfilled `${user_config.*}` placeholder) falls through to the system variables in the table above, then to the
built-in default. On Windows the server also reads persistent user and system variables straight from the registry,
so a variable set with `setx` works even if the host started before it was set.

Set them as persistent user variables (System Properties > Environment Variables, or `setx`); a `$env:` assignment in a
PowerShell session is not seen by Claude Desktop. Quit and reopen Claude Desktop after changing them.
The true/false form fields are text boxes for this reason: a checkbox would always have a value and could never fall through.

## Build

```powershell
npm i -g @anthropic-ai/mcpb        # once
uv run mcpb/build.py               # regenerate manifest -> stage -> validate -> pack -> dist/*.mcpb
uv run mcpb/build.py --check       # stop after staging and validation
uv run mcpb/smoke_test.py          # unpack the .mcpb, launch it as a host would, speak MCP to it
```

- `mcpb/gen_manifest.py` writes `manifest.json`. The tool list comes from the live server, so it cannot drift;
  `tests/test_mcpb.py` fails if `manifest.json` is stale.
- `mcpb/build.py` copies an explicit allow-list (`pyproject.toml`, `uv.lock`, `README.md`, `src/unifi_console_mcp/`,
  icons, manifest) into `dist/stage` and refuses to continue if anything credential- or capture-shaped is in it.
- The version comes from `src/unifi_console_mcp/__init__.py`. Bump it, run `build.py`, commit the regenerated manifest.

## Debugging

- Claude Desktop writes the server's stderr to its MCP logs (`%APPDATA%\Claude\logs\mcp-server-UniFi Console.log` on Windows).
  Set **Log level** to `DEBUG` for more detail.
- `uv run mcpb/smoke_test.py` reproduces a host launch outside Claude and prints what each tool returned.
- `mcpb info dist/unifi-console-mcp-<version>.mcpb` shows the package contents; `mcpb validate mcpb/manifest.json` checks the manifest.

## Notes

- The bundle is **not signed**. For sharing beyond your own machines, sign it with `mcpb sign`.
- A bundle contains everything in `src/` of the tree it was built from. Build a bundle you share from a clean
  checkout of [jaseonline/unifi-console-mcp](https://github.com/jaseonline/unifi-console-mcp).
