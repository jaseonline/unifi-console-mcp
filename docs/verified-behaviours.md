# Verified behaviours

Findings from live testing on a Cloud Key Gen2 Plus running Network 11.0.81 (October 2026). They may differ on other
versions. Where a finding explains a design choice in a tool, it says so.

## Login and session
* A local-only account logs in once, no MFA. Session lifetime follows the login's `rememberMe` flag: false is 2 hours,
  true is 30 days. The server uses false and logs in again once on a 401.
* No CSRF token rotation was seen across reads or a state-changing POST. The client still follows
  `x-updated-csrf-token` if it ever changes.
* Some calls return **HTTP 200 with an error inside the body** (for example the API-key list without permission).
  The server turns these into actionable errors.

## Permissions
* Control Plane View is not enough for backups, support files, firmware, syslog settings or API keys (`403`).
* Backups needed more than Control Plane Admin on a custom role; the full Super Admin role worked.

## Support files and backups
* The support-file download answers `423 Locked` while the file is being built; poll until it returns 200 (about 90 s).
* Backup creation returns 204 and the backup appears in the list within seconds.

## Writes: general
* Creating on a v2 endpoint returns 201; deleting a single item on some v2 endpoints is still a **POST** to a
  `batch-delete` route with a JSON array of ids (204), not a DELETE.
* The console accepts some values that make no sense (for example Dynamic DNS on a `wan2` interface of a one-WAN site,
  or MAC addresses it has never seen in a client group), so the tools validate more strictly than the console.
* A fixed IP applies when the client renews its lease.

## Application blocks
* The console keeps **one collection** at `firewall-app-blocks`. Every write is a `POST` of the complete array: an entry without
  `_id` is created, one with its `_id` is updated, one left out is deleted, and `[]` deletes everything. The UI sends one request
  for all the changes made before Apply, so the tool does too.
* The UI posts every list on every entry, including stale ones; the tool sends `[]` for the lists that do not apply.
* Schedule modes seen: `ALWAYS`, `EVERY_DAY`, `EVERY_WEEK`, `ONE_TIME_ONLY`, `CUSTOM`. All-day shapes for daily and one-time
  schedules, a network block for specific applications, and the mapping from application ids to the DPI lists are **not verified**.
* The console generates a `simple_app_block` firewall policy for each block (`origin_id` is the block's `_id`); the tool checks for it
  after applying.
* **Verified live** with `scripts/app_block_live_check.py` (dry run and `--run`, all checks passed): create, schedule change,
  rename, category switch, several changes in one request, rollback replay, and restoring the original set exactly. The items above
  marked not verified are still open.

## Devices
* Locate, restart and adopt are `POST cmd/devmgr` with the device **MAC** (`set-locate`, `unset-locate`, `restart` with
  `reboot_type: "hard"`, `adopt` with `client: "web"`). There is no soft reset. Remove is `POST cmd/sitemgr` with a list of MACs
  and `cmd: "delete-device"`.
* Disable, enable and settings changes are `PUT rest/device/{_id}` with the device `_id`, not the MAC. **Partial bodies are
  accepted**: `{"disabled": true}`, or `{"name": ..., "mgmt_network_id": ...}`, changed the device without the rest of the form.
  The `_id` changes after a remove and re-adopt, so the tool always reads it live.
* A restart is checked by watching the device leave and return (or its uptime drop); adopt and remove by the adopted flag.
* Firmware updates cannot run while scheduled upgrades are on, so they are not offered.
* **Verified live** with `scripts/device_live_check.py` on a small switch with two clients: locate on and off, rename and back
  (a partial `PUT` carrying only the name), LED override off and back, disable then enable (the device reconnected), and a hard
  restart (seen leaving and returning). Remove and adopt have also been run live (as two separate runs on the same switch) and
  passed. Removing a device drops its saved settings, so the script snapshots them first and restores the name, LED, SNMP and STP
  priority after adopt. A re-adopted switch comes back on a **dynamic** management address, not its previous static one; the
  script lists that, and the per-port settings, as not restored.

## Traffic objects and QoS
* Traffic objects use the v2 `object-oriented-network-config` resource. QoS limits are stored in **kbit/s**.
* The console rejects **PRIORITIZE with a limit or burst switched on** (`Invalid QoS rule objective`, HTTP 400). The
  traffic object tool switches both off when the mode becomes PRIORITIZE and refuses to set one in that mode.
* Dashboard **QoS rules** are a separate resource (`qos-rules`). An update must send the whole rule including `_id` and
  `index`; bursts are `OFF`, `SHORT` or `LONG`; the console drops `port_matching_type` from a client source but keeps
  it on an application destination, so the tool does not send it on the source.

## DNS over HTTPS
* A DoH save works with only the DoH POST. States are off, auto, manual (predefined) and custom.
* Auto sends the resolver names `cloudflare` and `google` and clears the custom list. A custom entry is a DNS stamp.
* The gateway answers REFUSED for some random names under certain domains but NXDOMAIN under others, so the safety
  probe tries several zones and only fails when none gets a good answer.

## Networks and Wi-Fi
* Editing a network makes the gateway re-provision (about 20 seconds).
* DHCP DNS servers are the keys `dhcpd_dns_1` to `dhcpd_dns_4`.

## Firewall policies
* A new policy can be created disabled; enabling and disabling go through a batch call; reordering uses
  `batch-reorder`; deletion uses `batch-delete`.
* Editing or deleting a policy can regenerate its automatic return policy; verified only on an empty zone pair.

## Clients
* The console accepts a partial fixed-IP update without the network id, and accepts `name` without `display_name`.
* Client live fields (last seen, last IP, uplink) change while connected and are excluded from the fingerprint.

## Still unverified
Enabled QoS or traffic objects on real traffic; overlapping enabled QoS rules; firewall policies on real zone pairs;
switch storm-control units; WAN identity changes; data retention writes on consoles not in manual mode.
