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
