# Write safety

## The flow
Every configuration write goes through one engine:

1. **Read** the object (and any lists the validator needs). A failed read blocks the write.
2. **Validate** the request against what the console is known to accept, and against the rest of your configuration.
3. **Preview** (`confirm=false`): returns `before`, `after`, `diff`, `warnings`, `errors`, `used_by`, the request that
   would be sent, a `fingerprint` and, if applying would be refused, `apply_blocked_reason`. Previews are always allowed.
4. **Apply** (`confirm=true` with the fingerprint): the object is re-read; if it changed since the preview the write is
   refused. The attempt is written to the journal before anything is sent.
5. **Send**, **read back** and **verify**. The result states `verified`, lists any `mismatches`, shows the `diff`, and
   gives the exact `rollback` call. Nothing is retried automatically.

## Gates
1. `UNIFI_CONSOLE_ENABLE_WRITES=true` in the server's own environment.
2. The entity key is in `UNIFI_CONSOLE_WRITE_ENTITIES` (default: none).
3. `confirm=true` with the matching `fingerprint`.
4. Tier C entities also need a non-empty `approval_note`, stored in the journal.

Tiers: **A** reversible, local effect. **B** changes how traffic or names resolve for several clients, or diagnostic
settings. **C** can cut connectivity or expose the network.

## Request body rules
* Legacy `rest/*` endpoints: send only the changed fields (arrays are replaced whole, so member helpers compute the
  full array).
* v2 endpoints and arrays of settings (switch `port_overrides`): read, change, send the whole object.
* Singleton settings groups (`set/setting/<key>`): send the whole group.
* Read-back verification is the safety net: if the stored object does not match the request the result says so.

## Guards
* **Journal:** `~/.unifi-console-mcp/journal/YYYY-MM.jsonl`, two lines per write (attempt, then result). If the journal
  cannot be written, nothing is sent. Secret fields are redacted, so a rollback never restores a secret.
* **Rollback instruction** in every result: update back to `before`, delete what was created, or recreate what was
  deleted.
* **System-defined objects** the console marks as not editable or not deletable are protected.
* **Reference check:** a network list or client group still used by a firewall policy or traffic object cannot be deleted.
* **Lock-out guards:** firewall, switch port, network and WAN changes that would cut management access are refused,
  with acknowledge flags where an override is reasonable.
* **Automatic restore (DoH, firewall policies, switch ports, networks, WAN):** a guard checks the network before and
  after (DNS probe, connected devices; for the WAN, gateway re-provision, WAN health and an internet probe). If the
  check fails after the change, the previous state is put back once and checked again; a failed restore is reported
  loudly with manual steps.
* **Exposure warnings:** enabling a port forward states what becomes reachable from the internet.
* **One object per call.** The only batch operations are those the console's own UI uses.
* **Secrets:** Wi-Fi passphrases and Dynamic DNS tokens are read from environment variables only and never appear in
  previews, results or the journal.

## Testing approach
Unit tests run against an in-memory fake console that reproduces known console behaviour (for example rejecting a PUT
that omits a required key). Live checks touch only throwaway `zz-` objects, or one nominated client restored afterwards.
