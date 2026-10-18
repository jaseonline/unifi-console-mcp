"""Prove the device tool on the real console, one device at a time, from low risk to high. Meant to be run by you.

    uv run scripts/device_live_check.py --ap "name or MAC"                          # dry run: prints the plan, touches nothing
    uv run scripts/device_live_check.py --ap "name or MAC" --run                    # locate, rename and LED only (the default stages)
    uv run scripts/device_live_check.py --ap ... --run --stages locate,rename,led,disable,restart
    uv run scripts/device_live_check.py --device aa:bb:cc:dd:ee:ff --run --stages remove    # run 1: forget the device
    uv run scripts/device_live_check.py --device aa:bb:cc:dd:ee:ff --run --stages adopt     # run 2: adopt it again

Stages, lowest risk first (default: locate, rename, led). `--ap` takes an access point or a switch:
  locate        flash the LED on, then off
  rename        rename the device to "<name>-check" (a partial PUT with just the name), then back
  led           set the LED override to "off", then back to what it was
  disable       disable the device, then enable it and wait for it to reconnect    (what is connected to it drops for a few minutes)
  restart       hard restart and wait for it to return                              (the same)
  remove        forget --device (a switch or AP with nothing behind it); first saves a snapshot of its settings
  adopt         adopt --device again, wait for it, then put back its name, LED, SNMP and STP priority from the snapshot
  remove-adopt  remove then adopt in one run

SAFETY
  * Goes through the real tool (preview, then confirm with the fingerprint, journal, read-back), in-process. Writes are enabled for
    THIS process only; the Claude Desktop server configuration is not changed.
  * The device must be an access point or a switch with no other UniFi device behind it, connected, and not the device running the
    console; otherwise nothing is done. Choose a quiet time for disable, restart and remove.
  * For --ap, a finally block puts back the name, the LED override, locate off and enabled, whatever happens.
  * remove forgets the device. UniFi then drops its settings: the name, the LED, a static management address and, on a switch,
    its PORT SETTINGS (VLAN per port, PoE, isolation). The script saves them to <journal dir>/device-snapshots/ before removing,
    restores what the device tool can (name, LED, SNMP, STP priority) after adopt, and lists what it cannot (ports, address) so you
    can put them back with the switch port tool or in the UniFi UI.
  * remove and adopt are never part of the default stages. The same device cannot be both --ap and --device in one run.
"""
from __future__ import annotations

import asyncio
import dataclasses
import json
import sys
import time
from pathlib import Path
from typing import Any

from mcp.client import Client

from unifi_console_mcp.config import Settings
from unifi_console_mcp.server import create_server
from unifi_console_mcp.writes import WriteEngine

TOOL = "unifi_console_device"
NOTE = "device_live_check.py, run by the operator"
DEFAULT_STAGES = ("locate", "rename", "led")
AP_STAGES = ("locate", "rename", "led", "disable", "restart")
LIFECYCLE = ("remove", "adopt", "remove-adopt")
ALL_STAGES = AP_STAGES + LIFECYCLE
SUFFIX = "-check"
KEEP = ("name", "led_override", "snmp_contact", "snmp_location", "stp_priority", "mgmt_network_id", "config_network", "port_overrides",
        "model", "type", "mac")
RESTORABLE = ("name", "led_override", "snmp_contact", "snmp_location", "stp_priority")

PLAN = """\
1. read the devices (read only); the device must be a connected access point or switch with nothing behind it, and not the console
2. locate: on, then off                                              (tier A, no configuration change)
3. rename: "<name>-check" then back; the request must carry only the name
4. led: LED override off, then back to what it was
5. disable: disable, enable, wait until the device is connected again (tier C)
6. restart: hard restart, wait until it is seen back                 (tier C for a switch)
7. remove: save a snapshot of the settings, then forget --device     (tier C; separate run)
8. adopt: adopt --device, wait, restore name/LED/SNMP/STP, list what is left to put back (separate run)
9. for --ap, always: restore the name, LED override, locate off and enabled, then report"""


async def tool(client: Client, args: dict[str, Any]) -> dict[str, Any]:
    res = await client.call_tool(TOOL, {"params": args})
    return json.loads(res.content[0].text)


async def apply(client: Client, args: dict[str, Any], *, approve: bool = False) -> dict[str, Any]:
    args = {**args, **({"approval_note": NOTE} if approve else {})}
    pre = await tool(client, args)
    if not pre.get("ok"):
        raise RuntimeError(f"preview failed: {pre.get('error')}")
    if pre["errors"] or pre["apply_blocked_reason"]:
        raise RuntimeError(f"preview not applicable: {pre['errors'] or pre['apply_blocked_reason']}")
    out = await tool(client, {**args, "confirm": True, "fingerprint": pre["fingerprint"]})
    if not out.get("ok"):
        raise RuntimeError(f"apply failed: {out.get('error')}")
    out["_preview"] = pre
    out.setdefault("verified", out.get("applied") is False)      # "already in the requested state" sends nothing and counts as fine
    return out


async def _pause(seconds: float) -> None:       # a seam for tests
    await asyncio.sleep(seconds)


async def wait_connected(engine: WriteEngine, mac: str, seconds: int = 240) -> bool:
    for _ in range(max(1, seconds // 5)):
        await _pause(5)
        try:
            rows = await engine._read_list("listDevicesBasic")
        except Exception:  # noqa: BLE001 - the console can be briefly unreachable
            continue
        if any(str(r.get("mac", "")).lower() == mac and r.get("state") == 1 and not r.get("disabled") for r in rows):
            return True
    return False


async def wait_pending(engine: WriteEngine, mac: str, seconds: int = 240) -> bool:
    """After a remove the device has to show up again as waiting to be adopted."""
    for _ in range(max(1, seconds // 5)):
        try:
            rows = await engine._read_list("listDevicesBasic")
        except Exception:  # noqa: BLE001
            rows = []
        if any(str(r.get("mac", "")).lower() == mac and not r.get("adopted") for r in rows):
            return True
        await _pause(5)
    return False


def pick(rows: list[dict[str, Any]], ref: str) -> dict[str, Any] | None:
    ref_l = ref.strip().lower()
    ref_mac = ref_l.replace("-", ":")
    hits = [r for r in rows if ref_l in (str(r.get("_id")).lower(), str(r.get("name", "")).lower()) or ref_mac == str(r.get("mac", "")).lower()]
    return hits[0] if len(hits) == 1 else None


def behind_of(rows: list[dict[str, Any]], mac: str) -> list[dict[str, Any]]:
    return [d for d in rows if str((d.get("uplink") or {}).get("uplink_mac", "")).lower() == mac]


def suitable(row: dict[str, Any], rows: list[dict[str, Any]]) -> bool:
    return (row.get("type") in ("uap", "usw") and row.get("state") == 1 and not row.get("disabled")
            and not behind_of(rows, str(row.get("mac", "")).lower()))


def snapshot_dir(settings: Settings) -> Path:
    return Path(settings.journal_dir) / "device-snapshots"


def save_snapshot(settings: Settings, row: dict[str, Any]) -> Path:
    directory = snapshot_dir(settings)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / f"{str(row['mac']).replace(':', '')}-{time.strftime('%Y%m%d-%H%M%S')}.json"
    path.write_text(json.dumps({k: row.get(k) for k in KEEP}, indent=2, default=str), encoding="utf-8")
    return path


def load_snapshot(settings: Settings, mac: str) -> dict[str, Any] | None:
    files = sorted(snapshot_dir(settings).glob(f"{mac.replace(':', '')}-*.json"))
    return json.loads(files[-1].read_text(encoding="utf-8")) if files else None


def entry_map(row: dict[str, Any]) -> dict[int, dict[str, Any]]:
    return {int(e["port_idx"]): e for e in row.get("port_overrides") or [] if isinstance(e, dict) and e.get("port_idx") is not None}


def not_restored(snap: dict[str, Any], row: dict[str, Any]) -> list[str]:
    left: list[str] = []
    if snap.get("mgmt_network_id") and snap.get("mgmt_network_id") != row.get("mgmt_network_id"):
        left.append(f"management network (was {snap.get('mgmt_network_id')}, now {row.get('mgmt_network_id')})")
    old, new = snap.get("config_network") or {}, row.get("config_network") or {}
    if old.get("type") == "static" and (new.get("type") != "static" or new.get("ip") != old.get("ip")):
        left.append(f"static management address {old.get('ip')} (now {new.get('ip') or new.get('type') or 'not set'})")
    a, b = entry_map(snap), entry_map(row)
    ports = sorted(i for i in set(a) | set(b) if a.get(i) != b.get(i))
    if ports:
        left.append("port settings for port(s) " + ", ".join(str(i) for i in ports) + " (the saved copy is in the snapshot file)")
    return left


async def ap_stages(client: Client, engine: WriteEngine, row: dict[str, Any], stages: tuple[str, ...]) -> int:
    failures = 0
    mac = str(row["mac"]).lower()
    name0, led0 = row.get("name"), row.get("led_override") or "default"
    try:
        if "locate" in stages:
            print("\n[2] locate on, then off")
            out = await apply(client, {"action": "locate", "target": mac})
            print(f"  on: verified={out['verified']}")
            failures += not out["verified"]
            out = await apply(client, {"action": "unlocate", "target": mac})
            print(f"  off: verified={out['verified']}")
            failures += not out["verified"]
        if "rename" in stages:
            print("\n[3] rename and back (partial body)")
            out = await apply(client, {"action": "update", "target": mac, "name": f"{name0}{SUFFIX}"})
            body = out["_preview"]["request"]["body"]
            print(f"  verified={out['verified']} request body={body}")
            failures += not out["verified"] or body != {"name": f"{name0}{SUFFIX}"}
            out = await apply(client, {"action": "update", "target": mac, "name": name0})
            print(f"  back: verified={out['verified']}")
            failures += not out["verified"]
        if "led" in stages:
            print("\n[4] LED override off, then back")
            out = await apply(client, {"action": "update", "target": mac, "led_override": "off"})
            print(f"  verified={out['verified']} body={out['_preview']['request']['body']}")
            failures += not out["verified"]
            out = await apply(client, {"action": "update", "target": mac, "led_override": led0})
            print(f"  back to {led0}: verified={out['verified']}")
            failures += not out["verified"]
        if "disable" in stages:
            print("\n[5] disable, enable, wait (what is connected to this device drops)")
            out = await apply(client, {"action": "disable", "target": mac}, approve=True)
            print(f"  disable: verified={out['verified']}")
            failures += not out["verified"]
            out = await apply(client, {"action": "enable", "target": mac})
            back = await wait_connected(engine, mac)
            print(f"  enable: verified={out['verified']}, connected again={back}")
            failures += not out["verified"] or not back
        if "restart" in stages:
            print("\n[6] hard restart, wait (what is connected to this device drops)")
            out = await apply(client, {"action": "restart", "target": mac, "wait_seconds": 300}, approve=True)
            print(f"  tier={out['tier']} verified={out['verified']} waited={out.get('waited_seconds')} s")
            failures += not out["verified"]
    except Exception as exc:  # report, then fall through to the restore
        failures += 1
        print(f"  ERROR: {type(exc).__name__}: {exc}")
    finally:
        for label, args in (("locate off", {"action": "unlocate", "target": mac}),
                            ("name", {"action": "update", "target": mac, "name": name0}),
                            ("LED", {"action": "update", "target": mac, "led_override": led0}),
                            ("enabled", {"action": "enable", "target": mac})):
            try:
                out = await apply(client, args)
                print(f"  restore {label}: {'already as it was' if out.get('applied') is False else 'put back'}, verified={out['verified']}")
                failures += not out["verified"]
            except Exception as exc:  # noqa: BLE001
                failures += 1
                print(f"  RESTORE {label} FAILED: {exc}. Put it back by hand in the UniFi UI (name '{name0}', LED '{led0}').")
    after = pick(await engine._read_list("listDevicesDetailed"), mac)
    ok = bool(after) and after.get("name") == name0 and not after.get("locating") and not after.get("disabled")
    print(f"\n[9] final: name='{(after or {}).get('name')}' locating={bool((after or {}).get('locating'))} "
          f"disabled={bool((after or {}).get('disabled'))} state={(after or {}).get('state')} -> {'as it was' if ok else 'CHECK THE UI'}")
    return failures + (not ok)


async def lifecycle(client: Client, engine: WriteEngine, settings: Settings, device: str, stages: tuple[str, ...]) -> int:
    failures = 0
    want_remove = "remove" in stages or "remove-adopt" in stages
    want_adopt = "adopt" in stages or "remove-adopt" in stages
    rows = await engine._read_list("listDevicesDetailed")
    row = pick(rows, device)
    mac = str((row or {}).get("mac") or device).strip().lower().replace("-", ":")
    snap: dict[str, Any] | None = None
    if want_remove:
        if row is None:
            print(f"\nNo single adopted device matches '{device}'. Nothing was removed.")
            return 1
        print(f"\n[7] remove {row.get('name')} ({mac}) type={row.get('type')} state={row.get('state')}")
        if not suitable(row, rows):
            print("  Not suitable: it must be a connected, enabled access point or switch with no other UniFi device behind it. Nothing was changed.")
            return 1
        path = save_snapshot(settings, row)
        snap = json.loads(path.read_text(encoding="utf-8"))
        print(f"  snapshot saved: {path}  (name, LED, SNMP, STP priority, management network and address, {len(entry_map(row))} port setting(s))")
        out = await apply(client, {"action": "remove", "target": mac, "acknowledge_removal": True, "wait_seconds": 120}, approve=True)
        print(f"  remove: verified={out['verified']}")
        failures += not out["verified"]
        if want_adopt:
            print("  waiting for the device to show as waiting to be adopted ...")
    if want_adopt:
        print(f"\n[8] adopt {mac}")
        snap = snap or load_snapshot(settings, mac)
        if snap is None:
            print("  note: no snapshot found for this device, so nothing will be restored afterwards")
        if not await wait_pending(engine, mac):
            print("  The console does not list it as waiting to be adopted yet. Check that it is powered and on the network "
                  "(a removed device may need a minute, or a factory reset), then run the adopt stage again.")
            return failures + 1
        out = await apply(client, {"action": "adopt", "target": mac, "wait_seconds": 300})
        print(f"  adopt: verified={out['verified']} new id={out.get('new_id')}")
        failures += not out["verified"]
        if out["verified"] and snap:
            now = pick(await engine._read_list("listDevicesDetailed"), mac) or {}
            todo = {k: snap[k] for k in RESTORABLE if snap.get(k) not in (None, "") and snap[k] != now.get(k)
                    and not (k == "stp_priority" and now.get("type") != "usw")}
            if todo:
                out = await apply(client, {"action": "update", "target": mac, **{k: (int(v) if k == "stp_priority" else v) for k, v in todo.items()}})
                print(f"  restored {', '.join(todo)}: verified={out['verified']}")
                failures += not out["verified"]
            else:
                print("  nothing to restore from the snapshot")
            left = not_restored(snap, pick(await engine._read_list("listDevicesDetailed"), mac) or {})
            if left:
                print("  NOT restored automatically (put these back with the switch port tool or in the UniFi UI):")
                for item in left:
                    print(f"    - {item}")
            else:
                print("  management network, address and port settings match the snapshot")
    return failures


async def main(run: bool, transport: Any = None, ap: str | None = None, stages: tuple[str, ...] = DEFAULT_STAGES,
               spare: str | None = None) -> int:
    print("Plan:\n" + PLAN)
    bad = [s for s in stages if s not in ALL_STAGES]
    if bad:
        print(f"\nUnknown stage(s): {', '.join(bad)}. Use: {', '.join(ALL_STAGES)}.")
        return 2
    print(f"\nStages selected: {', '.join(stages)}")
    if not run:
        print("\nDry run only. Add --run to perform it.")
        return 0
    ap_wanted = tuple(s for s in stages if s in AP_STAGES)
    life_wanted = tuple(s for s in stages if s in LIFECYCLE)
    if ap_wanted and not ap:
        print("\n--ap is required: the name or MAC of the access point or switch to test on.")
        return 2
    if life_wanted and not spare:
        print("\nremove and adopt need --device MAC, the device to forget and adopt again.")
        return 2
    if "remove-adopt" in life_wanted and ("remove" in life_wanted or "adopt" in life_wanted):
        print("\nUse either remove-adopt, or remove and adopt as separate runs.")
        return 2
    settings = dataclasses.replace(Settings.from_env(), enable_writes=True, write_entities=frozenset({"device"}))
    mcp, api = create_server(settings, transport=transport)
    engine = WriteEngine(api)
    failures = 0
    try:
        async with Client(mcp) as client:
            rows = await engine._read_list("listDevicesDetailed")
            row = None
            if ap_wanted:
                row = pick(rows, ap)
                if row is None:
                    print(f"\nNo single device matches '{ap}'. Nothing was changed.")
                    return 2
                mac = str(row["mac"]).lower()
                print(f"\n[1] {row.get('name')} ({mac}) type={row.get('type')} state={row.get('state')} disabled={bool(row.get('disabled'))} "
                      f"led_override={row.get('led_override')} devices behind it={len(behind_of(rows, mac))}")
                if not suitable(row, rows):
                    print("  Not suitable: it must be a connected, enabled access point or switch with no other UniFi device behind it. "
                          "Nothing was changed.")
                    return 2
            if life_wanted:
                other, chosen = pick(rows, spare), (pick(rows, ap) if ap else None)
                if chosen is not None and other is not None and other is chosen:
                    print("\n--device must be a different device from --ap. Nothing was changed.")
                    return 2
            if row is not None:
                failures += await ap_stages(client, engine, row, ap_wanted)
            if life_wanted:
                failures += await lifecycle(client, engine, settings, spare, life_wanted)
    finally:
        await api.client.aclose()
    print("\nRESULT:", "all checks passed" if not failures else f"{failures} check(s) FAILED")
    return 1 if failures else 0


def parse(argv: list[str]) -> dict[str, Any]:
    def value(*flags: str) -> str | None:
        for flag in flags:
            if flag in argv and argv.index(flag) + 1 < len(argv):
                return argv[argv.index(flag) + 1]
        return None

    stages = value("--stages")
    return {"run": "--run" in argv, "ap": value("--ap"), "spare": value("--device", "--spare"),
            "stages": tuple(s.strip() for s in stages.split(",") if s.strip()) if stages else DEFAULT_STAGES}


if __name__ == "__main__":
    sys.exit(asyncio.run(main(**parse(sys.argv[1:]))))
