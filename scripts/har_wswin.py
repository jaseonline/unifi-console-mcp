"""Websocket messages around network saves. Usage: uv run --with ijson scripts/har_wswin.py <har> <out.json>"""
import json, sys, collections
import ijson

har, out = sys.argv[1], sys.argv[2]
res = {}
with open(har, "rb") as f:
    for e in ijson.items(f, "log.entries.item"):
        if not e["request"]["url"].endswith("/default/events") and "wss/s/default/events" not in e["request"]["url"]:
            continue
        msgs = e.get("_webSocketMessages") or []
        rows, kinds = [], collections.Counter()
        dev = collections.defaultdict(list)
        for m in msgs:
            if m.get("type") != "receive":
                continue
            ts = float(m["time"])
            try:
                d = json.loads(m["data"])
            except Exception:
                kinds["unparsed"] += 1
                continue
            meta = (d.get("meta") or {}) if isinstance(d, dict) else {}
            kind = meta.get("message", "?")
            data = d.get("data") if isinstance(d, dict) else None
            first = data[0] if isinstance(data, list) and data else {}
            kinds[kind] += 1
            row = {"ts": round(ts, 1), "kind": kind}
            for k in ("mac", "name", "state", "adopt_state", "uptime", "last_seen", "key", "msg", "datetime",
                      "provisioned_at", "essid", "network", "type"):
                if isinstance(first, dict) and k in first:
                    row[k] = first[k]
            if isinstance(first, dict) and "mac" not in row and meta.get("mac"):
                row["mac"] = meta["mac"]
            rows.append(row)
        # keep only non-routine rows (events, anything not stat sync) plus device state/uptime per device
        keep = [r for r in rows if r["kind"] not in ("session-metadata:sync",) ]
        res = {"total_receive": len(rows), "kinds": dict(kinds), "rows": keep}
json.dump(res, open(out, "w"), indent=0, default=str)
print("ok", res.get("total_receive"), res.get("kinds"))
