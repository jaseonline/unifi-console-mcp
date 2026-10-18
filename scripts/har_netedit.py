"""Timeline + before/after diff of network edits in a HAR. Usage: uv run --with ijson scripts/har_netedit.py <har> <out.json>"""
import json, re, sys
import ijson

har, out = sys.argv[1], sys.argv[2]
SECRET = re.compile(r"(passphrase|psk|secret|password|x_)", re.I)
timeline, nets, ws = [], [], []
with open(har, "rb") as f:
    for e in ijson.items(f, "log.entries.item"):
        req, res = e["request"], e["response"]
        path = re.sub(r"\?.*", "", req["url"].split("//", 1)[-1].split("/", 1)[-1])
        t = e["startedDateTime"]
        timeline.append((t, req["method"], "/" + path, res["status"], round(e.get("time", 0))))
        txt = (res.get("content") or {}).get("text") or ""
        if req["method"] == "GET" and path.endswith("rest/networkconf") and txt:
            try:
                d = json.loads(txt)["data"]
                nets.append((t, {n["name"]: n for n in d}))
            except Exception as ex:
                nets.append((t, {"_err": str(ex)}))
        if "wss/" in path:
            msgs = e.get("_webSocketMessages") or []
            ws.append({"t": t, "path": "/" + path, "n": len(msgs),
                       "sample": [(m.get("time"), m.get("type"), (m.get("data") or "")[:300]) for m in msgs[:80]]})
timeline.sort()
res = {"timeline": [x for x in timeline if x[1] != "GET" or "networkconf" in x[2] or "stat/device" in x[2]
                    or "clients" in x[2] or "health" in x[2] or "enriched" in x[2]],
       "first": timeline[0][0], "last": timeline[-1][0], "n": len(timeline)}
# diff consecutive networkconf snapshots
diffs = []
nets.sort(key=lambda x: x[0])
for i in range(1, len(nets)):
    a, b = nets[i - 1][1], nets[i][1]
    for name in sorted(set(a) | set(b)):
        if name not in a or name not in b:
            diffs.append((nets[i][0], name, "added/removed")); continue
        ch = {k: (a[name].get(k), b[name].get(k)) for k in set(a[name]) | set(b[name])
              if a[name].get(k) != b[name].get(k) and not SECRET.search(k)}
        if ch:
            diffs.append((nets[i][0], name, ch))
res["snapshot_times"] = [t for t, _ in nets]
res["diffs"] = diffs
res["websockets"] = ws
json.dump(res, open(out, "w"), indent=1, default=str)
print("ok", len(timeline), len(nets), len(ws))
