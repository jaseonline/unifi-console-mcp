import json, sys, collections
d = json.load(open(sys.argv[1]))
rows = d["rows"]
print("time span", rows[0]["ts"], rows[-1]["ts"], "PUT1~1792298419 PUT2~1792298479")
for r in rows:
    if r["kind"] in ("networkconf:sync", "device:update") or r["kind"].startswith("evt") or r["kind"] == "?":
        print(r)
print("--- device:sync / unifi-device:sync per device: ts, state, uptime around the saves")
per = collections.defaultdict(list)
for r in rows:
    if r["kind"] in ("device:sync", "unifi-device:sync") and "mac" in r:
        per[r["mac"]].append((r["ts"], r.get("state"), r.get("uptime"), r.get("adopt_state")))
for mac, v in per.items():
    states = collections.Counter(x[1] for x in v)
    ups = [x[2] for x in v if x[2] is not None]
    print(mac, "n=", len(v), "states", dict(states), "uptime first/last", ups[:1], ups[-1:],
          "uptime monotonic", all(b >= a for a, b in zip(ups, ups[1:])))
print("--- client:sync count by 10s bucket")
b = collections.Counter(int(r["ts"] // 10 * 10) for r in rows if r["kind"] == "client:sync")
print(sorted(b.items()))
