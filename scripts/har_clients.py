import json, sys, collections
import ijson
c = collections.Counter(); names = collections.defaultdict(list)
with open(sys.argv[1], "rb") as f:
    for e in ijson.items(f, "log.entries.item"):
        if e["request"]["url"].split("?")[0].endswith("/clients/active"):
            for cl in json.loads(e["response"]["content"]["text"]):
                n = cl.get("network_name") or cl.get("last_connection_network_name") or "?"
                c[n] += 1
                if n in ("LAN_Sonos", "LAN_Guest"):
                    names[n].append((cl.get("display_name") or cl.get("name") or "?", cl.get("type"), cl.get("is_wired")))
print(dict(c))
print(dict(names))
