"""Find every wlanconf request/response in a HAR and show the apple SSID's band/enabled fields in order."""
import json, sys
har = json.load(open(sys.argv[1], encoding="utf-8"))
keys = ("name", "enabled", "wlan_bands", "wlan_band", "security", "is_guest", "hide_ssid", "networkconf_id")
for i, e in enumerate(har["log"]["entries"]):
    r = e["request"]; u = r["url"]
    if "wlanconf" not in u and "wlan" not in u.lower():
        continue
    print(f"#{i} {e.get('startedDateTime')} {r['method']} {u.split('/api/')[-1]} -> {e['response']['status']}")
    def show(label, txt):
        try:
            d = json.loads(txt)
        except Exception:
            return
        rows = d.get("data", d) if isinstance(d, dict) else d
        if isinstance(rows, dict):
            rows = [rows]
        if not isinstance(rows, list):
            return
        for w in rows:
            if isinstance(w, dict) and (w.get("name") == "apple" or r["method"] != "GET"):
                print("   ", label, {k: w.get(k) for k in keys if k in w})
    if r["method"] != "GET" and r.get("postData"):
        show("REQ ", r["postData"].get("text", ""))
    show("RESP", e["response"]["content"].get("text", "") or "")
