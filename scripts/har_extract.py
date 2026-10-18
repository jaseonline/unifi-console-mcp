"""Extract the API calls from a browser HAR without loading it all into memory.

    uv run --with ijson scripts/har_extract.py doh.har [out.json]

Streams `log.entries`, keeps only requests to the console API (`/proxy/` and `/api/`), and writes:
  * every non-GET call: method, path, query keys, status, request body, a response excerpt and, where the HAR holds
    an earlier read of the same object, `before` (that object as last read) and `changed` (request keys whose values
    differ from it, secrets masked). `before` is null when no earlier read of the collection was captured or the object
    is not in it (for example a create, or a list route that is named differently from the write route).
  * for GET calls: a count per normalised path and status
Headers, cookies and tokens are never read into the output. Secret-looking JSON fields (x_*, password, token,
key, secret, psk) are redacted. The output goes to har-files/ (git-ignored) unless a path is given.
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

SECRET = re.compile(r'("(?:x_[A-Za-z_]*|password|passphrase|secret|token|api_?key|key|psk)"\s*:\s*)"(?:[^"\\]|\\.)*"', re.I)
SECRET_KEY = re.compile(r"^(?:x_.*|password|passphrase|secret|token|api_?key|key|psk)$", re.I)
CACHE_LIMIT = 3_000_000  # characters of one GET body kept for the before-lookup
BEFORE_LIMIT = 6000


def redact(text: str | None, limit: int) -> str | None:
    if text is None:
        return None
    return SECRET.sub(r'\1"<redacted>"', text[:limit])


def norm(path: str) -> str:
    path = re.sub(r"[0-9a-f]{24}", "{id}", path)
    path = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "{uuid}", path)
    return re.sub(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", "{mac}", path)


def _mask(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: ("<redacted>" if SECRET_KEY.match(k) else _mask(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_mask(v) for v in obj]
    return obj


def _rows(text: str | None) -> list[dict]:
    try:
        data = json.loads(text or "")
    except ValueError:
        return []
    if isinstance(data, dict):
        data = data.get("data", data)
    if isinstance(data, dict):
        data = [data]
    return [r for r in data if isinstance(r, dict)] if isinstance(data, list) else []


def find_before(cache: dict[str, str], raw_path: str, body_text: str | None) -> tuple[Any, dict[str, Any] | None]:
    """Return (ids, before object) for a write, using the last cached GET of its collection."""
    parts = raw_path.rstrip("/").rsplit("/", 1)
    if len(parts) != 2:
        return None, None
    collection, last = parts
    ids: list[str] = []
    if "/group/" in raw_path or collection.endswith("/group"):          # group/<name> with {"id": [...]} in the body
        collection = raw_path.replace("/group/", "/rest/", 1)
        try:
            ids = [str(i) for i in (json.loads(body_text or "{}").get("id") or [])]
        except (ValueError, AttributeError):
            ids = []
    elif re.fullmatch(r"[0-9a-f]{24}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", last, re.I):
        ids = [last]
    if not ids:
        return None, None
    text = cache.get(norm(collection))
    for row in _rows(text):
        if str(row.get("_id", row.get("id"))) == ids[0] or str(row.get("mac", "")).lower() == ids[0].lower():
            return ids, row
    return ids, None


def changed_keys(before: dict[str, Any], body_text: str | None) -> dict[str, Any] | None:
    try:
        body = json.loads(body_text or "")
    except ValueError:
        return None
    if not isinstance(body, dict):
        return None
    payload = body.get("data") if isinstance(body.get("data"), dict) and "id" in body else body
    if not isinstance(payload, dict):
        return None
    out: dict[str, Any] = {}
    for key, new in payload.items():
        if key not in before and SECRET_KEY.match(key):
            out[key] = {"before": "<absent>", "after": "<redacted>"}
        elif before.get(key) != new:
            secret = bool(SECRET_KEY.match(key))
            out[key] = {"before": "<redacted>" if secret else _mask(before.get(key, "<absent>")),
                        "after": "<redacted>" if secret else _mask(new)}
    return out


def main() -> None:
    import ijson  # imported here so the pure helpers can be tested without it

    src = Path(sys.argv[1])
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(__file__).resolve().parent.parent / "har-files" / (src.stem + "_extract.json")
    out.parent.mkdir(exist_ok=True)
    total = 0
    gets: Counter[str] = Counter()
    others: list[dict] = []
    cache: dict[str, str] = {}
    with src.open("rb") as fh:
        for entry in ijson.items(fh, "log.entries.item"):
            total += 1
            req = entry.get("request", {})
            res = entry.get("response", {})
            url = urlsplit(req.get("url", ""))
            if not (url.path.startswith("/proxy/") or url.path.startswith("/api/")):
                continue
            method = req.get("method", "")
            status = res.get("status")
            content = res.get("content") or {}
            text = content.get("text") if content.get("encoding") != "base64" else None
            if method == "GET":
                gets[f"{norm(url.path)} {status}"] += 1
                if text and status == 200 and len(text) <= CACHE_LIMIT:
                    cache[norm(url.path)] = text  # only the latest read of each path is kept
                continue
            body = (req.get("postData") or {}).get("text")
            ids, before = find_before(cache, url.path, body)
            item = {
                "method": method, "path": norm(url.path), "query_keys": sorted(parse_qs(url.query)),
                "status": status, "request_body": redact(body, 8000), "response_excerpt": redact(text, 3000),
                "before": None, "changed": None,
            }
            if before is not None:
                item["before"] = redact(json.dumps(before, default=str), BEFORE_LIMIT)
                item["changed"] = changed_keys(before, body) if method in {"PUT", "POST", "PATCH"} else None
            others.append(item)
    out.write_text(json.dumps({"entries_total": total, "non_get": others, "get_paths": dict(sorted(gets.items()))},
                              indent=1, default=str), encoding="utf-8")
    print(f"{total} entries; {len(others)} non-GET API calls; {len(gets)} distinct GET paths -> {out}")
    for o in others:
        changed = "" if o["changed"] is None else f"  changed={list(o['changed'])}"
        print(f"{o['method']:6} {o['status']} {o['path']}{changed}  body={str(o['request_body'])[:140]}")


if __name__ == "__main__":
    main()
