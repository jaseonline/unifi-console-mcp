"""Secret redaction and response shaping.

UniFi responses carry plain-text secrets in `x_`-prefixed fields (x_passphrase, x_authkey, x_aes_gcm,
x_password, ...) and some other credential-looking fields. They are always removed before anything
reaches the model. There is deliberately no switch to turn this off.
"""

from __future__ import annotations

import json
import re
from typing import Any

REDACTED = "[redacted]"

_SECRET_SUBSTRINGS = ("password", "passphrase", "secret", "private_key", "preshared", "psk", "api_key", "apikey")
_SECRET_EXACT = {"token", "api_token", "access_token", "auth_token", "apikey", "api_key", "jwt", "csrf_token"}


def is_secret_key(key: str) -> bool:
    lowered = key.lower()
    if lowered.startswith("x_"):
        return True
    if lowered in _SECRET_EXACT:
        return True
    return any(part in lowered for part in _SECRET_SUBSTRINGS)


def redact(value: Any) -> Any:
    """Return a deep copy of `value` with secret-looking fields replaced."""
    if isinstance(value, dict):
        return {
            k: (REDACTED if isinstance(k, str) and is_secret_key(k) and v not in (None, "", [], {}) else redact(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


def unwrap(payload: Any) -> Any:
    """Strip response envelopes: legacy `{"meta": {...}, "data": [...]}` and UniFi OS `{"code", "codeS", "msg", "data"}`."""
    if isinstance(payload, dict) and "data" in payload:
        if "meta" in payload or "codeS" in payload:
            return payload["data"]
        if set(payload) <= {"data", "count", "err_code", "message", "offset", "limit", "totalCount"}:
            return payload["data"]
    return payload


def project_fields(items: Any, fields: list[str] | None, pattern: str | None = None) -> Any:
    """Keep only selected keys of each dict in a list (or of a single dict).

    `fields` are exact keys; `pattern` is a regex matched against keys. Both may be combined.
    """
    if not fields and not pattern:
        return items
    rx = re.compile(pattern) if pattern else None

    def keep(d: dict) -> dict:
        return {k: v for k, v in d.items() if (fields and k in fields) or (rx and rx.search(k))}

    if isinstance(items, list):
        return [keep(i) if isinstance(i, dict) else i for i in items]
    if isinstance(items, dict):
        return keep(items)
    return items


def filter_text(items: Any, needle: str | None) -> Any:
    """Case-insensitive substring filter over the JSON text of each list item."""
    if not needle or not isinstance(items, list):
        return items
    lowered = needle.lower()
    return [i for i in items if lowered in json.dumps(i, default=str).lower()]


def page(items: Any, offset: int = 0, limit: int | None = None) -> tuple[Any, dict[str, Any]]:
    """Slice a list. Returns (slice, meta). Non-lists pass through with empty meta."""
    if not isinstance(items, list):
        return items, {}
    total = len(items)
    end = total if limit is None else min(total, offset + limit)
    sliced = items[offset:end]
    meta: dict[str, Any] = {"total": total, "offset": offset, "returned": len(sliced)}
    if end < total:
        meta["next_offset"] = end
    return sliced, meta


def fit(payload: Any, max_chars: int) -> tuple[str, dict[str, Any]]:
    """Serialise `payload` as compact JSON no longer than ~max_chars.

    Lists are cut to the number of whole items that fit. Dicts have their largest list values
    cut. Anything else is truncated as text. The returned meta says what was dropped so the caller
    can narrow the request instead of guessing.
    """
    text = json.dumps(payload, separators=(",", ":"), default=str)
    if len(text) <= max_chars:
        return text, {}

    meta: dict[str, Any] = {"truncated": True, "full_chars": len(text)}

    if isinstance(payload, list):
        kept: list[Any] = []
        used = 2
        for item in payload:
            size = len(json.dumps(item, separators=(",", ":"), default=str)) + 1
            if used + size > max_chars:
                break
            kept.append(item)
            used += size
        meta.update(total=len(payload), returned=len(kept), next_offset=len(kept))
        meta["hint"] = "Use limit/offset, search or fields to narrow the result."
        return json.dumps(kept, separators=(",", ":"), default=str), meta

    if isinstance(payload, dict):
        shrunk = dict(payload)
        for key in sorted(shrunk, key=lambda k: -len(json.dumps(shrunk[k], default=str))):
            if len(json.dumps(shrunk, separators=(",", ":"), default=str)) <= max_chars:
                break
            value = shrunk[key]
            if isinstance(value, list) and value:
                body, sub = fit(value, max(1_000, max_chars // 2))
                shrunk[key] = json.loads(body)
                meta.setdefault("truncated_keys", {})[key] = sub
        text = json.dumps(shrunk, separators=(",", ":"), default=str)
        if len(text) <= max_chars:
            meta["hint"] = "Large lists were cut; narrow with fields/search or call a more specific operation."
            return text, meta

    meta["hint"] = "Response cut at the character limit; narrow the request."
    return text[:max_chars], meta
