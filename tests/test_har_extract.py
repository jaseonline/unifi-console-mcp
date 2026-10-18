"""The HAR extractor keeps the earlier read of an object so a write can be shown as a diff."""
from __future__ import annotations

import json

from test_doh import load_script

ID = "99fbeab43464437389315c1f2e3a4b5c"[:24]


def mod():
    return load_script("har_extract")


def cache(rows):
    return {"/proxy/network/api/s/default/rest/wlanconf": json.dumps({"meta": {"rc": "ok"}, "data": rows})}


def test_before_and_changed_keys_for_a_put():
    m = mod()
    c = cache([{"_id": ID, "name": "apple", "wlan_bands": ["2g", "5g"], "x_iapp_key": "s3cret"},
               {"_id": "f" * 24, "name": "other"}])
    path = f"/proxy/network/api/s/default/rest/wlanconf/{ID}"
    body = json.dumps({"name": "apple", "wlan_bands": ["5g"], "x_iapp_key": "changed"})
    ids, before = m.find_before(c, path, body)
    assert ids == [ID] and before["name"] == "apple"
    changed = m.changed_keys(before, body)
    assert changed["wlan_bands"] == {"before": ["2g", "5g"], "after": ["5g"]}
    assert "name" not in changed
    assert changed["x_iapp_key"] == {"before": "<redacted>", "after": "<redacted>"}
    assert "s3cret" not in json.dumps(changed)


def test_no_earlier_read_gives_no_before():
    m = mod()
    path = f"/proxy/network/api/s/default/rest/wlanconf/{ID}"
    assert m.find_before({}, path, "{}") == ([ID], None)
    assert m.find_before(cache([{"_id": "e" * 24}]), path, "{}") == ([ID], None)


def test_create_and_collection_posts_have_no_before():
    m = mod()
    assert m.find_before(cache([{"_id": ID}]), "/proxy/network/api/s/default/rest/wlanconf", "{}") == (None, None)


def test_group_endpoint_looks_up_the_rest_collection():
    m = mod()
    c = {"/proxy/network/api/s/default/rest/networkconf": json.dumps({"data": [{"_id": ID, "enabled": True}]})}
    body = json.dumps({"id": [ID], "data": {"enabled": False}})
    ids, before = m.find_before(c, "/proxy/network/api/s/default/group/networkconf", body)
    assert ids == [ID] and before["enabled"] is True
    assert m.changed_keys(before, body) == {"enabled": {"before": True, "after": False}}


def test_secrets_are_masked_in_before():
    m = mod()
    assert m._mask({"x_passphrase": "abc", "name": "n", "nested": {"token": "t"}}) == {
        "x_passphrase": "<redacted>", "name": "n", "nested": {"token": "<redacted>"}}
