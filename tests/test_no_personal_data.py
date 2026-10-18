"""Guard: tracked text files may only contain documentation-style MAC addresses.

Allowed first octets are locally administered or documentation ranges used by the tests and the spec examples.
A real device MAC in a fixture, script or document fails this test, so it cannot be published by accident.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP = {".git", ".venv", "__pycache__", ".pytest_cache", "node_modules"}
EXT = {".py", ".md", ".yaml", ".yml", ".toml", ".xml", ".json", ".txt"}
MAC = re.compile(r"(?<![0-9A-Fa-f:-])([0-9A-Fa-f]{2})([:-][0-9A-Fa-f]{2}){5}(?![0-9A-Fa-f:-])")
ALLOWED_PREFIXES = ("02:", "00:00:5e", "aa:", "cc:", "00:11:22", "66:77", "11:", "22:", "33:", "44:", "55:", "0a:")


def test_only_documentation_macs():
    bad = []
    for p in ROOT.rglob("*"):
        if not p.is_file() or p.suffix not in EXT or p.name == "uv.lock" or any(x in p.parts for x in SKIP):
            continue
        for m in MAC.finditer(p.read_text(encoding="utf-8", errors="ignore")):
            mac = m.group(0).lower().replace("-", ":")
            if not mac.startswith(ALLOWED_PREFIXES):
                bad.append(f"{p.relative_to(ROOT).as_posix()}: {mac}")
    assert not bad, "real-looking MAC addresses found: " + ", ".join(sorted(set(bad)))
