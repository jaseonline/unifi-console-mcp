"""Build the MCPB bundle for unifi-console-mcp.

    uv run mcpb/build.py            # regenerate manifest, stage, validate, pack  -> dist/unifi-console-mcp-<version>.mcpb
    uv run mcpb/build.py --check    # stage and validate only (no .mcpb written)

The bundle is assembled from an explicit allow-list into dist/stage, never by zipping the working tree, so
captures (har-files/), probe output, journals, logs, .env files and git history cannot leak into it.
Requires the `mcpb` CLI (npm i -g @anthropic-ai/mcpb) and `uv` on PATH.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DIST = ROOT / "dist"
STAGE = DIST / "stage"

FILES = ["pyproject.toml", "uv.lock", "README.md"]  # copied if present (uv.lock strongly recommended)
TREES = [("src/unifi_console_mcp", "src/unifi_console_mcp"), ("mcpb/icons", "icons")]
SKIP_DIRS = {"__pycache__", ".pytest_cache", ".venv"}
SKIP_SUFFIXES = {".pyc", ".pyo", ".log", ".har", ".env"}
# Anything that looks like a credential or capture must stop the build, not be quietly included.
SUSPECT = re.compile(r"(\.env|\.har$|har-files|probe_out|journal|secret|\.pem$|\.key$|id_rsa)", re.IGNORECASE)


def run(cmd: list[str]) -> str:
    exe = shutil.which(cmd[0])
    if not exe:
        raise SystemExit(f"'{cmd[0]}' not found on PATH")
    proc = subprocess.run([exe, *cmd[1:]], cwd=ROOT, capture_output=True, text=True)
    out = (proc.stdout + proc.stderr).strip()
    if proc.returncode:
        raise SystemExit(f"{' '.join(cmd)} failed ({proc.returncode}):\n{out}")
    return out


def stage() -> list[Path]:
    if STAGE.exists():
        shutil.rmtree(STAGE)
    STAGE.mkdir(parents=True)
    copied: list[Path] = []
    for name in FILES:
        src = ROOT / name
        if src.is_file():
            shutil.copy2(src, STAGE / name)
            copied.append(STAGE / name)
        elif name == "uv.lock":
            print("warning: no uv.lock; dependencies will resolve fresh on first launch", file=sys.stderr)
    for src_rel, dst_rel in TREES:
        for path in sorted((ROOT / src_rel).rglob("*")):
            rel = path.relative_to(ROOT / src_rel)
            if path.is_dir() or SKIP_DIRS & set(rel.parts) or path.suffix in SKIP_SUFFIXES:
                continue
            dst = STAGE / dst_rel / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, dst)
            copied.append(dst)
    shutil.copy2(HERE / "manifest.json", STAGE / "manifest.json")
    copied.append(STAGE / "manifest.json")
    bad = [p for p in copied if SUSPECT.search(str(p.relative_to(STAGE)))]
    if bad:
        raise SystemExit(
            "refusing to bundle suspicious files:\n  " + "\n  ".join(str(p.relative_to(STAGE)) for p in bad)
        )
    return copied


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="stage and validate only")
    args = ap.parse_args()

    print(run(["uv", "run", str(HERE / "gen_manifest.py")]))
    files = stage()
    print(f"staged {len(files)} files in {STAGE}")
    print(run(["mcpb", "validate", str(STAGE / "manifest.json")]))
    if args.check:
        return
    version = re.search(r'"version":\s*"([^"]+)"', (HERE / "manifest.json").read_text()).group(1)  # type: ignore[union-attr]
    out = DIST / f"unifi-console-mcp-{version}.mcpb"
    out.unlink(missing_ok=True)
    print(run(["mcpb", "pack", str(STAGE), str(out)]))
    print(run(["mcpb", "info", str(out)]))
    print(f"\nbuilt {out} ({out.stat().st_size / 1024:.0f} KiB)")


if __name__ == "__main__":
    main()
