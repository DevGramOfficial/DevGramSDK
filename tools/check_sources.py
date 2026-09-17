#!/usr/bin/env python3
"""Fast repository checks which don't require the Android build tree."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    python_files = sorted((ROOT / "python").rglob("*.py"))
    if not python_files:
        raise SystemExit("Python sources are missing")
    for path in python_files:
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    runtime = ROOT / "python/devgram_plugins.py"
    if "DEVGRAM_PLUGIN_API = 3" not in runtime.read_text(encoding="utf-8"):
        raise SystemExit("Unexpected DevGram plugin API level")

    for required in (
        ROOT / "android/org/telegram/messenger/DevGramPlugins.java",
        ROOT / "android/org/telegram/messenger/DevGramDevServer.java",
    ):
        if not required.is_file():
            raise SystemExit(f"Required source is missing: {required}")

    manifest_path = ROOT / "SOURCE_MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for name, expected in manifest["files"].items():
        path = ROOT / name
        if not path.is_file() or sha256(path) != expected:
            raise SystemExit(f"Source manifest mismatch: {name}")

    generated = list(ROOT.rglob("__pycache__")) + list(ROOT.rglob("*.pyc"))
    if generated:
        raise SystemExit(f"Generated Python files found: {generated[0]}")
    print(f"Checked {len(python_files)} Python files and source manifest")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
