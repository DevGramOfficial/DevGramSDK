#!/usr/bin/env python3
"""Synchronize the public SDK/runtime sources from a DevGram checkout."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[1]
FILES = {
    "TMessagesProj/src/main/python/devgram_plugins.py": "python/devgram_plugins.py",
    "TMessagesProj/src/main/java/org/telegram/messenger/DevGramPlugins.java":
        "android/org/telegram/messenger/DevGramPlugins.java",
    "TMessagesProj/src/main/java/org/telegram/messenger/DevGramDevServer.java":
        "android/org/telegram/messenger/DevGramDevServer.java",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_commit(root: Path) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def modified_sources(root: Path) -> list[str]:
    tracked = ["TMessagesProj/src/main/python/devgram"] + list(FILES)
    try:
        output = subprocess.check_output(
            ["git", "-C", str(root), "status", "--short", "--", *tracked],
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return []
    return [line.rstrip() for line in output.splitlines() if line.strip()]


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: sync_from_devgram.py /path/to/DevGram", file=sys.stderr)
        return 2

    source_root = Path(sys.argv[1]).expanduser().resolve()
    python_source = source_root / "TMessagesProj/src/main/python/devgram"
    if not python_source.is_dir():
        print(f"DevGram checkout not found: {source_root}", file=sys.stderr)
        return 1

    copied: list[Path] = []
    target_package = REPOSITORY / "python/devgram"
    if target_package.exists():
        shutil.rmtree(target_package)
    shutil.copytree(
        python_source,
        target_package,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )
    copied.extend(sorted(target_package.rglob("*.py")))

    for source_name, target_name in FILES.items():
        source = source_root / source_name
        target = REPOSITORY / target_name
        if not source.is_file():
            print(f"Required source is missing: {source}", file=sys.stderr)
            return 1
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        copied.append(target)

    manifest = {
        "source_repository": "https://github.com/firedragoq/DevGram",
        "source_commit": git_commit(source_root),
        "source_worktree_changes": modified_sources(source_root),
        "plugin_api": 3,
        "files": {
            str(path.relative_to(REPOSITORY)): sha256(path)
            for path in sorted(copied)
        },
    }
    (REPOSITORY / "SOURCE_MANIFEST.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Synchronized {len(copied)} files from {source_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
