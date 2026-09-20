#!/usr/bin/env python3
"""CLI для просмотра и безопасной распаковки .dgplugin."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.dgplugin_tools import PackageError, extract_package, inspect_package


def _default_output(package: str, suffix: str) -> Path:
    path = Path(package).expanduser().resolve()
    name = path.name[:-9] if path.name.endswith(".dgplugin") else path.stem
    return path.with_name(name + suffix)


def _info(args: argparse.Namespace) -> None:
    info = inspect_package(args.package)
    print(json.dumps(info.manifest, ensure_ascii=False, indent=2))
    print("\nФормат: открытые исходники .py")
    print(f"Файлов: {len(info.files)}")
    print(f"Размер распакованных данных: {info.total_size} байт")
    if args.files:
        print("\nСодержимое:")
        for name in info.files:
            print(name)


def _unpack(args: argparse.Namespace) -> None:
    output = Path(args.output).resolve() if args.output else _default_output(args.package, "-source")
    files = extract_package(args.package, output, overwrite=args.force)
    print(f"Распаковано: {output}")
    print(f"Файлов: {len(files)}")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        prog="dgplugin",
        description="Просмотр и безопасная распаковка пакетов DevGram",
    )
    commands = result.add_subparsers(dest="command", required=True)
    info = commands.add_parser("info", help="показать манифест и сведения о пакете")
    info.add_argument("package")
    info.add_argument("--files", action="store_true", help="показать список файлов")
    info.set_defaults(handler=_info)

    unpack = commands.add_parser("unpack", help="распаковать пакет с исходниками")
    unpack.add_argument("package")
    unpack.add_argument("output", nargs="?")
    unpack.add_argument("-f", "--force", action="store_true", help="перезаписать файлы")
    unpack.set_defaults(handler=_unpack)

    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        args.handler(args)
        return 0
    except (OSError, PackageError) as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
