#!/usr/bin/env python3
"""CLI для просмотра и расшифровки структуры .dgplugin."""

from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.dgplugin_tools import (
    PackageError,
    decode_package,
    extract_package,
    has_protected_sources,
    inspect_package,
    is_package_encrypted,
)


def _default_output(package: str, suffix: str) -> Path:
    path = Path(package).expanduser().resolve()
    name = path.name[:-9] if path.name.endswith(".dgplugin") else path.stem
    return path.with_name(name + suffix)


def _password(args: argparse.Namespace, *, sources: bool = False) -> str | None:
    password = args.password or os.environ.get("DEVGRAM_PLUGIN_PASSWORD")
    if password:
        return password
    if is_package_encrypted(args.package):
        return getpass.getpass("Пароль пакета: ")
    if sources and has_protected_sources(args.package):
        return getpass.getpass("Пароль для расшифровки исходников: ")
    return None


def _info(args: argparse.Namespace) -> None:
    info = inspect_package(args.package, password=_password(args))
    print(json.dumps(info.manifest, ensure_ascii=False, indent=2))
    print(f"\nФормат: {'байткод .pyc' if info.compiled else 'исходники .py'}")
    print(f"Файлов: {len(info.files)}")
    print(f"Размер распакованных данных: {info.total_size} байт")
    print(f"Исходники защищены: {'да' if info.protected_sources else 'нет'}")
    if args.files:
        print("\nСодержимое:")
        for name in info.files:
            print(name)


def _unpack(args: argparse.Namespace) -> None:
    output = Path(args.output).resolve() if args.output else _default_output(args.package, "-source")
    files = extract_package(args.package, output, password=_password(args, sources=True), overwrite=args.force)
    print(f"Распаковано: {output}")
    print(f"Файлов: {len(files)}")


def _decode(args: argparse.Namespace) -> None:
    output = Path(args.output).resolve() if args.output else _default_output(args.package, "-decoded")
    result = decode_package(args.package, output, password=_password(args, sources=True), overwrite=args.force)
    print(f"Распаковано: {result.output}")
    print(f"Файлов: {len(result.extracted)}")
    print(f"Листингов байткода: {len(result.disassembled)}")
    if result.disassembled:
        print("Точный исходный код из .pyc не восстанавливается; созданы файлы .dis.txt.")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        prog="dgplugin",
        description="Просмотр и безопасная распаковка пакетов DevGram",
    )
    commands = result.add_subparsers(dest="command", required=True)
    info = commands.add_parser("info", help="показать манифест и сведения о пакете")
    info.add_argument("package")
    info.add_argument("--files", action="store_true", help="показать список файлов")
    info.add_argument("-p", "--password", help="пароль старого полностью зашифрованного пакета")
    info.set_defaults(handler=_info)

    unpack = commands.add_parser("unpack", help="распаковать пакет с исходниками")
    unpack.add_argument("package")
    unpack.add_argument("output", nargs="?")
    unpack.add_argument("-p", "--password", help="пароль исходников (или DEVGRAM_PLUGIN_PASSWORD)")
    unpack.add_argument("-f", "--force", action="store_true", help="перезаписать файлы")
    unpack.set_defaults(handler=_unpack)

    decode = commands.add_parser("decode", help="распаковать пакет и разобрать .pyc")
    decode.add_argument("package")
    decode.add_argument("output", nargs="?")
    decode.add_argument("-p", "--password", help="пароль исходников (или DEVGRAM_PLUGIN_PASSWORD)")
    decode.add_argument("-f", "--force", action="store_true", help="перезаписать файлы")
    decode.set_defaults(handler=_decode)
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
