"""Безопасное чтение и распаковка пакетов ``.dgplugin`` с открытыми исходниками."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path, PurePosixPath
import stat
import zipfile


MAX_ENTRIES = 4096


class PackageError(ValueError):
    """Пакет повреждён или содержит небезопасную структуру."""


@dataclass(frozen=True)
class PackageInfo:
    path: Path
    manifest: dict
    files: tuple[str, ...]
    total_size: int


def _safe_name(value: str) -> str:
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    if (
        not normalized
        or normalized.startswith("/")
        or path.is_absolute()
        or any(part in ("", ".", "..") for part in path.parts)
        or (path.parts and ":" in path.parts[0])
    ):
        raise PackageError(f"небезопасный путь в пакете: {value!r}")
    return path.as_posix()


def _validated_entries(archive: zipfile.ZipFile) -> list[tuple[zipfile.ZipInfo, str]]:
    infos = archive.infolist()
    if len(infos) > MAX_ENTRIES:
        raise PackageError(f"в пакете больше {MAX_ENTRIES} записей")
    entries: list[tuple[zipfile.ZipInfo, str]] = []
    names: set[str] = set()
    for info in infos:
        name = _safe_name(info.filename.rstrip("/"))
        if name in names:
            raise PackageError(f"повторяющееся имя в пакете: {name}")
        names.add(name)
        mode = info.external_attr >> 16
        if mode and stat.S_ISLNK(mode):
            raise PackageError(f"символическая ссылка запрещена: {name}")
        entries.append((info, name))
    return entries


def _read_manifest(archive: zipfile.ZipFile, names: set[str]) -> dict:
    if "manifest.json" not in names:
        raise PackageError("в пакете отсутствует manifest.json")
    try:
        manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PackageError(f"ошибка manifest.json: {error}") from error
    if not isinstance(manifest, dict):
        raise PackageError("manifest.json должен содержать JSON-объект")
    main = _safe_name(str(manifest.get("main", "main.py")))
    if not main.lower().endswith(".py"):
        raise PackageError("точка входа плагина должна быть открытым файлом .py")
    if main not in names:
        raise PackageError(f"точка входа не найдена: {main}")
    bytecode = next((name for name in names if name.lower().endswith((".pyc", ".pyo"))), None)
    if bytecode:
        raise PackageError(f"байткод .pyc/.pyo запрещён; добавьте открытые исходники .py: {bytecode}")
    return manifest


def _target_path(destination: Path, name: str) -> Path:
    target = destination.joinpath(*PurePosixPath(name).parts)
    try:
        target.resolve(strict=False).relative_to(destination)
    except ValueError as error:
        raise PackageError(f"путь выходит за каталог распаковки: {name}") from error
    return target


def inspect_package(package: str | Path) -> PackageInfo:
    """Проверить source-only пакет и вернуть манифест и список файлов."""
    path = Path(package).expanduser().resolve()
    if not path.is_file() or not zipfile.is_zipfile(path):
        raise PackageError(f"файл не является .dgplugin ZIP-архивом: {path}")
    with zipfile.ZipFile(path) as archive:
        entries = _validated_entries(archive)
        names = {name for _info, name in entries}
        manifest = _read_manifest(archive, names)
        files = tuple(name for entry, name in entries if not entry.is_dir())
        total_size = sum(entry.file_size for entry, _name in entries if not entry.is_dir())
    return PackageInfo(path, manifest, files, total_size)


def extract_package(
    package: str | Path,
    output: str | Path,
    *,
    overwrite: bool = False,
) -> tuple[Path, ...]:
    """Безопасно распаковать ``.dgplugin`` без обхода каталога и ссылок."""
    info = inspect_package(package)
    destination = Path(output).expanduser().resolve()
    extracted: list[Path] = []
    with zipfile.ZipFile(info.path) as archive:
        entries = _validated_entries(archive)
        conflicts = [
            _target_path(destination, name)
            for entry, name in entries
            if not entry.is_dir() and _target_path(destination, name).exists()
        ]
        if conflicts and not overwrite:
            raise PackageError(f"файл уже существует: {conflicts[0]}")
        for entry, name in entries:
            target = _target_path(destination, name)
            if entry.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(entry) as source, target.open("wb") as sink:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    sink.write(chunk)
            extracted.append(target)
    return tuple(extracted)
