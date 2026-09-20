"""Безопасное чтение, распаковка и анализ пакетов ``.dgplugin``.

Внешний пакет всегда остаётся ZIP-совместимым и устанавливается без пароля.
Защищённая сборка запускает ``.pyc``, а оригинальные ``.py`` хранит во
вложенном AES-контейнере, который этот модуль раскрывает по паролю автора.
"""

from __future__ import annotations

from dataclasses import dataclass
import dis
import importlib.util
import io
import json
import marshal
from pathlib import Path, PurePosixPath
import stat
from types import CodeType
import zipfile


MAX_ENTRIES = 4096
PROTECTED_SOURCES_PATH = ".devgram/protected-sources.zip"


class PackageError(ValueError):
    """Пакет повреждён или содержит небезопасную структуру."""


class PackagePasswordRequired(PackageError):
    """Зашифрованному пакету требуется пароль."""


class PackagePasswordError(PackageError):
    """Переданный пароль не подходит к пакету."""


@dataclass(frozen=True)
class PackageInfo:
    path: Path
    manifest: dict
    files: tuple[str, ...]
    total_size: int
    compiled: bool
    protected_sources: bool


@dataclass(frozen=True)
class DecodeResult:
    output: Path
    extracted: tuple[Path, ...]
    disassembled: tuple[Path, ...]


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


def is_package_encrypted(package: str | Path) -> bool:
    """Вернуть ``True``, если хотя бы одна запись ZIP защищена паролем."""
    path = Path(package).expanduser().resolve()
    if not path.is_file() or not zipfile.is_zipfile(path):
        raise PackageError(f"файл не является .dgplugin ZIP-архивом: {path}")
    try:
        with zipfile.ZipFile(path) as archive:
            return any(info.flag_bits & 0x1 for info in archive.infolist())
    except zipfile.BadZipFile as error:
        raise PackageError(f"пакет повреждён: {error}") from error


def _open_archive(path: Path, password: str | bytes | None):
    if not is_package_encrypted(path):
        return zipfile.ZipFile(path)
    if password is None or password == "" or password == b"":
        raise PackagePasswordRequired("пакет зашифрован; укажите пароль")
    try:
        import pyzipper
    except ImportError as error:
        raise PackageError("для AES-пакета установите pyzipper: pip install pyzipper") from error
    archive = pyzipper.AESZipFile(path)
    archive.setpassword(password.encode("utf-8") if isinstance(password, str) else password)
    return archive


def _password_error(error: BaseException) -> PackageError:
    message = str(error).lower()
    if any(value in message for value in ("password", "hmac", "authentication")):
        return PackagePasswordError("неверный пароль или пакет повреждён")
    return PackageError(f"не удалось прочитать пакет: {error}")


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
    if main not in names:
        raise PackageError(f"точка входа не найдена: {main}")
    return manifest


def _protected_source_path(manifest: dict, names: set[str]) -> str | None:
    builder = manifest.get("devgram_builder")
    protected = builder.get("protected_sources") if isinstance(builder, dict) else None
    if not isinstance(protected, dict):
        return None
    if protected.get("format") != "aes-zip-v1":
        raise PackageError("неподдерживаемый формат защищённых исходников")
    path = _safe_name(str(protected.get("path") or PROTECTED_SOURCES_PATH))
    if path not in names:
        raise PackageError(f"контейнер защищённых исходников не найден: {path}")
    return path


def _target_path(destination: Path, name: str) -> Path:
    target = destination.joinpath(*PurePosixPath(name).parts)
    try:
        target.resolve(strict=False).relative_to(destination)
    except ValueError as error:
        raise PackageError(f"путь выходит за каталог распаковки: {name}") from error
    return target


def inspect_package(package: str | Path, *, password: str | bytes | None = None) -> PackageInfo:
    """Проверить пакет и вернуть манифест, список файлов и тип сборки."""
    path = Path(package).expanduser().resolve()
    if not path.is_file() or not zipfile.is_zipfile(path):
        raise PackageError(f"файл не является .dgplugin ZIP-архивом: {path}")
    try:
        with _open_archive(path, password) as archive:
            entries = _validated_entries(archive)
            names = {name for _info, name in entries}
            manifest = _read_manifest(archive, names)
            protected_path = _protected_source_path(manifest, names)
            files = tuple(name for entry, name in entries if not entry.is_dir())
            total_size = sum(entry.file_size for entry, _name in entries if not entry.is_dir())
    except PackageError:
        raise
    except (RuntimeError, NotImplementedError, zipfile.BadZipFile) as error:
        raise _password_error(error) from error
    compiled = str(manifest.get("main", "main.py")).endswith(".pyc") or any(
        name.endswith(".pyc") for name in files
    )
    return PackageInfo(path, manifest, files, total_size, compiled, protected_path is not None)


def has_protected_sources(package: str | Path, *, password: str | bytes | None = None) -> bool:
    """Вернуть ``True``, если пакет содержит AES-контейнер оригинальных исходников."""
    return inspect_package(package, password=password).protected_sources


def _open_protected_sources(data: bytes, password: str | bytes | None):
    if password is None or password == "" or password == b"":
        raise PackagePasswordRequired("исходники защищены; укажите пароль")
    try:
        import pyzipper
    except ImportError as error:
        raise PackageError("для расшифровки исходников установите pyzipper: pip install pyzipper") from error
    archive = pyzipper.AESZipFile(io.BytesIO(data))
    archive.setpassword(password.encode("utf-8") if isinstance(password, str) else password)
    return archive


def extract_package(
    package: str | Path,
    output: str | Path,
    *,
    password: str | bytes | None = None,
    overwrite: bool = False,
) -> tuple[Path, ...]:
    """Безопасно распаковать ``.dgplugin`` без обхода каталога и ссылок."""
    info = inspect_package(package, password=password)
    destination = Path(output).expanduser().resolve()
    extracted: list[Path] = []
    try:
        with _open_archive(info.path, password) as archive:
            entries = _validated_entries(archive)
            names = {name for _entry, name in entries}
            protected_path = _protected_source_path(info.manifest, names)
            runtime_entries = [item for item in entries if item[1] != protected_path]
            source_archive = None
            source_entries: list[tuple[zipfile.ZipInfo, str]] = []
            if protected_path is not None:
                source_archive = _open_protected_sources(archive.read(protected_path), password)
                source_entries = _validated_entries(source_archive)
                if any(not entry.is_dir() and not name.endswith(".py") for entry, name in source_entries):
                    raise PackageError("контейнер исходников содержит неподдерживаемые файлы")
                damaged = source_archive.testzip()
                if damaged is not None:
                    raise PackageError(f"повреждённый файл защищённых исходников: {damaged}")
            conflicts = [
                _target_path(destination, name)
                for entry, name in runtime_entries + source_entries
                if not entry.is_dir() and _target_path(destination, name).exists()
            ]
            if conflicts and not overwrite:
                raise PackageError(f"файл уже существует: {conflicts[0]}")
            try:
                for current_archive, current_entries in (
                    (archive, runtime_entries),
                    (source_archive, source_entries),
                ):
                    if current_archive is None:
                        continue
                    for entry, name in current_entries:
                        target = _target_path(destination, name)
                        if entry.is_dir():
                            target.mkdir(parents=True, exist_ok=True)
                            continue
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with current_archive.open(entry) as source, target.open("wb") as sink:
                            while True:
                                chunk = source.read(1024 * 1024)
                                if not chunk:
                                    break
                                sink.write(chunk)
                        extracted.append(target)
            finally:
                if source_archive is not None:
                    source_archive.close()
    except PackageError:
        raise
    except (RuntimeError, NotImplementedError, zipfile.BadZipFile) as error:
        raise _password_error(error) from error
    return tuple(extracted)


def disassemble_pyc(data: bytes, *, filename: str = "<plugin>") -> str:
    """Вернуть дизассемблирование ``.pyc`` для текущей версии Python."""
    if len(data) < 16:
        raise PackageError(f"повреждённый .pyc: {filename}")
    if data[:4] != importlib.util.MAGIC_NUMBER:
        actual = data[:4].hex()
        expected = importlib.util.MAGIC_NUMBER.hex()
        raise PackageError(
            f"{filename}: несовместимая версия Python (magic {actual}, ожидается {expected})"
        )
    try:
        code = marshal.loads(data[16:])
    except (EOFError, TypeError, ValueError) as error:
        raise PackageError(f"не удалось прочитать байткод {filename}: {error}") from error
    if not isinstance(code, CodeType):
        raise PackageError(f"{filename}: внутри .pyc нет объекта кода")
    output = io.StringIO()
    dis.dis(code, file=output, depth=None)
    return output.getvalue()


def decode_package(
    package: str | Path,
    output: str | Path,
    *,
    password: str | bytes | None = None,
    overwrite: bool = False,
) -> DecodeResult:
    """Распаковать пакет и создать ``.dis.txt`` для каждого файла байткода."""
    destination = Path(output).expanduser().resolve()
    extracted = extract_package(package, destination, password=password, overwrite=overwrite)
    listings: list[Path] = []
    for path in extracted:
        if path.suffix != ".pyc":
            continue
        listing = path.with_suffix(path.suffix + ".dis.txt")
        if listing.exists() and not overwrite:
            raise PackageError(f"файл уже существует: {listing}")
        listing.write_text(disassemble_pyc(path.read_bytes(), filename=path.name), "utf-8")
        listings.append(listing)
    return DecodeResult(destination, extracted, tuple(listings))
