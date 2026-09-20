from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from tools.dgplugin_tools import PackageError, extract_package, inspect_package


def write_package(path: Path, main: str, data: bytes) -> None:
    manifest = {"id": "test.plugin", "name": "Test", "version": "1", "main": main}
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        archive.writestr(main, data)


class DgpluginToolsTest(unittest.TestCase):
    def test_inspect_and_extract_source_package(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "test.dgplugin"
            write_package(package, "main.py", b"value = 42\n")
            info = inspect_package(package)
            self.assertEqual(info.manifest["id"], "test.plugin")
            output = root / "source"
            extract_package(package, output)
            self.assertEqual((output / "main.py").read_text(), "value = 42\n")

    def test_rejects_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / "unsafe.dgplugin"
            with zipfile.ZipFile(package, "w") as archive:
                archive.writestr("manifest.json", '{"main":"../main.py"}')
                archive.writestr("../main.py", "")
            with self.assertRaises(PackageError):
                inspect_package(package)

    def test_rejects_existing_symlink_escape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "unsafe-link.dgplugin"
            with zipfile.ZipFile(package, "w") as archive:
                archive.writestr("manifest.json", '{"main":"src/main.py"}')
                archive.writestr("src/main.py", "")
            output = root / "output"
            output.mkdir()
            (output / "src").symlink_to(root / "outside", target_is_directory=True)
            with self.assertRaises(PackageError):
                extract_package(package, output)

    def test_rejects_bytecode_entrypoint(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "compiled.dgplugin"
            write_package(package, "main.pyc", b"bytecode")
            with self.assertRaisesRegex(PackageError, "открытым файлом .py"):
                inspect_package(package)

    def test_rejects_hidden_bytecode_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / "mixed.dgplugin"
            write_package(package, "main.py", b"answer = 42\n")
            with zipfile.ZipFile(package, "a") as archive:
                archive.writestr("module.pyc", b"bytecode")
            with self.assertRaisesRegex(PackageError, "байткод"):
                inspect_package(package)


if __name__ == "__main__":
    unittest.main()
