from __future__ import annotations

import importlib.util
import json
import marshal
from pathlib import Path
import tempfile
import unittest
import zipfile

from tools.dgplugin_tools import (
    PackageError,
    PackagePasswordError,
    PackagePasswordRequired,
    decode_package,
    extract_package,
    inspect_package,
    is_package_encrypted,
)


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
            self.assertFalse(info.compiled)
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

    def test_decodes_current_python_bytecode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "compiled.dgplugin"
            code = compile("answer = 42\n", "main.py", "exec")
            pyc = importlib.util.MAGIC_NUMBER + (b"\0" * 12) + marshal.dumps(code)
            write_package(package, "main.pyc", pyc)
            result = decode_package(package, root / "decoded")
            self.assertEqual(len(result.disassembled), 1)
            listing = result.disassembled[0].read_text("utf-8")
            self.assertIn("STORE_NAME", listing)

    def test_reads_aes_encrypted_package_with_password(self) -> None:
        import pyzipper

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "encrypted.dgplugin"
            manifest = {"id": "test.plugin", "name": "Test", "main": "main.py"}
            with pyzipper.AESZipFile(package, "w", compression=pyzipper.ZIP_DEFLATED) as archive:
                archive.setpassword(b"correct-password")
                archive.setencryption(pyzipper.WZ_AES, nbits=256)
                archive.writestr("manifest.json", json.dumps(manifest))
                archive.writestr("main.py", "value = 42\n")
            self.assertTrue(is_package_encrypted(package))
            with self.assertRaises(PackagePasswordRequired):
                inspect_package(package)
            with self.assertRaises(PackagePasswordError):
                inspect_package(package, password="wrong-password")
            info = inspect_package(package, password="correct-password")
            self.assertEqual(info.manifest["id"], "test.plugin")
            output = root / "decoded"
            extract_package(package, output, password="correct-password")
            self.assertEqual((output / "main.py").read_text(), "value = 42\n")


if __name__ == "__main__":
    unittest.main()
