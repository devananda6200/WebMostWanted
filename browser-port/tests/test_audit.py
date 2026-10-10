"""Audit safety and parser regression tests use only synthetic test inputs."""

import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from tools.audit_installation import analyze_startup, audit, inspect_pe, interface_evidence
from tools.game_config import load_game_root, require_external_output


def minimal_pe() -> bytes:
    """A tiny original PE32 metadata fixture (one RET instruction), never run."""
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 1, 0, 0, 0, 224, 0x102)
    offset = 0x98
    struct.pack_into("<HBB", data, offset, 0x10B, 1, 0)
    struct.pack_into("<III", data, offset + 4, 512, 0, 0)
    struct.pack_into("<III", data, offset + 16, 0x1000, 0x1000, 0)
    struct.pack_into("<III", data, offset + 28, 0x400000, 0x1000, 0x200)
    struct.pack_into("<HH", data, offset + 40, 4, 0)
    struct.pack_into("<II", data, offset + 56, 0x2000, 0x200)
    struct.pack_into("<HH", data, offset + 68, 3, 0)
    struct.pack_into("<IIIIII", data, offset + 72, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    section = offset + 224
    data[section:section + 8] = b".text\0\0\0"
    struct.pack_into("<IIIIIIHHI", data, section + 8, 1, 0x1000, 512, 512, 0, 0, 0, 0, 0x60000020)
    data[512] = 0xC3
    return bytes(data)


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.game = self.root / "installation with spaces"
        self.game.mkdir()

    def tearDown(self):
        self.temporary.cleanup()

    def test_environment_overrides_config(self):
        (self.root / "config.local.json").write_text('{"game_root":"missing"}', encoding="utf-8")
        with patch.dict(os.environ, {"NFS_GAME_ROOT": str(self.game)}):
            self.assertEqual(load_game_root(self.root), self.game.resolve())

    def test_relative_local_configuration(self):
        (self.root / "config.local.json").write_text(json.dumps({"game_root": self.game.name}), encoding="utf-8")
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(load_game_root(self.root), self.game.resolve())

    def test_missing_configuration_fails(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, "NFS_GAME_ROOT"):
                load_game_root(self.root)

    def test_output_in_installation_rejected(self):
        with self.assertRaisesRegex(ValueError, "read-only"):
            require_external_output(self.game / "report.json", self.game)
        self.assertEqual(require_external_output(self.root / "report.json", self.game), self.root / "report.json")

    def test_pe_metadata_and_hash(self):
        binary = self.game / "synthetic.exe"
        binary.write_bytes(minimal_pe())
        result = inspect_pe(binary)
        self.assertEqual(result["machine"], 0x14C)
        self.assertEqual(result["entry_point_va"], 0x401000)
        self.assertEqual(result["entry_point_section"], ".text")
        self.assertEqual(len(result["sha256"]), 64)
        self.assertTrue(result["sections"][0]["executable"])
        self.assertFalse(result["sections"][0]["writable"])
        self.assertEqual(result["imports"], [])

    def test_inventory_and_no_installation_writes(self):
        (self.game / "synthetic.exe").write_bytes(minimal_pe())
        assets = self.game / "assets"
        assets.mkdir()
        (assets / "sample.BIN").write_bytes(b"original test bytes")
        before = {str(path): (path.read_bytes(), path.stat().st_mtime_ns) for path in self.game.rglob("*") if path.is_file()}
        result = audit(self.game)
        after = {str(path): (path.read_bytes(), path.stat().st_mtime_ns) for path in self.game.rglob("*") if path.is_file()}
        self.assertEqual(before, after)
        self.assertEqual(result["file_count"], 2)
        self.assertEqual(result["extensions"][".bin"]["files"], 1)
        self.assertEqual(result["directories"]["assets"]["files"], 1)
        self.assertTrue(result["read_only_observation"]["size_mtime_inventory_unchanged"])

    def test_malformed_executable_reports_parse_error(self):
        binary = self.game / "bad.exe"
        binary.write_bytes(b"not a PE executable")
        result = inspect_pe(binary)
        self.assertIn("parse_error", result)
        self.assertEqual(len(result["sha256"]), 64)

    def test_interface_evidence_is_import_based(self):
        evidence = interface_evidence([{"dll": "D3D9.dll", "symbols": [{"name": "Direct3DCreate9", "ordinal": None}]}])
        self.assertEqual(evidence["graphics"], ["D3D9.dll!Direct3DCreate9"])

    def test_input_not_misclassified_as_network(self):
        evidence = interface_evidence([{"dll": "USER32.dll", "symbols": [{"name": "SendInput", "ordinal": None}]}])
        self.assertNotIn("network", evidence)

    def test_bounded_analysis_stops_at_return(self):
        binary = self.game / "synthetic.exe"
        binary.write_bytes(minimal_pe())
        result = analyze_startup(binary, [])
        function = result["functions"]["0x401000"]
        self.assertEqual(len(function["instructions"]), 1)
        self.assertEqual(function["instructions"][0]["mnemonic"], "ret")
        self.assertFalse(function["limit_reached"])

    def test_callback_table_rejects_outside_image(self):
        binary = self.game / "synthetic.exe"
        binary.write_bytes(minimal_pe())
        with self.assertRaisesRegex(ValueError, "inside the image"):
            analyze_startup(binary, [], [(0, 4)])


if __name__ == "__main__":
    unittest.main()
