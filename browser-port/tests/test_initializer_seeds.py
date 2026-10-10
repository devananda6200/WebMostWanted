"""Constructor seeding regressions use authored bytes and a fake PE section map."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools import seed_initializers as seeding


class FakeImage:
    def __init__(self, entries=None):
        self.base = 0x400000
        self.entry = self.base + 0x1000
        size = seeding.TABLE_END - seeding.TABLE_BEGIN
        raw = bytearray(0x400 + size)
        raw[0x200:0x400] = b"\xc3" * 0x200
        for index, target in (entries or {0: self.entry, 2: self.entry + 2}).items():
            struct.pack_into("<I", raw, 0x400 + index * 4, target)
        self.data = bytes(raw)
        self.sha256 = hashlib.sha256(self.data).hexdigest()
        self.pe = SimpleNamespace(sections=[
            SimpleNamespace(VirtualAddress=0x1000, Misc_VirtualSize=0x200, SizeOfRawData=0x200,
                            PointerToRawData=0x200, Characteristics=0x60000020),
            SimpleNamespace(VirtualAddress=seeding.TABLE_BEGIN - self.base, Misc_VirtualSize=size,
                            SizeOfRawData=size, PointerToRawData=0x400, Characteristics=0x40000040),
        ])


class InitializerSeedsTests(unittest.TestCase):
    def setUp(self):
        self.image = FakeImage()
        self.hash_patch = patch.object(seeding, "EXE_SHA", self.image.sha256)
        self.hash_patch.start()
        self.addCleanup(self.hash_patch.stop)
        self.trace = {
            "status": 2, "eip": self.image.entry, "fault": {"code": 3, "address": self.image.entry},
            "steps": 123, "captured_at_utc": "2026-10-11T00:00:00Z",
            "manifest": {"schema": 1, "kind": "startup-probe",
                         "provenance": {"executable_sha256": self.image.sha256, "entry": self.image.entry},
                         "image": {"address": self.image.base}},
        }
        self.saved = {"input_sha256": self.image.sha256, "seeds": [self.image.entry + 9], "note": "preserve"}

    def plan(self, count=3):
        return seeding.make_plan(self.image, self.trace, self.saved, count)

    def change_entries(self, entries):
        self.image = FakeImage(entries)
        seeding.EXE_SHA = self.image.sha256
        self.trace["manifest"]["provenance"]["executable_sha256"] = self.image.sha256
        self.saved["input_sha256"] = self.image.sha256

    def test_bounded_slots_skip_null_and_preserve_progress(self):
        updated, evidence = self.plan()
        self.assertEqual(updated["seeds"], [self.image.entry, self.image.entry + 2, self.image.entry + 9])
        self.assertEqual(updated["note"], "preserve")
        self.assertEqual(self.saved["seeds"], [self.image.entry + 9])
        self.assertEqual([slot["slot"] for slot in evidence["selected_slots"]],
                         [seeding.TABLE_BEGIN, seeding.TABLE_BEGIN + 4, seeding.TABLE_BEGIN + 8])
        self.assertEqual([slot["added"] for slot in evidence["selected_slots"]], [True, False, True])
        self.assertEqual(evidence["added_seed_count"], 2)
        self.assertEqual(evidence["table"]["end"], seeding.TABLE_END)
        again, evidence = seeding.make_plan(self.image, self.trace, updated, 3)
        self.assertEqual(again, updated)
        self.assertEqual(evidence["added_seed_count"], 0)

    def test_count_bounds_and_default(self):
        for count in (0, -1, 65, True, "4", 1.5):
            with self.subTest(count=count), self.assertRaisesRegex(ValueError, "1..64"):
                self.plan(count)
        self.assertEqual(len(self.plan(1)[1]["selected_slots"]), 1)
        self.assertEqual(len(self.plan(64)[1]["selected_slots"]), 64)
        self.assertEqual(len(seeding.make_plan(self.image, self.trace, self.saved)[1]["selected_slots"]), 32)

    def test_selection_stops_at_exclusive_table_end(self):
        last_index = (seeding.TABLE_END - seeding.TABLE_BEGIN) // 4 - 1
        self.change_entries({last_index: self.image.entry})
        _, evidence = self.plan(64)
        self.assertEqual(len(evidence["selected_slots"]), 1)
        self.assertEqual(evidence["selected_slots"][0]["slot"], seeding.TABLE_END - 4)

    def test_observed_duplicate_target_is_ambiguous(self):
        self.change_entries({0: self.image.entry, 11: self.image.entry})
        with self.assertRaisesRegex(ValueError, "ambiguous.*inspect the actual table pointer"):
            self.plan()

    def test_fault_must_match_current_constructor(self):
        for change in ({"fault": {"code": 5, "address": self.image.entry}},
                       {"fault": {"code": 3, "address": self.image.entry + 1}},
                       {"status": 1}, {"eip": 0}, {"eip": True}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                seeding.make_plan(self.image, {**self.trace, **change}, self.saved)
        self.trace["eip"] += 7
        self.trace["fault"]["address"] = self.trace["eip"]
        with self.assertRaisesRegex(ValueError, "not an audited constructor"):
            self.plan()

    def test_image_trace_and_saved_hash_mismatches(self):
        original = self.image.sha256
        self.image.sha256 = "0" * 64
        with self.assertRaisesRegex(ValueError, "Executable hash mismatch"):
            self.plan()
        self.image.sha256 = original
        self.trace["manifest"]["provenance"]["executable_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "evidence executable hash mismatch"):
            self.plan()
        self.trace["manifest"]["provenance"]["executable_sha256"] = original
        self.saved["input_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "different executable"):
            self.plan()

    def test_mismatched_pe_layout(self):
        for key in ("entry", "address"):
            changed = copy.deepcopy(self.trace)
            owner = changed["manifest"]["provenance" if key == "entry" else "image"]
            owner[key] += 4
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "address/entry"):
                seeding.make_plan(self.image, changed, self.saved)

    def test_malformed_manifest_and_json_shapes(self):
        for key, value in (("schema", 2), ("kind", "fixture"), ("provenance", []), ("image", None)):
            changed = copy.deepcopy(self.trace)
            changed["manifest"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                seeding.make_plan(self.image, changed, self.saved)
        for trace, saved in (([], self.saved), (self.trace, []), ({**self.trace, "manifest": None}, self.saved)):
            with self.subTest(trace=trace, saved=saved), self.assertRaises(ValueError):
                seeding.make_plan(self.image, trace, saved)

    def test_nonexecutables_and_virtual_tails_are_rejected(self):
        for target in (seeding.TABLE_BEGIN, self.image.entry + 0x200, 0xffffffff):
            self.change_entries({0: self.image.entry, 1: target})
            self.image.pe.sections[0].Misc_VirtualSize = 0x1000
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.plan()

    def test_saved_seed_validation(self):
        for seeds in (None, "[]", [True], [0], [2**32], ["0x401000"], [seeding.TABLE_BEGIN]):
            with self.subTest(seeds=seeds), self.assertRaises(ValueError):
                seeding.make_plan(self.image, self.trace, {**self.saved, "seeds": seeds})

    def test_truncated_ambiguous_and_virtual_table_bytes(self):
        self.image.data = self.image.data[:-1]
        with self.assertRaisesRegex(ValueError, "truncated"):
            self.plan()
        self.image = FakeImage()
        self.image.pe.sections.append(copy.copy(self.image.pe.sections[-1]))
        with self.assertRaisesRegex(ValueError, "unambiguous"):
            self.plan()
        self.image = FakeImage()
        self.image.pe.sections[-1].SizeOfRawData -= 4
        with self.assertRaisesRegex(ValueError, "file-backed"):
            self.plan()


class InitializerSeedFilesTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.project = self.root / "project with spaces"
        self.game = self.root / "read only authored inputs"
        for path in (self.project / "build", self.project / "generated", self.project / "artifacts", self.game):
            path.mkdir(parents=True)
        self.image = FakeImage()
        self.binary = self.game / "speed.exe"
        self.binary.write_bytes(self.image.data)
        (self.project / "config.local.json").write_text(json.dumps({"game_root": str(self.game)}), encoding="utf-8")
        self.manifest = {"schema": 1, "kind": "startup-probe",
                         "provenance": {"executable_sha256": self.image.sha256, "entry": self.image.entry},
                         "image": {"address": self.image.base, "sha256": hashlib.sha256(b"mapped authored bytes").hexdigest()},
                         "artifact_sha256": {"startup.wasm": hashlib.sha256(b"authored wasm identity").hexdigest()}}
        self.trace = {"status": 2, "eip": self.image.entry, "fault": {"code": 3, "address": self.image.entry},
                      "manifest": self.manifest}
        self.saved = {"input_sha256": self.image.sha256, "seeds": [self.image.entry + 9]}
        self.write_json("build/startup.json", self.manifest)
        self.write_json("artifacts/startup-node.json", self.trace)
        self.write_json(seeding.SEEDS_RELATIVE, self.saved)
        (self.project / "build/startup.wasm").write_bytes(b"authored wasm identity")
        (self.project / "build/game-image.bin").write_bytes(b"mapped authored bytes")
        for patcher in (patch.object(seeding, "EXE_SHA", self.image.sha256),
                        patch.object(seeding, "PEImage", return_value=self.image),
                        patch.dict(os.environ, {"NFS_GAME_ROOT": ""})):
            patcher.start()
            self.addCleanup(patcher.stop)

    def write_json(self, relative, value):
        (self.project / relative).write_text(json.dumps(value), encoding="utf-8")

    def run_seeder(self):
        return seeding.seed_initializers(3, self.project)

    def test_writes_only_contained_json_and_preserves_authored_input(self):
        before = self.binary.read_bytes(), self.binary.stat().st_mtime_ns
        report = self.run_seeder()
        self.assertEqual(report["added_seed_count"], 2)
        self.assertEqual(report["startup_wasm_sha256"], self.manifest["artifact_sha256"]["startup.wasm"])
        self.assertEqual(len(report["trace_sha256"]), 64)
        stored = json.loads((self.project / seeding.SEEDS_RELATIVE).read_text())
        self.assertIn(self.image.entry + 9, stored["seeds"])
        self.assertEqual(json.loads((self.project / seeding.EVIDENCE_RELATIVE).read_text()), report)
        self.assertEqual(before, (self.binary.read_bytes(), self.binary.stat().st_mtime_ns))
        self.assertEqual(self.run_seeder()["added_seed_count"], 0)
        self.assertFalse(list(self.project.rglob("*.tmp")))

    def test_missing_seed_file_starts_hash_bound_progress(self):
        (self.project / seeding.SEEDS_RELATIVE).unlink()
        report = self.run_seeder()
        self.assertIsNone(report["previous_seeds_sha256"])
        self.assertEqual(report["previous_seed_count"], 0)

    def test_stale_manifest_wasm_or_mapped_image_fails_without_writes(self):
        seeds_before = (self.project / seeding.SEEDS_RELATIVE).read_bytes()
        for relative, replacement, expected in (("build/startup.json", b"{}", "build manifest"),
                                                ("build/startup.wasm", b"different", "Wasm hash"),
                                                ("build/game-image.bin", b"different", "mapped-image hash")):
            target = self.project / relative
            before = target.read_bytes()
            target.write_bytes(replacement)
            with self.subTest(relative=relative), self.assertRaisesRegex(ValueError, expected):
                self.run_seeder()
            self.assertEqual((self.project / seeding.SEEDS_RELATIVE).read_bytes(), seeds_before)
            self.assertFalse((self.project / seeding.EVIDENCE_RELATIVE).exists())
            target.write_bytes(before)

    def test_concurrent_seed_update_is_preserved(self):
        original = seeding.make_plan
        newer = {**self.saved, "seeds": [self.image.entry + 10]}
        def concurrent(*args):
            result = original(*args)
            self.write_json(seeding.SEEDS_RELATIVE, newer)
            return result
        with patch.object(seeding, "make_plan", side_effect=concurrent):
            with self.assertRaisesRegex(ValueError, "seeds changed"):
                self.run_seeder()
        self.assertEqual(json.loads((self.project / seeding.SEEDS_RELATIVE).read_text()), newer)
        self.assertFalse((self.project / seeding.EVIDENCE_RELATIVE).exists())

    def test_output_containment_and_installation_protection(self):
        for relative in ("../escape.json", "generated/../tools/escape.json", "build/escape.json"):
            with self.subTest(relative=relative), self.assertRaisesRegex(ValueError, "designated ignored"):
                seeding.output_path(self.project, self.game, relative)
        with self.assertRaisesRegex(ValueError, "read-only installation"):
            seeding.output_path(self.game / "nested project", self.game, seeding.SEEDS_RELATIVE)

    def test_output_link_escape_rejected(self):
        link = self.project / seeding.EVIDENCE_RELATIVE
        destination = self.root / "outside.json"
        destination.write_text("preserve", encoding="utf-8")
        try:
            link.symlink_to(destination)
        except OSError as exc:
            self.skipTest(f"Symbolic links unavailable: {exc}")
        with self.assertRaisesRegex(ValueError, "escapes"):
            self.run_seeder()
        self.assertEqual(destination.read_text(), "preserve")


if __name__ == "__main__":
    unittest.main()
