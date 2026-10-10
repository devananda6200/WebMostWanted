"""Executable fetches must respect PE virtual-to-file section boundaries."""

from pathlib import Path
import struct
import tempfile
import unittest

from tests.test_audit import minimal_pe
from translator.lift import PEImage, lift


def adjacent_executable_sections() -> bytes:
    """Two adjacent virtual sections whose raw file data are not adjacent.

    The mapped instruction is MOV EAX,1 across the boundary. Reading linearly
    through the raw file would instead fabricate MOV EAX,0x12345678.
    """
    data = bytearray(0x2200)
    data[:1024] = minimal_pe()
    struct.pack_into("<H", data, 0x86, 2)
    struct.pack_into("<I", data, 0x98 + 16, 0x1FFF)
    struct.pack_into("<I", data, 0x98 + 56, 0x3000)
    first_section = 0x98 + 224
    struct.pack_into("<IIII", data, first_section + 8, 0x1000, 0x1000, 0x1000, 0x200)
    second_section = first_section + 40
    data[second_section:second_section + 8] = b".more\0\0\0"
    struct.pack_into(
        "<IIIIIIHHI", data, second_section + 8,
        0x200, 0x2000, 0x200, 0x2000, 0, 0, 0, 0, 0x60000020,
    )
    data[0x11FF:0x1204] = bytes.fromhex("b8 78 56 34 12")
    data[0x2000:0x2005] = bytes.fromhex("01 00 00 00 c3")
    return bytes(data)


class PEInstructionBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.binary = self.directory / "synthetic-boundary.exe"
        self.binary.write_bytes(adjacent_executable_sections())

    def tearDown(self):
        self.temporary.cleanup()

    def test_read_clips_at_original_executable_section(self):
        image = PEImage(self.binary)
        self.assertTrue(image.executable(image.entry))
        self.assertTrue(image.executable(image.entry + 4))
        mapped = image.pe.get_memory_mapped_image()
        self.assertEqual(mapped[0x1FFF:0x2004], bytes.fromhex("b8 01 00 00 00"))
        self.assertEqual(image.read(image.entry, 15), bytes.fromhex("b8"))

    def test_partial_boundary_instruction_is_not_translated(self):
        image = PEImage(self.binary)
        output = self.directory / "translated.cpp"
        result = lift(image, [image.entry], output, limit=8)
        self.assertEqual(result["instruction_count"], 0)
        self.assertEqual(result["untranslated_targets"], [image.entry])
        self.assertNotIn("0x12345678", output.read_text(encoding="utf-8"))
        self.assertNotIn("case 0x401fff", output.read_text(encoding="utf-8"))

    def test_complete_instruction_at_last_byte_is_accepted(self):
        data = bytearray(self.binary.read_bytes())
        data[0x11FF] = 0xC3  # A complete original synthetic RET at the boundary.
        self.binary.write_bytes(data)
        image = PEImage(self.binary)
        result = lift(image, [image.entry], self.directory / "ret.cpp", limit=8)
        self.assertEqual(result["instruction_count"], 1)
        self.assertEqual(result["mnemonics"], {"ret": 1})
        self.assertEqual(result["untranslated_targets"], [])


if __name__ == "__main__":
    unittest.main()
