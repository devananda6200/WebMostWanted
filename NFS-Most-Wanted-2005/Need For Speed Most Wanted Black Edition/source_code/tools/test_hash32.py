"""Compare the reconstructed routine, compiled to Wasm, with original x86 in Unicorn."""
import hashlib
import json
from pathlib import Path
import random
import subprocess

import capstone
import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EIP

from inspect_inputs import ROOT, GAME, sha256


def main():
    source = GAME / "speed.exe"
    if sha256(source) != "80774c2e5d619b4f120b48d4462896fd504c263399d203a238769cffde1d253c":
        raise ValueError("Unexpected executable identity")
    with pefile.PE(str(source)) as pe:
        machine_code = pe.get_data(0x460bf0 - pe.OPTIONAL_HEADER.ImageBase, 33)
    if hashlib.sha256(machine_code).hexdigest() != "c5798f0490c6fc265ff0ebd063a7c536e8281fb2789eb4434900ebb3d3896808":
        raise ValueError("Unexpected routine bytes")
    output = ROOT / "evidence" / "hash32"
    output.mkdir(exist_ok=True)
    disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    (output / "original.asm").write_text("\n".join(
        f"{item.address:08x}  {item.bytes.hex():30s}  {item.mnemonic} {item.op_str}"
        for item in disassembler.disasm(machine_code, 0x460bf0)) + "\n")
    rng = random.Random(0x460BF0)
    inputs = [b"", b"a", b"speed.exe", b"CAR", b"GLOBAL/gameplay.bin", b"A\0ignored", bytes(range(1, 256))]
    inputs += [bytes([value]) for value in range(1, 256)]
    inputs += [bytes(rng.randrange(1, 256) for _ in range(rng.randrange(0, 1025))) for _ in range(1000)]
    inputs += [b"\xff" * 8192, b"A" * 8192]
    cases = []
    emulator = Uc(UC_ARCH_X86, UC_MODE_32)
    emulator.mem_map(0x460000, 0x10000)
    emulator.mem_map(0x200000, 0x10000)
    emulator.mem_map(0x300000, 0x10000)
    emulator.mem_map(0x400000, 0x1000)
    emulator.mem_write(0x460bf0, machine_code)
    for index, value in enumerate(inputs):
        emulator.mem_write(0x300000, value + b"\0")
        emulator.mem_write(0x20ff00, (0x400000).to_bytes(4, "little") + (0x300000).to_bytes(4, "little"))
        emulator.reg_write(UC_X86_REG_ESP, 0x20ff00)
        for register in (UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX):
            emulator.reg_write(register, rng.getrandbits(32))
        emulator.emu_start(0x460bf0, 0x400000, count=100000)
        if emulator.reg_read(UC_X86_REG_EIP) != 0x400000:
            raise ValueError("Reference instruction budget exhausted before return")
        expected = emulator.reg_read(UC_X86_REG_EAX)
        if bytes(emulator.mem_read(0x300000, len(value) + 1)) != value + b"\0":
            raise ValueError("Original routine changed the input buffer")
        cases.append({"index": index, "input_hex": value.hex(), "expected": expected})
    (output / "reference.json").write_text(json.dumps(cases), encoding="utf-8")
    sdk = GAME.parents[1] / "browser-port" / ".tools" / "emsdk-4.0.23"
    clang = sdk / "upstream" / "bin" / "clang.exe"
    node_candidates = sorted((sdk / "node").glob("*/bin/node.exe"))
    if not clang.is_file() or not node_candidates:
        raise ValueError("Existing browser-port LLVM/Node SDK is required")
    command = [str(clang), "--target=wasm32", "-ffreestanding", "-O2", "-nostdlib",
               "-Wl,--no-entry", "-Wl,--export=nfsmw_hash32", "-Wl,--export-memory",
               str(ROOT / "reconstructed" / "hash32.c"), "-o", str(output / "hash32.wasm")]
    subprocess.run(command, check=True)
    subprocess.run([str(node_candidates[0]), str(ROOT / "tools" / "test_hash32.mjs")], check=True)


if __name__ == "__main__":
    main()
