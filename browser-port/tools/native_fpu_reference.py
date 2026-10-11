"""Measure x87 control-word readback with authored, import-free native PE32 probes.

Run with ``python -m tools.native_fpu_reference`` on non-elevated x86 Windows.
Inputs are the assembly templates below and the pinned local compiler tools.
All generated source, binaries and results stay in artifacts/native-fpu-control/.
No game installation, game binary, external input executable or network is used.
"""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

import capstone
import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
from unicorn import x86_const as x86

from tools.toolchain import clang_path, linker_command, linker_path, sha256


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "artifacts/native-fpu-control"
CONTROL_WORDS = (
    0x0000, 0x003F, 0x0040, 0x0080, 0x00BF, 0x00FF, 0x013F, 0x023F,
    0x027F, 0x033F, 0x037F, 0x0F3F, 0x1000, 0x2000, 0x4000, 0x8000,
    0x537F, 0xFFFF,
)
ALLOWED_INSTRUCTIONS = {"mov", "movzx", "sub", "add", "fninit", "fnstcw", "fldcw", "ret"}
SOURCE_URLS = [
    "https://cdrdv2-public.intel.com/843827/253665-sdm-vol-1-dec-24.pdf",
    "https://cdrdv2-public.intel.com/819712/253666-sdm-vol-2a.pdf",
]


def require_native_platform() -> None:
    if sys.platform != "win32" or platform.machine().upper() not in {"AMD64", "X86", "I386", "I686"}:
        raise RuntimeError("This probe requires native x86/x64 Windows; emulated ARM execution is not a hardware x87 oracle.")


def is_elevated() -> bool:
    """Read the current token; fail closed if token inspection is unavailable."""
    require_native_platform()
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.OpenProcessToken.restype = wintypes.BOOL
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                         wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi.GetTokenInformation.restype = wintypes.BOOL
    token, elevated, length = wintypes.HANDLE(), wintypes.DWORD(), wintypes.DWORD()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x8, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not advapi.GetTokenInformation(token, 20, ctypes.byref(elevated),
                                         ctypes.sizeof(elevated), ctypes.byref(length)):
            raise ctypes.WinError(ctypes.get_last_error())
        if length.value != ctypes.sizeof(elevated):
            raise RuntimeError("Unexpected TokenElevation result size; refusing native execution.")
        return bool(elevated.value)
    finally:
        kernel.CloseHandle(token)


def require_non_elevated() -> None:
    if is_elevated():
        raise RuntimeError("Refusing native execution with an elevated token. Run from a normal, non-administrator terminal.")


def artifact_path(name: str) -> Path:
    path = OUTPUT / name
    # Fixed names only; also reject an artifact directory/file redirected outside
    # this project through a junction or symbolic link before writing or running.
    if Path(name).name != name or not path.resolve().is_relative_to(ROOT):
        raise RuntimeError(f"Artifact path escapes the project: {path}")
    return path


def run_command(command: list[str], timeout: int = 20) -> dict:
    result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=timeout,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    return {"command": command, "return_code": result.returncode,
            "stdout": result.stdout.decode("utf-8", errors="replace"),
            "stderr": result.stderr.decode("utf-8", errors="replace")}


def validate_pe(data: bytes) -> tuple[pefile.PE, list[dict]]:
    """Check the just-compiled fixture before it can become a native process."""
    pe = pefile.PE(data=data)
    if pe.FILE_HEADER.Machine != 0x14C or pe.OPTIONAL_HEADER.Magic != 0x10B:
        raise RuntimeError("Compiled fixture is not PE32 i386.")
    # No loader callbacks, imports or imported delay-load code are allowed.
    for directory_id in (1, 9, 13):
        directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[directory_id]
        if directory.VirtualAddress or directory.Size:
            raise RuntimeError(f"Compiled fixture has unexpected PE directory {directory_id}.")
    if getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        raise RuntimeError("Compiled fixture has imports.")
    rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    section = pe.get_section_by_rva(rva)
    if section is None or not section.Characteristics & 0x20000000:
        raise RuntimeError("Fixture entry is not in an executable section.")
    remaining = section.Misc_VirtualSize - (rva - section.VirtualAddress)
    raw_remaining = section.SizeOfRawData - (rva - section.VirtualAddress)
    if remaining <= 0 or remaining > raw_remaining:
        raise RuntimeError("Fixture entry is not fully file-backed.")
    code = pe.get_data(rva, remaining)
    entry = pe.OPTIONAL_HEADER.ImageBase + rva
    instructions = []
    for instruction in capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32).disasm(code, entry):
        if instruction.mnemonic not in ALLOWED_INSTRUCTIONS:
            raise RuntimeError(f"Unexpected authored fixture instruction: {instruction.mnemonic} {instruction.op_str}")
        instructions.append({"address": instruction.address, "bytes": instruction.bytes.hex(),
                             "mnemonic": instruction.mnemonic, "operands": instruction.op_str})
    if (not instructions or instructions[-1]["mnemonic"] != "ret"
            or sum(len(bytes.fromhex(item["bytes"])) for item in instructions) != len(code)
            or any(item["mnemonic"] == "ret" for item in instructions[:-1])):
        raise RuntimeError("Fixture must decode completely as one straight-line sequence ending in RET.")
    return pe, instructions


def unicorn_return(pe: pefile.PE) -> tuple[int, str]:
    reference = Uc(UC_ARCH_X86, UC_MODE_32)
    reference.ctl_set_cpu_model(x86.UC_CPU_X86_PENTIUM3)
    base = pe.OPTIONAL_HEADER.ImageBase
    size = (pe.OPTIONAL_HEADER.SizeOfImage + 4095) & ~4095
    image = pe.get_memory_mapped_image()
    reference.mem_map(base, size)
    reference.mem_write(base, image)
    reference.mem_map(0x2000000, 0x10000)
    reference.mem_map(0x3000000, 4096)
    stack, stop = 0x2008000, 0x3000000
    reference.mem_write(stack, stop.to_bytes(4, "little"))
    reference.reg_write(x86.UC_X86_REG_ESP, stack)
    # Protected-mode numerical exceptions enabled, EM/TS clear. No host APIs.
    reference.reg_write(x86.UC_X86_REG_CR0,
                        (reference.reg_read(x86.UC_X86_REG_CR0) | 0x22) & ~0xC)
    reference.emu_start(base + pe.OPTIONAL_HEADER.AddressOfEntryPoint, stop,
                        timeout=1_000_000, count=100)
    if reference.reg_read(x86.UC_X86_REG_EIP) != stop:
        raise RuntimeError("Unicorn fixture failed to reach its return sentinel.")
    return reference.reg_read(x86.UC_X86_REG_EAX), hashlib.sha256(image).hexdigest()


def probe(report: dict, name: str, body: str, requested: int | None = None,
          expected: int | None = None) -> None:
    source_path, object_path, executable_path = (artifact_path(name + suffix) for suffix in (".S", ".obj", ".exe"))
    source = ".text\n.intel_syntax noprefix\n.code32\n.globl _entry\n_entry:\n" + body + "\n"
    case = {"name": name, "requested_control": requested, "status": "building", "commands": []}
    report["cases"].append(case)
    try:
        source_path.write_text(source, encoding="utf-8")
        case.update({"source": str(source_path.relative_to(ROOT)), "source_sha256": sha256(source_path)})
        commands = [
            [str(clang_path()), "--target=i686-pc-windows-msvc", "-c", str(source_path), "-o", str(object_path)],
            [*linker_command(), "/machine:x86", "/subsystem:console", "/entry:entry", "/nodefaultlib",
             "/fixed", "/base:0x400000", "/timestamp:0", "/safeseh:no", "/out:" + str(executable_path), str(object_path)],
        ]
        for command in commands:
            result = run_command(command)
            case["commands"].append(result)
            if result["return_code"]:
                raise RuntimeError(f"{name}: compiler failed: {result['stderr'].strip()}")
        data = executable_path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        pe, instructions = validate_pe(data)
        case.update({"executable": str(executable_path.relative_to(ROOT)), "executable_sha256": digest,
                     "object_sha256": sha256(object_path), "architecture": "PE32 i386",
                     "imports": [], "instructions": instructions, "status": "executing"})
        require_non_elevated()
        if sha256(executable_path) != digest:
            raise RuntimeError("Fixture binary changed after validation; refusing execution.")
        native = run_command([str(executable_path)], timeout=5)
        case["native_process"] = native
        returned = native["return_code"] & 0xFFFFFFFF
        case.update({"native_return": returned, "native_hex": f"0x{returned:08x}", "native_elevated": False})
        if native["stdout"] or native["stderr"]:
            raise RuntimeError(f"{name}: import-free fixture unexpectedly produced output.")
        if (expected is not None and returned != expected) or (expected is None and returned > 0xFFFF):
            raise RuntimeError(f"{name}: unexpected process return 0x{returned:08x}; possible native fault.")
        emulated, image_hash = unicorn_return(pe)
        case.update({"unicorn_return": emulated, "unicorn_hex": f"0x{emulated:08x}",
                     "unicorn_input_executable_sha256": digest, "unicorn_mapped_image_sha256": image_hash})
        if expected is not None and emulated != expected:
            raise RuntimeError(f"{name}: Unicorn plumbing/default check returned 0x{emulated:08x}.")
        if requested is not None:
            case["matches_observed_host_rule"] = returned == ((requested & 0x1F3F) | 0x40)
        case["status"] = "measured"
    except Exception as error:
        case.update({"status": "failed", "error": str(error)})
        raise


def main() -> int:
    argparse.ArgumentParser(description=__doc__).parse_args()
    report = {"schema": 1, "captured_at_utc": datetime.now(timezone.utc).isoformat(), "status": "starting",
              "script": "tools/native_fpu_reference.py", "script_sha256": sha256(Path(__file__)),
              "host_os": platform.platform(), "host_architecture": platform.machine(),
              "host_processor": os.environ.get("PROCESSOR_IDENTIFIER"), "cases": [],
              "scope": "Authored PE32 fixtures only. Native observations characterize this host, not every x87 CPU or native Pentium III hardware.",
              "boundaries": {"inputs": "Assembly strings in this script and pinned local compiler tools; no game input.",
                             "outputs": "artifacts/native-fpu-control/ only; no installation files or machine settings modified."},
              "documentation": {"source_urls": SOURCE_URLS,
                                "intel_reserved_bits": "SDM section 1.3.2 says reserved bits are undefined/unpredictable; retaining written reserved bits is not guaranteed.",
                                "intel_control_word": "Volume 1 section 8.1.5 defines control fields and FNINIT default 0x037f. It does not establish our measured normalization mask for all processors."},
              "unicorn_profile": {"version": importlib.metadata.version("unicorn"), "cpu_model": "UC_CPU_X86_PENTIUM3",
                                  "scope": "Emulator profile only; not a measurement on physical Pentium III hardware."}}
    result_path = None
    try:
        require_non_elevated()
        report["elevated"] = False
        result_path = artifact_path("results.json")
        result_path.parent.mkdir(parents=True, exist_ok=True)
        report["tools"] = {}
        for name, command, binary in (("clang", [str(clang_path()), "--version"], clang_path()),
                                      ("lld", [*linker_command(), "--version"], linker_path())):
            version = run_command(command)
            if version["return_code"]:
                raise RuntimeError(f"Failed to query {name} version: {version['stderr']}")
            report["tools"][name] = {"version": version["stdout"].splitlines()[0], "sha256": sha256(binary)}
        report["dependencies"] = {name: importlib.metadata.version(name) for name in ("pefile", "capstone", "unicorn")}
        probe(report, "exit_constant", "mov eax, 0x12345678\nret", expected=0x12345678)
        probe(report, "fninit_default", "sub esp,8\nfninit\nfnstcw word ptr [esp+2]\nmovzx eax,word ptr [esp+2]\nadd esp,8\nret", expected=0x037F)
        for control in CONTROL_WORDS:
            probe(report, f"fldcw_{control:04x}",
                  f"sub esp,8\nfninit\nmov word ptr [esp],0x{control:04x}\nfldcw word ptr [esp]\n"
                  "fnstcw word ptr [esp+2]\nmovzx eax,word ptr [esp+2]\nfninit\nadd esp,8\nret", requested=control)
        report["observed_rule"] = "(input & 0x1f3f) | 0x40"
        report["native_rule_matches_all_cases"] = all(case.get("matches_observed_host_rule", True) for case in report["cases"])
        report["status"] = "measured"
    except Exception as error:
        report.update({"status": "failed", "error": str(error)})
    if result_path is not None:
        result_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    summary = {key: report[key] for key in ("status", "host_processor")}
    summary.update({"cases_measured": sum(case["status"] == "measured" for case in report["cases"]),
                    "native_rule_matches_all_cases": report.get("native_rule_matches_all_cases"),
                    "evidence": str(result_path) if result_path else None})
    if "error" in report:
        summary["error"] = report["error"]
    print(json.dumps(summary, indent=2))
    return 0 if report["status"] == "measured" else 1


if __name__ == "__main__":
    raise SystemExit(main())
