"""Observe trusted system Win32 NLS calls on authored strings, never game code."""
from __future__ import annotations

import ctypes
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

from tools.toolchain import ROOT, sha256


def main():
    if sys.platform != "win32":
        raise SystemExit("This optional reference probe requires native Windows.")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    convert = kernel.WideCharToMultiByte
    convert.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p,
                       ctypes.c_int, ctypes.c_void_p, ctypes.c_int,
                       ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]
    convert.restype = ctypes.c_int
    extended = [0x20ac, 0x81, 0x201a, 0x192, 0x201e, 0x2026, 0x2020, 0x2021,
                0x2c6, 0x2030, 0x160, 0x2039, 0x152, 0x8d, 0x17d, 0x8f,
                0x90, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2013, 0x2014,
                0x2dc, 0x2122, 0x161, 0x203a, 0x153, 0x9d, 0x17e, 0x178]
    cases = [
        ("nul-size-query", [0], 0, 1, 0, None),
        ("ascii-prefix", [65, 66, 67], 0, 3, 2, None),
        ("default-outside-prefix", [65, 66, 0x2603], 0x400, 3, 2, None),
        ("default-inside-prefix", [0x2603, 65, 66], 0x400, 3, 2, None),
        ("custom-default", [0x2603, 65], 0x400, 2, 8, b"!"),
        ("default-size-query", [0x2603, 65], 0x400, 2, 0, None),
        ("literal-question", [63], 0x400, 1, 8, None),
        ("exact-extended-repertoire", extended, 0x400, len(extended), len(extended), None),
        ("terminated-length", [65, 66, 0], 0, -1, 8, None),
        # Recorded as a host observation, not a promise of XP compatibility.
        ("undocumented-negative-length", [65, 66, 0], 0, -2, 0, None),
        ("negative-capacity", [65], 0, 1, -1, None),
    ]
    results = []
    for name, units, flags, count, capacity, default in cases:
        wide = (ctypes.c_uint16 * (len(units) + 1))(*units, 0)
        output_size = max(capacity, 8) + 8
        output = (ctypes.c_ubyte * output_size)(*([0xcc] * output_size))
        used = ctypes.c_int(99)
        ctypes.set_last_error(777)
        value = convert(1252, flags, wide, count, output, capacity, default, ctypes.byref(used))
        results.append({"case": name, "code_page": 1252, "utf16_units": units,
                        "flags": flags, "count": count, "capacity": capacity,
                        "default": default.hex() if default else None,
                        "return": value, "output_hex": bytes(output).hex(),
                        "used_default": used.value, "last_error": ctypes.get_last_error()})
    info = (ctypes.c_ubyte * 20)(*([0xcc] * 20))
    kernel.GetCPInfo.argtypes = [ctypes.c_uint, ctypes.c_void_p]
    info_return = kernel.GetCPInfo(1252, info)
    inverse = kernel.MultiByteToWideChar
    inverse.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p,
                        ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
    inverse.restype = ctypes.c_int
    inverse_results = []
    for name, raw, flags, count, capacity in [
        ("all-bytes", bytes(range(256)), 0, 256, 256),
        ("all-bytes-strict", bytes(range(256)), 8, 256, 256),
        ("terminated-query", b"A\x80\0", 0, -1, 0),
        ("explicit-embedded-nul", b"A\0B", 1, 3, 4),
        ("partial-buffer", b"ABC", 0, 3, 2),
        ("negative-capacity", b"A", 0, 1, -1),
    ]:
        source = ctypes.create_string_buffer(raw)
        output = (ctypes.c_uint16 * (max(capacity, 4) + 4))(*([0xcccc] * (max(capacity, 4) + 4)))
        ctypes.set_last_error(777)
        value = inverse(1252, flags, source, count, output, capacity)
        inverse_results.append({"case": name, "source_hex": raw.hex(), "flags": flags,
                                "count": count, "capacity": capacity, "return": value,
                                "utf16_output": list(output), "last_error": ctypes.get_last_error()})
    repertoire = list(range(128)) + extended + list(range(160, 256))
    classify = kernel.GetStringTypeW
    classify.argtypes = [ctypes.c_uint, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
    classify.restype = ctypes.c_int
    classification = []
    for name, units, count in [
        ("cp1252-ctype1", repertoire, 256),
        ("nul", [0], 1), ("terminated", [65, 9, 0], -1),
        ("other-negative", [65, 9, 0], -2), ("zero-length", [0], 0),
    ]:
        source = (ctypes.c_uint16 * (len(units) + 1))(*units, 0)
        output = (ctypes.c_uint16 * (len(units) + 1))(*([0xcccc] * (len(units) + 1)))
        ctypes.set_last_error(777)
        value = classify(1, source, count, output)
        classification.append({"case": name, "utf16_units": units, "count": count,
                               "return": value, "ctype1_output": list(output),
                               "last_error": ctypes.get_last_error()})
    module_name = ctypes.create_unicode_buffer(32768)
    kernel.GetModuleFileNameW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint]
    if not kernel.GetModuleFileNameW(kernel._handle, module_name, len(module_name)):
        raise ctypes.WinError(ctypes.get_last_error())
    path = Path(module_name.value)
    report = {"captured_at_utc": datetime.now(timezone.utc).isoformat(),
              "command": [sys.executable, "-m", "tools.win32_nls_reference"],
              "python": sys.version, "windows": str(sys.getwindowsversion()),
              "kernel32_path": str(path), "kernel32_sha256": sha256(path),
              "scope": "Trusted host Windows NLS APIs and authored strings only; no game/native executable execution. Current host observations do not establish all XP semantics.",
              "get_cp_info": {"return": info_return, "raw_20_bytes": bytes(info).hex()},
              "cases": results, "multibyte_cases": inverse_results,
              "classification_cases": classification}
    destination = ROOT / "artifacts/win32-nls-reference.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Recorded {len(results)+len(inverse_results)+len(classification)} native system-API observations: {destination}")


if __name__ == "__main__":
    main()
