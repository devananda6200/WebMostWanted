"""Observe trusted Windows heap APIs using authored private-heap allocations."""
from __future__ import annotations

import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

from tools.toolchain import ROOT, sha256


def main():
    if sys.platform != "win32":
        raise SystemExit("This optional heap reference probe requires native Windows.")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.HeapCreate.argtypes = [wintypes.DWORD, ctypes.c_size_t, ctypes.c_size_t]
    kernel.HeapCreate.restype = ctypes.c_void_p
    kernel.HeapAlloc.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_size_t]
    kernel.HeapAlloc.restype = ctypes.c_void_p
    kernel.HeapReAlloc.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, ctypes.c_size_t]
    kernel.HeapReAlloc.restype = ctypes.c_void_p
    kernel.HeapSize.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p]
    kernel.HeapSize.restype = ctypes.c_size_t
    kernel.HeapDestroy.argtypes = [ctypes.c_void_p]
    kernel.HeapDestroy.restype = wintypes.BOOL
    kernel.GetModuleFileNameW.argtypes = [ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD]
    kernel.GetModuleFileNameW.restype = wintypes.DWORD

    module_path = ctypes.create_unicode_buffer(32768)
    length = kernel.GetModuleFileNameW(kernel._handle, module_path, len(module_path))
    if not length:
        raise OSError(f"Cannot identify loaded kernel32: {ctypes.WinError(ctypes.get_last_error())}")
    if length >= len(module_path):
        raise RuntimeError("Loaded kernel32 path exceeds the identification buffer")
    report = {"captured_at_utc": datetime.now(timezone.utc).isoformat(),
              "command": [sys.executable, "-m", "tools.win32_heap_reference"],
              "python": sys.version, "windows": str(sys.getwindowsversion()),
              "pointer_bits": ctypes.sizeof(ctypes.c_void_p) * 8,
              "kernel32_path": module_path.value, "kernel32_sha256": sha256(Path(module_path.value)),
              "scope": "Host private heap and authored bytes; historical XP behavior unverified", "cases": []}
    heap = kernel.HeapCreate(0, 65536, 65536)
    if not heap:
        raise OSError(f"HeapCreate failed for the private 64 KiB probe heap: {ctypes.WinError(ctypes.get_last_error())}")
    try:
        for initial, flags, requested in ((13, 0, 0), (13, 8, 0), (13, 8, 15), (13, 8, 9)):
            block = kernel.HeapAlloc(heap, 0, initial)
            if not block:
                raise RuntimeError(f"HeapAlloc failed for {initial} authored bytes; this API does not set last error")
            ctypes.memset(block, 0xA5, initial)
            ctypes.set_last_error(777)
            result = kernel.HeapReAlloc(heap, flags, block, requested)
            error = ctypes.get_last_error()
            if not result:
                raise RuntimeError(f"HeapReAlloc failed for flags={flags:#x}, size={requested}; this API does not set last error")
            size = kernel.HeapSize(heap, 0, result)
            if size == ctypes.c_size_t(-1).value:
                raise RuntimeError(f"HeapSize rejected a successful HeapReAlloc result for size={requested}")
            if size < requested:
                raise RuntimeError(f"HeapSize reported {size} bytes after requesting {requested}; refusing an out-of-range read")
            report["cases"].append({"initial_size": initial, "flags": flags, "requested": requested,
                                    "returned_nonnull": True, "reported_size": size,
                                    "last_error": error, "bytes": list(ctypes.string_at(result, requested))})
    finally:
        if not kernel.HeapDestroy(heap):
            raise OSError(f"HeapDestroy failed while releasing the private probe heap: {ctypes.WinError(ctypes.get_last_error())}")
    output = ROOT / "artifacts/heap-realloc-reference.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Recorded {len(report['cases'])} native system heap cases: {output}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError) as exc:
        raise SystemExit(f"Native heap reference failed: {exc}") from exc
