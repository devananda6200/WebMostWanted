"""Compile and execute standalone Wasm checks for the narrow Win32 API surface."""
from __future__ import annotations
from datetime import datetime, timezone
import json
import subprocess
from tools.toolchain import ROOT, compile_wasm, node_path, sha256


def main():
    output = ROOT / "build/win32-contract.cjs"
    compile_wasm(ROOT / "tests/win32_test.cpp", output, [
        "-I" + str(ROOT), "-std=c++17", "-O1", "-sENVIRONMENT=node",
        "-sINITIAL_MEMORY=83886080", "-sSTACK_SIZE=1048576", "-sASSERTIONS=2",
    ])
    command = [str(node_path()), str(output)]
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=60)
    observed = json.loads(result.stdout) if result.returncode == 0 else {}
    reference_path = ROOT / "artifacts/win32-nls-reference.json"
    comparison = {"status": "unverified", "reason": "Run tools.win32_nls_reference on Windows for the optional NLS oracle."}
    if observed and reference_path.exists():
        reference = json.loads(reference_path.read_text(encoding="utf-8"))
        if "multibyte_cases" in reference and "classification_cases" in reference:
            decode = next(c for c in reference["multibyte_cases"] if c["case"] == "all-bytes")["utf16_output"][:256]
            types = next(c for c in reference["classification_cases"] if c["case"] == "cp1252-ctype1")["ctype1_output"][:256]
            matched = observed["cp1252_decode"] == decode and observed["ctype1"] == types
            comparison = {"status": "passed" if matched else "failed", "compared_values": 512,
                          "reference_sha256": sha256(reference_path), "windows": reference["windows"],
                          "scope": "CP1252 decoding and CT_CTYPE1 for 256 characters; not a complete Windows or XP oracle"}
    report = {"captured_at_utc": datetime.now(timezone.utc).isoformat(), "command": command,
              "exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr,
              "wasm_sha256": sha256(output.with_suffix(".wasm")),
              "scope": "API contract tests in Node Wasm with optional native NLS repertoire comparison",
              "native_nls_comparison": comparison}
    path = ROOT / "artifacts/win32-contract-tests.json"
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if observed:
        print(json.dumps({"status": observed["status"], "groups": observed["groups"],
                          "native_nls_comparison": comparison}))
    else:
        print(result.stdout, end="")
    if result.returncode:
        print(result.stderr)
        raise SystemExit(result.returncode)
    if comparison["status"] == "failed":
        raise SystemExit("Wasm NLS repertoire differs from the captured native reference")
    print(f"Evidence: {path}")


if __name__ == "__main__":
    main()
