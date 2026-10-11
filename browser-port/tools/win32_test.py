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
            if "mapping_cases" in reference and "individual_case_mappings" in reference:
                for flags, key in ((0x100, "lowercase"), (0x200, "uppercase")):
                    expected = []
                    for locale in (0, 0x409, 0x7f):
                        case = next(c for c in reference["mapping_cases"] if c["case"] == f"repertoire-{locale:x}-{flags:x}")
                        expected.extend(case["utf16_output"][:256])
                    individual = next(c for c in reference["individual_case_mappings"] if c["flags"] == flags)
                    matched = matched and observed[key] == expected and individual["lengths"] == [1] * 256
                    matched = matched and [c[0] for c in individual["mapped"]] == expected[:256]
                comparison.update(status="passed" if matched else "failed", compared_values=2048,
                                  scope="CP1252 decode/classification and lower/uppercase at locales 0, 0x409, 0x7f; historical XP equivalence unverified")
            bestfit = [c for c in reference["cases"] if c["case"].startswith("f-hook-")]
            if len(bestfit) == 8 and "bestfit_observations" in observed:
                fields = ("return", "used_default", "last_error", "output_hex")
                expected = [{key: c[key] for key in fields} for c in bestfit]
                matched = matched and observed["bestfit_observations"] == expected
                comparison.update(status="passed" if matched else "failed", bestfit_cases=8)
    heap_reference_path = ROOT / "artifacts/heap-realloc-reference.json"
    heap_comparison = {"status": "unverified", "reason": "Optional authored native heap probe has not been captured."}
    if observed and heap_reference_path.exists():
        heap_reference = json.loads(heap_reference_path.read_text(encoding="utf-8"))
        heap_comparison = {"status": "passed" if observed.get("heap_realloc_observations") == heap_reference["cases"] else "failed",
                           "compared_cases": len(heap_reference["cases"]), "reference_sha256": sha256(heap_reference_path),
                           "windows": heap_reference["windows"], "scope": heap_reference["scope"]}
    report = {"captured_at_utc": datetime.now(timezone.utc).isoformat(), "command": command,
              "exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr,
              "wasm_sha256": sha256(output.with_suffix(".wasm")),
              "scope": "API contract tests in Node Wasm with optional native NLS repertoire comparison",
              "native_nls_comparison": comparison, "native_heap_realloc_comparison": heap_comparison}
    path = ROOT / "artifacts/win32-contract-tests.json"
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if observed:
        print(json.dumps({"status": observed["status"], "groups": observed["groups"],
                          "native_nls_comparison": comparison, "native_heap_realloc_comparison": heap_comparison}))
    else:
        print(result.stdout, end="")
    if result.returncode:
        print(result.stderr)
        raise SystemExit(result.returncode)
    if comparison["status"] == "failed":
        raise SystemExit("Wasm NLS repertoire differs from the captured native reference")
    if heap_comparison["status"] == "failed":
        raise SystemExit("Wasm HeapReAlloc observations differ from the captured native reference")
    print(f"Evidence: {path}")


if __name__ == "__main__":
    main()
