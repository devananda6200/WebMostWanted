"""Check export integrity against the original PE bytes, not decompiler semantics."""
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

import pefile

from inspect_inputs import BINARIES, GAME, ROOT, inventory, sha256


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def validate_binary(name):
    folder = ROOT / "recovered" / name
    summary = load(folder / "summary.json")
    digest = sha256(GAME / name)
    if summary["binary_sha256"].lower() != digest:
        raise ValueError(f"Input identity mismatch: {name}")
    functions = list(csv.DictReader((folder / "functions.tsv").open(encoding="utf-8", newline=""), delimiter="\t"))
    if len(functions) != summary["functions_attempted"]:
        raise ValueError(f"Function count mismatch: {name}")
    addresses = set()
    succeeded = 0
    for function in functions:
        address = function["address"]
        if address in addresses:
            raise ValueError(f"Duplicate function address: {name}:{address}")
        addresses.add(address)
        code = (folder / function["file"]).resolve()
        if not code.is_relative_to(folder.resolve()):
            raise ValueError("Export path escapes its binary directory")
        content = code.read_text(encoding="utf-8")
        if "AUTO-DECOMPILED RECONSTRUCTION" not in content or f"Address: {address} |" not in content:
            raise ValueError(f"Missing provenance header: {code}")
        succeeded += function["status"] == "decompiled_unverified"
    if succeeded != summary["functions_decompiled"] or len(functions) - succeeded != summary["functions_failed"]:
        raise ValueError(f"Decompilation status mismatch: {name}")
    if len(list((folder / "functions").glob("*.c"))) != len(functions):
        raise ValueError(f"Missing or stale function files: {name}")
    with pefile.PE(str(GAME / name)) as pe:
        image = pe.get_memory_mapped_image()
        base = pe.OPTIONAL_HEADER.ImageBase
        count = 0
        matched_bytes = 0
        with (folder / "disassembly.tsv").open(encoding="utf-8", newline="") as stream:
            for item in csv.DictReader(stream, delimiter="\t"):
                offset = int(item["address"], 16) - base
                expected = bytes.fromhex(item["bytes_hex"])
                if offset < 0 or image[offset:offset + len(expected)] != expected:
                    raise ValueError(f"Instruction bytes differ: {name}:{item['address']}")
                count += 1
                matched_bytes += len(expected)
    if count != summary["instructions"]:
        raise ValueError(f"Instruction count mismatch: {name}")
    metadata = load(ROOT / "evidence" / name / "pe.json")
    for item in metadata["sections"] + metadata["resources"]:
        if sha256(ROOT / "evidence" / name / item["file"]) != item["sha256"]:
            raise ValueError(f"Extracted section/resource changed: {name}:{item['file']}")
    return {"file": name, "sha256": digest, "function_files": len(functions),
            "decompiled": succeeded, "failed": len(functions) - succeeded,
            "instructions_matching_input_bytes": count, "instruction_bytes_matched": matched_bytes,
            "source_equivalence_tested": False, "compilability_tested": False}


def main():
    baseline = load(ROOT / "evidence" / "input_inventory.json")["files"]
    current = inventory()
    if baseline != current:
        raise ValueError("Original input files changed since baseline")
    binaries = [validate_binary(name) for name in BINARIES]
    result = {"created_utc": datetime.now(timezone.utc).isoformat(),
              "status": "export_integrity_passed", "all_original_files_unchanged": True,
              "original_files_checked": len(current), "binaries": binaries,
              "limitation": "These are input/output integrity checks, not proof of correct or complete recovered source."}
    (ROOT / "evidence" / "validation.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
